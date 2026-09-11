//! 非流单元（2.2）：一发一收，超时/不可达映射为网关级错误而非挂起。

use {
    super::{
        empty_body_response,
        forward_headers,
        protocol_header_value,
        pump::now_secs,
        should_pump_stream,
    },
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            audit::AuditPolicy,
            block_inject,
            credential_vault::CredentialVault,
            llm_gateway::{
                self,
                EmptyAction,
                GatewayMetrics,
                Protocol,
                classify_empty,
                extract_usage_nonstream,
            },
            metrics::{ChatRecord, MetricsStore},
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    axum::{
        Json,
        body::Body,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::Value,
    std::{path::PathBuf, sync::Arc, time::Instant},
};

/// 2.2 `nonstream` 一发一收的上下文：显式传入的请求级依赖快照。
/// `req_start`/`sqlite_precise` 以快照值传入，保持 `record_chat` 快照语义。
pub struct NonstreamCtx {
    pub protocol: Protocol,
    pub normalized_out: bool,
    pub stream_flag: bool,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub audit_mode: AuditMode,
    pub audit_policy_file: Option<PathBuf>,
    /// T1/P2-1：非流审计白名单（与流式 `StreamPumpCtx.approval_whitelist` 同口径，
    /// `AUDIT_MODE=approve` 空白名单降级 block；生产非空由启动门禁保证，
    /// 见 `src/config/env_parse.rs:307-310`）。
    pub approval_whitelist: Vec<String>,
    /// 非流 approve 建单表（P0-1.4：`NeedApproval` 记 pending，不断链）。
    pub pending: Arc<PendingApprovals>,
    /// F2：非流对话响应体上限（`NONSTREAM_MAX_BYTES`，严格超限 502）。
    pub nonstream_max_bytes: usize,
}

/// `serve_nonstream` 的结果：完整响应，或上游意外回 SSE 时把未消费的
/// `reqwest::Response` 连同请求会话标识交回调用方转流泵（原 `looks_sse` 语义；
/// E12/D7：泵内终端帧复用请求会话，不再空值合成）。
pub enum NonstreamOutcome {
    Responded(Response),
    Stream(reqwest::Response, Option<String>),
}

/// 2.2 `nonstream` 一发一收：接收改写后请求，返回完整上游响应；
/// 上游超时/不可达映射为网关级错误状态码而非挂起。
/// `client` 为只读引用（单例由 1.x 负责），本单元内不新建 Client。
pub async fn serve_nonstream(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    ctx: NonstreamCtx,
) -> NonstreamOutcome {
    let fwd_headers = forward_headers(&headers, &ctx.gateway_metrics);
    // E12/D7：转泵用请求会话标识（fetch 会 move `body`，须提前提取）。
    let req_conv = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| llm_gateway::extract_conv_id(&v));
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return NonstreamOutcome::Responded(empty_body_response()),
    };
    if llm_gateway::is_passthrough(ctx.protocol) {
        // P0-4.2/F1：非对话臂保持字节透传（与 Python 直通语义一致：无用量/
        // 审计/还原），记 `nondialog_passthrough` 供流量验证；若需补还原另立任务。
        ctx.gateway_metrics.record_nondialog_passthrough();
        let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        let mut resp_headers = HeaderMap::new();
        for (k, v) in up.headers().iter() {
            if let (Ok(n), Ok(val)) = (
                k.to_string().parse::<axum::http::HeaderName>(),
                axum::http::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                resp_headers.insert(n, val);
            }
        }
        // M1/D4：解码与剥头配对——tower-http 仅在实际解压成功后移除
        // `content-encoding`；该头仍在 ⇒ 未解压（不支持编码/别名/多值），
        // 保留编码头与压缩字节供下游自解，不得剥头造成「无编码头 + 压缩字节」。
        let decode_enabled = llm_gateway::downstream_decode_enabled(up.headers());
        llm_gateway::filter_hop_headers_counted(
            &mut resp_headers,
            "downstream",
            decode_enabled,
            Some(&ctx.gateway_metrics),
        );
        for (k, v) in resp_headers.iter() {
            builder = builder.header(k, v);
        }
        return NonstreamOutcome::Responded(
            builder
                .body(Body::from_stream(up.bytes_stream()))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response()),
        );
    }
    // P0-1.1 + N2/D6：502/401 不再早返原始字节，走完整后处理链（用量记录 +
    // 审计判定 + 凭据/PII 还原，还原失败回退原文）；所有 4xx/5xx 的非 JSON
    // 错误体按下文显式豁免透传（无 JSON 可提取用量/工具调用，见尾部
    // `is_error_status` 分支），不再合成 502 `E_EMPTY_BODY`。
    let status_u16 = up.status().as_u16();
    let is_error_status = status_u16 >= 400;
    let resp_ct = up
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let looks_sse = should_pump_stream(&resp_ct, ctx.stream_flag);
    if looks_sse {
        // E12/D7：转泵时透传请求会话标识（泵内终端帧复用，不断审计链）；
        // 缺失则为 None，由调用方回退合成并记 `conv_missing`。
        return NonstreamOutcome::Stream(up, req_conv);
    }
    let bytes = up.bytes().await.unwrap_or_default();
    let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
    // F2/D2：先定空体分类（对齐 Python 先算 `_is_empty`），再判超限
    // （严格 `len > cap`，体形态对齐 `_llm.py:2942`），最后才落空体 502：
    // 空体 len=0 恒不超限，非 JSON 超限体不落空体分支（与 Python 可观测结果一致）。
    // 精化：超限仅对非错误状态（`status < 400`）生效——4xx/5xx 错误体按 N2/D6
    // 语义透传或走完整链，不因体大被改写为 502。
    let empty_action = classify_empty(true, bytes.len(), is_json, status_u16);
    if status_u16 < 400 && bytes.len() > ctx.nonstream_max_bytes {
        return NonstreamOutcome::Responded(oversize_response());
    }
    if empty_action == EmptyAction::NonStreamTo502 {
        return NonstreamOutcome::Responded(empty_body_response());
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        let usage = extract_usage_nonstream(ctx.protocol, &v);
        // C13：模型分桶取上游回显值（缺失归 `unknown_model`）。
        let upstream_model = v.get("model").and_then(|m| m.as_str()).unwrap_or("");
        ctx.admin_metrics.record_chat(ChatRecord {
            protocol: ctx.protocol,
            model: upstream_model,
            latency_ms: ctx.req_start.elapsed().as_millis() as u64,
            usage: usage.as_ref(),
            truncated_mode: None,
            is_precise: ctx.sqlite_precise,
            ts_secs: now_secs(),
        });
        // 非流 tool 提取 + 审计（§2.3）：阻断时返回协议正确的 block 体代替上游响应。
        let audit_policy = match ctx.audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let conv_id = llm_gateway::extract_conv_id(&v).unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(None, &v, Some(&ctx.gateway_metrics), "nonstream-block").0
        });
        // T1/P2-1：白名单随 ctx 显式注入，与流式 `evaluate_with_whitelist` 同口径。
        let blocked = block_inject::evaluate_nonstream(
            ctx.protocol,
            &v,
            ctx.audit_mode,
            &audit_policy,
            &conv_id,
            &ctx.approval_whitelist,
            &ctx.pending,
        );
        if let Some(block_body) = blocked {
            // T3/D3：审计命中统一记 `audit_blocks` 列（含错误状态不合成阻断体的场景）。
            ctx.admin_metrics
                .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 1);
            if status_u16 < 300 {
                // E4：2xx 非流阻断恒 200（与流式恒 200 闭合对称，不再沿用上游码）。
                let mut resp = (StatusCode::OK, Json(block_body)).into_response();
                if ctx.normalized_out {
                    resp.headers_mut().insert(
                        "x-veil-normalized",
                        header::HeaderValue::from_static("json-whitespace"),
                    );
                }
                resp.headers_mut().insert(
                    "x-veil-protocol",
                    header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
                );
                return NonstreamOutcome::Responded(resp);
            }
            // T3/D3：错误状态（4xx/5xx）不合成阻断体，保留上游状态与正文，审计照记
            // （日志 + 指标）；危险调用落入错误响应不构成实际执行，合成 200 会掩盖
            // 故障并误导下游（README §7.2 声明背书）。
            tracing::warn!(
                status = status_u16,
                protocol = ?ctx.protocol,
                "非流上游错误状态审计命中 Block，保留上游状态与正文（不合成 200 阻断体）"
            );
        } else {
            ctx.admin_metrics
                .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 0);
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (restored, spans) = ctx.scope.restore_response_with_spans(&ctx.vault, &text);
        let mut restored = ctx
            .scope
            .redact_response_new_pii_with_skip(&ctx.vault, &ctx.detector, &restored, &spans)
            .await;
        // P0-1.2：还原后双 `_jloads` 校验（对标 Python `_nonstream_build`）：
        // 还原/脱敏可能把未转义明文写回 JSON 串内致破裂；E5/D3 先 `strip_partials`
        // 重试一次（半截形态可挽回时用剥离体），仍失败才回退上游原文并记 metrics + warn。
        if serde_json::from_str::<Value>(&restored).is_err() {
            if let Some(stripped) = retry_stripped(&restored) {
                tracing::warn!("非流还原后 JSON 校验失败，残缺剥离后挽回");
                restored = stripped;
            } else {
                let preview: String = restored.chars().take(4000).collect();
                tracing::warn!("非流还原后 JSON 校验失败，已回退上游原文: {preview}");
                ctx.gateway_metrics.record_restore_fallback();
                restored = text;
            }
        }
        // P0-1.3：出口显式残缺剥离（凭据 `__VG_CRED_` + PII `__PII_` 半截形态）。
        // 还原/脱敏路径内已带剥离，此处幂等兜底响应侧关闭等旁路。
        let restored = crate::service::redaction::strip_partials(&restored);
        let mut resp = (
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
            restored,
        )
            .into_response();
        if ctx.normalized_out {
            resp.headers_mut().insert(
                "x-veil-normalized",
                header::HeaderValue::from_static("json-whitespace"),
            );
        }
        resp.headers_mut().insert(
            "x-veil-protocol",
            header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
        );
        return NonstreamOutcome::Responded(resp);
    }
    // N2/D6 显式豁免：`status>=400` 的非 JSON 错误体（含空体）走此透传
    //（无用量/工具调用可提取，按设计备选路径原样透传，状态码与正文字节保留，
    // 不吞错转空体）；`status>=400` 的错误 JSON（如 400 `truncation:disabled`）
    // 已在上方 `if let Ok(v)` 分支走完整后处理链（用量记录 + 审计判定 + 还原），
    // 非字节等价为有意行为。
    if is_error_status {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        return NonstreamOutcome::Responded((status, bytes.to_vec()).into_response());
    }
    NonstreamOutcome::Responded(empty_body_response())
}

/// E5/D3 重试判定（纯函数）：还原体破裂时剥离残缺形态，剥离后可解析则返回
/// 剥离体（挽回），否则返回 `None`（调用方回退上游原文）。
fn retry_stripped(restored: &str) -> Option<String> {
    let stripped = crate::service::redaction::strip_partials(restored);
    serde_json::from_str::<Value>(&stripped)
        .is_ok()
        .then_some(stripped)
}

/// F2：对话非流响应体超限 502（体形态与 Python `_llm.py:2942` 同字）。
fn oversize_response() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "error": {"message": "response too large", "type": "response_too_large"}
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests;
