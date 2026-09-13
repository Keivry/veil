//! 非流单元（2.2）：一发一收，超时/不可达映射为网关级错误而非挂起。

use {
    super::{
        empty_body_response,
        forward_headers,
        protocol_header_value,
        pump::now_secs,
        should_pump_stream,
        with_protocol_header,
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
    /// A1/D1：审计落盘单例（verdict 命中/放行经 `spawn_blocking` 写 JSONL）。
    pub audit_sink: Arc<crate::service::audit::AuditSink>,
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
        Err(_) => return NonstreamOutcome::Responded(empty_body_response(ctx.protocol)),
    };
    if llm_gateway::is_passthrough(ctx.protocol) {
        // P0-4.2/F1：非对话臂保持字节透传（与 Python 直通语义一致：无用量/
        // 审计/还原），记 `nondialog_passthrough` 供流量验证；专用入口
        // `serve_nondialog_passthrough` 与之共用本装配函数（H11/D11）。
        return NonstreamOutcome::Responded(passthrough_upstream_response(
            up,
            &ctx.gateway_metrics,
        ));
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
    let resp_headers = snapshot_downstream_headers(&up, &ctx.gateway_metrics);
    // T4/D4：`content-length` 预检（仅 `status<400`）——声明值严格超限时立即 502
    // 且不读 body，避免 `bytes()` 无界读入；`len == cap` 放行。
    if status_u16 < 400
        && up
            .content_length()
            .is_some_and(|n| n > ctx.nonstream_max_bytes as u64)
    {
        return NonstreamOutcome::Responded(oversize_response(ctx.protocol));
    }
    // T4/D4：无 `content-length`/分块场景改用有界累计读取，累计超限即停读并 502；
    // `status>=400` 错误体维持既有全量透传语义（不受上限改写）。
    let bytes = if status_u16 < 400 {
        match read_bounded_body(up, ctx.nonstream_max_bytes).await {
            BoundedBody::Complete(b) => b,
            BoundedBody::Oversize => {
                return NonstreamOutcome::Responded(oversize_response(ctx.protocol));
            }
        }
    } else {
        up.bytes().await.unwrap_or_default().to_vec()
    };
    let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
    // F2/D2：先定空体分类（对齐 Python 先算 `_is_empty`），再判超限
    // （严格 `len > cap`，体形态对齐 `_llm.py:2942`），最后才落空体 502：
    // 空体 len=0 恒不超限，非 JSON 超限体不落空体分支（与 Python 可观测结果一致）。
    // 精化：超限仅对非错误状态（`status < 400`）生效——4xx/5xx 错误体按 N2/D6
    // 语义透传或走完整链，不因体大被改写为 502。超限动作已由上方有界读取前置，
    // 本处仅保留空体分类判序。
    let empty_action = classify_empty(true, bytes.len(), is_json, status_u16);
    if empty_action == EmptyAction::NonStreamTo502 {
        return NonstreamOutcome::Responded(empty_body_response(ctx.protocol));
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
        // H3/D3：运行时加载并捕获进程 env 快照（判定纯逻辑零 env 直读）。
        let audit_policy = AuditPolicy::load_for_runtime(ctx.audit_policy_file.as_deref());
        // A1/D1：非流逐 tool verdict 命中/放行经单例落盘（与流式同口径；
        // `Block` 即止，与紧随的 `evaluate_nonstream` 决策一致）。
        if !matches!(ctx.audit_mode, AuditMode::Off) {
            let proto = protocol_header_value(ctx.protocol);
            for call in llm_gateway::extract_tool_calls(ctx.protocol, &v) {
                let name = call.name.as_deref().unwrap_or("");
                let verdict = ctx
                    .audit_sink
                    .evaluate_and_record(
                        ctx.audit_mode,
                        name,
                        &call.args,
                        &audit_policy,
                        &ctx.approval_whitelist,
                        Some(proto),
                    )
                    .await;
                if matches!(verdict, crate::service::audit::AuditVerdict::Block { .. }) {
                    break;
                }
            }
        }
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
        // T6/D6：与流式帧同源，用 JSON 转义变体还原（明文含 `"`/`\`/控制字符时
        // 写回仍为合法 JSON，不再破帧后回退上游原文泄漏占位符）。
        let (restored, spans) = ctx
            .scope
            .restore_response_with_spans_json(&ctx.vault, &text);
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
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK);
        return NonstreamOutcome::Responded(build_downstream_response(
            status,
            &resp_headers,
            restored.into_bytes(),
            ctx.protocol,
            ctx.normalized_out,
            Some("application/json"),
        ));
    }
    // N2/D6 显式豁免：`status>=400` 的非 JSON 错误体（含空体）走此透传
    //（无用量/工具调用可提取，按设计备选路径原样透传，状态码与正文字节保留，
    // 不吞错转空体）；`status>=400` 的错误 JSON（如 400 `truncation:disabled`）
    // 已在上方 `if let Ok(v)` 分支走完整后处理链（用量记录 + 审计判定 + 还原），
    // 非字节等价为有意行为。
    if is_error_status {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        return NonstreamOutcome::Responded(build_downstream_response(
            status,
            &resp_headers,
            bytes.to_vec(),
            ctx.protocol,
            false,
            None,
        ));
    }
    NonstreamOutcome::Responded(empty_body_response(ctx.protocol))
}

/// H11/D11：NonDialog 专用透传入口——类型即契约（返回 `Response`，无 `Stream` 臂），
/// 非对话臂不再经 `serve_nonstream` 的 `NonstreamOutcome` 分派；与兼容分支共用
/// [`passthrough_upstream_response`] 装配，字节语义不变。
pub async fn serve_nondialog_passthrough(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    protocol: Protocol,
    metrics: &GatewayMetrics,
) -> Response {
    let fwd_headers = forward_headers(&headers, metrics);
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return empty_body_response(protocol),
    };
    passthrough_upstream_response(up, metrics)
}

/// H11/D11：NonDialog 透传响应装配（计数 + hop 过滤 + 字节流），供专用入口与
/// `serve_nonstream` 的 `is_passthrough` 兼容分支单一复用。
fn passthrough_upstream_response(up: reqwest::Response, metrics: &GatewayMetrics) -> Response {
    metrics.record_nondialog_passthrough();
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
        Some(metrics),
    );
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from_stream(up.bytes_stream()))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// T4/D4：非流响应体有界读取结果——完整体或累计超限（调用方转 502）。
enum BoundedBody {
    Complete(Vec<u8>),
    Oversize,
}

/// T4/D4：以 `chunk()` 有界累计读取上游 body，累计超过 `cap` 立即停止并返回
/// `Oversize`（不先全量缓存）；读取错误与既有 `up.bytes().await.unwrap_or_default()`
/// 同口径退化为空体，交空体分类处置。
async fn read_bounded_body(mut up: reqwest::Response, cap: usize) -> BoundedBody {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match up.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len().saturating_add(chunk.len()) > cap {
                    return BoundedBody::Oversize;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return BoundedBody::Complete(buf),
            Err(_) => return BoundedBody::Complete(Vec::new()),
        }
    }
}

/// E5/D3 重试判定（纯函数）：还原体破裂时剥离残缺形态，剥离后可解析则返回
/// 剥离体（挽回），否则返回 `None`（调用方回退上游原文）。
fn retry_stripped(restored: &str) -> Option<String> {
    let stripped = crate::service::redaction::strip_partials(restored);
    serde_json::from_str::<Value>(&stripped)
        .is_ok()
        .then_some(stripped)
}

/// T2/D2：消费上游 body 前快照响应头，经逐跳过滤后剥除上游 `x-veil-*`
/// （网关自有同名头在转发后覆盖写入，上游声明不得生效）。
fn snapshot_downstream_headers(up: &reqwest::Response, metrics: &GatewayMetrics) -> HeaderMap {
    let mut resp_headers = HeaderMap::new();
    for (k, v) in up.headers().iter() {
        if let (Ok(n), Ok(val)) = (
            k.to_string().parse::<axum::http::HeaderName>(),
            axum::http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            resp_headers.insert(n, val);
        }
    }
    let decode_enabled = llm_gateway::downstream_decode_enabled(up.headers());
    llm_gateway::filter_hop_headers_counted(
        &mut resp_headers,
        "downstream",
        decode_enabled,
        Some(metrics),
    );
    let veil_keys: Vec<axum::http::HeaderName> = resp_headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-veil-"))
        .cloned()
        .collect();
    for k in veil_keys {
        resp_headers.remove(&k);
    }
    resp_headers
}

/// T2/D2：按上游快照头构造下游响应；`default_content_type` 仅在上游缺
/// `content-type` 时回退（JSON 后处理分支回退 `application/json`）。
fn build_downstream_response(
    status: StatusCode,
    resp_headers: &HeaderMap,
    body: Vec<u8>,
    protocol: Protocol,
    normalized_out: bool,
    default_content_type: Option<&str>,
) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    if let Some(ct) = default_content_type
        && !resp_headers.contains_key(header::CONTENT_TYPE)
    {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    if normalized_out {
        builder = builder.header("x-veil-normalized", "json-whitespace");
    }
    builder
        .header("x-veil-protocol", protocol_header_value(protocol))
        .body(Body::from(body))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// F2：对话非流响应体超限 502（体形态与 Python `_llm.py:2942` 同字）。
/// `S6` 复用：流式上游非 SSE/错误体同样受 `NONSTREAM_MAX_BYTES` 约束。
pub(crate) fn oversize_response(protocol: Protocol) -> Response {
    with_protocol_header(
        (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": {"message": "response too large", "type": "response_too_large"}
            })),
        )
            .into_response(),
        protocol,
    )
}

#[cfg(test)]
mod tests;
