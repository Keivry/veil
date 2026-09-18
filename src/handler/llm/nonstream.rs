//! 非流单元（2.2）：一发一收，超时/不可达映射为网关级错误而非挂起。

use {
    super::{
        empty_body_response,
        forward_headers,
        protocol_header_value,
        pump::{RequestCtx, now_secs},
        should_pump_stream,
        with_protocol_header,
    },
    crate::{
        config::AuditMode,
        error::VeilError,
        service::{
            block_inject,
            json_walk,
            llm_gateway::{
                self,
                EmptyAction,
                GatewayMetrics,
                Protocol,
                classify_empty,
                extract_usage_nonstream,
            },
            metrics::ChatRecord,
            redaction::{
                leaf::{NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE, PROTOCOL_HEADER_NAME},
                restore_guard::restore_guard_ok,
            },
        },
    },
    axum::{
        Json,
        body::Body,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::Value,
};

/// 2.2 `nonstream` 一发一收的上下文：共享请求上下文 + 非流专属字段。
/// `req_start`/`sqlite_precise` 以快照值传入（见 [`RequestCtx`]），保持 `record_chat` 快照语义。
pub struct NonstreamCtx {
    /// ARH-3（7.2）：与 `StreamPumpCtx` 共享的请求级字段（单一装配点构造）。
    pub req: RequestCtx,
    /// 客户端是否要求流式（`stream: true`）。
    pub stream_flag: bool,
    /// F2：非流对话响应体上限（`NONSTREAM_MAX_BYTES`，严格超限 502）。
    pub nonstream_max_bytes: usize,
    /// R8-16/D12：2xx 非 `text/event-stream` 分流的非 JSON 策略位。
    /// `false`（原生非流）：2xx 非 JSON/空体维持 502 `E_EMPTY_BODY` 语义不变；
    /// `true`（`stream:true` + 2xx 非 SSE，仅 dispatch 新分流臂）：非 JSON 正文
    /// 按字节透传 + warn + 透传计数，JSON 正文照常走完整后处理链。
    pub non_json_passthrough: bool,
}

/// `serve_nonstream` 的结果：完整响应，或上游意外回 SSE 时把未消费的
/// `reqwest::Response` 连同请求会话标识交回调用方转流泵（原 `looks_sse` 语义；
/// E12/D7：泵内终端帧复用请求会话，不再空值合成）。
pub enum NonstreamOutcome {
    Responded(Response),
    Stream(reqwest::Response, Option<String>),
}

/// R5-23（5.1/D1）：生产请求体/上游响应体 JSON 解析统一经中央 `json_walk`——
/// 先按 UTF-8 解码再剥前导 BOM，使 BOM 前缀体与非 BOM 体解析结果一致。
fn parse_json_bytes(bytes: &[u8]) -> Option<Value> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| json_walk::jloads(json_walk::strip_bom(s)).ok())
}

/// 2.2 `nonstream` 一发一收：接收改写后请求，返回完整上游响应；
/// 上游超时/不可达映射为网关级错误状态码而非挂起。
/// `client` 为只读引用（单例由 1.x 负责），本单元内不新建 Client。
/// R8-16/D12：本函数只保留转发前装配（转发头、请求快照、fetch 与失败收敛），
/// 取回上游响应后的全部分类/后处理委托 [`process_upstream_response`]。
pub async fn serve_nonstream(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    ctx: NonstreamCtx,
) -> NonstreamOutcome {
    let fwd_headers = forward_headers(&headers, &ctx.req.gateway_metrics);
    // E12/D7：转泵用请求会话标识（fetch 会 move `body`，须提前提取）。
    // NLP-2：同时快照请求侧 `model`，供响应体缺失 `model` 时回退分桶。
    let req_value = parse_json_bytes(&body);
    let req_conv = req_value.as_ref().and_then(llm_gateway::extract_conv_id);
    let req_model = req_value
        .as_ref()
        .and_then(|v| v.get("model"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return NonstreamOutcome::Responded(empty_body_response(ctx.req.protocol)),
    };
    process_upstream_response(up, ctx, req_conv, req_model).await
}

/// R8-16/D5/D12：上游响应取得后的统一后处理入口（原 `serve_nonstream` 尾段逐字抽取）——
/// 非对话透传 / SSE 转泵 / 有界读 / 空体分类 / redact-only / JSON 完整链 / 错误体透传
/// 全在本函数内；JSON 与非 JSON 的分类内置（`up` 在此被消费，调用方无法先读后传）。
/// `req_conv`/`req_model` 为 fetch 前的请求体快照派生值，随参传入。
pub(super) async fn process_upstream_response(
    up: reqwest::Response,
    ctx: NonstreamCtx,
    req_conv: Option<String>,
    req_model: &str,
) -> NonstreamOutcome {
    if llm_gateway::is_passthrough(ctx.req.protocol) {
        // P0-4.2/F1：非对话臂保持字节透传（与 Python 直通语义一致：无用量/
        // 审计/还原），记 `nondialog_passthrough` 供流量验证；专用入口
        // `serve_nondialog_passthrough` 与之共用本装配函数（H11/D11）。
        return NonstreamOutcome::Responded(passthrough_upstream_response(
            up,
            &ctx.req.gateway_metrics,
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
    // N1/D10：错误状态先于 SSE 内容类型判定——`status>=400` + `text/event-stream`
    // 一律走错误体透传（状态码与正文字节保留），SHALL NOT 经 `build_sse_response`
    // 合成硬编码 200 的假流；与流式分支既有 `status>=400` 守卫同口径。
    // FIX 4：redact-only 变体（`count_tokens`）走本函数时 SHALL NOT 进 SSE 泵——
    // 其契约为「跳过四类后处理、上游字节保真透传」，异常 SSE content-type 亦按
    // 非 JSON 体经下方空体分类处置（与其它非 JSON 响应同口径），不伪造 200 流。
    if looks_sse && status_u16 < 400 && !ctx.req.redact_only {
        // E12/D7：转泵时透传请求会话标识（泵内终端帧复用，不断审计链）；
        // 缺失则为 None，由调用方回退合成并记 `conv_missing`。
        return NonstreamOutcome::Stream(up, req_conv);
    }
    let resp_headers = snapshot_downstream_headers(&up, &ctx.req.gateway_metrics);
    // T4/D4：`content-length` 预检（仅 `status<400`）——声明值严格超限时立即 502
    // 且不读 body，避免 `bytes()` 无界读入；`len == cap` 放行。
    if status_u16 < 400
        && up
            .content_length()
            .is_some_and(|n| n > ctx.nonstream_max_bytes as u64)
    {
        return NonstreamOutcome::Responded(oversize_response(ctx.req.protocol));
    }
    // T4/D4：无 `content-length`/分块场景改用有界累计读取，累计超限即停读并 502；
    // NLP-5/D11：`status>=400` 错误体同样有界读——累计超限时转为**流式转发**
    // （仅缓冲上限内前缀），保证内存有界且下行状态码与正文字节语义不变，
    // 不合成 502 `response_too_large`（TRN-3 同理，见 transport-fidelity-fix spec）。
    let bytes = if status_u16 < 400 {
        match read_bounded_body(up, ctx.nonstream_max_bytes, &ctx.req.gateway_metrics).await {
            BoundedBody::Complete(b) => b,
            BoundedBody::Oversize => {
                return NonstreamOutcome::Responded(oversize_response(ctx.req.protocol));
            }
        }
    } else {
        match read_error_body_bounded(up, ctx.nonstream_max_bytes, &ctx.req.gateway_metrics).await {
            ErrorBody::Complete(b) => b,
            ErrorBody::Oversize { prefix, head, rest } => {
                return NonstreamOutcome::Responded(error_streaming_response(
                    status_u16,
                    &resp_headers,
                    prefix,
                    head,
                    rest,
                    ctx.req.protocol,
                ));
            }
        }
    };
    let is_json = parse_json_bytes(&bytes).is_some();
    // R8-16/D5/D12：`stream:true` + 2xx 非 SSE 非 JSON 分流的字节透传臂——先于
    // `classify_empty`（原生非流 `non_json_passthrough:false` 仍走下方 502 语义）。
    // 非 JSON 无结构化字段可审计/还原，按状态与正文字节透传并记 warn 与既有
    // 透传类计数（`GatewayMetrics` 层、非 admin 导出字段，不新增 admin 键）。
    if status_u16 < 400 && !is_json && ctx.non_json_passthrough {
        tracing::warn!(
            status = status_u16,
            protocol = ?ctx.req.protocol,
            "stream 请求上游 2xx 非 SSE 非 JSON 正文，按字节透传（R8-16）"
        );
        ctx.req.gateway_metrics.record_nondialog_passthrough();
        return NonstreamOutcome::Responded(build_downstream_response(
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
            &resp_headers,
            bytes,
            ctx.req.protocol,
            ctx.req.normalized_out,
            None,
        ));
    }
    // F2/D2：先定空体分类（对齐 Python 先算 `_is_empty`），再判超限
    // （严格 `len > cap`，体形态对齐 `_llm.py:2951-2961`），最后才落空体 502：
    // 空体 len=0 恒不超限，非 JSON 超限体不落空体分支（与 Python 可观测结果一致）。
    // 精化：超限仅对非错误状态（`status < 400`）生效——4xx/5xx 错误体按 N2/D6
    // 语义透传或走完整链，不因体大被改写为 502。超限动作已由上方有界读取前置，
    // 本处仅保留空体分类判序。
    let empty_action = classify_empty(true, bytes.len(), is_json, status_u16);
    if empty_action == EmptyAction::NonStreamTo502 {
        return NonstreamOutcome::Responded(empty_body_response(ctx.req.protocol));
    }
    // C/3.2：redact-only 变体（Anthropic `count_tokens`）——请求侧脱敏已在
    // `request_rewrite` 完成；此处**显式跳过**四类后处理：① 用量记账（`record_chat`/
    // `record_aux_counts`）；② 审计判定（逐 tool `evaluate_and_record` 与
    // `evaluate_nonstream`）；③ 响应侧还原与新 PII 扫描（`restore_response_with_spans_json`
    // + `redact_response_new_pii_with_skip`）；④ 阻断合成（`blocked` → `block_body`）。
    // 保留 hop 过滤与有界读（体量受 `NONSTREAM_MAX_BYTES` 约束），按上游字节保真透传。
    if ctx.req.redact_only {
        return NonstreamOutcome::Responded(build_downstream_response(
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
            &resp_headers,
            bytes,
            ctx.req.protocol,
            ctx.req.normalized_out,
            is_json.then_some("application/json"),
        ));
    }
    if let Some(v) = parse_json_bytes(&bytes) {
        let usage = extract_usage_nonstream(ctx.req.protocol, &v);
        // C13/NLP-2：模型分桶优先上游回显值，缺失回退请求 model（对照 Python
        // `_llm.py:2975-2977`），双侧均缺才归 `unknown_model`。
        let upstream_model = v
            .get("model")
            .and_then(|m| m.as_str())
            .filter(|m| !m.is_empty())
            .unwrap_or(req_model);
        ctx.req.admin_metrics.record_chat(ChatRecord {
            protocol: ctx.req.protocol,
            model: upstream_model,
            latency_ms: ctx.req.req_start.elapsed().as_millis() as u64,
            usage: usage.as_ref(),
            truncated_mode: None,
            is_precise: ctx.req.sqlite_precise,
            ts_secs: now_secs(),
        });
        // 非流 tool 提取 + 审计（§2.3）：阻断时返回协议正确的 block 体代替上游响应。
        // A1/D1：非流逐 tool verdict 命中/放行经单例落盘（与流式同口径；
        // `Block` 即止，与紧随的 `evaluate_nonstream` 决策一致）。
        if !matches!(ctx.req.audit_mode, AuditMode::Off) {
            let proto = protocol_header_value(ctx.req.protocol);
            for call in llm_gateway::extract_tool_calls(ctx.req.protocol, &v) {
                let name = call.name.as_deref().unwrap_or("");
                let verdict = ctx
                    .req
                    .audit_sink
                    .evaluate_and_record(
                        ctx.req.audit_mode,
                        name,
                        &call.args,
                        &ctx.req.audit_policy,
                        &ctx.req.approval_whitelist,
                        Some(proto),
                    )
                    .await;
                if matches!(verdict, crate::service::audit::AuditVerdict::Block { .. }) {
                    break;
                }
            }
        }
        let response_id = llm_gateway::extract_conv_id(&v);
        let wrote = response_id
            .as_deref()
            .is_some_and(|id| ctx.req.scope.record_response_id(ctx.req.protocol, id));
        // R5-09/D10：写回失败仅「响应 id 缺失/为空」这一真实失败计一次；无写回上下文
        // （`request` 模式/键未推导）与非 Responses 协议门控 MUST NOT 计入。
        // D7：仅成功响应（`status<400`）计入——`status>=400` 错误体（如 400）本就不承载
        // 可写回的响应 id，非真实写回失败，不得虚计。
        if !wrote
            && status_u16 < 400
            && ctx.req.protocol.is_responses()
            && response_id.is_none()
            && ctx.req.scope.has_conversation()
        {
            ctx.req.gateway_metrics.record_conversation_writeback_miss();
        }
        let conv_id = response_id.unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(
                None,
                &v,
                Some(&ctx.req.gateway_metrics),
                "nonstream-block",
            )
            .0
        });
        // T1/P2-1：白名单随 ctx 显式注入，与流式 `evaluate_with_whitelist` 同口径。
        let blocked = block_inject::evaluate_nonstream(
            ctx.req.protocol,
            &v,
            ctx.req.audit_mode,
            &ctx.req.audit_policy,
            &conv_id,
            &ctx.req.approval_whitelist,
            &ctx.req.pending,
        );
        if let Some(block_body) = blocked {
            // T3/D3：审计命中统一记 `audit_blocks` 列（含错误状态不合成阻断体的场景）。
            ctx.req
                .admin_metrics
                .record_aux_counts(ctx.req.protocol, now_secs(), 0, 0, 1);
            if status_u16 < 300 {
                // E4：2xx 非流阻断恒 200（与流式恒 200 闭合对称，不再沿用上游码）。
                let mut resp = (StatusCode::OK, Json(block_body)).into_response();
                if ctx.req.normalized_out {
                    resp.headers_mut().insert(
                        NORMALIZED_HEADER_NAME,
                        header::HeaderValue::from_static(NORMALIZED_HEADER_VALUE),
                    );
                }
                resp.headers_mut().insert(
                    PROTOCOL_HEADER_NAME,
                    header::HeaderValue::from_static(protocol_header_value(ctx.req.protocol)),
                );
                return NonstreamOutcome::Responded(resp);
            }
            // T3/D3：错误状态（4xx/5xx）不合成阻断体，保留上游状态与正文，审计照记
            // （日志 + 指标）；危险调用落入错误响应不构成实际执行，合成 200 会掩盖
            // 故障并误导下游（README §7.2 声明背书）。
            tracing::warn!(
                status = status_u16,
                protocol = ?ctx.req.protocol,
                "非流上游错误状态审计命中 Block，保留上游状态与正文（不合成 200 阻断体）"
            );
        } else {
            ctx.req
                .admin_metrics
                .record_aux_counts(ctx.req.protocol, now_secs(), 0, 0, 0);
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // T6/D6：与流式帧同源，用 JSON 转义变体还原（明文含 `"`/`\`/控制字符时
        // 写回仍为合法 JSON，不再破帧后回退上游原文泄漏占位符）。
        let (restored, spans) = ctx
            .req
            .scope
            .restore_response_with_spans_json(&ctx.req.vault, &text);
        let restored = ctx
            .req
            .scope
            .redact_response_new_pii_with_skip(&ctx.req.vault, &ctx.req.detector, &restored, &spans)
            .await;
        // R5-14/D5：响应侧新检出注册遇熵源/内部故障 fail-closed——不将未 token 化的
        // 明文下发（MUST NOT 明文外泄），以 502 + E_PII_UNAVAILABLE 收敛。
        if ctx.req.scope.pii_unavailable() {
            return NonstreamOutcome::Responded(VeilError::PiiUnavailable.into_response());
        }
        // P0-1.2 + R8-03/D2：还原后双 `_jloads` 校验（对标 Python `_nonstream_build`）
        // 与回退阶梯——守卫破裂先 `retry_stripped` 挽回，仍失败回退已掩码占位符帧，
        // 掩码回退本身失败则 502 `E_PII_UNAVAILABLE` fail-closed；MUST NOT 回退未掩码
        // 上游原文（旧 `restored = text` 路径已删除）。
        let restored = match restore_ladder(&ctx.req, restored, &text).await {
            Ok(r) => r,
            Err(err) => return NonstreamOutcome::Responded(err.into_response()),
        };
        // P0-1.3：出口显式残缺剥离（凭据 `__VG_CRED_` + PII `__PII_` 半截形态）。
        // 还原/脱敏路径内已带剥离，此处幂等兜底响应侧关闭等旁路。
        let restored = crate::service::redaction::strip_partials(&restored);
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK);
        return NonstreamOutcome::Responded(build_downstream_response(
            status,
            &resp_headers,
            restored.into_bytes(),
            ctx.req.protocol,
            ctx.req.normalized_out,
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
            ctx.req.protocol,
            false,
            None,
        ));
    }
    // NLP-6：非 200 非错误状态（201/204/304 等）空体/非 JSON 不被 502 门控改写——
    // 按原状态码与正文字节透传（对齐 Python `_llm.py:3009-3013` 仅 `status==200` 门控）。
    // `status==200` 不可达此（上方空体分类已 502 早返），保留兜底防御。
    if status_u16 == 200 {
        return NonstreamOutcome::Responded(empty_body_response(ctx.req.protocol));
    }
    let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK);
    NonstreamOutcome::Responded(build_downstream_response(
        status,
        &resp_headers,
        bytes.to_vec(),
        ctx.req.protocol,
        false,
        None,
    ))
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

/// ARC-4/D4：上游响应头克隆 + 逐跳过滤单一 helper——downstream 方向克隆上游头，
/// 按 `downstream_decode_enabled` 做解码配对剥头并经
/// `src/service/llm_gateway/metrics.rs::GatewayMetrics::record_hop_filtered` 计数
/// （读取侧 `hop_filtered_count`；`hop_filtered_total` 为其 Prometheus **度量名**
/// 约定、非可解析的 Rust 符号）。
/// `passthrough_upstream_response` 与 `snapshot_downstream_headers` 共用本 helper；
/// 调用方各自保留 `x-veil-*` 剔除与响应装配职责。R8-09：`dispatch.rs::
/// stream_upstream_passthrough` 亦改调本 helper（不再内联重复克隆）。
pub(super) fn clone_upstream_headers(
    up: &reqwest::Response,
    metrics: &GatewayMetrics,
) -> HeaderMap {
    let mut resp_headers = HeaderMap::new();
    for (k, v) in up.headers().iter() {
        if let (Ok(n), Ok(val)) = (
            k.to_string().parse::<axum::http::HeaderName>(),
            axum::http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            // AUDIT-03：`append` 而非 `insert`——同名多值上游头（如多条
            // `warning`/`set-cookie`）逐值保留，不得被折叠为末值。
            resp_headers.append(n, val);
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
    resp_headers
}

/// H11/D11：NonDialog 透传响应装配（计数 + hop 过滤 + 字节流），供专用入口与
/// `serve_nonstream` 的 `is_passthrough` 兼容分支单一复用。
fn passthrough_upstream_response(up: reqwest::Response, metrics: &GatewayMetrics) -> Response {
    metrics.record_nondialog_passthrough();
    let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    let resp_headers = clone_upstream_headers(&up, metrics);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .body(Body::from_stream(up.bytes_stream()))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// T4/D4：非流响应体有界读取结果——完整体或累计超限（调用方转 502）。
pub(super) enum BoundedBody {
    Complete(Vec<u8>),
    Oversize,
}

/// T4/D4：以 `chunk()` 有界累计读取上游 body，累计超过 `cap` 立即停止并返回
/// `Oversize`（不先全量缓存）；读取错误记 warn + 指标后退化为空体，交空体分类处置。
pub(super) async fn read_bounded_body(
    mut up: reqwest::Response,
    cap: usize,
    metrics: &GatewayMetrics,
) -> BoundedBody {
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
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    read_bytes = buf.len(),
                    "上游响应体读取失败，退化为空体"
                );
                metrics.record_upstream_read_error();
                return BoundedBody::Complete(Vec::new());
            }
        }
    }
}

/// NLP-5/D11：错误状态（`status>=400`）响应体的有界读结果——上限内完整体，或
/// 「已缓冲前缀 + 当前分片 + 上游余流」的流式转发三元组（内存有界、字节保真）。
pub(super) enum ErrorBody {
    Complete(Vec<u8>),
    Oversize {
        prefix: Vec<u8>,
        head: bytes::Bytes,
        rest: reqwest::Response,
    },
}

/// NLP-5/D11：错误状态响应体的有界读——累计读至超过 `cap` 即停止缓冲，把已读
/// 前缀与上游余流交调用方流式转发；内存占用不随错误体体积线性增长，且下行状态码
/// 与正文字节保持上游原值（不截断、不合成 502）。读取错误退化为已读前缀。
pub(super) async fn read_error_body_bounded(
    mut up: reqwest::Response,
    cap: usize,
    metrics: &GatewayMetrics,
) -> ErrorBody {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match up.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len().saturating_add(chunk.len()) > cap {
                    return ErrorBody::Oversize {
                        prefix: buf,
                        head: chunk,
                        rest: up,
                    };
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return ErrorBody::Complete(buf),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    read_bytes = buf.len(),
                    "上游错误响应体读取失败，退化为已读前缀"
                );
                metrics.record_upstream_read_error();
                return ErrorBody::Complete(buf);
            }
        }
    }
}

/// NLP-5/D11：错误体超限时的流式转发响应——上游状态码与 hop 过滤后响应头原样，
/// 正文按「前缀 → 当前分片 → 上游余流」顺序逐段转发，`x-veil-protocol` 照常标注。
fn error_streaming_response(
    status_u16: u16,
    resp_headers: &HeaderMap,
    prefix: Vec<u8>,
    head: bytes::Bytes,
    mut rest: reqwest::Response,
    protocol: Protocol,
) -> Response {
    let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
    let stream = async_stream::stream! {
        if !prefix.is_empty() {
            yield Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(prefix));
        }
        yield Ok(head);
        loop {
            match rest.chunk().await {
                Ok(Some(chunk)) => yield Ok(chunk),
                Ok(None) => break,
                Err(err) => {
                    yield Err(std::io::Error::other(err));
                    break;
                }
            }
        }
    };
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .header(PROTOCOL_HEADER_NAME, protocol_header_value(protocol))
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// R8-03/D2：非流还原回退阶梯——① `restored`（已掩码）② `retry_stripped` 残缺
/// 剥离挽回 ③ 回退**已应用响应侧新 PII 掩码**的占位符帧 ④ 掩码回退本身失败
/// （PII 注册熵源/内部故障）→ `VeilError::PiiUnavailable`（502 fail-closed）。
/// MUST NOT 回退未掩码上游原文或未掩码占位符帧；失败记 warn + `restore_fallback`
/// 恰一次，使回退可观测（与流式 `emit_restored_json_frame` 同阶梯）。
async fn restore_ladder(
    req: &RequestCtx,
    restored: String,
    placeholder: &str,
) -> Result<String, VeilError> {
    if restore_guard_ok(&restored, placeholder, None) {
        return Ok(restored);
    }
    if let Some(stripped) =
        retry_stripped(&restored).filter(|s| restore_guard_ok(s, placeholder, None))
    {
        tracing::warn!("非流还原后 JSON 校验失败，残缺剥离后挽回");
        return Ok(stripped);
    }
    tracing::warn!("非流还原后 JSON 校验失败，回退已掩码占位符帧（fail-closed）");
    req.gateway_metrics.record_restore_fallback();
    let masked = req
        .scope
        .redact_response_new_pii_with_skip(&req.vault, &req.detector, placeholder, &[])
        .await;
    if req.scope.pii_unavailable() {
        tracing::warn!("非流占位符帧掩码回退失败（PII 不可用），改 502 fail-closed");
        return Err(VeilError::PiiUnavailable);
    }
    Ok(masked)
}

/// E5/D3 重试判定（纯函数）：还原体破裂时剥离残缺形态，剥离后可解析则返回
/// 剥离体（挽回），否则返回 `None`（调用方回退占位符帧）。
fn retry_stripped(restored: &str) -> Option<String> {
    let stripped = crate::service::redaction::strip_partials(restored);
    json_walk::jloads(json_walk::strip_bom(&stripped))
        .is_ok()
        .then_some(stripped)
}

/// T2/D2：消费上游 body 前快照响应头，经逐跳过滤后剥除上游 `x-veil-*`
/// （网关自有同名头在转发后覆盖写入，上游声明不得生效）。
fn snapshot_downstream_headers(up: &reqwest::Response, metrics: &GatewayMetrics) -> HeaderMap {
    let mut resp_headers = clone_upstream_headers(up, metrics);
    llm_gateway::strip_veil_internal_headers(&mut resp_headers);
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
        builder = builder.header(NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE);
    }
    builder
        .header(PROTOCOL_HEADER_NAME, protocol_header_value(protocol))
        .body(Body::from(body))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

/// F2：对话非流响应体超限 502（体形态与 Python `_llm.py:2951-2961` 同字）。
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

#[cfg(test)]
mod read_error_tests;

#[cfg(test)]
mod pii_fail_closed_tests;
