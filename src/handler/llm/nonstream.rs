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
            metrics::MetricsStore,
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
}

/// `serve_nonstream` 的结果：完整响应，或上游意外回 SSE 时把未消费的
/// `reqwest::Response` 交回调用方转流泵（原 `looks_sse` 语义）。
pub enum NonstreamOutcome {
    Responded(Response),
    Stream(reqwest::Response),
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
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return NonstreamOutcome::Responded(empty_body_response()),
    };
    if ctx.protocol == Protocol::NonDialog {
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
        llm_gateway::filter_hop_headers_counted(
            &mut resp_headers,
            "downstream",
            llm_gateway::DECODE_ENABLED,
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
    let status_u16 = up.status().as_u16();
    if status_u16 == 502 || status_u16 == 401 {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        let bytes = up.bytes().await.unwrap_or_default();
        return NonstreamOutcome::Responded((status, bytes.to_vec()).into_response());
    }
    let resp_ct = up
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let looks_sse = should_pump_stream(&resp_ct, ctx.stream_flag);
    if looks_sse {
        return NonstreamOutcome::Stream(up);
    }
    let bytes = up.bytes().await.unwrap_or_default();
    let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
    if classify_empty(true, false, bytes.len(), is_json, status_u16) == EmptyAction::NonStreamTo502
    {
        return NonstreamOutcome::Responded(empty_body_response());
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        let usage = extract_usage_nonstream(ctx.protocol, &v);
        ctx.admin_metrics.record_chat(
            ctx.protocol,
            ctx.req_start.elapsed().as_millis() as u64,
            usage.as_ref(),
            None,
            ctx.sqlite_precise,
            now_secs(),
        );
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
        if let Some(block_body) = block_inject::evaluate_nonstream(
            ctx.protocol,
            &v,
            ctx.audit_mode,
            &audit_policy,
            &conv_id,
        ) {
            ctx.admin_metrics
                .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 1);
            let mut resp = (
                StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
                Json(block_body),
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
        ctx.admin_metrics
            .record_aux_counts(ctx.protocol, now_secs(), 0, 0, 0);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (restored, spans) = ctx.scope.restore_response_with_spans(&ctx.vault, &text);
        let restored = ctx
            .scope
            .redact_response_new_pii_with_skip(&ctx.vault, &ctx.detector, &restored, &spans)
            .await;
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
    NonstreamOutcome::Responded(empty_body_response())
}
