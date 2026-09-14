//! LLM 网关入口分发（D2 自 `mod.rs` 拆出）：`llm_proxy_handler` 入口 +
//! `gateway_serve` 协议分发（对话改写/流泵 vs 非对话透传）。

use {
    super::{
        NonstreamCtx,
        NonstreamOutcome,
        StreamPumpCtx,
        build_sse_response,
        forward_headers,
        serve_nondialog_passthrough,
        serve_nonstream,
        spawn_stream_pump,
    },
    crate::{
        service::{
            llm_gateway::{self, Protocol, resolve_protocol, resolve_upstream},
            redaction::Scope,
        },
        state::AppState,
    },
    axum::{
        Json,
        body::Body,
        extract::{Request, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
    std::{sync::Arc, time::Instant},
};

/// 通用 ingress 超限响应：413 + 错误码 `E_PAYLOAD_TOO_LARGE`（spec 锁定）。
fn payload_too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"error":{"code":"E_PAYLOAD_TOO_LARGE","message":format!("请求体超过上限 {limit} 字节")}})),
    )
        .into_response()
}

/// spawn 包裹 + 立即 await 的语义容器（A3/D2）：
/// 1) panic 兜底：spawn 任务内 panic 被隔离为 `JoinError`，统一转 500 （不穿透为下游连接中断）；
/// 2) 断连续跑：任务所有权脱离 handler future，客户端断连致 handler 被 `drop`
///    时任务仍续跑至完成（审计/用量落库完整）。
///
/// 正常路径与直接 await 等价，无并发收益。
async fn spawn_contained<F>(fut: F) -> Response
where
    F: std::future::Future<Output = Response> + Send + 'static,
{
    match tokio::spawn(fut).await {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":{"code":"E_INTERNAL","message":"内部错误"}})),
        )
            .into_response(),
    }
}

pub async fn llm_proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    spawn_contained(async move {
        // 通用 ingress JSON 检查点 10MB（spec `admin-ratelimit-contract` + design D4）：
        // 超限返回 413，MUST NOT 以 `unwrap_or_default` 静默为空体继续处理。
        let body_bytes = match axum::body::to_bytes(body, super::GATEWAY_BODY_LIMIT_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return payload_too_large(super::GATEWAY_BODY_LIMIT_BYTES),
        };
        gateway_serve(&state, &mut parts, &path, body_bytes).await
    })
    .await
}

/// T1/D1：入站 query 保序拼接上游 URL。`path` 取 `uri.path()`，query 取
/// `Uri::query()` 原始切片（不重排、不重编码、不丢空值参数），无 query 时
/// SHALL NOT 追加 `?`；上游基址自带 query（`?x=y`）时把入站 query 以 `&`
/// 合并到基址 query 之后，避免双 `?`（T1.2 边界）。
fn build_upstream_url(base: &str, path: &str, inbound_query: Option<&str>) -> String {
    let (raw_path, base_query) = match base.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base, None),
    };
    let base_path = raw_path.trim_end_matches('/');
    let mut url = format!("{base_path}{path}");
    let query = match (base_query, inbound_query) {
        (Some(b), Some(i)) => Some(format!("{b}&{i}")),
        (Some(b), None) => Some(b.to_string()),
        (None, Some(i)) => Some(i.to_string()),
        (None, None) => None,
    };
    if let Some(q) = query {
        url.push('?');
        url.push_str(&q);
    }
    url
}

/// A1/D8 入口宿主机端口解析：`]` 存在时按方括号 IPv6 取 `]:` 后段端口
/// （如 `[::1]:8878` → `8878`）；无方括号且冒号恰一时取尾段（`host:port`）；
/// 裸 IPv6（多冒号无方括号，如 `::1`）与缺失/非法一律回退 `None`（缺省上游），不猜测。
fn parse_ingress_port(host: &str) -> Option<u16> {
    if let Some(end) = host.rfind(']') {
        return host[end + 1..]
            .strip_prefix(':')?
            .trim()
            .parse::<u16>()
            .ok();
    }
    if host.chars().filter(|c| *c == ':').count() != 1 {
        return None;
    }
    host.rsplit(':').next()?.trim().parse::<u16>().ok()
}

pub(crate) async fn gateway_serve(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    path: &str,
    body_bytes: Vec<u8>,
) -> Response {
    let req_start = Instant::now();
    let ct = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // dispatcher 仅保留 protocol/url 分发。
    let protocol = resolve_protocol(path, ct.as_deref(), Some(&state.gateway_metrics));
    let is_chat = !llm_gateway::is_passthrough(protocol);
    // 入口宿主机端口（entry-transport）：`Host` 经 `parse_ingress_port` 解析
    //（方括号 IPv6/裸 IPv6/非法一律有定义），缺失/非法回退 None（缺省上游），不猜测。
    let ingress_port: Option<u16> = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_ingress_port);
    let upstream_base = match resolve_upstream(&state.config, ingress_port) {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游未配置"}})),
            )
                .into_response();
        }
    };
    let url = build_upstream_url(&upstream_base, path, parts.uri.query());
    let client: &reqwest::Client = &state.http_client;
    // T3/D3：流式（SSE）分支用无总超时的独立 client，长流不被 `HTTP_TIMEOUT_SECS` 截断；
    // 非流与 NonDialog 透传保持既有总超时 client。
    let stream_client: &reqwest::Client = &state.http_stream_client;
    let scope = Arc::new(Scope::with_opts(
        state.config.pii_response_side,
        state.config.pii_fuzzy_restore,
    ));
    // 全局单例快照（credential-vault-singleton）：网关只读复用进程级
    // vault/detector，不得每请求新建空映射致还原断链。
    let vault = state.vault.clone();
    let detector = state.detector.clone();
    let sqlite_precise = state.sqlite_ok();
    let hold_max = state.config.audit_hold_max_bytes.max(1) as usize;
    let audit_mode = state.config.audit_mode;
    let audit_policy = state.audit_policy.clone();
    let approval_whitelist = state.config.approval_whitelist.clone();
    let pii_boundary_chars = if state.config.pii_response_side {
        state.config.pii_hold_max.max(1) as usize
    } else {
        0
    };

    if !is_chat {
        // H11/D11：NonDialog 走专用透传入口（返回 `Response`，无 `Stream` 死臂）；
        // 上游意外回 SSE 亦按字节透传，类型即契约。
        let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        return serve_nondialog_passthrough(
            client,
            upstream_method,
            &url,
            parts.headers.clone(),
            body_bytes,
            protocol,
            &state.gateway_metrics,
        )
        .await;
    }

    let rw = super::request_rewrite(
        body_bytes,
        protocol,
        &state.config,
        scope.clone(),
        vault.clone(),
        detector.clone(),
    )
    .await;
    let dialog_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let pump_ctx = || StreamPumpCtx {
        protocol,
        scope: scope.clone(),
        vault: vault.clone(),
        detector: detector.clone(),
        audit_mode,
        audit_policy: audit_policy.clone(),
        approval_whitelist: approval_whitelist.clone(),
        audit_sink: state.audit_sink.clone(),
        hold_max,
        pii_boundary_chars,
        gateway_metrics: state.gateway_metrics.clone(),
        admin_metrics: state.admin.metrics.clone(),
        sqlite_precise,
        req_start,
        pending: state.pending.clone(),
        init_conv: rw.init_conv.clone(),
        normalized_out: rw.normalized_out,
    };
    if rw.stream_flag {
        let fwd_headers = forward_headers(&parts.headers, &state.gateway_metrics);
        match llm_gateway::fetch_upstream_with_retry(
            stream_client,
            dialog_method,
            &url,
            fwd_headers,
            rw.body,
        )
        .await
        {
            Ok(up) => {
                let status_u16 = up.status().as_u16();
                let resp_ct = up
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                // S6/D7：仅 `status<400` 且上游正文为 `text/event-stream` 才转 SSE 泵；
                // 上游错误状态（4xx/5xx）或 2xx 非 SSE 正文按非流口径保状态保正文透传，
                // 不得改写为 200 SSE 假流（客户端会误判为流式成功）。
                if status_u16 >= 400 || !resp_ct.contains("text/event-stream") {
                    return stream_upstream_passthrough(
                        up,
                        rw.normalized_out,
                        protocol,
                        state.config.nonstream_max_bytes,
                        &state.gateway_metrics,
                    )
                    .await;
                }
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
            Err(_) => super::empty_body_response(protocol),
        }
    } else {
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: rw.normalized_out,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy: audit_policy.clone(),
            approval_whitelist: approval_whitelist.clone(),
            audit_sink: state.audit_sink.clone(),
            pending: state.pending.clone(),
            nonstream_max_bytes: state.config.nonstream_max_bytes,
        };
        match serve_nonstream(
            client,
            dialog_method,
            &url,
            parts.headers.clone(),
            rw.body,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 客户端未要求流但上游回 SSE 时，转字节泵保证终止闭合。
            // E12/D7：泵 conv 首选透传的请求会话（与 `rw.init_conv` 同源），
            // 缺失才用改写输出的会话。
            NonstreamOutcome::Stream(up, req_conv) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let mut pctx = pump_ctx();
                if req_conv.is_some() {
                    pctx.init_conv = req_conv;
                }
                let _pump = spawn_stream_pump(up, tx, pctx);
                build_sse_response(rx, rw.normalized_out)
            }
        }
    }
}

/// S6/D7：流式请求命中上游错误状态（`status>=400`）或非 `text/event-stream` 正文时，
/// 读取正文字节并按原状态返回（受 `NONSTREAM_MAX_BYTES` 约束），hop 头过滤后附
/// `x-veil-protocol`，对齐非流错误/非 JSON 透传口径；不进入 SSE 泵。
/// 非错误状态严格超限走 502 `response_too_large`（与非流一致），4xx/5xx 错误体
/// 不因体大改写。
pub(super) async fn stream_upstream_passthrough(
    up: reqwest::Response,
    normalized_out: bool,
    protocol: Protocol,
    max_bytes: usize,
    metrics: &llm_gateway::GatewayMetrics,
) -> Response {
    let status_u16 = up.status().as_u16();
    let mut resp_headers = HeaderMap::new();
    for (k, v) in up.headers().iter() {
        if let (Ok(n), Ok(val)) = (
            k.to_string().parse::<axum::http::HeaderName>(),
            axum::http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            resp_headers.insert(n, val);
        }
    }
    // TRN-4：剔除上游 `x-veil-*` 内部头（大小写不敏感），网关自置头在剔除后写入，
    // 上游同名声不得覆盖或泄漏。
    let veil_keys: Vec<axum::http::HeaderName> = resp_headers
        .keys()
        .filter(|k| k.as_str().starts_with("x-veil-"))
        .cloned()
        .collect();
    for k in veil_keys {
        resp_headers.remove(&k);
    }
    let decode_enabled = llm_gateway::downstream_decode_enabled(up.headers());
    // TRN-3：先判 `content-length`（仅非错误状态），超限即 502 且不读 body。
    if status_u16 < 400
        && up
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
    {
        return super::nonstream::oversize_response(protocol);
    }
    llm_gateway::filter_hop_headers_counted(
        &mut resp_headers,
        "downstream",
        decode_enabled,
        Some(metrics),
    );
    let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        builder = builder.header(k, v);
    }
    if normalized_out {
        builder = builder.header("x-veil-normalized", "json-whitespace");
    }
    let builder = builder.header("x-veil-protocol", super::protocol_header_value(protocol));
    // TRN-3：`status >= 400` 错误体按透传语义保状态保字节，流式转发仅为内存安全，
    // 不改写为 502、不缓冲放大。
    if status_u16 >= 400 {
        return builder
            .body(Body::from_stream(up.bytes_stream()))
            .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response());
    }
    // TRN-3：非错误状态有界读（至多 `max_bytes + 1`），严格超限 fail-closed 502。
    let bytes = match super::nonstream::read_bounded_body(up, max_bytes, metrics).await {
        super::nonstream::BoundedBody::Complete(b) => b,
        super::nonstream::BoundedBody::Oversize => {
            return super::nonstream::oversize_response(protocol);
        }
    };
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response())
}

#[cfg(test)]
mod entry_tests {
    use super::{
        super::{
            AUDIT_SUBLIMIT_CEILING_BYTES,
            GATEWAY_BODY_LIMIT_BYTES,
            audit_scan_body_over_limit,
            should_pump_stream,
        },
        *,
    };

    #[test]
    fn build_upstream_url_query_join_and_absent() {
        // 无 query 不追加 `?`；有 query 原样拼接；基址自带 query 以 `&` 合并。
        assert_eq!(
            super::build_upstream_url("http://up:1", "/v1/models", None),
            "http://up:1/v1/models"
        );
        assert_eq!(
            super::build_upstream_url(
                "http://up:1",
                "/v1/models",
                Some("limit=&tag=a&tag=b&q=a+b&x=a%2Fb")
            ),
            "http://up:1/v1/models?limit=&tag=a&tag=b&q=a+b&x=a%2Fb"
        );
        assert_eq!(
            super::build_upstream_url("http://up:1?base=1", "/v1/models", Some("limit=")),
            "http://up:1/v1/models?base=1&limit="
        );
        assert_eq!(
            super::build_upstream_url("http://up:1/?base=1", "/v1/models", None),
            "http://up:1/v1/models?base=1"
        );
    }

    #[test]
    fn ingress_port_bracketed_ipv6_and_bare_fallback_a1() {
        // A1/D8：方括号 IPv6 取端口；裸 IPv6 回退 None（不误取尾段）。
        assert_eq!(super::parse_ingress_port("[::1]:8878"), Some(8878));
        assert_eq!(super::parse_ingress_port("[2001:db8::1]:8879"), Some(8879));
        assert_eq!(super::parse_ingress_port("::1"), None);
        assert_eq!(super::parse_ingress_port("[::1]"), None);
        assert_eq!(super::parse_ingress_port("[::1]:abc"), None);
        assert_eq!(super::parse_ingress_port("127.0.0.1:8878"), Some(8878));
        assert_eq!(super::parse_ingress_port("example.com"), None);
    }

    #[test]
    fn stream_flag_with_json_combo_routes_to_pump() {
        assert!(should_pump_stream("text/event-stream", false));
        assert!(should_pump_stream("text/event-stream", true));
        assert!(should_pump_stream("application/json", true));
        assert!(!should_pump_stream("application/json", false));
        assert!(!should_pump_stream("", false));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn body_limits_tiered_values_match_spec() {
        assert_eq!(GATEWAY_BODY_LIMIT_BYTES, 10 * 1024 * 1024);
        assert_eq!(AUDIT_SUBLIMIT_CEILING_BYTES, 8 * 1024 * 1024);
        assert!(GATEWAY_BODY_LIMIT_BYTES > AUDIT_SUBLIMIT_CEILING_BYTES);
        assert!(!audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES));
        assert!(audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES + 1));
    }

    #[tokio::test]
    async fn oversized_body_returns_413_with_error_code() {
        let resp = payload_too_large(GATEWAY_BODY_LIMIT_BYTES);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "E_PAYLOAD_TOO_LARGE");
    }

    #[tokio::test]
    async fn panic_in_spawned_task_maps_to_500_not_connection_abort() {
        let resp = super::spawn_contained(async { panic!("注入 panic") }).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "E_INTERNAL");
        let ok = super::spawn_contained(async { (StatusCode::OK, "ok").into_response() }).await;
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_body_rejected_by_to_bytes_not_silent_empty() {
        let over = vec![b'x'; 64];
        let err = axum::body::to_bytes(axum::body::Body::from(over), 16).await;
        assert!(err.is_err());
        // 恰达上限放行：结果体内容与长度精确对拍，不得静默为空。
        let ok = axum::body::to_bytes(axum::body::Body::from(vec![b'x'; 16]), 16)
            .await
            .expect("恰达上限须放行");
        assert_eq!(ok.len(), 16, "结果体长度须等于输入: {ok:?}");
        assert_eq!(&ok[..], &[b'x'; 16][..], "结果体内容须逐字节保留");
        // 超限一字节即报错（非 Ok 空体），不静默截断。
        let over_by_one = axum::body::to_bytes(axum::body::Body::from(vec![b'y'; 17]), 16).await;
        assert!(over_by_one.is_err(), "17 字节超 16 上限须报错而非静默");
    }
}
