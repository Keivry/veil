//! LLM 网关入口分发（D2 自 `mod.rs` 拆出）：`llm_proxy_handler` 入口 +
//! `gateway_serve` 协议分发（对话改写/流泵 vs 非对话透传）。

use {
    super::{
        NonstreamCtx,
        NonstreamOutcome,
        StreamPumpCtx,
        build_sse_response,
        forward_headers,
        serve_nonstream,
        spawn_stream_pump,
    },
    crate::{
        service::{
            llm_gateway::{self, resolve_protocol, resolve_upstream},
            redaction::Scope,
        },
        state::AppState,
    },
    axum::{
        Json,
        extract::{Request, State},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::{Value, json},
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
    let url = format!("{}{}", upstream_base.trim_end_matches('/'), path);
    let client: &reqwest::Client = &state.http_client;
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
    let audit_policy_file = state.config.audit_policy_file.clone();
    let approval_whitelist = state.config.approval_whitelist.clone();
    let pii_boundary_chars = if state.config.pii_response_side {
        state.config.pii_hold_max.max(1) as usize
    } else {
        0
    };

    if !is_chat {
        // D6：NonDialog 请求体快照：上游意外回 SSE 转泵时 conv 归档与对话路径
        // 同源（同一 `resolve_conv_id`，未知体归档不断链）；仅 Stream 臂使用。
        let nondialog_body: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);
        let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy_file: audit_policy_file.clone(),
            approval_whitelist: approval_whitelist.clone(),
            pending: state.pending.clone(),
            nonstream_max_bytes: state.config.nonstream_max_bytes,
        };
        return match serve_nonstream(
            client,
            upstream_method,
            &url,
            parts.headers.clone(),
            body_bytes,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 非对话本不应回 SSE；上游意外回流时仍按字节泵闭合。
            NonstreamOutcome::Stream(up, req_conv) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let pctx = StreamPumpCtx {
                    protocol,
                    scope,
                    vault,
                    detector,
                    audit_mode: state.config.audit_mode,
                    audit_policy_file: state.config.audit_policy_file.clone(),
                    approval_whitelist: state.config.approval_whitelist.clone(),
                    hold_max,
                    pii_boundary_chars: if state.config.pii_response_side {
                        state.config.pii_hold_max.max(1) as usize
                    } else {
                        0
                    },
                    gateway_metrics: state.gateway_metrics.clone(),
                    admin_metrics: state.admin.metrics.clone(),
                    sqlite_precise,
                    req_start,
                    pending: state.pending.clone(),
                    // D6 + E12/D7：转泵 conv 首选透传的请求会话，缺失才经同一
                    // `resolve_conv_id` 归档（记 `conv_missing`，不断链），
                    // 阻断帧 id 与对话路径同源。
                    init_conv: req_conv.or_else(|| {
                        Some(
                            llm_gateway::resolve_conv_id(
                                None,
                                &nondialog_body,
                                Some(&state.gateway_metrics),
                                "nondialog-stream",
                            )
                            .0,
                        )
                    }),
                    normalized_out: false,
                };
                let _pump = spawn_stream_pump(up, tx, pctx);
                build_sse_response(rx, false)
            }
        };
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
        audit_policy_file: audit_policy_file.clone(),
        approval_whitelist: approval_whitelist.clone(),
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
            client,
            dialog_method,
            &url,
            fwd_headers,
            rw.body,
        )
        .await
        {
            Ok(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
            Err(_) => super::empty_body_response(),
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
            audit_policy_file: audit_policy_file.clone(),
            approval_whitelist: approval_whitelist.clone(),
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
        let ok = axum::body::to_bytes(axum::body::Body::from(vec![b'x'; 16]), 16).await;
        assert!(ok.is_ok());
    }
}
