//! 路由装配与入口中间件。
//!
//! `build_router` 将凭据 API（`/credential`、`/registrations`、注册/吊销/哈希变更）与 LLM
//! 代理通配路由（`/` + `/{*tail}` + fallback）及 `/_admin` 管理面装配到同一 `Router`；
//! `observability_gate` 中间件按 `Config::admin_surface_enabled`（显式禁用或 admin
//! token 为空）对 `/_admin*` 全返回 `404`（与 token 有效性无关）。入口三态与监听端口语义见
//! `src/main.rs` 与 工程参考 §1。
//!
//! `request_context` 为最外层 `route_layer`：每个已匹配路由都包一层 ERROR 级
//! `http` span（`request_id`/`method`/`route`），使该请求派生出的日志行可关联。
//! 请求路径派生的后台任务经 `crate::logging::spawn_in_request_span` 继承当前 span；
//! 后台驱动（清扫、指标、TPM、Matrix 驱动等）不继承，保持原样。

use {
    crate::{
        config::targets::REQUEST_ID_HEADER,
        handler::{self, admin},
        service::credential::AppStateParts,
        state::AppState,
    },
    axum::{
        Json,
        Router,
        extract::{MatchedPath, Request, State},
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{any, get, post},
    },
    serde_json::json,
    std::{
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
        },
        time::SystemTime,
    },
    tracing::Instrument,
};

/// 入站 `x-request-id` 是否可原样沿用：1..=64 字节，且仅 `[A-Za-z0-9._-]`。
/// 该值会进入日志字段，须拒绝可伪造字段边界或注入结构的字节。
fn is_valid_request_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// 生成缺省 `request_id`：启动以来纳秒数 + 进程内单调序号（均十六进制，无新依赖）。
pub(crate) fn generated_request_id() -> String {
    static START: OnceLock<SystemTime> = OnceLock::new();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let start = *START.get_or_init(SystemTime::now);
    let elapsed_nanos = start.elapsed().unwrap_or_default().as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{elapsed_nanos:x}-{seq:x}")
}

/// 请求标识（进 `Request` extensions 供 LLM 分发读取落库，不下发响应头）。
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// 请求作用域日志上下文：为每个已匹配路由建一个 ERROR 级 `http` span。
///
/// `error_span!` 而非 `info_span!`：默认 `RUST_LOG=warn` 下 span 须仍启用。`route` 只取
/// `MatchedPath` 静态模式（缺失为 `-`），MUST NOT 回退 `uri().path()`（用户可控且高基数）。
/// 不写任何响应头。
async fn request_context(mut req: Request, next: Next) -> Response {
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_valid_request_id(value))
        .map_or_else(generated_request_id, str::to_owned);
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "-".to_string(), |path| path.as_str().to_string());
    let span = tracing::error_span!(
        "http",
        request_id = %request_id,
        method = %req.method(),
        route = %route,
    );
    req.extensions_mut().insert(RequestId(request_id));
    next.run(req).instrument(span).await
}

async fn observability_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !state.config().admin_surface_enabled() && req.uri().path().starts_with("/_admin") {
        // 未启用期 404 复用管理面统一安全头（五项通用头，不泄露
        // 管理面存在性；与 `admin_not_found` 同语义）。
        return admin::with_security_headers(
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": {"code": "E_NOT_FOUND", "message": "管理面已禁用"}})),
            )
                .into_response(),
        );
    }
    next.run(req).await
}

pub fn build_router(state: AppState) -> Router {
    {
        let cfg = state.config();
        if cfg.observability_disabled {
            tracing::warn!("OBSERVABILITY_DISABLE=1：管理面已禁用，/_admin 全返回 404");
        } else if !cfg.admin_surface_enabled() {
            tracing::warn!("OBSERVABILITY_ADMIN_TOKEN 缺失：管理面未启用，/_admin 全返回 404");
        }
    }
    Router::new()
        .route("/_admin/", get(admin::admin_index))
        .route("/_admin", get(admin::admin_index))
        .route("/_admin/health", get(admin::admin_health))
        .route("/_admin/metrics", get(admin::admin_metrics))
        .route("/_admin/series", get(admin::admin_series))
        .route("/_admin/events", get(admin::admin_events))
        .route("/_admin/events/stream", get(admin::admin_events_stream))
        .route("/_admin/commands", get(admin::admin_commands))
        .route("/_admin/requests", get(admin::admin_requests))
        .route("/_admin/{*rest}", any(admin::admin_not_found))
        .route("/health", get(handler::health_handler))
        .route("/credential", post(handler::credential_handler))
        .route("/registrations", get(handler::registrations_handler))
        .route("/register-caller", post(handler::register_caller_handler))
        .route("/revoke", post(handler::revoke_handler))
        .route("/revoke/emergency", post(handler::emergency_revoke_handler))
        .route(
            "/approve-hash-change",
            post(handler::approve_hash_change_handler),
        )
        .route("/commands", get(handler::commands_handler))
        .route(
            "/commands/{id}/invoke",
            post(handler::command_invoke_handler),
        )
        .route("/", any(handler::llm_proxy_handler))
        .route("/{*tail}", any(handler::llm_proxy_handler))
        .fallback(handler::llm_proxy_handler)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            observability_gate,
        ))
        .route_layer(middleware::from_fn(request_context))
        .with_state(state)
}

#[cfg(test)]
mod tests;
