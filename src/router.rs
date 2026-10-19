//! 路由装配与入口中间件。
//!
//! `build_router` 将凭据 API（`/credential`、`/registrations`、注册/吊销/哈希变更）与 LLM
//! 代理通配路由（`/{*tail}` + fallback）及 `/_admin` 管理面装配到同一 `Router`；
//! `observability_gate` 中间件按 `Config::admin_surface_enabled`（显式禁用或 admin
//! token 为空）对 `/_admin*` 全返回 `404`（与 token 有效性无关）。入口三态与监听端口语义见
//! `src/main.rs` 与 工程参考 §1。

use {
    crate::{
        handler::{self, admin},
        service::credential::AppStateParts,
        state::AppState,
    },
    axum::{
        Json,
        Router,
        extract::{Request, State},
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{any, get, post},
    },
    serde_json::json,
};

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
        .route("/{*tail}", any(handler::llm_proxy_handler))
        .fallback(handler::llm_proxy_handler)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            observability_gate,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests;
