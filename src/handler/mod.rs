//! 处理器入口：凭据面（`credential`）与 LLM 网关面（`llm`）的装配与重导出。
//! 路由（`router.rs`）只经本模块访问两面，对外路径保持 `handler::*` 不变。

pub mod admin;
pub mod credential;
pub mod llm;
pub mod peer_ip;

use {
    crate::{service, state::AppState},
    axum::{Json, extract::State},
    serde_json::{Value, json},
};
pub use {credential::*, llm::*, peer_ip::PeerIp};

pub async fn health_handler(State(state): State<AppState>) -> Json<Value> {
    let health = service::health_status(&state);
    // 加性超集：既有字段只增不删；`pending`（待审批数）与
    // `llm_secrets`（已注册凭据数）补齐 Go `get status` 可直接解析的形态。
    Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "status": if health.sqlite_ok { "ok" } else { "degraded" },
        "unlocked": health.unlocked,
        "pending": health.pending,
        "llm_secrets": health.llm_secrets,
        "pii_custom_disabled": state.detector.disabled_snapshot().len(),
    }))
}

#[cfg(test)]
mod tests;
