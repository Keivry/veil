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
    Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "status": if health.sqlite_ok { "ok" } else { "degraded" },
        "unlocked": state.keepass.is_unlocked(),
    }))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Config, state::SqliteOutcome},
        std::{collections::HashMap, path::PathBuf},
    };

    #[tokio::test]
    async fn health_handler_exposes_service_status() {
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
        ]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        );
        let Json(body) = health_handler(State(state)).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["sqlite_ok"], true);
    }
}
