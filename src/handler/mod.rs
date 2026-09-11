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
    // GO/D8.2 加性超集：既有字段只增不删；`pending`（待审批数）与
    // `llm_secrets`（已注册凭据数）补齐 Go `get status` 可直接解析的形态。
    Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "status": if health.sqlite_ok { "ok" } else { "degraded" },
        "unlocked": state.keepass.is_unlocked(),
        "pending": state.pending.len(),
        "llm_secrets": state.vault.len(),
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

    #[tokio::test]
    async fn health_superset_fields() {
        // GO/D8.2：`/health` 加性超集——既有 `ok/sqlite_ok/sqlite_error` 保留，
        // 补 `status/unlocked`，新旧客户端解析均不失败。
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
        assert!(body["sqlite_error"].is_null());
        assert_eq!(body["status"], "ok");
        assert!(
            body["unlocked"].is_boolean(),
            "unlocked 须存在且为布尔: {body}"
        );
    }

    #[tokio::test]
    async fn health_go_client_fields_present_and_numeric() {
        // GO/D8.2：补齐 Go `get status` 所需 `pending`（待审批数）与
        // `llm_secrets`（已注册凭据数），存在、数值正确，既有字段不删。
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
        state
            .pending
            .insert(crate::approval::PendingRecord::new("k-health", "test"));
        state.vault.register("health-secret-001").unwrap();
        let Json(body) = health_handler(State(state)).await;
        assert_eq!(body["pending"], 1, "pending 须为待审批数: {body}");
        assert!(body["pending"].is_u64(), "pending 须为数值: {body}");
        assert_eq!(
            body["llm_secrets"], 1,
            "llm_secrets 须为已注册凭据数: {body}"
        );
        assert!(body["llm_secrets"].is_u64(), "llm_secrets 须为数值: {body}");
        assert!(body["status"].is_string(), "status 须为字符串: {body}");
        assert!(body["unlocked"].is_boolean(), "unlocked 须为布尔: {body}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["sqlite_ok"], true);
        assert!(body["sqlite_error"].is_null());
        assert_eq!(body["status"], "ok");
    }
}
