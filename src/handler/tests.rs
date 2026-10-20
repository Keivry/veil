use {
    super::*,
    crate::{config::Config, state::SqliteOutcome},
    std::{collections::HashMap, path::PathBuf, sync::Arc},
};

const HEALTH_KEYS: [&str; 12] = [
    "ok",
    "sqlite_ok",
    "sqlite_error",
    "status",
    "unlocked",
    "pending",
    "llm_secrets",
    "pii_custom_disabled",
    "tpm_ok",
    "tpm_error",
    "master_password_cached",
    "authorization_expiring",
];

fn base_env() -> HashMap<String, String> {
    HashMap::from([
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
    ])
}

fn state_from(env: &HashMap<String, String>) -> AppState {
    AppState::new(
        Config::load_from(env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    )
}

/// 生产由 `main` 注入真实健康缓存；测试同样显式注入（类型默认值 fail-closed）。
fn state_with_env() -> AppState { state_with_tpm(true, None) }

fn state_with_tpm(ok: bool, error: Option<&str>) -> AppState {
    let dir = unique_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seal.pub"), b"pub").unwrap();
    std::fs::write(dir.join("seal.priv"), b"priv").unwrap();
    let cache = crate::service::tpm::TpmHealthCache::new(
        dir,
        crate::service::tpm::TpmHealth {
            ok,
            error: error.map(str::to_string),
        },
    );
    state_from(&base_env()).with_tpm_health(Arc::new(cache))
}

fn unique_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "veil-handler-health-{}-{nanos}",
        std::process::id()
    ))
}

#[tokio::test]
async fn health_handler_exposes_service_status() {
    let state = state_with_env();
    let Json(body) = health_handler(State(state)).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["sqlite_ok"], true);
}

#[tokio::test]
async fn health_superset_fields() {
    // GO/D8.2：`/health` 加性超集——既有 `ok/sqlite_ok/sqlite_error` 保留，
    // 补 `status/unlocked`，新旧客户端解析均不失败。
    let state = state_with_env();
    let Json(body) = health_handler(State(state)).await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["sqlite_ok"], true);
    assert!(body["sqlite_error"].is_null());
    assert_eq!(body["status"], "ok");
    assert!(
        body["unlocked"].is_boolean(),
        "unlocked 须存在且为布尔: {body}"
    );
    assert!(body["tpm_ok"].is_boolean(), "tpm_ok 须为布尔: {body}");
    assert_eq!(body["tpm_ok"], true, "Mock 缓存恒可用: {body}");
    assert!(
        body["tpm_error"].is_null() || body["tpm_error"].is_string(),
        "tpm_error 须为 null 或字符串: {body}"
    );
    assert!(
        body["tpm_error"].is_null(),
        "可用时 tpm_error 须为 null: {body}"
    );
    assert!(
        body["master_password_cached"].is_boolean(),
        "master_password_cached 须为布尔: {body}"
    );
}

#[tokio::test]
async fn health_go_client_fields_present_and_numeric() {
    // GO/D8.2：补齐 Go `veilctl status` 所需 `pending`（待审批数）与
    // `llm_secrets`（已注册凭据数），存在、数值正确，既有字段不删。
    let state = state_with_env();
    crate::service::credential::test_support::seed_health_fixtures(&state);
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

#[tokio::test]
async fn health_pii_custom_disabled() {
    // P2/D3：停用自定义规则计数只增字段，连续 3 次超时后在 health 可见。
    let state = state_with_env();
    let Json(before) = health_handler(State(state.clone())).await;
    assert_eq!(
        before["pii_custom_disabled"], 0,
        "无停用时计数须为 0: {before}"
    );
    for _ in 0..3 {
        state.detector.account_rule("slow", true);
    }
    assert!(
        state
            .detector
            .disabled_snapshot()
            .contains(&"slow".to_string())
    );
    let Json(body) = health_handler(State(state)).await;
    assert!(
        body["pii_custom_disabled"].as_u64().unwrap_or(0) >= 1,
        "停用后 health 须可见: {body}"
    );
    assert_eq!(body["ok"], true, "既有字段只增不改: {body}");
    assert_eq!(body["sqlite_ok"], true);
    assert!(body["status"].is_string());
    assert!(body["llm_secrets"].is_u64());
}

#[tokio::test]
async fn health_degraded_when_tpm_unavailable() {
    // 密封对象缺失 → `snapshot()` 覆盖为不可用，`ok`/`status` 同步降级，
    // 但 HTTP 状态码仍为 200（`/health` 恒 200 的既有契约不变）。
    let state = state_with_tpm(false, Some("tpm2_pcrread 不存在"));
    let Json(body) = health_handler(State(state)).await;
    assert_eq!(body["tpm_ok"], false, "tpm_ok 须为 false: {body}");
    assert_eq!(
        body["tpm_error"], "tpm2_pcrread 不存在",
        "tpm_error 须透出因由: {body}"
    );
    assert_eq!(body["ok"], false, "ok 须派生为 false: {body}");
    assert_eq!(body["status"], "degraded", "status 须降级: {body}");
    assert_eq!(body["sqlite_ok"], true, "sqlite 维度不受影响: {body}");
}

#[tokio::test]
async fn health_reports_eleven_keys_without_approval_bypass() {
    // 字段集合固定为 11 个；审批豁免概念已删除，不得回显 `approval_bypass`。
    let state = state_with_tpm(true, None);
    let Json(body) = health_handler(State(state)).await;
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), HEALTH_KEYS.len(), "字段数须为 12: {keys:?}");
    for key in HEALTH_KEYS {
        assert!(body.get(key).is_some(), "缺字段 {key}: {body}");
    }
    assert!(
        body.get("approval_bypass").is_none(),
        "不得出现 approval_bypass: {body}"
    );
}

#[tokio::test]
async fn health_ok_requires_both_sqlite_and_tpm() {
    let sqlite_down = AppState::new(
        Config::load_from(&base_env()).unwrap(),
        SqliteOutcome {
            sqlite_ok: false,
            sqlite_error: Some("ENOSPC".to_string()),
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    )
    .with_tpm_health(Arc::new(crate::service::tpm::TpmHealthCache::mock()));
    let Json(body) = health_handler(State(sqlite_down)).await;
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["tpm_ok"], true, "TPM 维度仍为可用: {body}");
}
