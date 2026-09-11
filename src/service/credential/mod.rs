//! 凭据业务：三因子鉴权 / 注册吊销 / 审批双模 / KeePass 查询 / 限流表。
//!
//! A1 解耦说明：本层经 [`AppStateParts`] trait 读态，不再命名 `AppState`
//! 具体类型（`service -> state` 边已断）；`state.rs`
//! 聚合本层类型并实现本 trait（`state -> service` 单向，无环）。
//! 旧路径 `crate::service::{handle_credential, RateTable, ...}` 经
//! `service/mod.rs` 的 `pub use credential::*` 保持编译。
//!
//! A2 按职责拆模块：`auth`（三因子鉴权入口）、`approval`（审批/pending 链）、
//! `vault_ops`（KeePass 查询 + 注册表运维）、`ratelimit`（限流表）；
//! 本模块留守读态 trait、DTO 类型与重导出。

use {
    super::{admin, credential_vault, llm_gateway, matrix},
    crate::{
        approval::PendingApprovals,
        config::{AutoApprove, Config},
        keepass::KeePassBackend,
        registry::{CallerEntry, CallerRegistry},
    },
    serde::{Deserialize, Serialize},
    std::{path::PathBuf, sync::Arc},
};

pub mod approval;
pub mod auth;
pub mod ratelimit;
pub mod vault_ops;

pub use {
    approval::{await_audit_approval, await_credential_approval},
    auth::handle_credential,
    ratelimit::RateTable,
    vault_ops::{
        approve_hash_change,
        emergency_revoke,
        list_registrations,
        query_keepass,
        register_caller,
        register_caller_extended,
        revoke_caller,
    },
};

/// 服务层读态 trait（A1 依赖倒置）：凭据/健康/管理业务只经本 trait
/// 访问共享状态，不触 `AppState` 具体类型；`AppState` 在 `state.rs`
/// 中实现本 trait（构造链签名不变，调用方传 `&AppState` 仍编译）。
pub trait AppStateParts {
    fn config(&self) -> &Arc<Config>;
    fn sqlite_ok_flag(&self) -> bool;
    fn sqlite_error_text(&self) -> Option<String>;
    fn registry(&self) -> &Arc<tokio::sync::RwLock<CallerRegistry>>;
    fn registry_path(&self) -> &PathBuf;
    /// 写路径全序点（B1/D1）：仅三条低频管理写路径经此串行化落盘，读路径不经过。
    fn registry_save_lock(&self) -> &Arc<tokio::sync::Mutex<()>>;
    fn keepass(&self) -> &Arc<dyn KeePassBackend>;
    fn pending(&self) -> &Arc<PendingApprovals>;
    fn approval(&self) -> &Arc<matrix::MatrixApproval>;
    fn http_client(&self) -> &Arc<reqwest::Client>;
    fn vault(&self) -> &Arc<credential_vault::CredentialVault>;
    fn credential_hits(&self) -> &Arc<tokio::sync::Mutex<RateTable>>;
    fn register_hits(&self) -> &Arc<tokio::sync::Mutex<RateTable>>;
    fn gateway_metrics(&self) -> &Arc<llm_gateway::GatewayMetrics>;
    fn admin_state(&self) -> &Arc<admin::AdminState>;
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub sqlite_ok: bool,
    pub sqlite_error: Option<String>,
}

pub fn health_status(state: &impl AppStateParts) -> HealthStatus {
    HealthStatus {
        sqlite_ok: state.sqlite_ok_flag(),
        sqlite_error: state.sqlite_error_text(),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthBlock {
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    /// Go 互操作别名：`body.auth.get_binary_hash` 等价 `X-Get-Binary-Hash` 头。
    #[serde(default)]
    pub get_binary_hash: Option<String>,
    /// Go 互操作别名：`body.auth.get_binary_secret` 等价 `X-Get-Binary-Secret` 头（及
    /// `body.secret`）。
    #[serde(default)]
    pub get_binary_secret: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
    /// 取用选择器：条目名（Go `get credential <entry> <field>` 的 entry）。
    #[serde(default)]
    pub entry: Option<String>,
    /// 取用选择器：字段名单数形态。
    #[serde(default)]
    pub field: Option<String>,
    /// 取用选择器：字段名复数形态（接受字符串或字符串数组，兼容 Go 侧形态）。
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
    /// 脱敏开关：`None` 默认 true；`password` 与受保护自定义属性按 `use_token` 脱敏。
    #[serde(default)]
    pub token: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct CredentialHeaders {
    pub binary_hash: Option<String>,
    pub binary_secret: Option<String>,
}

impl CredentialHeaders {
    pub fn new(binary_hash: Option<String>, binary_secret: Option<String>) -> Self {
        Self {
            binary_hash,
            binary_secret,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationView {
    pub caller_path: String,
    pub enabled: bool,
    pub revoked: bool,
    pub status: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allow_mode: Option<AutoApprove>,
    /// Go 加性兼容（D8.3）：与 `caller_path` 同值，只增不改。
    #[serde(default)]
    pub script_path: String,
    /// Go 加性兼容（D8.3）：注册脚本哈希（`expected_hash` 回显）。
    #[serde(default)]
    pub script_hash: String,
    /// Go 加性兼容（D8.3）：条目→字段授权映射回显。
    #[serde(default)]
    pub entries: std::collections::BTreeMap<String, Vec<String>>,
}

pub(crate) fn registration_view(entry: &CallerEntry) -> RegistrationView {
    RegistrationView {
        caller_path: entry.caller_path.clone(),
        enabled: entry.enabled,
        revoked: entry.revoked,
        status: entry.status_emoji().to_string(),
        name: entry.name.clone(),
        description: entry.description.clone(),
        allow_mode: entry.allow_mode.or(entry.auto_approve),
        script_path: entry.caller_path.clone(),
        script_hash: entry.expected_hash.clone(),
        entries: entry.entries.clone(),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::{super::vault_ops, AuthBlock, CredentialBody, CredentialHeaders},
        crate::{
            config::Config,
            registry::RegisterParams,
            state::{AppState, SqliteOutcome},
        },
        std::{
            collections::{BTreeMap, HashMap},
            path::PathBuf,
            sync::Arc,
        },
    };

    pub(crate) type TestMap = BTreeMap<String, Vec<String>>;

    pub(crate) fn test_state(sqlite_ok: bool) -> AppState {
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
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok,
                sqlite_error: if sqlite_ok {
                    None
                } else {
                    Some("ENOSPC".to_string())
                },
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
    }

    pub(crate) fn cred_env(extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut env = HashMap::from([
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
            ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
            ("GET_BINARY_HASH".to_string(), "gethash".to_string()),
        ]);
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        env
    }

    pub(crate) fn cred_state(env: &HashMap<String, String>) -> AppState {
        let state = AppState::new(
            Config::load_from(env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        );
        state.with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()))
    }

    pub(crate) fn body(hash: &str, path: &str, secret: Option<&str>) -> CredentialBody {
        CredentialBody {
            secret: secret.map(|s| s.to_string()),
            auth: Some(AuthBlock {
                caller_hash: Some(hash.to_string()),
                caller_path: Some(path.to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            entry: Some("网易".to_string()),
            field: Some("授权码".to_string()),
            fields: None,
            token: None,
        }
    }

    pub(crate) fn credential_value(out: &serde_json::Value) -> &str {
        out.get("value").and_then(|v| v.as_str()).unwrap_or("")
    }

    pub(crate) fn headers(hash: &str, secret: Option<&str>) -> CredentialHeaders {
        CredentialHeaders::new(Some(hash.to_string()), secret.map(|s| s.to_string()))
    }

    pub(crate) fn entries_for(entry: &str, fields: &[&str]) -> TestMap {
        TestMap::from([(
            entry.to_string(),
            fields.iter().map(|s| (*s).to_string()).collect(),
        )])
    }

    pub(crate) async fn enrolled_with_entries(
        state: &AppState,
        path: &str,
        hash: &str,
        entries: TestMap,
    ) {
        vault_ops::register_caller_extended(
            state,
            &RegisterParams {
                caller_path: path.to_string(),
                caller_hash: hash.to_string(),
                name: "test".to_string(),
                description: String::new(),
                entries,
                allow_mode: None,
            },
            &format!("acl-test-{path}"),
        )
        .await
        .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled(path, true)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use {super::*, test_support::*};

    #[test]
    fn health_status_exposes_degraded_flag() {
        assert!(health_status(&test_state(true)).sqlite_ok);
        let degraded = health_status(&test_state(false));
        assert!(!degraded.sqlite_ok);
        assert_eq!(degraded.sqlite_error.as_deref(), Some("ENOSPC"));
    }

    #[test]
    fn disk_full_classified_and_degraded_flags_paired() {
        let full = anyhow::anyhow!(std::io::Error::from(std::io::ErrorKind::StorageFull));
        assert!(crate::state::is_no_space_error(&full));
        let other = anyhow::anyhow!(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(!crate::state::is_no_space_error(&other));
        let out = crate::state::SqliteOutcome {
            sqlite_ok: false,
            sqlite_error: Some("ENOSPC (disk full)".to_string()),
            db_path: std::path::PathBuf::from("/tmp/x.sqlite"),
        };
        assert!(!out.sqlite_ok, "降级须与 sqlite_error 成对出现");
    }
}
