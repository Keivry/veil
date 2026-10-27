//! 凭据业务：三因子鉴权 / 注册吊销 / 审批双模 / KeePass 查询 / 限流表。
//!
//! 解耦说明：本层经 [`AppStateParts`] trait 读态，不再命名 `AppState`
//! 具体类型（`service -> state` 边已断）；`state.rs`
//! 聚合本层类型并实现本 trait（`state -> service` 单向，无环）。
//! 旧路径 `crate::service::{handle_credential, RateTable, ...}` 经
//! `service/mod.rs` 的 `pub use credential::*` 保持编译。
//!
//! 按职责拆模块：`auth`（三因子鉴权入口）、`approval`（审批/pending 链）、
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
pub mod decision;
pub mod ratelimit;
pub mod register_map;
pub mod vault_ops;

pub use {
    approval::{await_audit_approval, await_credential_approval},
    auth::{handle_credential, verify_three_factor, verify_three_factor_write},
    ratelimit::RateTable,
    vault_ops::{
        approve_hash_change,
        emergency_revoke,
        list_registrations,
        query_keepass,
        register_caller,
        register_caller_extended,
        register_caller_with_approval,
        revoke_caller,
        revoke_caller_with_approval,
    },
};

/// 服务层读态 trait（依赖倒置）：凭据/健康/管理业务只经本 trait
/// 访问共享状态，不触 `AppState` 具体类型；`AppState` 在 `state.rs`
/// 中实现本 trait（构造链签名不变，调用方传 `&AppState` 仍编译）。
///
/// 只读快照契约：`health_status` 经 `keepass()`/`pending()`/`vault()` 组装
/// `unlocked`/`pending`/`llm_secrets`，仅读取快照、不触发状态迁移；handler 仅
/// 序列化本层结果，不得直读进程内状态字段（层边界归本 trait 收口）。
pub trait AppStateParts {
    fn config(&self) -> &Arc<Config>;
    fn sqlite_ok_flag(&self) -> bool;
    fn sqlite_error_text(&self) -> Option<String>;
    fn registry(&self) -> &Arc<tokio::sync::RwLock<CallerRegistry>>;
    fn registry_path(&self) -> &PathBuf;
    /// 写路径全序点：仅三条低频管理写路径经此串行化落盘，读路径不经过。
    fn registry_save_lock(&self) -> &Arc<tokio::sync::Mutex<()>>;
    fn keepass(&self) -> &Arc<dyn KeePassBackend>;
    fn pending(&self) -> &Arc<PendingApprovals>;
    fn approval(&self) -> &Arc<matrix::MatrixApproval>;
    /// 受管审批决策表（进程级 `static` 已移除），所有决策读写经此访问。
    fn decisions(&self) -> &Arc<std::sync::Mutex<approval::DecisionTable>>;
    fn http_client(&self) -> &Arc<reqwest::Client>;
    fn vault(&self) -> &Arc<credential_vault::CredentialVault>;
    fn credential_hits(&self) -> &Arc<tokio::sync::Mutex<RateTable>>;
    fn register_hits(&self) -> &Arc<tokio::sync::Mutex<RateTable>>;
    fn gateway_metrics(&self) -> &Arc<llm_gateway::GatewayMetrics>;
    fn admin_state(&self) -> &Arc<admin::AdminState>;
    /// 失败/审批通知统一有界 spool（应用层单例）。
    fn notify(&self) -> &Arc<matrix::NotificationSpool>;
    /// 命令面运行时（配置、授权、执行后端、日志与幂等表）。
    fn command(&self) -> &Arc<crate::service::command::CommandRuntime>;
    /// TPM 运行期健康快照（后台周期探测写入，此处只读）。
    fn tpm_health(&self) -> &Arc<crate::service::tpm::TpmHealthCache>;
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub sqlite_ok: bool,
    pub sqlite_error: Option<String>,
    pub unlocked: bool,
    pub pending: usize,
    pub llm_secrets: usize,
    pub tpm_ok: bool,
    pub tpm_error: Option<String>,
    pub master_password_cached: bool,
    /// 24h 内到期且 `enabled && !revoked` 的条目数（每次 `/health` 现算，不缓存）。
    pub authorization_expiring: usize,
}

pub fn health_status(state: &impl AppStateParts) -> HealthStatus {
    let tpm = state.tpm_health().snapshot();
    HealthStatus {
        sqlite_ok: state.sqlite_ok_flag(),
        sqlite_error: state.sqlite_error_text(),
        unlocked: state.keepass().is_unlocked(),
        pending: state.pending().len(),
        llm_secrets: state.vault().len(),
        tpm_ok: tpm.ok,
        tpm_error: tpm.error,
        master_password_cached: state.keepass().master_password_cached(),
        authorization_expiring: count_authorization_expiring(state),
    }
}

/// 健康面授权到期预警计数：仅统计仍生效且将在 24h 内到期的条目。
/// 现算不缓存——注册表规模是调用方数量，线性扫描成本可忽略，且避免与
/// 吊销/审批落定产生失效同步问题。
fn count_authorization_expiring(state: &impl AppStateParts) -> usize {
    const WINDOW_SECS: u64 = 86_400;
    let Ok(registry) = state.registry().try_read() else {
        // 写锁被占（审批落定/吊销正在落盘）时本字段降级为 0。`/health` 是同步只读
        // 探针，为它引入 async 会传染整条调用链；此字段仅作预警，且写锁持有窗口
        // 极短，下一次探测即可恢复真值，故接受这一近似并记录以便排查。
        tracing::debug!("authorization_expiring 读取注册表失败（写锁占用），本次按 0 计");
        return 0;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let horizon = now.saturating_add(WINDOW_SECS);
    registry
        .snapshot()
        .iter()
        .filter(|entry| entry.enabled && !entry.revoked)
        .filter_map(crate::registry::authorization_expires_at)
        .filter(|expires_at| *expires_at > now && *expires_at <= horizon)
        .count()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthBlock {
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    /// Go 互操作别名：`body.auth.veilctl_binary_hash` 等价 `X-Veilctl-Binary-Hash` 头。
    #[serde(default)]
    pub veilctl_binary_hash: Option<String>,
    /// Go 互操作别名：`body.auth.veilctl_secret` 等价 `X-Veilctl-Secret` 头（及
    /// `body.secret`）。
    #[serde(default)]
    pub veilctl_secret: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
    /// 取用选择器：条目名（Go `veilctl credential <entry> <field>` 的 entry）。
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
    /// 无 body 的 GET 端点（如 `GET /commands`）从头发送调用者身份。
    pub caller_hash: Option<String>,
    pub caller_path: Option<String>,
}

impl CredentialHeaders {
    pub fn new(binary_hash: Option<String>, binary_secret: Option<String>) -> Self {
        Self {
            binary_hash,
            binary_secret,
            caller_hash: None,
            caller_path: None,
        }
    }

    pub fn with_caller(mut self, caller_hash: Option<String>, caller_path: Option<String>) -> Self {
        self.caller_hash = caller_hash;
        self.caller_path = caller_path;
        self
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
    /// Go 加性兼容：与 `caller_path` 同值，只增不改。
    #[serde(default)]
    pub script_path: String,
    /// Go 加性兼容：注册脚本哈希（`expected_hash` 回显）。
    #[serde(default)]
    pub script_hash: String,
    /// Go 加性兼容：条目→字段授权映射回显。
    #[serde(default)]
    pub entries: std::collections::BTreeMap<String, Vec<String>>,
    /// 授权窗口起点（unix 秒）；`null` 表示从未落定带窗口的批准。
    #[serde(default)]
    pub authorized_at: Option<u64>,
    /// 授权窗口长度（秒）；`null` 表示无期限。
    #[serde(default)]
    pub authorized_ttl_secs: Option<u64>,
    /// 到期时刻：由后端按 `authorized_at + authorized_ttl_secs` 饱和相加得出，
    /// 客户端 SHALL NOT 自行相加。
    #[serde(default)]
    pub authorization_expires_at: Option<u64>,
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
        authorized_at: entry.authorized_at,
        // 未落定批准前不对外回显窗口长度：条目上的 `authorized_ttl_secs` 此时只是
        // 「待批请求值」，与「本次授权有效期」语义不同，回显会自相矛盾。
        authorized_ttl_secs: entry.authorized_at.and(entry.authorized_ttl_secs),
        authorization_expires_at: crate::registry::authorization_expires_at(entry),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::{super::vault_ops, AuthBlock, CredentialBody, CredentialHeaders},
        crate::{
            config::Config,
            registry::RegisterParams,
            service::matrix::{
                MatrixBot,
                NOTIFICATION_QUEUE_CAPACITY,
                NotificationSink,
                NotificationSpool,
            },
            state::{AppState, SqliteOutcome},
        },
        std::{
            collections::{BTreeMap, HashMap},
            future::Future,
            path::PathBuf,
            pin::Pin,
            sync::{
                Arc,
                atomic::{AtomicU64, Ordering},
            },
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
            ("VEILCTL_SECRET".to_string(), "s3cr3t".to_string()),
            ("VEILCTL_BINARY_HASH".to_string(), "gethash".to_string()),
        ]);
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        env
    }

    pub(crate) fn cred_state(env: &HashMap<String, String>) -> AppState {
        cred_state_with_sink(env, InjectSink::success())
    }

    /// 测试注入 sink：成功返回自增真实 id（`$test-event-{n}`），失败返回 `None`。
    /// tracked 正文留存在 `texts()`，供票面文案断言。
    #[derive(Debug)]
    pub(crate) struct InjectSink {
        next: AtomicU64,
        fail: bool,
        texts: std::sync::Mutex<Vec<String>>,
    }

    impl InjectSink {
        pub(crate) fn success() -> Arc<Self> {
            Arc::new(Self {
                next: AtomicU64::new(1),
                fail: false,
                texts: std::sync::Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn failing() -> Arc<Self> {
            Arc::new(Self {
                next: AtomicU64::new(1),
                fail: true,
                texts: std::sync::Mutex::new(Vec::new()),
            })
        }

        pub(crate) fn texts(&self) -> Vec<String> {
            self.texts
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default()
        }
    }

    impl NotificationSink for InjectSink {
        fn send_text(&self, _text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }

        fn send_text_tracked(
            &self,
            text: String,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
            if let Ok(mut guard) = self.texts.lock() {
                guard.push(text);
            }
            let id = (!self.fail)
                .then(|| format!("$test-event-{}", self.next.fetch_add(1, Ordering::SeqCst)));
            Box::pin(async move { id })
        }
    }

    /// 测试 sink：记录 best-effort 文本，供宽限通知去重断言。
    #[derive(Debug, Default)]
    pub(crate) struct CountingSink {
        texts: std::sync::Mutex<Vec<String>>,
    }

    impl CountingSink {
        pub(crate) fn new() -> Arc<Self> { Arc::new(Self::default()) }

        pub(crate) fn texts(&self) -> Vec<String> {
            self.texts
                .lock()
                .map(|guard| guard.clone())
                .unwrap_or_default()
        }
    }

    impl NotificationSink for CountingSink {
        fn send_text(&self, text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                if let Ok(mut guard) = self.texts.lock() {
                    guard.push(text);
                }
            })
        }
    }

    /// 以注入 sink 覆盖 `AppState.notify`（审批 tracked 发送改走注入 sink）。
    pub(crate) fn inject_sink(mut state: AppState, sink: Arc<dyn NotificationSink>) -> AppState {
        let bot = Arc::new(MatrixBot::new(
            state.config.homeserver.clone(),
            state.config.room_id.clone(),
            state.config.matrix_access_token.clone(),
        ));
        state.notify = Arc::new(NotificationSpool::with_sink(
            bot,
            sink,
            NOTIFICATION_QUEUE_CAPACITY,
        ));
        state
    }

    pub(crate) fn cred_state_with_sink(
        env: &HashMap<String, String>,
        sink: Arc<dyn NotificationSink>,
    ) -> AppState {
        inject_sink(
            AppState::new(
                Config::load_from(env).unwrap(),
                SqliteOutcome {
                    sqlite_ok: true,
                    sqlite_error: None,
                    db_path: PathBuf::from("/tmp/x.sqlite"),
                },
            )
            .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked())),
            sink,
        )
    }

    pub(crate) fn body(hash: &str, path: &str, secret: Option<&str>) -> CredentialBody {
        CredentialBody {
            secret: secret.map(|s| s.to_string()),
            auth: Some(AuthBlock {
                caller_hash: Some(hash.to_string()),
                caller_path: Some(path.to_string()),
                veilctl_binary_hash: None,
                veilctl_secret: None,
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

    /// 测试装配：注册并启用具备 `网易/授权码` 放行权限的调用方；
    /// `name` 取 `path` 以保证多次调用不触发重名 409。
    pub(crate) async fn enroll_allow(state: &AppState, path: &str, hash: &str) {
        vault_ops::register_caller_extended(
            state,
            &RegisterParams {
                caller_path: path.to_string(),
                caller_hash: hash.to_string(),
                name: path.to_string(),
                entries: entries_for("网易", &["授权码"]),
                ..RegisterParams::default()
            },
            &format!("enroll-{path}"),
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
                authorization_ttl: crate::registry::AuthorizationTtl::Absent,
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

    pub(crate) fn seed_health_fixtures(state: &AppState) {
        state
            .pending
            .insert(crate::approval::PendingRecord::new("k-health", "test"));
        state.vault.register("health-secret-001").unwrap();
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
    fn health_status_full_fields() {
        let state = cred_state(&cred_env(&[]));
        let health = health_status(&state);
        assert!(health.sqlite_ok);
        assert!(health.unlocked, "unlocked 经 trait 数据组装");
        assert_eq!(health.pending, 0);
        assert_eq!(health.llm_secrets, 0);
        state
            .pending
            .insert(crate::approval::PendingRecord::new("k-h", "t"));
        state.vault.register("h-secret-1").unwrap();
        let health = health_status(&state);
        assert_eq!(health.pending, 1, "pending 经 trait 数据组装");
        assert_eq!(health.llm_secrets, 1, "llm_secrets 经 trait 数据组装");
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

#[cfg(test)]
mod authorization_ttl_tests {
    use {super::*, test_support::*};

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn registration_view_echoes_window_and_computes_expiry() {
        let state = cred_state(&cred_env(&[]));
        enrolled_with_entries(
            &state,
            "/s/view-ttl.sh",
            "h-view-ttl",
            entries_for("网易", &["授权码"]),
        )
        .await;
        let at = now_secs();
        state
            .registry
            .write()
            .await
            .set_authorization_window("/s/view-ttl.sh", Some(at), Some(3_600))
            .unwrap();
        let views = list_registrations(&state, Some("observability-admin-token-0123456789"), None)
            .await
            .expect("查询须成功");
        let view = views
            .iter()
            .find(|v| v.caller_path == "/s/view-ttl.sh")
            .expect("条目须在列表中");
        assert_eq!(view.authorized_at, Some(at));
        assert_eq!(view.authorized_ttl_secs, Some(3_600));
        assert_eq!(
            view.authorization_expires_at,
            Some(at + 3_600),
            "到期时刻须由后端相加得出"
        );
        assert_eq!(view.status, "✅", "到期不改变状态徽标");
        assert!(view.enabled && !view.revoked);
    }

    #[tokio::test]
    async fn registration_view_unbounded_entry_has_null_expiry() {
        let state = cred_state(&cred_env(&[]));
        enrolled_with_entries(
            &state,
            "/s/view-none.sh",
            "h-view-none",
            entries_for("网易", &["授权码"]),
        )
        .await;
        let views = list_registrations(&state, Some("observability-admin-token-0123456789"), None)
            .await
            .unwrap();
        let view = views
            .iter()
            .find(|v| v.caller_path == "/s/view-none.sh")
            .unwrap();
        assert_eq!(view.authorized_at, None);
        assert_eq!(view.authorized_ttl_secs, None);
        assert_eq!(view.authorization_expires_at, None);
    }

    #[tokio::test]
    async fn health_counts_only_enabled_unrevoked_entries_expiring_within_24h() {
        let state = cred_state(&cred_env(&[]));
        let now = now_secs();
        let soon = now + 3_600;
        let later = now + 86_400 * 2;
        for (path, hash, at, ttl) in [
            ("/s/exp-soon.sh", "h-soon", now, Some(soon - now)),
            ("/s/exp-later.sh", "h-later", now, Some(later - now)),
        ] {
            vault_ops::register_caller_extended(
                &state,
                &crate::registry::RegisterParams {
                    caller_path: path.to_string(),
                    caller_hash: hash.to_string(),
                    name: path.to_string(),
                    entries: entries_for("网易", &["授权码"]),
                    ..crate::registry::RegisterParams::default()
                },
                path,
            )
            .await
            .unwrap();
            state
                .registry
                .write()
                .await
                .set_enabled(path, true)
                .unwrap();
            state
                .registry
                .write()
                .await
                .set_authorization_window(path, Some(at), ttl)
                .unwrap();
        }
        assert_eq!(
            health_status(&state).authorization_expiring,
            1,
            "仅计 24h 内到期的生效条目"
        );

        state
            .registry
            .write()
            .await
            .set_enabled("/s/exp-soon.sh", false)
            .unwrap();
        assert_eq!(
            health_status(&state).authorization_expiring,
            0,
            "停用条目不计入"
        );
    }

    #[tokio::test]
    async fn health_authorization_expiring_boundary_is_exclusive_now_inclusive_horizon() {
        // 边界语义 `(now, now+86400]`：恰好到期于 now 的已属过期（不计入），
        // 恰好到期于 now+86400 的仍算「24h 内将到期」（计入）。
        let state = cred_state(&cred_env(&[]));
        let now = now_secs();
        for (path, hash, at, ttl) in [
            ("/s/exp-at-now.sh", "h-at-now", now, Some(0)),
            ("/s/exp-at-edge.sh", "h-at-edge", now, Some(86_400)),
            (
                "/s/exp-at-edge-plus.sh",
                "h-at-edge-plus",
                now,
                Some(86_401),
            ),
        ] {
            vault_ops::register_caller_extended(
                &state,
                &crate::registry::RegisterParams {
                    caller_path: path.to_string(),
                    caller_hash: hash.to_string(),
                    name: path.to_string(),
                    entries: entries_for("网易", &["授权码"]),
                    ..crate::registry::RegisterParams::default()
                },
                path,
            )
            .await
            .unwrap();
            state
                .registry
                .write()
                .await
                .set_enabled(path, true)
                .unwrap();
            state
                .registry
                .write()
                .await
                .set_authorization_window(path, Some(at), ttl)
                .unwrap();
        }
        // `Some(0)` 窗口在 `authorization_expires_at` 中等于起点时刻，即已过期。
        assert_eq!(
            health_status(&state).authorization_expiring,
            1,
            "仅 now+86400 恰好落在窗口内边界"
        );
    }

    #[tokio::test]
    async fn health_authorization_expiring_is_zero_without_deadlines() {
        let state = cred_state(&cred_env(&[]));
        enrolled_with_entries(
            &state,
            "/s/exp-none.sh",
            "h-exp-none",
            entries_for("网易", &["授权码"]),
        )
        .await;
        assert_eq!(health_status(&state).authorization_expiring, 0);
    }
}
