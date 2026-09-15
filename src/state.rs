//! 共享状态与 sqlite 初始化。
//!
//! 口径对标原仓 `_metrics.py`：WAL + `busy_timeout=5000` +
//! `synchronous=NORMAL` + `user_version=1`，库文件及 `-wal`/`-shm`
//! 均 0600；`ENOSPC` 降级内存-only 且 `sqlite_ok=false`，进程不崩。
//!
//! 并发约束：rusqlite 调用一律包在 `spawn_blocking` 内，禁 async 直调。

use {
    crate::{
        approval::PendingApprovals,
        config::Config,
        error::{Result, VeilError},
        keepass::{KeePassBackend, MockKeePass},
        registry::CallerRegistry,
        service::metrics::PiiSamplerConfig,
    },
    std::{
        path::{Path, PathBuf},
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    },
};

/// sqlite 库文件名。
pub const SQLITE_FILE_NAME: &str = "metrics.sqlite";
/// 忙等待超时（毫秒）：归属 `fs_perm` 单一来源，此处转发防外部引用断裂。
pub use crate::fs_perm::SQLITE_BUSY_TIMEOUT_MS;
/// 用户版本号，与原仓 `user_version=1` 同值。
pub const SQLITE_USER_VERSION: i64 = 1;

/// 可被多任务共享的应用状态，axum `State` 要求 `Clone` 故内层全 `Arc`。
#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sqlite_ok: Arc<AtomicBool>,
    pub sqlite_error: Arc<Mutex<Option<String>>>,
    pub db_path: PathBuf,
    pub registry: Arc<tokio::sync::RwLock<CallerRegistry>>,
    pub registry_path: PathBuf,
    /// 写路径全序点（B1/D1）：序列化三条管理写路径的落盘次序，防旧快照覆盖新快照。
    pub registry_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub keepass: Arc<dyn KeePassBackend>,
    pub pending: Arc<PendingApprovals>,
    pub approval: Arc<crate::service::matrix::MatrixApproval>,
    /// `ARC-2`：受管审批决策表（替代原 `approval.rs` 进程级 `static`）。
    pub decisions: Arc<Mutex<crate::service::credential::approval::DecisionTable>>,
    pub credential_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub register_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub gateway_metrics: Arc<crate::service::llm_gateway::GatewayMetrics>,
    pub admin: Arc<crate::service::admin::AdminState>,
    /// A1/D1：`AuditLogger` 启动期单例（`audit_sink` 持同一 `Arc` 写盘）。
    pub audit_logger: Arc<crate::service::audit::AuditLogger>,
    /// A1/D1：审计落盘 + 事件环接线单例（`DATA_DIR/audit.log`，`spawn_blocking` 写盘）。
    pub audit_sink: Arc<crate::service::audit::AuditSink>,
    /// `POL-1`/D1：启动期 fail-fast 加载并注入的审计策略单例；请求路径复用，不再每请求读盘。
    pub audit_policy: Arc<crate::service::audit::AuditPolicy>,
    pub http_client: Arc<reqwest::Client>,
    /// T3/D3：流式（SSE）转发专用 client——不设覆盖整响应体读取的总超时，
    /// 避免长流被 `HTTP_TIMEOUT_SECS` 截断；非流与 NonDialog 仍用 `http_client`。
    /// 读空闲超时默认禁用（无），失活连接依赖 TCP keepalive；口径见 README §7.2。
    pub http_stream_client: Arc<reqwest::Client>,
    pub vault: Arc<crate::service::credential_vault::CredentialVault>,
    pub detector: Arc<crate::service::pii::PiiDetector>,
    /// H10/D10：失败/审批通知统一有界 spool（单 Bot + 有界队列 + 常驻消费者）。
    /// 消费者由 `main` 启动期 `start()` 拉起；未启动时 `notify_text` 按满队列丢弃。
    pub notify: Arc<crate::service::matrix::NotificationSpool>,
}

impl AppState {
    /// 生产入口：以 fail-fast 语义构造。任一辈子系统加载失败（注册表损坏、
    /// 自定义 PII 文件再读失败）记 `error` 日志并 panic 终止启动（`CRD-1`/`DCD-1`）。
    pub fn new(config: Config, outcome: SqliteOutcome) -> Self {
        match Self::try_new(config, outcome) {
            Ok(state) => state,
            Err(err) => {
                tracing::error!("AppState 初始化失败，拒绝启动: {err:#}");
                panic!("AppState 初始化失败，拒绝启动: {err:#}");
            }
        }
    }

    /// 可测的 fail-fast 构造核心：注册表加载错误上抛（不再 `.unwrap_or_default()`
    /// 静默吞空表），并把已校验的自定义 PII 文件注入运行时检测器。
    pub fn try_new(config: Config, outcome: SqliteOutcome) -> Result<Self> {
        let registry_path = config.registry_path.clone();
        // `CRD-1`/C14：加载失败（解析失败或完整性失配）一律上抛拒启动，不以空表放行。
        let registry = CallerRegistry::load_from(&registry_path)?;
        let admin = Arc::new(crate::service::admin::AdminState::new(
            outcome.db_path.clone(),
            PiiSamplerConfig::from_config(&config),
        ));
        let approval = Arc::new(crate::service::matrix::MatrixApproval::new(
            config.approval_whitelist.clone(),
            config.audit_timeout_secs.max(1) as u64,
        ));
        let audit_logger = Arc::new(crate::service::audit::AuditLogger::new(
            config.data_dir.clone(),
        ));
        let audit_sink = Arc::new(crate::service::audit::AuditSink::new(
            audit_logger.clone(),
            admin.clone(),
        ));
        let http_client = Arc::new(build_http_client(&config));
        let http_stream_client = Arc::new(build_stream_http_client(&config));
        let notify = Arc::new(crate::service::matrix::NotificationSpool::new(
            Arc::new(crate::service::matrix::MatrixBot::with_client(
                config.homeserver.clone(),
                config.room_id.clone(),
                config.matrix_access_token.clone(),
                (*http_client).clone(),
            )),
            crate::service::matrix::NOTIFICATION_QUEUE_CAPACITY,
        ));
        let vault = Arc::new(crate::service::credential_vault::CredentialVault::new());
        let detector = Arc::new(crate::service::pii::PiiDetector::new());
        detector.set_hardening(config.pii_detection_hardening);
        // `DCD-1`：把配置期已 fail-closed 校验的自定义规则/字典在启动装配时注入
        // 运行时检测器（此前仅校验、从不生效）；再读/解析失败仍拒启动。
        let (custom_patterns, custom_dict) = crate::service::pii::custom::load_custom_from_paths(
            config.pii_custom_rules_file.as_deref(),
            config.pii_custom_patterns_file.as_deref(),
            config.pii_custom_dict_file.as_deref(),
        )
        .map_err(|message| VeilError::Config {
            var: "PII_CUSTOM_*".to_string(),
            message,
        })?;
        if !custom_patterns.is_empty() || !custom_dict.is_empty() {
            let (rules, dict) = detector.load_custom_all(&custom_patterns, &custom_dict);
            tracing::info!("PII 自定义规则运行时注入: 正则 {rules} 条、字典 {dict} 条");
        }
        Ok(Self {
            config: Arc::new(config),
            sqlite_ok: Arc::new(AtomicBool::new(outcome.sqlite_ok)),
            sqlite_error: Arc::new(Mutex::new(outcome.sqlite_error)),
            db_path: outcome.db_path,
            registry: Arc::new(tokio::sync::RwLock::new(registry)),
            registry_path,
            registry_save_lock: Arc::new(tokio::sync::Mutex::new(())),
            keepass: Arc::new(MockKeePass::locked()),
            pending: Arc::new(PendingApprovals::default()),
            approval,
            decisions: Arc::new(Mutex::new(
                crate::service::credential::approval::DecisionTable::default(),
            )),
            credential_hits: Arc::new(tokio::sync::Mutex::new(crate::service::RateTable::new())),
            register_hits: Arc::new(tokio::sync::Mutex::new(crate::service::RateTable::new())),
            gateway_metrics: Arc::new(crate::service::llm_gateway::GatewayMetrics::default()),
            admin,
            audit_logger,
            audit_sink,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            http_client,
            http_stream_client,
            vault,
            detector,
            notify,
        })
    }

    pub fn sqlite_ok(&self) -> bool { self.sqlite_ok.load(Ordering::SeqCst) }

    pub fn with_keepass(mut self, backend: Arc<dyn KeePassBackend>) -> Self {
        self.keepass = backend;
        self
    }

    /// `POL-1`/D1：`main` 在副作用点前注入启动期 fail-fast 加载的审计策略实例。
    pub fn with_audit_policy(mut self, policy: Arc<crate::service::audit::AuditPolicy>) -> Self {
        self.audit_policy = policy;
        self
    }
}

/// A1 依赖倒置：`AppState` 实现服务层读态 trait，本文件是 `service -> state`
/// 反向边的唯一承载点（`service` 内业务代码不再命名 `AppState`）。
impl crate::service::credential::AppStateParts for AppState {
    fn config(&self) -> &Arc<crate::config::Config> { &self.config }

    fn sqlite_ok_flag(&self) -> bool { self.sqlite_ok.load(Ordering::SeqCst) }

    fn sqlite_error_text(&self) -> Option<String> {
        match self.sqlite_error.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        }
    }

    fn registry(&self) -> &Arc<tokio::sync::RwLock<CallerRegistry>> { &self.registry }

    fn registry_path(&self) -> &std::path::PathBuf { &self.registry_path }

    fn registry_save_lock(&self) -> &Arc<tokio::sync::Mutex<()>> { &self.registry_save_lock }

    fn keepass(&self) -> &Arc<dyn KeePassBackend> { &self.keepass }

    fn pending(&self) -> &Arc<crate::approval::PendingApprovals> { &self.pending }

    fn approval(&self) -> &Arc<crate::service::matrix::MatrixApproval> { &self.approval }

    fn decisions(&self) -> &Arc<Mutex<crate::service::credential::approval::DecisionTable>> {
        &self.decisions
    }

    fn http_client(&self) -> &Arc<reqwest::Client> { &self.http_client }

    fn vault(&self) -> &Arc<crate::service::credential_vault::CredentialVault> { &self.vault }

    fn credential_hits(&self) -> &Arc<tokio::sync::Mutex<crate::service::RateTable>> {
        &self.credential_hits
    }

    fn register_hits(&self) -> &Arc<tokio::sync::Mutex<crate::service::RateTable>> {
        &self.register_hits
    }

    fn gateway_metrics(&self) -> &Arc<crate::service::llm_gateway::GatewayMetrics> {
        &self.gateway_metrics
    }

    fn admin_state(&self) -> &Arc<crate::service::admin::AdminState> { &self.admin }

    fn notify(&self) -> &Arc<crate::service::matrix::NotificationSpool> { &self.notify }
}

/// `C6`/D6：网关侧清理接线——Matrix 文本指令经此读写真实口令缓存、
/// KeePass 会话、内存/矩阵 pending 与 token 映射，避免 Matrix 层依赖 `AppState`。
impl crate::service::matrix::GatewayCleanup for AppState {
    fn keepass_unlocked(&self) -> bool { self.keepass.is_unlocked() }

    fn vault_len(&self) -> usize { self.vault.len() }

    fn lock_cleanup(&self) -> usize {
        let cleared = self.vault.clear();
        self.keepass.clear_cache();
        let master_cleared = self.keepass.clear_master_password();
        let pending = self.pending.clear_all();
        tracing::info!(
            "lock 清理: 口令缓存 {cleared} 条、内存待审 {pending} 条、KeePass 会话已清、TPM 主密码缓存清 {master_cleared}"
        );
        cleared
    }

    fn forget_cleanup(&self) -> usize {
        let cleared = self.vault.clear();
        tracing::info!("forget 清理: token 映射 {cleared} 条");
        cleared
    }
}

/// H9/D9：构造失败降级告警文案（纯函数，供测试断言含注入原因）。
fn http_client_degrade_warning(reason: &str) -> String {
    format!("HTTP client 构造失败，已降级为默认 Client（timeout/连接池配置未生效）: {reason}")
}

/// H9/D9：构造核心——`build` 失败经 `warn` 显式告警并降级 `Client::new()`，
/// 不再静默 `unwrap_or_else`；`warn` 注入供测试捕获告警文案。
fn finish_http_client_with<F>(build: F, warn: impl Fn(&str)) -> reqwest::Client
where
    F: FnOnce() -> Result<reqwest::Client, String>,
{
    match build() {
        Ok(client) => client,
        Err(reason) => {
            warn(&http_client_degrade_warning(&reason));
            reqwest::Client::new()
        }
    }
}

fn finish_http_client<F>(build: F) -> reqwest::Client
where
    F: FnOnce() -> Result<reqwest::Client, String>,
{
    finish_http_client_with(build, |msg| tracing::warn!("{msg}"))
}

pub fn build_http_client(config: &Config) -> reqwest::Client {
    use std::time::Duration;
    finish_http_client(|| {
        http_client_builder(config)
            .timeout(Duration::from_secs(config.http_timeout_secs.max(1)))
            .build()
            .map_err(|e| e.to_string())
    })
}

/// T3/D3：流式 client 与 `build_http_client` 共用解码/连接池配置，但**不调
/// `.timeout()`**——reqwest `ClientBuilder::timeout` 是「请求总时长（含响应体
/// 读取）」而非连接超时，长 SSE 流必然被 `HTTP_TIMEOUT_SECS` 截断；读空闲超时
/// 亦不配置（默认禁用）。非流/NonDialog 的总超时语义由 `build_http_client` 保持。
pub fn build_stream_http_client(config: &Config) -> reqwest::Client {
    finish_http_client(|| {
        http_client_builder(config)
            .build()
            .map_err(|e| e.to_string())
    })
}

fn http_client_builder(config: &Config) -> reqwest::ClientBuilder {
    use std::time::Duration;
    reqwest::Client::builder()
        .gzip(crate::service::llm_gateway::DECODE_ENABLED)
        .brotli(crate::service::llm_gateway::DECODE_ENABLED)
        .deflate(crate::service::llm_gateway::DECODE_ENABLED)
        .pool_max_idle_per_host(config.http_pool_max_idle_per_host.max(1))
        .pool_idle_timeout(Duration::from_secs(
            config.http_pool_idle_timeout_secs.max(1),
        ))
}

/// sqlite 初始化结果：健康或内存-only 降级（降级由 `sqlite_ok=false` +
/// `sqlite_error` 表达）。
#[derive(Debug)]
pub struct SqliteOutcome {
    pub sqlite_ok: bool,
    pub sqlite_error: Option<String>,
    pub db_path: PathBuf,
}

/// 异步入口：阻塞工作下沉到 `spawn_blocking`，绝不在 async 上下文直调 rusqlite。
pub async fn init_sqlite(data_dir: &Path) -> Result<SqliteOutcome> {
    let dir = data_dir.to_path_buf();
    let worker_dir = dir.clone();
    let opened = tokio::task::spawn_blocking(move || open_sqlite_blocking(&worker_dir))
        .await
        .map_err(|e| VeilError::internal(anyhow::anyhow!("sqlite 初始化任务异常: {e}")))?;
    let db_path = dir.join(SQLITE_FILE_NAME);
    outcome_from_open_result(db_path, opened)
}

fn outcome_from_open_result(
    db_path: PathBuf,
    opened: anyhow::Result<rusqlite::Connection>,
) -> Result<SqliteOutcome> {
    match opened {
        Ok(conn) => {
            drop(conn);
            Ok(SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path,
            })
        }
        Err(err) => {
            if is_no_space_error(&err) {
                tracing::error!("metrics.sqlite ENOSPC，降级内存-only: {err:#}");
                Ok(SqliteOutcome {
                    sqlite_ok: false,
                    sqlite_error: Some(format!("ENOSPC ({err:#})")),
                    db_path,
                })
            } else {
                Err(VeilError::Storage {
                    message: format!("sqlite 初始化失败: {err:#}"),
                })
            }
        }
    }
}

fn open_sqlite_blocking(data_dir: &Path) -> anyhow::Result<rusqlite::Connection> {
    std::fs::create_dir_all(data_dir)?;
    chmod_dir_0700(data_dir);

    let db_path = data_dir.join(SQLITE_FILE_NAME);
    let conn = crate::fs_perm::open_wal(&db_path)?;
    conn.execute_batch(&format!("PRAGMA user_version={SQLITE_USER_VERSION};"))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
    )?;
    crate::fs_perm::ensure_0600(&db_path);
    Ok(conn)
}

fn chmod_dir_0700(dir: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!("chmod 700 失败: {}: {e}", dir.display());
    }
}

/// 磁盘满判定：SQLITE_FULL 主码，或消息命中 ENOSPC 特征，或 IO 存储满。
pub fn is_no_space_error(err: &anyhow::Error) -> bool {
    if let Some(io) = err.downcast_ref::<std::io::Error>()
        && io.kind() == std::io::ErrorKind::StorageFull
    {
        return true;
    }
    if let Some(sqlite) = err.downcast_ref::<rusqlite::Error>()
        && let rusqlite::Error::SqliteFailure(ffi_err, _) = sqlite
        && ffi_err.code == rusqlite::ffi::ErrorCode::DiskFull
    {
        return true;
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("no space") || msg.contains("disk is full") || msg.contains("enospc")
}

#[cfg(test)]
mod tests;
