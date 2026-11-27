//! 共享状态与 sqlite 初始化。
//!
//! 口径：WAL + `busy_timeout=5000` +
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
/// 用户版本号（`user_version=1`）。
pub const SQLITE_USER_VERSION: i64 = 1;

/// 可被多任务共享的应用状态，axum `State` 要求 `Clone` 故内层全 `Arc`。
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub sqlite_ok: Arc<AtomicBool>,
    pub sqlite_error: Arc<Mutex<Option<String>>>,
    pub db_path: PathBuf,
    pub registry: Arc<tokio::sync::RwLock<CallerRegistry>>,
    pub registry_path: PathBuf,
    /// 写路径全序点：序列化三条管理写路径的落盘次序，防旧快照覆盖新快照。
    pub registry_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub keepass: Arc<dyn KeePassBackend>,
    pub pending: Arc<PendingApprovals>,
    pub approval: Arc<crate::service::matrix::MatrixApproval>,
    /// 受管审批决策表（替代原 `approval.rs` 进程级 `static`）。
    pub decisions: Arc<Mutex<crate::service::credential::approval::DecisionTable>>,
    pub credential_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub register_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub gateway_metrics: Arc<crate::service::llm_gateway::GatewayMetrics>,
    pub admin: Arc<crate::service::admin::AdminState>,
    /// 逐请求日志（`llm_requests` + `request_model_rollup`）：与 `admin.metrics`
    /// 同库不同表；有界队列 + 2s 周期刷盘，关闭路径由 `flush_blocking` 兜底。
    pub request_log: Arc<crate::service::request_log::RequestLog>,
    /// `AuditLogger` 启动期单例（`audit_sink` 持同一 `Arc` 写盘）。
    pub audit_logger: Arc<crate::service::audit::AuditLogger>,
    /// 审计落盘 + 事件环接线单例（`DATA_DIR/audit.log`，`spawn_blocking` 写盘）。
    pub audit_sink: Arc<crate::service::audit::AuditSink>,
    /// 启动期 fail-fast 加载并注入的审计策略单例；请求路径复用，不再每请求读盘。
    pub audit_policy: Arc<crate::service::audit::AuditPolicy>,
    pub http_client: Arc<reqwest::Client>,
    /// 流式（SSE）转发专用 client——不设覆盖整响应体读取的总超时，
    /// 避免长流被 `HTTP_TIMEOUT_SECS` 截断；非流与 NonDialog 仍用 `http_client`。
    /// 读空闲超时默认禁用（无），失活连接依赖 TCP keepalive；口径见 工程参考 §7.2。
    pub http_stream_client: Arc<reqwest::Client>,
    pub vault: Arc<crate::service::credential_vault::CredentialVault>,
    pub detector: Arc<crate::service::pii::PiiDetector>,
    /// 会话级 PII 作用域存储（`PII_SCOPE_MODE=conversation` 时构造并跨请求
    /// 共享；`request` 模式为 `None` 且不使用）。
    pub conversation_scope_store: Option<Arc<crate::service::redaction::ConversationScopeStore>>,
    /// 会话别名表：上游标识（`conversation.id`/`response.id`）→ canonical 会话键
    /// （租户分域、跨请求共享；`request` 模式同样可用，仅不建会话作用域）。
    pub session_alias_map: Arc<crate::service::redaction::SessionAliasMap>,
    /// 会话键/租户指纹 HMAC 密钥（进程内随机、跨请求稳定；不落盘、不进日志）。
    pub conversation_secret: Arc<[u8]>,
    /// 失败/审批通知统一有界 spool（单 Bot + 有界队列 + 常驻消费者）。
    /// 消费者由 `main` 启动期 `start()` 拉起；未启动时 `notify_text` 按满队列丢弃。
    pub notify: Arc<crate::service::matrix::NotificationSpool>,
    /// 命令面运行时（`[command].enabled = false` 时为零行为差异的禁用态）。
    pub command: Arc<crate::service::command::CommandRuntime>,
    /// TPM 运行期健康快照（`/health` 的 `tpm_ok`/`tpm_error` 来源）。
    pub tpm_health: Arc<crate::service::tpm::TpmHealthCache>,
}

/// 手工 `Debug`：`conversation_secret`（会话 HMAC 密钥）派生 `Debug`
/// 会打印密钥字节；一律以 `[redacted]` 呈现，其余字段保持既有呈现。
impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("config", &self.config)
            .field("sqlite_ok", &self.sqlite_ok)
            .field("sqlite_error", &self.sqlite_error)
            .field("db_path", &self.db_path)
            .field("registry", &self.registry)
            .field("registry_path", &self.registry_path)
            .field("registry_save_lock", &self.registry_save_lock)
            .field("keepass", &self.keepass)
            .field("pending", &self.pending)
            .field("approval", &self.approval)
            .field("decisions", &self.decisions)
            .field("credential_hits", &self.credential_hits)
            .field("register_hits", &self.register_hits)
            .field("gateway_metrics", &self.gateway_metrics)
            .field("admin", &self.admin)
            .field("request_log", &self.request_log)
            .field("audit_logger", &self.audit_logger)
            .field("audit_sink", &self.audit_sink)
            .field("audit_policy", &self.audit_policy)
            .field("http_client", &self.http_client)
            .field("http_stream_client", &self.http_stream_client)
            .field("vault", &self.vault)
            .field("detector", &self.detector)
            .field("conversation_scope_store", &self.conversation_scope_store)
            .field("session_alias_map", &self.session_alias_map)
            .field("conversation_secret", &"[redacted]")
            .field("notify", &self.notify)
            .field("command", &self.command)
            .field("tpm_health", &self.tpm_health)
            .finish()
    }
}

/// 一次成功重载的可观测结果（编排层产出，处理器直接序列化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadReport {
    /// 生效库路径；Mock/测试后端为 `None`。
    pub db_path: Option<PathBuf>,
    /// 本次作废的凭据 token 映射条数。
    pub tokens_invalidated: usize,
    /// 从进入编排到快照替换 + token 作废完成（含等待串行点）的毫秒数。
    pub elapsed_ms: u64,
}

impl AppState {
    /// 生产入口：以 fail-fast 语义构造。任一辈子系统加载失败（注册表损坏、
    /// 自定义 PII 文件再读失败）记 `error` 日志并 panic 终止启动。
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
        // 加载失败（解析失败或完整性失配）一律上抛拒启动，不以空表放行。
        let registry = CallerRegistry::load_from(&registry_path)?;
        let admin = Arc::new(crate::service::admin::AdminState::new(
            outcome.db_path.clone(),
            PiiSamplerConfig::from_config(&config),
        ));
        // 与 metrics 同库同文件（`metrics.sqlite`）不同表：`llm_requests` 会话/请求行。
        let request_log = Arc::new(crate::service::request_log::RequestLog::new(
            outcome.db_path.clone(),
            config.request_log_enabled,
            config.request_log_retention_days,
        ));
        let approval = Arc::new(crate::service::matrix::MatrixApproval::new(
            config.approval_whitelist.clone(),
            config.audit_timeout_secs.max(1),
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
        let notify_bot = Arc::new(crate::service::matrix::MatrixBot::with_client(
            config.homeserver.clone(),
            config.room_id.clone(),
            config.matrix_access_token.clone(),
            (*http_client).clone(),
        ));
        let notify = if config.matrix_enabled() {
            Arc::new(crate::service::matrix::NotificationSpool::new(
                notify_bot,
                crate::service::matrix::NOTIFICATION_QUEUE_CAPACITY,
            ))
        } else {
            // Matrix 三要素缺失：保留 MatrixBot 构造（建单/通知正文格式化
            // （`format_ticket`/`format_notice`）仍需），但注入 no-op sink，不触网、不排队。
            Arc::new(crate::service::matrix::NotificationSpool::with_sink(
                notify_bot,
                Arc::new(crate::service::matrix::NoopSink),
                crate::service::matrix::NOTIFICATION_QUEUE_CAPACITY,
            ))
        };
        let vault = Arc::new(crate::service::credential_vault::CredentialVault::new());
        let detector = Arc::new(crate::service::pii::PiiDetector::new());
        detector.set_hardening(config.pii_detection_hardening);
        // 把配置期已 fail-closed 校验的自定义规则/字典在启动装配时注入
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
        let gateway_metrics = Arc::new(crate::service::llm_gateway::GatewayMetrics::default());
        let conversation_scope_store = config.pii_scope_mode.is_conversation().then(|| {
            let capacity = config.pii_scope_max_conversations;
            let ttl = std::time::Duration::from_secs(config.pii_scope_ttl_secs.max(1));
            Arc::new(
                crate::service::redaction::ConversationScopeStore::new(capacity, ttl)
                    .with_metrics(gateway_metrics.clone()),
            )
        });
        // 会话密钥**无条件生成**：`request` 模式同样需要它做别名表键与出站标识
        // 的域分离 HMAC（否则空密钥）。
        let conversation_secret: Arc<[u8]> = generate_conversation_secret();
        // 别名表容量来自 `[session].alias_max_entries`（按别名条目计，与
        // `[pii_scope].max_conversations` 解耦）；两种模式都装配。
        let session_alias_map = Arc::new(
            crate::service::redaction::SessionAliasMap::new(config.session_alias_max_entries)
                .with_metrics(gateway_metrics.clone()),
        );
        let command = Arc::new(crate::service::command::CommandRuntime::new(
            config.command.clone(),
            &config.data_dir,
        )?);
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
            gateway_metrics,
            admin,
            request_log,
            audit_logger,
            audit_sink,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            http_client,
            http_stream_client,
            vault,
            detector,
            conversation_scope_store,
            session_alias_map,
            conversation_secret,
            notify,
            command,
            tpm_health: Arc::new(crate::service::tpm::TpmHealthCache::uninitialized()),
        })
    }

    pub fn sqlite_ok(&self) -> bool { self.sqlite_ok.load(Ordering::SeqCst) }

    pub fn with_keepass(mut self, backend: Arc<dyn KeePassBackend>) -> Self {
        self.keepass = backend;
        self
    }

    /// `main` 在 TPM 启动门禁之后注入健康缓存（`try_new` 内不重复探测 TPM）。
    pub fn with_tpm_health(mut self, cache: Arc<crate::service::tpm::TpmHealthCache>) -> Self {
        self.tpm_health = cache;
        self
    }

    /// `main` 在副作用点前注入启动期 fail-fast 加载的审计策略实例。
    pub fn with_audit_policy(mut self, policy: Arc<crate::service::audit::AuditPolicy>) -> Self {
        self.audit_policy = policy;
        self
    }

    /// 显式重载 KeePass 快照：成功后作废全部凭据 token（方案 B）。
    /// `Ok(None)`（Mock/测试后端）同样视为成功并作废 token。
    /// 失败时后端保证旧快照仍在；本函数不触碰 pending/PII/会话别名。
    pub async fn reload_keepass(&self) -> Result<ReloadReport> {
        let started = std::time::Instant::now();
        let outcome = self.keepass.reload().await?;
        let tokens_invalidated = self.vault.clear();
        Ok(ReloadReport {
            db_path: outcome.map(|outcome| outcome.db_path),
            tokens_invalidated,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }
}

/// 信号转发失败原因：供调用方输出准确的跳过日志，避免把「队列满/通道关闭」
/// 误报成「重载进行中」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardSkip {
    /// 已有重载在跑（信号单飞闸）。
    Busy,
    /// 有界队列（cap 1）已满。
    QueueFull,
    /// 接收端已关闭（停机后）。
    Closed,
}

/// 信号转发闸：重载进行中或队列已满时不入队。
pub fn forward_if_idle(
    busy: &std::sync::atomic::AtomicBool,
    sender: &tokio::sync::mpsc::Sender<()>,
) -> std::result::Result<(), ForwardSkip> {
    if busy.load(Ordering::SeqCst) {
        return Err(ForwardSkip::Busy);
    }
    match sender.try_send(()) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Err(ForwardSkip::QueueFull),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(ForwardSkip::Closed),
    }
}

/// `busy` 的 RAII 复位：循环体 panic 展开时也不会把单飞闸永久留在 true。
struct BusyGuard<'a>(&'a AtomicBool);

impl<'a> BusyGuard<'a> {
    fn set(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self(flag)
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::SeqCst); }
}

/// SIGHUP 重载循环：每次事件执行一次重载；重载进行中的事件由转发闸跳过。
/// 收到停机广播后退出。事件源抽成参数，生产由 `main` 把 Unix 信号转发进来。
pub async fn hangup_reload_loop(
    state: AppState,
    busy: Arc<AtomicBool>,
    mut events: tokio::sync::mpsc::Receiver<()>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            event = events.recv() => {
                if event.is_none() {
                    break;
                }
                let _busy = BusyGuard::set(&busy);
                let mut skipped = 0usize;
                while events.try_recv().is_ok() {
                    skipped += 1;
                }
                if skipped > 0 {
                    tracing::warn!("重载启动前已排队的 {skipped} 次 SIGHUP，已跳过（单飞）");
                }
                match state.reload_keepass().await {
                    Ok(report) => tracing::info!(
                        trigger = "signal",
                        tokens_invalidated = report.tokens_invalidated,
                        elapsed_ms = report.elapsed_ms,
                        db_path = ?report.db_path,
                        "KeePass 重载成功"
                    ),
                    Err(err) => tracing::warn!(
                        "SIGHUP 触发的 KeePass 重载失败（忽略本次，旧快照继续服务）: {err}"
                    ),
                }
            }
        }
    }
}

/// 依赖倒置：`AppState` 实现服务层读态 trait，本文件是 `service -> state`
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

    fn command(&self) -> &Arc<crate::service::command::CommandRuntime> { &self.command }

    fn tpm_health(&self) -> &Arc<crate::service::tpm::TpmHealthCache> { &self.tpm_health }
}

/// 网关侧清理接线——Matrix 文本指令经此读写真实口令缓存、
/// KeePass 会话、内存/矩阵 pending 与 token 映射，避免 Matrix 层依赖 `AppState`。
impl crate::service::matrix::GatewayCleanup for AppState {
    fn keepass_unlocked(&self) -> bool { self.keepass.is_unlocked() }

    fn master_password_cached(&self) -> bool { self.keepass.master_password_cached() }

    fn vault_len(&self) -> usize { self.vault.len() }

    fn lock_cleanup(&self) -> crate::service::matrix::LockCleanupReport {
        let vault_cleared = self.vault.clear();
        self.keepass.clear_cache();
        let master_cleared = self.keepass.clear_master_password();
        let pending = self.pending.clear_all();
        let pii_scopes_cleared = self
            .conversation_scope_store
            .as_ref()
            .map(|store| store.clear())
            .unwrap_or(0);
        // 别名表与会话作用域分离，但 `lock` SHALL 同时清空两表并分别报条数。
        let alias_entries_cleared = self.session_alias_map.clear();
        tracing::info!(
            "lock 清理: 口令缓存 {vault_cleared} 条、内存待审 {pending} 条、KeePass 会话已清、TPM 主密码缓存清 {master_cleared}、PII 会话作用域 {pii_scopes_cleared} 个、会话别名 {alias_entries_cleared} 条"
        );
        crate::service::matrix::LockCleanupReport {
            vault_cleared,
            pii_scopes_cleared,
            alias_entries_cleared,
        }
    }

    fn forget_cleanup(&self) -> usize {
        let cleared = self.vault.clear();
        tracing::info!("forget 清理: token 映射 {cleared} 条");
        cleared
    }
}

/// 构造失败降级告警文案（纯函数，供测试断言含注入原因）。
fn http_client_degrade_warning(reason: &str) -> String {
    format!("HTTP client 构造失败，已降级为默认 Client（timeout/连接池配置未生效）: {reason}")
}

/// 构造核心——`build` 失败经 `warn` 显式告警并降级 `Client::new()`，
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

/// 进程内会话 HMAC 密钥（32 字节 CSPRNG；进程内稳定、不落盘、不进日志）。
fn generate_conversation_secret() -> Arc<[u8]> {
    let (buf, os_ok) = conversation_secret_bytes(|b| {
        use rand::{rand_core::TryRng as _, rngs::SysRng};
        SysRng.try_fill_bytes(b).is_ok()
    });
    if !os_ok {
        tracing::warn!("会话 HMAC 密钥熵源不可用，回退时间/进程派生（仅进程内隔离，非 CSPRNG）");
    }
    Arc::from(buf.to_vec().into_boxed_slice())
}

/// 密钥字节生成核心（可测）：`os_fill` 返回 `true` 表示 CSPRNG 填充成功。
/// `SysRng` 失败时回退 [`fallback_secret_bytes`]，**恒产出完整 32 字节**，
/// 不遗留零填充半成键（上半 16 字节为零会显著削弱进程内隔离）。
fn conversation_secret_bytes(os_fill: impl FnOnce(&mut [u8; 32]) -> bool) -> ([u8; 32], bool) {
    let mut buf = [0u8; 32];
    if os_fill(&mut buf) {
        return (buf, true);
    }
    (fallback_secret_bytes(), false)
}

/// 熵源失败回退：SHA-256 吸收多源低熵材料（高精度时间、进程 id、ASLR 栈/堆
/// 地址），输出完整 32 字节且无零填充。非 CSPRNG 替代，仅保「进程内稳定 +
/// 跨进程相异」最低隔离；调用方已打 warn。
fn fallback_secret_bytes() -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    hasher.update(now.as_nanos().to_le_bytes());
    hasher.update(now.subsec_nanos().to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let stack_probe = 0u8;
    hasher.update((&stack_probe as *const u8 as usize).to_le_bytes());
    let heap_probe = Box::new(0u8);
    hasher.update((std::ptr::from_ref(heap_probe.as_ref()) as usize).to_le_bytes());
    let local_probe = 0u8;
    hasher.update((std::ptr::from_ref(&local_probe) as usize).to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
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

/// 流式 client 与 `build_http_client` 共用解码/连接池配置，但**不调
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
