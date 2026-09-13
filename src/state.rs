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
    pub credential_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub register_hits: Arc<tokio::sync::Mutex<crate::service::RateTable>>,
    pub gateway_metrics: Arc<crate::service::llm_gateway::GatewayMetrics>,
    pub admin: Arc<crate::service::admin::AdminState>,
    /// A1/D1：`AuditLogger` 启动期单例（`audit_sink` 持同一 `Arc` 写盘）。
    pub audit_logger: Arc<crate::service::audit::AuditLogger>,
    /// A1/D1：审计落盘 + 事件环接线单例（`DATA_DIR/audit.log`，`spawn_blocking` 写盘）。
    pub audit_sink: Arc<crate::service::audit::AuditSink>,
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
    pub fn new(config: Config, outcome: SqliteOutcome) -> Self {
        let registry_path = config.registry_path.clone();
        let registry = CallerRegistry::load_from(&registry_path).unwrap_or_default();
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
        Self {
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
            credential_hits: Arc::new(tokio::sync::Mutex::new(crate::service::RateTable::new())),
            register_hits: Arc::new(tokio::sync::Mutex::new(crate::service::RateTable::new())),
            gateway_metrics: Arc::new(crate::service::llm_gateway::GatewayMetrics::default()),
            admin,
            audit_logger,
            audit_sink,
            http_client,
            http_stream_client,
            vault,
            detector,
            notify,
        }
    }

    pub fn sqlite_ok(&self) -> bool { self.sqlite_ok.load(Ordering::SeqCst) }

    pub fn with_keepass(mut self, backend: Arc<dyn KeePassBackend>) -> Self {
        self.keepass = backend;
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
        let pending = self.pending.clear_all();
        tracing::info!("lock 清理: 口令缓存 {cleared} 条、内存待审 {pending} 条、KeePass 会话已清");
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
mod tests {
    use {super::*, std::sync::atomic::AtomicU64};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_dir() -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "veil-sqlite-test-{}-{}-{n}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn now_ms() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    }

    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn sqlite_init_applies_wal_and_0600_perms() {
        let dir = unique_temp_dir();
        let worker_dir = dir.clone();
        let conn = tokio::task::spawn_blocking(move || open_sqlite_blocking(&worker_dir))
            .await
            .unwrap()
            .unwrap();
        let journal: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal.to_lowercase(), "wal");
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 1);
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(busy, SQLITE_BUSY_TIMEOUT_MS);
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SQLITE_USER_VERSION);
        drop(conn);

        let outcome = init_sqlite(&dir).await.unwrap();
        assert!(outcome.sqlite_ok);

        assert_eq!(file_mode(&dir.join(SQLITE_FILE_NAME)), 0o600);
        for suffix in ["-wal", "-shm"] {
            let p = dir.join(format!("{SQLITE_FILE_NAME}{suffix}"));
            if p.exists() {
                assert_eq!(file_mode(&p), 0o600, "{}", p.display());
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_space_classifier_detects_sqlite_full() {
        let full = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(13),
            Some("database or disk is full".to_string()),
        );
        assert!(is_no_space_error(&anyhow::Error::from(full)));
        assert!(is_no_space_error(&anyhow::anyhow!(
            "ENOSPC: No space left on device"
        )));
        assert!(!is_no_space_error(&anyhow::anyhow!("boom")));
    }

    #[test]
    fn disk_full_degrades_without_crash() {
        let full = anyhow::Error::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(13),
            Some("database or disk is full".to_string()),
        ));
        let outcome =
            outcome_from_open_result(PathBuf::from("/data/metrics.sqlite"), Err(full)).unwrap();
        assert!(!outcome.sqlite_ok);
        assert!(outcome.sqlite_error.as_deref().unwrap().contains("ENOSPC"));
    }

    #[test]
    fn non_disk_full_error_propagates() {
        let outcome = outcome_from_open_result(
            PathBuf::from("/data/metrics.sqlite"),
            Err(anyhow::anyhow!("boom")),
        );
        assert!(outcome.is_err());
    }

    #[tokio::test]
    async fn http_client_singleton_shared_across_forwards() {
        let dir = unique_temp_dir();
        let env = std::collections::HashMap::from([
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
            ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
        ]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: dir.join("m.sqlite"),
            },
        );
        let again = state.clone();
        assert!(Arc::ptr_eq(&state.http_client, &again.http_client));
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        let url = format!("http://{addr}/");
        for _ in 0..2 {
            let resp = again.http_client.get(&url).send().await.unwrap();
            assert_eq!(resp.status().as_u16(), 200);
        }
        handle.abort();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn http_client_build_failure_visible() {
        let captured: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let client = finish_http_client_with(
            || Err("injected-construct-failure".to_string()),
            |msg| captured.lock().unwrap().push(msg.to_string()),
        );
        let logs = captured.lock().unwrap();
        assert_eq!(logs.len(), 1, "注入失败须恰一条 warn");
        assert!(
            logs[0].contains("injected-construct-failure"),
            "warn 须含失败原因，实际 {:?}",
            logs[0]
        );
        assert!(
            client.get("http://127.0.0.1:1/").build().is_ok(),
            "降级客户端须仍可用"
        );
    }

    #[tokio::test]
    async fn stream_client_has_no_total_timeout() {
        // T3/D3：流式 client 无总超时——总时长 > `HTTP_TIMEOUT_SECS` 的慢流仍两帧俱达。
        let cfg = config_with_timeout_secs(1);
        let stream = build_stream_http_client(&cfg);
        let (url, server) = slow_sse_server(std::time::Duration::from_millis(1500)).await;
        let resp = stream
            .get(&url)
            .send()
            .await
            .expect("流式 client 须拿到响应头");
        let body = resp.bytes().await.expect("长流不得因总超时被截断");
        server.abort();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("data: first") && text.contains("data: second"),
            "两帧均须到达，实际 {text:?}"
        );
    }

    #[tokio::test]
    async fn nonstream_keeps_total_timeout() {
        // T3/D3：非流 client 保持 `HTTP_TIMEOUT_SECS` 总超时——慢体读取映射为报错。
        let cfg = config_with_timeout_secs(1);
        let client = build_http_client(&cfg);
        let (url, server) = slow_sse_server(std::time::Duration::from_millis(1500)).await;
        let resp = client.get(&url).send().await.expect("须先拿到响应头");
        let err = resp.bytes().await;
        server.abort();
        assert!(
            err.is_err(),
            "非流 client 须按 HTTP_TIMEOUT_SECS 超时，实际 {:?}",
            err.map(|b| b.len())
        );
    }

    /// T3 测试装配：以指定 `HTTP_TIMEOUT_SECS` 构造合法 `Config`。
    fn config_with_timeout_secs(secs: u64) -> Config {
        let env = std::collections::HashMap::from([
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
            ("HTTP_TIMEOUT_SECS".to_string(), secs.to_string()),
        ]);
        Config::load_from(&env).expect("测试配置须合法")
    }

    /// T3 测试上游：响应头后先发一帧，`delay` 后再发第二帧并关闭（总时长 > 超时预算）。
    async fn slow_sse_server(delay: std::time::Duration) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/v1/chat/completions",
            listener.local_addr().unwrap()
        );
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 65536];
                let _ = sock.read(&mut buf).await;
                let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
                if sock.write_all(head.as_bytes()).await.is_err() {
                    continue;
                }
                if sock.write_all(b"data: first\n\n").await.is_err() {
                    continue;
                }
                let _ = sock.flush().await;
                tokio::time::sleep(delay).await;
                let _ = sock.write_all(b"data: second\n\n").await;
                let _ = sock.shutdown().await;
            }
        });
        (url, handle)
    }

    #[test]
    fn vault_and_detector_singletons_shared_across_clones() {
        let env = std::collections::HashMap::from([
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
        let again = state.clone();
        assert!(Arc::ptr_eq(&state.vault, &again.vault));
        assert!(Arc::ptr_eq(&state.detector, &again.detector));
        // 同一 vault 注册复用：跨请求同秘密同 token。
        let first = state.vault.register("跨请求秘密-abc123").unwrap();
        let second = again.vault.register("跨请求秘密-abc123").unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("__VG_CRED_"));
    }

    /// `C6` 测试后端：`clear_cache` 即上锁，使 `lock` 清理后可断言凭据取用失败。
    #[derive(Debug)]
    struct LockableKeePass {
        unlocked: AtomicBool,
    }

    impl LockableKeePass {
        fn new(unlocked: bool) -> Self {
            Self {
                unlocked: AtomicBool::new(unlocked),
            }
        }
    }

    impl KeePassBackend for LockableKeePass {
        fn is_unlocked(&self) -> bool { self.unlocked.load(Ordering::SeqCst) }

        fn fetch_entry(
            &self,
            title: String,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::keepass::EntrySnapshot>> + Send + '_,
            >,
        > {
            Box::pin(async move {
                if !self.unlocked.load(Ordering::SeqCst) {
                    return Err(VeilError::Unavailable {
                        message: "KeePass 未解锁".to_string(),
                    });
                }
                Ok(crate::keepass::EntrySnapshot {
                    title,
                    username: "u".to_string(),
                    password: "p".to_string(),
                    url: String::new(),
                    custom: Vec::new(),
                })
            })
        }

        fn clear_cache(&self) { self.unlocked.store(false, Ordering::SeqCst); }
    }

    fn state_with_keepass(backend: Arc<dyn KeePassBackend>) -> AppState {
        let env = std::collections::HashMap::from([
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
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(backend)
    }

    #[tokio::test]
    async fn lock_clears_vault_and_pending() {
        use crate::service::matrix::{MatrixBot, MatrixBranch, TextCommand};
        let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
        state.vault.register("lock-secret-1234").unwrap();
        state
            .pending
            .insert(crate::approval::PendingRecord::new("k1", "reason"));
        state
            .approval
            .submit_branch("$evt-lock", MatrixBranch::Credential)
            .await;
        let reply =
            MatrixBot::handle_text_command_full(&state.approval, TextCommand::Lock, &state).await;
        assert!(reply.is_some_and(|s| s.contains("🔒 Proxy 已锁定")));
        assert!(state.vault.is_empty(), "lock 后口令缓存须清空");
        assert_eq!(state.pending.len(), 0, "lock 后内存 pending 须清零");
        assert_eq!(
            state.approval.pending_len().await,
            0,
            "lock 后矩阵 pending 须清零"
        );
        assert!(
            state.keepass.fetch_entry("网易".to_string()).await.is_err(),
            "lock 后凭据取用须失败"
        );
    }

    #[tokio::test]
    async fn forget_clears_token_map_counted() {
        use crate::service::matrix::{MatrixBot, TextCommand};
        let state = state_with_keepass(Arc::new(LockableKeePass::new(true)));
        state.vault.register("forget-secret-a1").unwrap();
        state.vault.register("forget-secret-b2").unwrap();
        assert_eq!(state.vault.len(), 2);
        let reply =
            MatrixBot::handle_text_command_full(&state.approval, TextCommand::Forget, &state)
                .await
                .expect("forget 须有回执");
        assert!(reply.contains('2'), "回执计数须与清理数一致: {reply}");
        assert!(state.vault.is_empty(), "forget 后 token 映射须清空");
    }
}
