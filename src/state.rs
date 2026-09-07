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
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Instant,
    },
};

/// sqlite 库文件名。
pub const SQLITE_FILE_NAME: &str = "metrics.sqlite";
/// 忙等待超时（毫秒），与原仓 `busy_timeout=5000` 同值。
pub const SQLITE_BUSY_TIMEOUT_MS: i64 = 5000;
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
    pub keepass: Arc<dyn KeePassBackend>,
    pub pending: Arc<PendingApprovals>,
    pub approval: Arc<crate::service::matrix::MatrixApproval>,
    pub credential_hits: Arc<Mutex<HashMap<String, Instant>>>,
    pub register_hits: Arc<Mutex<HashMap<String, Instant>>>,
    pub gateway_metrics: Arc<crate::service::llm_gateway::GatewayMetrics>,
    pub admin: Arc<crate::service::admin::AdminState>,
    pub http_client: Arc<reqwest::Client>,
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
        let http_client = Arc::new(build_http_client(&config));
        Self {
            config: Arc::new(config),
            sqlite_ok: Arc::new(AtomicBool::new(outcome.sqlite_ok)),
            sqlite_error: Arc::new(Mutex::new(outcome.sqlite_error)),
            db_path: outcome.db_path,
            registry: Arc::new(tokio::sync::RwLock::new(registry)),
            registry_path,
            keepass: Arc::new(MockKeePass::locked()),
            pending: Arc::new(PendingApprovals::default()),
            approval,
            credential_hits: Arc::new(Mutex::new(HashMap::new())),
            register_hits: Arc::new(Mutex::new(HashMap::new())),
            gateway_metrics: Arc::new(crate::service::llm_gateway::GatewayMetrics::default()),
            admin,
            http_client,
        }
    }

    pub fn sqlite_ok(&self) -> bool { self.sqlite_ok.load(Ordering::SeqCst) }

    pub fn with_keepass(mut self, backend: Arc<dyn KeePassBackend>) -> Self {
        self.keepass = backend;
        self
    }
}

pub fn build_http_client(config: &Config) -> reqwest::Client {
    use std::time::Duration;
    reqwest::Client::builder()
        .gzip(crate::service::llm_gateway::DECODE_ENABLED)
        .brotli(crate::service::llm_gateway::DECODE_ENABLED)
        .deflate(crate::service::llm_gateway::DECODE_ENABLED)
        .timeout(Duration::from_secs(config.http_timeout_secs.max(1)))
        .pool_max_idle_per_host(config.http_pool_max_idle_per_host.max(1))
        .pool_idle_timeout(Duration::from_secs(
            config.http_pool_idle_timeout_secs.max(1),
        ))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// sqlite 初始化结果：健康或内存-only 降级。
#[derive(Debug)]
pub struct SqliteOutcome {
    pub sqlite_ok: bool,
    pub sqlite_error: Option<String>,
    pub db_path: PathBuf,
    pub memory_only: bool,
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
                memory_only: false,
            })
        }
        Err(err) => {
            if is_no_space_error(&err) {
                tracing::error!("metrics.sqlite ENOSPC，降级内存-only: {err:#}");
                Ok(SqliteOutcome {
                    sqlite_ok: false,
                    sqlite_error: Some(format!("ENOSPC ({err:#})")),
                    db_path,
                    memory_only: true,
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
    chmod_path(data_dir, 0o700);

    let db_path = data_dir.join(SQLITE_FILE_NAME);
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute_batch(&format!(
        "PRAGMA journal_mode=WAL;\
         PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};\
         PRAGMA synchronous=NORMAL;\
         PRAGMA user_version={SQLITE_USER_VERSION};"
    ))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
    )?;
    chmod_sqlite_files(&db_path);
    Ok(conn)
}

fn chmod_sqlite_files(db_path: &Path) {
    chmod_path(db_path, 0o600);
    for suffix in ["-wal", "-shm"] {
        let mut sibling = db_path.as_os_str().to_owned();
        sibling.push(suffix);
        chmod_path(Path::new(&sibling), 0o600);
    }
}

fn chmod_path(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    if !path.exists() {
        return;
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        tracing::warn!("chmod {mode:o} 失败: {}: {e}", path.display());
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
    async fn 初始化口径与0600权限() {
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
        assert!(outcome.sqlite_ok && !outcome.memory_only);

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
    fn 磁盘满分类器识别sqlite_full() {
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
    fn 磁盘满降级内存only且进程不崩() {
        let full = anyhow::Error::from(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(13),
            Some("database or disk is full".to_string()),
        ));
        let outcome =
            outcome_from_open_result(PathBuf::from("/data/metrics.sqlite"), Err(full)).unwrap();
        assert!(!outcome.sqlite_ok);
        assert!(outcome.memory_only);
        assert!(outcome.sqlite_error.as_deref().unwrap().contains("ENOSPC"));
    }

    #[test]
    fn 非磁盘满错误向上传播() {
        let outcome = outcome_from_open_result(
            PathBuf::from("/data/metrics.sqlite"),
            Err(anyhow::anyhow!("boom")),
        );
        assert!(outcome.is_err());
    }

    #[tokio::test]
    async fn client_singleton_两次转发共享同一句柄() {
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
                memory_only: false,
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
}
