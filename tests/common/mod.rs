#![allow(dead_code)]

//! H12/D12：集成测试统一脚手架。
//!
//! 导出 `base_env` / `test_app` / `test_app_router` / `test_state` / `serve`，
//! 以 [`TestOpts`] 覆盖现存的 `extra`/`cfg_mut`/`db`/`locked` 四参数族与两类返回
//! （`Router` 或 `(Router, AppState)`）。各 `tests/*.rs` 经 `mod common;` 复用，
//! 不新建 `[[test]]` target、不引入 dev-dependency。

use {
    std::{
        collections::HashMap,
        future::Future,
        path::PathBuf,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    },
    tokio::task::JoinHandle,
    veil::{
        config::Config,
        keepass::KeePassBackend,
        router::build_router,
        service::matrix::{
            MatrixBot,
            NOTIFICATION_QUEUE_CAPACITY,
            NotificationSink,
            NotificationSpool,
        },
        state::{AppState, SqliteOutcome},
    },
};

/// `F1` e2e 注入 sink：审批 tracked 发送返回自增真实 id，避免触发真实 Matrix 网络。
#[derive(Debug)]
struct TestSink {
    next: AtomicU64,
}

impl NotificationSink for TestSink {
    fn send_text(&self, _text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn send_text_tracked(
        &self,
        _text: String,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let id = format!("$e2e-event-{}", self.next.fetch_add(1, Ordering::SeqCst));
        Box::pin(async move { Some(id) })
    }
}

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

/// 管理面鉴权 token（与生产默认测试口径一致）。
pub const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";
/// 三因子部署密钥。
pub const GET_SECRET: &str = "s3cr3t";
/// 三因子二进制哈希。
pub const GET_HASH: &str = "gethash1";

/// 统一基础环境（四必填 + 三因子常量）；各文件差异经 [`TestOpts::new`] 的 `extra` 覆盖。
pub fn base_env() -> HashMap<String, String> {
    HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN.to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), GET_SECRET.to_string()),
        ("GET_BINARY_HASH".to_string(), GET_HASH.to_string()),
    ])
}

/// 基础环境 + `extra` 覆盖（保留旧 `base_env(extra)` 调用形态）。
pub fn base_env_with(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut env = base_env();
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    env
}

/// 建 app 参数：覆盖 `extra`/`cfg_mut`/`db`/`locked` 四族。
type CfgMut = Box<dyn FnOnce(&mut Config)>;

#[derive(Default)]
pub struct TestOpts {
    extra: Vec<(String, String)>,
    db: Option<PathBuf>,
    locked: bool,
    cfg_mut: Option<CfgMut>,
}

impl From<&[(&str, &str)]> for TestOpts {
    fn from(extra: &[(&str, &str)]) -> Self { Self::new(extra) }
}

impl<const N: usize> From<&[(&str, &str); N]> for TestOpts {
    fn from(extra: &[(&str, &str); N]) -> Self { Self::new(extra) }
}

impl TestOpts {
    pub fn new(extra: &[(&str, &str)]) -> Self {
        Self {
            extra: extra
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            ..Self::default()
        }
    }

    /// 追加/覆盖单个环境变量（如自定义 `OBSERVABILITY_ADMIN_TOKEN`）。
    pub fn set(mut self, key: &str, value: &str) -> Self {
        self.extra.push((key.to_string(), value.to_string()));
        self
    }

    /// 指定 sqlite 路径（默认每调用唯一，并预清理残留）。
    pub fn db(mut self, db: impl Into<PathBuf>) -> Self {
        self.db = Some(db.into());
        self
    }

    /// 以锁定 KeePass 启动（默认若为 unlocked）。
    pub fn locked(mut self, locked: bool) -> Self {
        self.locked = locked;
        self
    }

    /// 在 `Config` 载入后、`AppState` 构造前注入变更（如缩短审批超时）。
    pub fn cfg_mut(mut self, mutate: impl FnOnce(&mut Config) + 'static) -> Self {
        self.cfg_mut = Some(Box::new(mutate));
        self
    }

    fn env(&self) -> HashMap<String, String> {
        let mut env = base_env();
        for (k, v) in &self.extra {
            env.insert(k.clone(), v.clone());
        }
        env
    }
}

/// 建 `(Router, AppState)`：`opts` 可传 `&[(&str, &str)]` 或 [`TestOpts`]。
pub fn test_app(opts: impl Into<TestOpts>) -> (axum::Router, AppState) {
    let opts = opts.into();
    let mut config = Config::load_from(&opts.env()).expect("测试配置须合法");
    if let Some(mutate) = opts.cfg_mut {
        mutate(&mut config);
    }
    let db_path = match opts.db {
        Some(db) => db,
        None => {
            let n = APP_SEQ.fetch_add(1, Ordering::SeqCst);
            let db = PathBuf::from(format!("/tmp/veil-e2e-common-{n}.sqlite"));
            let _ = std::fs::remove_file(&db);
            db
        }
    };
    let keepass: Arc<dyn KeePassBackend> = if opts.locked {
        Arc::new(veil::keepass::MockKeePass::locked())
    } else {
        Arc::new(veil::keepass::MockKeePass::unlocked())
    };
    let mut state = AppState::new(
        config,
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path,
        },
    )
    .with_keepass(keepass);
    let bot = Arc::new(MatrixBot::new(
        state.config.homeserver.clone(),
        state.config.room_id.clone(),
        state.config.matrix_access_token.clone(),
    ));
    state.notify = Arc::new(NotificationSpool::with_sink(
        bot,
        Arc::new(TestSink {
            next: AtomicU64::new(1),
        }),
        NOTIFICATION_QUEUE_CAPACITY,
    ));
    (build_router(state.clone()), state)
}

/// 仅需 `Router` 时使用；与 [`test_app`] 同源（丢弃 state）。
pub fn test_app_router(opts: impl Into<TestOpts>) -> axum::Router { test_app(opts).0 }

/// 兼容旧 `test_app(extra, db)` 形态：显式 sqlite 路径。
pub fn test_app_db(extra: &[(&str, &str)], db: &str) -> axum::Router {
    test_app_router(TestOpts::from(extra).db(db))
}

/// 兼容旧 `test_app(extra, cfg_mut)` 形态：返回 `(Router, AppState)`。
pub fn test_app_cfg(
    extra: &[(&str, &str)],
    cfg_mut: impl FnOnce(&mut Config) + 'static,
) -> (axum::Router, AppState) {
    test_app(TestOpts::from(extra).cfg_mut(cfg_mut))
}

/// 仅需 `AppState` 时使用（如矩阵审批注入场景）。
pub fn test_state(opts: impl Into<TestOpts>) -> AppState { test_app(opts).1 }

/// `AUTH-4` e2e 装配：注册并启用具备 `网易/授权码` 放行权限的调用方。
pub async fn enroll_allow(state: &AppState, path: &str, hash: &str) {
    use veil::registry::RegisterParams;
    veil::service::credential::register_caller_extended(
        state,
        &RegisterParams {
            caller_path: path.to_string(),
            caller_hash: hash.to_string(),
            name: path.to_string(),
            entries: std::collections::BTreeMap::from([(
                "网易".to_string(),
                vec!["授权码".to_string()],
            )]),
            ..RegisterParams::default()
        },
        &format!("e2e-enroll-{path}"),
    )
    .await
    .expect("e2e 注册装配须成功");
    state
        .registry
        .write()
        .await
        .set_enabled(path, true)
        .unwrap();
}

/// 绑定回环随机端口并启动 axum 服务，返回 `(base_url, JoinHandle)`。
pub async fn serve(app: axum::Router) -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let addr = listener.local_addr().expect("回环地址须可读");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}
