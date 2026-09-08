use {
    crate::error::{Result, VeilError},
    std::{
        future::Future,
        path::PathBuf,
        pin::Pin,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    },
    zeroize::Zeroizing,
};

#[derive(Debug, Clone)]
pub struct CustomProp {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone)]
pub struct EntrySnapshot {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub custom: Vec<CustomProp>,
}

impl EntrySnapshot {
    pub fn custom_value(&self, name: &str) -> Option<&CustomProp> {
        self.custom.iter().find(|c| c.name == name)
    }
}

pub trait KeePassBackend: Send + Sync + std::fmt::Debug {
    fn is_unlocked(&self) -> bool;
    fn fetch_entry(
        &self,
        title: String,
    ) -> Pin<Box<dyn Future<Output = Result<EntrySnapshot>> + Send + '_>>;
    fn open_count(&self) -> usize { 0 }
    fn clear_cache(&self) {}
}

#[derive(Debug, Default)]
pub struct MockKeePass {
    unlocked: AtomicBool,
}

impl MockKeePass {
    pub fn locked() -> Self {
        Self {
            unlocked: AtomicBool::new(false),
        }
    }

    pub fn unlocked() -> Self {
        Self {
            unlocked: AtomicBool::new(true),
        }
    }

    pub fn set_unlocked(&self, value: bool) { self.unlocked.store(value, Ordering::SeqCst); }

    pub fn fetch_credential(&self, caller: &str) -> Result<String> {
        if !self.is_unlocked() {
            return Err(VeilError::Unavailable {
                message: "KeePass 未解锁".to_string(),
            });
        }
        Ok(format!("__MOCK_CRED_{caller}__"))
    }
}

impl KeePassBackend for MockKeePass {
    fn is_unlocked(&self) -> bool { self.unlocked.load(Ordering::SeqCst) }

    fn fetch_entry(
        &self,
        title: String,
    ) -> Pin<Box<dyn Future<Output = Result<EntrySnapshot>> + Send + '_>> {
        Box::pin(async move {
            if !self.is_unlocked() {
                return Err(VeilError::Unavailable {
                    message: "KeePass 未解锁".to_string(),
                });
            }
            Ok(EntrySnapshot {
                title: title.clone(),
                username: format!("{title}-user"),
                password: format!("__MOCK_CRED_{title}__"),
                url: String::new(),
                custom: vec![CustomProp {
                    name: "授权码".to_string(),
                    value: format!("__MOCK_CRED_{title}-授权码__"),
                    protected: true,
                }],
            })
        })
    }
}

pub type PasswordProvider =
    std::sync::Arc<dyn Fn() -> anyhow::Result<Zeroizing<Vec<u8>>> + Send + Sync>;

pub fn tpm_password_provider(tpm_dir: PathBuf, allow_mock: bool) -> PasswordProvider {
    let cache: std::sync::Arc<Mutex<Option<Zeroizing<Vec<u8>>>>> =
        std::sync::Arc::new(Mutex::new(None));
    std::sync::Arc::new(move || {
        if let Ok(guard) = cache.lock()
            && let Some(cached) = guard.as_ref()
        {
            return Ok(cached.clone());
        }
        let sealed = crate::service::tpm::startup_tpm_in(&tpm_dir, allow_mock)
            .map_err(|e| anyhow::anyhow!("TPM 解封主密码失败: {e:#}"))?;
        if sealed.is_empty() {
            anyhow::bail!("TPM 解封返回空密码");
        }
        if sealed.len() < 4 {
            anyhow::bail!("TPM 解封返回的密码过短（{} 字符）", sealed.len());
        }
        let guarded = Zeroizing::new(sealed);
        if let Ok(mut slot) = cache.lock() {
            *slot = Some(guarded.clone());
        }
        Ok(guarded)
    })
}

pub struct RealKeePass {
    db_path: PathBuf,
    keyfile_path: Option<PathBuf>,
    password_provider: PasswordProvider,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    cache: Mutex<Option<keepass::Database>>,
    open_count: AtomicUsize,
}

impl std::fmt::Debug for RealKeePass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealKeePass")
            .field("db_path", &self.db_path)
            .field("keyfile_path", &self.keyfile_path)
            .field("open_count", &self.open_count.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl RealKeePass {
    pub fn new(
        db_path: PathBuf,
        keyfile_path: Option<PathBuf>,
        password_provider: PasswordProvider,
    ) -> Self {
        Self {
            db_path,
            keyfile_path,
            password_provider,
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            cache: Mutex::new(None),
            open_count: AtomicUsize::new(0),
        }
    }

    pub fn db_path(&self) -> &std::path::Path { &self.db_path }

    async fn fetch_entry_async(&self, title: String) -> Result<EntrySnapshot> {
        if !self.db_path.is_file() {
            return Err(VeilError::Unavailable {
                message: "密码库未配置".to_string(),
            });
        }
        // 单飞许可（tokio 信号量）可跨 await 持有；下方缓存锁（std Mutex）
        // 绝不跨 await：每次只在同步小临界区内加锁，拿完快照立即释放。
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| VeilError::KeePass {
                message: format!("KeePass 内部错误: 信号量获取失败: {e}"),
            })?;
        {
            if let Some(snapshot) = self.lookup_cached(&title) {
                return Ok(snapshot);
            }
            if self.is_cached() {
                return Err(VeilError::NotFound {
                    message: format!("条目未找到: {title}"),
                });
            }
        }
        let db_path = self.db_path.clone();
        let keyfile_path = self.keyfile_path.clone();
        let provider = self.password_provider.clone();
        let db = tokio::task::spawn_blocking(move || {
            open_blocking(&db_path, keyfile_path.as_deref(), &provider)
        })
        .await
        .map_err(|e| VeilError::KeePass {
            message: format!("KeePass 内部错误: 解密任务异常: {e}"),
        })??;
        let snapshot = snapshot_of(&db, &title).ok_or_else(|| VeilError::NotFound {
            message: format!("条目未找到: {title}"),
        })?;
        self.open_count.fetch_add(1, Ordering::SeqCst);
        match self.cache.lock() {
            Ok(mut guard) => {
                *guard = Some(db);
            }
            Err(_) => {
                return Err(VeilError::KeePass {
                    message: "KeePass 内部错误: 缓存锁定失败".to_string(),
                });
            }
        }
        Ok(snapshot)
    }

    fn is_cached(&self) -> bool { self.cache.lock().is_ok_and(|g| g.is_some()) }

    fn lookup_cached(&self, title: &str) -> Option<EntrySnapshot> {
        self.cache
            .lock()
            .ok()
            .as_ref()
            .and_then(|guard| guard.as_ref())
            .and_then(|db| snapshot_of(db, title))
    }
}

impl KeePassBackend for RealKeePass {
    fn is_unlocked(&self) -> bool { self.db_path.is_file() }

    fn fetch_entry(
        &self,
        title: String,
    ) -> Pin<Box<dyn Future<Output = Result<EntrySnapshot>> + Send + '_>> {
        Box::pin(self.fetch_entry_async(title))
    }

    fn open_count(&self) -> usize { self.open_count.load(Ordering::SeqCst) }

    fn clear_cache(&self) {
        if let Ok(mut guard) = self.cache.lock() {
            *guard = None;
        }
    }
}

fn open_blocking(
    db_path: &std::path::Path,
    keyfile_path: Option<&std::path::Path>,
    provider: &PasswordProvider,
) -> Result<keepass::Database> {
    let keyfile_bytes: Option<Zeroizing<Vec<u8>>> = match keyfile_path {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| VeilError::KeePass {
                message: format!("KeePass 内部错误: keyfile 不可读 {}: {e}", path.display()),
            })?;
            Some(Zeroizing::new(bytes))
        }
        None => None,
    };
    let password: Zeroizing<Vec<u8>> = provider().map_err(|e| VeilError::KeePass {
        message: format!("KeePass 内部错误: 主密码派生失败: {e:#}"),
    })?;
    let mut key = keepass::DatabaseKey::new().with_password(&String::from_utf8_lossy(&password));
    if let Some(bytes) = keyfile_bytes.as_ref() {
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        key = key
            .with_keyfile(&mut cursor)
            .map_err(|e| VeilError::KeePass {
                message: format!("KeePass 内部错误: keyfile 解析失败: {e}"),
            })?;
    }
    let mut file = std::fs::File::open(db_path).map_err(|e| VeilError::KeePass {
        message: format!("KeePass 内部错误: 库文件打开失败: {e}"),
    })?;
    keepass::Database::open(&mut file, key).map_err(|e| VeilError::KeePass {
        message: format!("KeePass 内部错误: 解密失败: {e}"),
    })
}

fn snapshot_of(db: &keepass::Database, title: &str) -> Option<EntrySnapshot> {
    let mut all = Vec::new();
    collect_entries(db.root(), &mut all);
    let mut candidates: Vec<&EntrySnapshot> = all.iter().filter(|e| e.title == title).collect();
    candidates.sort_by(|a, b| a.username.cmp(&b.username).then_with(|| a.url.cmp(&b.url)));
    candidates.into_iter().next().cloned()
}

fn collect_entries(group: keepass::db::GroupRef<'_>, out: &mut Vec<EntrySnapshot>) {
    if group.name == "Recycle Bin" {
        return;
    }
    for entry in group.entries() {
        out.push(EntrySnapshot {
            title: entry.get_title().unwrap_or_default().to_string(),
            username: entry.get_username().unwrap_or_default().to_string(),
            password: entry.get_password().unwrap_or_default().to_string(),
            url: entry.get_url().unwrap_or_default().to_string(),
            custom: entry
                .fields
                .iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "Title" | "UserName" | "Password" | "URL" | "Notes"
                    )
                })
                .map(|(k, v)| CustomProp {
                    name: k.clone(),
                    value: v.as_str().to_string(),
                    protected: v.is_protected(),
                })
                .collect(),
        });
    }
    for subgroup in group.groups() {
        collect_entries(subgroup, out);
    }
}

#[cfg(test)]
pub type FixtureEntry = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Vec<(String, String, bool)>,
);

#[cfg(test)]
pub fn build_test_kdbx(path: &std::path::Path, password: &[u8], entries: &[FixtureEntry]) {
    use keepass::{
        Database,
        DatabaseKey,
        db::fields::{PASSWORD, TITLE, URL, USERNAME},
    };
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        for (title, username, secret, url, customs) in entries {
            let mut entry = root.add_entry();
            entry.set_unprotected(TITLE, *title);
            entry.set_unprotected(USERNAME, *username);
            entry.set_protected(PASSWORD, *secret);
            if !url.is_empty() {
                entry.set_unprotected(URL, *url);
            }
            for (name, value, protected) in customs.iter() {
                if *protected {
                    entry.set_protected(name.clone(), value.clone());
                } else {
                    entry.set_unprotected(name.clone(), value.clone());
                }
            }
        }
    }
    let key = DatabaseKey::new().with_password(&String::from_utf8_lossy(password));
    let mut bytes = Vec::new();
    db.save(&mut bytes, key).expect("测试固件 kdbx 构建须成功");
    std::fs::write(path, bytes).expect("测试固件 kdbx 落盘须成功");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 未解锁返回503() {
        let backend = MockKeePass::locked();
        let err = backend.fetch_credential("c1").unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn 解锁后下发占位载荷() {
        let backend = MockKeePass::unlocked();
        assert!(backend.fetch_credential("c1").is_ok());
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "veil-keepass-test-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_backend(dir: &std::path::Path) -> RealKeePass {
        let db_path = dir.join("vault.kdbx");
        build_test_kdbx(
            &db_path,
            b"fixture-master-pw",
            &[
                (
                    "网易",
                    "mail-user",
                    "mail-secret-001",
                    "https://mail.example.com",
                    vec![
                        ("授权码".to_string(), "authcode-abc-123".to_string(), true),
                        ("备注".to_string(), "plain-note".to_string(), false),
                    ],
                ),
                ("备用", "backup-user", "backup-secret-002", "", vec![]),
            ],
        );
        let provider: PasswordProvider =
            std::sync::Arc::new(|| Ok(Zeroizing::new(b"fixture-master-pw".to_vec())));
        RealKeePass::new(db_path, None, provider)
    }

    #[tokio::test]
    async fn 真实固件整条目回放() {
        let dir = unique_temp_dir("full");
        let backend = fixture_backend(&dir);
        assert!(backend.is_unlocked());
        let snapshot = backend.fetch_entry("网易".to_string()).await.unwrap();
        assert_eq!(snapshot.title, "网易");
        assert_eq!(snapshot.username, "mail-user");
        assert_eq!(snapshot.password, "mail-secret-001");
        assert_eq!(snapshot.url, "https://mail.example.com");
        let authcode = snapshot.custom_value("授权码").expect("自定义字段须存在");
        assert_eq!(authcode.value, "authcode-abc-123");
        assert!(authcode.protected);
        let note = snapshot.custom_value("备注").expect("明文字段须存在");
        assert!(!note.protected);
        assert_eq!(backend.open_count(), 1);
        let _ = backend.fetch_entry("网易".to_string()).await.unwrap();
        assert_eq!(backend.open_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 缺条目返回404具名() {
        let dir = unique_temp_dir("missing");
        let backend = fixture_backend(&dir);
        let err = backend.fetch_entry("不存在".to_string()).await.unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
        assert!(err.to_string().contains("不存在"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 无库返回503且不尝试解锁() {
        let dir = unique_temp_dir("nodb");
        let opened = std::sync::Arc::new(AtomicBool::new(false));
        let flag = opened.clone();
        let provider: PasswordProvider = std::sync::Arc::new(move || {
            flag.store(true, Ordering::SeqCst);
            Ok(Zeroizing::new(b"pw".to_vec()))
        });
        let backend = RealKeePass::new(dir.join("absent.kdbx"), None, provider);
        assert!(!backend.is_unlocked());
        let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(!opened.load(Ordering::SeqCst));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 错误主密码返回500() {
        let dir = unique_temp_dir("badpw");
        let db_path = dir.join("vault.kdbx");
        build_test_kdbx(&db_path, b"correct-pw", &[("网易", "u", "s", "", vec![])]);
        let provider: PasswordProvider =
            std::sync::Arc::new(|| Ok(Zeroizing::new(b"wrong-pw".to_vec())));
        let backend = RealKeePass::new(db_path, None, provider);
        let err = backend.fetch_entry("网易".to_string()).await.unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 并发冷缓存仅单次open() {
        let dir = unique_temp_dir("race");
        let backend = std::sync::Arc::new(fixture_backend(&dir));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let backend = backend.clone();
            handles.push(tokio::spawn(async move {
                backend.fetch_entry("备用".to_string()).await.unwrap()
            }));
        }
        for handle in handles {
            let snapshot = handle.await.unwrap();
            assert_eq!(snapshot.password, "backup-secret-002");
        }
        assert_eq!(backend.open_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 清缓存后重新open() {
        let dir = unique_temp_dir("invalidate");
        let backend = fixture_backend(&dir);
        backend.fetch_entry("备用".to_string()).await.unwrap();
        assert_eq!(backend.open_count(), 1);
        backend.clear_cache();
        backend.fetch_entry("备用".to_string()).await.unwrap();
        assert_eq!(backend.open_count(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tpm口令提供器缓存复用() {
        let dir = unique_temp_dir("tpm-cache");
        let provider = tpm_password_provider(dir.clone(), true);
        let first = provider().expect("mock 放行须解封成功");
        assert!(first.len() >= 4);
        let second = provider().expect("二次调用须复用缓存");
        assert_eq!(first.as_slice(), second.as_slice());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn 二次查询不重解主密码() {
        let dir = unique_temp_dir("tpm-reuse");
        let db_path = dir.join("vault.kdbx");
        build_test_kdbx(
            &db_path,
            b"fixture-master-pw",
            &[("网易", "u", "s", "", vec![])],
        );
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let provider: PasswordProvider = std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(b"fixture-master-pw".to_vec()))
        });
        let backend = RealKeePass::new(db_path, None, provider);
        backend.fetch_entry("网易".to_string()).await.unwrap();
        backend.fetch_entry("网易".to_string()).await.unwrap();
        assert_eq!(backend.open_count(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
