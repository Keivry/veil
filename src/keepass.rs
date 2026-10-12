//! KeePass 后端（真实 kdbx + Mock）：并发查询经 `Semaphore(1)` 串行化
//! （`Semaphore(1)`），缓存锁（std Mutex）绝不跨 await，
//! 只在同步小临界区内加锁，拿完快照立即释放。

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
    #[cfg(test)]
    pub(crate) fn custom_value(&self, name: &str) -> Option<&CustomProp> {
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
    /// 清除并零化 TPM 派生主密码缓存；无该缓存的实现默认 no-op。
    fn clear_master_password(&self) -> bool { false }
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

    #[cfg(test)]
    pub(crate) fn fetch_credential(&self, caller: &str) -> Result<String> {
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

/// TPM 派生主密码缓存的可清理句柄：`lock` 经此清除并以 `Zeroizing`
/// 零化缓存，使再次解锁必须重新经 TPM 解封。
#[derive(Clone, Default)]
pub struct MasterPasswordCache {
    slot: std::sync::Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
}

impl std::fmt::Debug for MasterPasswordCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterPasswordCache")
            .field("has_cached", &self.has_cached())
            .finish()
    }
}

impl MasterPasswordCache {
    /// 清除并零化缓存；返回原本是否存在缓存值。
    pub fn clear(&self) -> bool {
        self.slot
            .lock()
            .map(|mut slot| slot.take().is_some())
            .unwrap_or(false)
    }

    /// 缓存是否非空（观测/测试用）。
    pub fn has_cached(&self) -> bool { self.slot.lock().is_ok_and(|slot| slot.is_some()) }
}

pub fn tpm_password_provider(tpm_dir: PathBuf, allow_mock: bool) -> PasswordProvider {
    tpm_password_provider_with_cache(tpm_dir, allow_mock).0
}

/// 带可清理句柄的 TPM 主密码 provider：缓存经 [`MasterPasswordCache`]
/// 暴露，`lock` 清除后再次取用重新经 TPM 解封。
pub fn tpm_password_provider_with_cache(
    tpm_dir: PathBuf,
    allow_mock: bool,
) -> (PasswordProvider, MasterPasswordCache) {
    let cache = MasterPasswordCache::default();
    let shared = cache.clone();
    let provider: PasswordProvider = std::sync::Arc::new(move || {
        if let Ok(guard) = shared.slot.lock()
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
        if let Ok(mut slot) = shared.slot.lock() {
            *slot = Some(guarded.clone());
        }
        Ok(guarded)
    });
    (provider, cache)
}

pub struct RealKeePass {
    db_path: PathBuf,
    keyfile_path: Option<PathBuf>,
    password_provider: PasswordProvider,
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    cache: Mutex<Option<keepass::Database>>,
    password_cache: Option<MasterPasswordCache>,
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
            password_cache: None,
            open_count: AtomicUsize::new(0),
        }
    }

    /// 挂接 TPM 主密码缓存可清理句柄，使 `lock` 可清除并零化该缓存。
    pub fn with_master_password_cache(mut self, cache: MasterPasswordCache) -> Self {
        self.password_cache = Some(cache);
        self
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
    /// 快检：库文件存在即视为配置就绪（`/health` 用，不触发解密、无副作用）。
    /// 取用路径失败仍以 `fetch_entry` 的实时错误为准，本函数不做解锁承诺。
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

    fn clear_master_password(&self) -> bool {
        self.password_cache
            .as_ref()
            .is_some_and(MasterPasswordCache::clear)
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

/// 同名多条目取首条：按库内遍历序（组深度优先、条目插入序）返回首个命中，
/// 不做二次排序。语义为「首条胜出」；按用户名/URL 再排序会改变既有库的取用
/// 结果，属于静默行为漂移，故此处只取首条。调用方如需确定性，应在库内保证
/// 同名唯一（注册表侧约束），而非依赖网关排序。
fn snapshot_of(db: &keepass::Database, title: &str) -> Option<EntrySnapshot> {
    let mut all = Vec::new();
    collect_entries(db.root(), &mut all);
    all.into_iter().find(|e| e.title == title)
}

/// 条目收集：跳过 `Recycle Bin` 整组（含其子组，删除条目不得被取用）；
/// `Notes` 字段不纳入自定义字段（备注常含长文本，转审/审计时会放大明文面，
/// 且各版本对其口径不一，此处显式声明跳过，其余标准字段映射见上）。
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
mod tests;
