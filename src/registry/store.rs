//! 注册表存储（B6/D6 自 `registry.rs` 拆出）：加载/原子落盘/完整性/绑定哈希。

use {
    super::entry::{CallerEntry, OLD_HASH_GRACE_SECS, RegisterParams},
    crate::{
        auth::sha256_hex,
        error::{Result, VeilError},
        fs_perm::ensure_0600,
    },
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, path::Path},
};

#[derive(Debug, Clone, Default)]
pub struct CallerRegistry {
    pub(super) entries: BTreeMap<String, CallerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct RegistryFile {
    pub(super) entries: BTreeMap<String, CallerEntry>,
    pub(super) sha256: String,
}

pub(super) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 脚本绑定哈希大小上限（D5）：超限不读全量，按派生公式回退。
pub const BIND_SCRIPT_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// 脚本路径长度上限（D5，PATH_MAX 口径）。
const BIND_SCRIPT_MAX_PATH_LEN: usize = 4096;

/// 纯字节哈希（D5）：异步入口在阻塞池内复用，单测可直调。
pub fn script_sha256_of_bytes(bytes: &[u8]) -> String { sha256_hex(bytes) }

/// 派生回退（既有语义）：`sha256(expected_hash:caller_path)`。
fn derived_script_sha256(expected_hash: &str, caller_path: &str) -> String {
    sha256_hex(format!("{expected_hash}:{caller_path}").as_bytes())
}

/// 有界读取（D5）：空/超长路径、非文件、超大小上限、空文件一律 `None`。
fn read_script_bounded(caller_path: &str) -> Option<Vec<u8>> {
    if caller_path.is_empty() || caller_path.len() > BIND_SCRIPT_MAX_PATH_LEN {
        return None;
    }
    let meta = std::fs::metadata(caller_path).ok()?;
    if !meta.is_file() || meta.len() > BIND_SCRIPT_MAX_BYTES {
        return None;
    }
    let bytes = std::fs::read(caller_path).ok()?;
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// 同步绑定（迁移与测试用；生产写路径走 [`bind_script_sha256_async`]）。
pub fn bind_script_sha256(caller_path: &str, expected_hash: &str) -> String {
    match read_script_bounded(caller_path) {
        Some(bytes) => script_sha256_of_bytes(&bytes),
        None => derived_script_sha256(expected_hash, caller_path),
    }
}

/// 异步绑定（D5）：文件读取在阻塞池完成；空/超长路径、超限或不可读
/// 回退 `sha256(expected_hash:caller_path)` 并 warn，注册流程保持可用。
pub async fn bind_script_sha256_async(caller_path: String, expected_hash: String) -> String {
    let path_for_read = caller_path.clone();
    let read = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        {
            BIND_READ_ENTERED.store(true, std::sync::atomic::Ordering::SeqCst);
            let delay_ms = BIND_READ_DELAY_MS.load(std::sync::atomic::Ordering::SeqCst);
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
        }
        read_script_bounded(&path_for_read)
    });
    match read.await {
        Ok(Some(bytes)) => script_sha256_of_bytes(&bytes),
        Ok(None) => {
            tracing::warn!(
                "脚本哈希读取回退（空/超长路径、非文件、超 {BIND_SCRIPT_MAX_BYTES} 字节或不可读）: {caller_path}"
            );
            derived_script_sha256(&expected_hash, &caller_path)
        }
        Err(e) => {
            tracing::warn!("脚本哈希读取任务异常，回退派生: {caller_path}: {e}");
            derived_script_sha256(&expected_hash, &caller_path)
        }
    }
}

/// 测试钩子（仅测试）：`write_atomic` 落盘延迟毫秒数。
#[cfg(test)]
pub(crate) static SAVE_TEST_DELAY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// 测试钩子（仅测试）：`write_atomic` 进入次数（并发回归用）。
#[cfg(test)]
pub(crate) static SAVE_TEST_WRITE_STARTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// 测试钩子（仅测试）：脚本绑定读取延迟毫秒数（B5 锁外读取回归用）。
#[cfg(test)]
pub(crate) static BIND_READ_DELAY_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// 测试钩子（仅测试）：脚本绑定读取进入标记（B5 锁外读取回归用）。
#[cfg(test)]
pub(crate) static BIND_READ_ENTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 纯字节原子落盘（B1/D1）：`create_dir_all` + tmp 写 + `0600` + rename + `0600`，
/// 不引用 `CallerRegistry`，可在 `spawn_blocking` 中于写锁外调用。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(test)]
    {
        use std::sync::atomic::Ordering;
        SAVE_TEST_WRITE_STARTS.fetch_add(1, Ordering::SeqCst);
        let delay_ms = SAVE_TEST_DELAY_MS.load(Ordering::SeqCst);
        if delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| VeilError::Storage {
            message: format!("注册表目录创建失败: {e}"),
        })?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| VeilError::Storage {
        message: format!("注册表暂存写入失败: {e}"),
    })?;
    ensure_0600(&tmp);
    std::fs::rename(&tmp, path).map_err(|e| VeilError::Storage {
        message: format!("注册表原子提交失败: {e}"),
    })?;
    ensure_0600(path);
    Ok(())
}

// 测试钩子（仅测试，线程局部）：本线程置位后 `integrity_of` 恒返回错误（B4 故障注入）。
#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_INTEGRITY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 完整性哈希（B4/D4）：序列化失败显式返回错误，不得以空串/默认值弱化校验。
pub(super) fn integrity_of(entries: &BTreeMap<String, CallerEntry>) -> Result<String> {
    #[cfg(test)]
    if FAIL_INTEGRITY.with(std::cell::Cell::get) {
        return Err(VeilError::Storage {
            message: "注册表完整性计算失败（测试注入）".to_string(),
        });
    }
    let canonical = serde_json::to_string(entries).map_err(|e| VeilError::Storage {
        message: format!("注册表完整性计算失败: {e}"),
    })?;
    Ok(sha256_hex(canonical.as_bytes()))
}

impl CallerRegistry {
    pub fn empty() -> Self { Self::default() }

    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read(path).map_err(|e| VeilError::Storage {
            message: format!("注册表读取失败: {}: {e}", path.display()),
        })?;
        let file: RegistryFile = serde_json::from_slice(&raw).map_err(|e| VeilError::Storage {
            message: format!("注册表解析失败: {e}"),
        })?;
        if file.sha256 != integrity_of(&file.entries)? {
            return Err(VeilError::Storage {
                message: "注册表完整性校验失败（sha256 失配），拒绝加载".to_string(),
            });
        }
        Ok(Self {
            entries: file.entries,
        })
    }

    /// 锁内纯段（B1/D1）：仅构造完整性并序列化（纯 CPU，不触文件系统）。
    /// 调用方在 `registry.write().await` 守卫内取 bytes，随后立即释放写锁。
    pub fn to_file_bytes(&self) -> Result<Vec<u8>> {
        let file = RegistryFile {
            entries: self.entries.clone(),
            sha256: integrity_of(&self.entries)?,
        };
        serde_json::to_vec_pretty(&file).map_err(|e| VeilError::Storage {
            message: format!("注册表序列化失败: {e}"),
        })
    }

    /// 锁外纯字节落盘（B1/D1）：目录/tmp/权限/原子 rename，不引用注册表，
    /// 供 `spawn_blocking` 在写锁释放后调用。
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let bytes = self.to_file_bytes()?;
        write_atomic(path, &bytes)
    }

    pub fn lookup_by_path(&self, caller_path: &str) -> Option<&CallerEntry> {
        self.entries.get(caller_path)
    }

    pub fn lookup_by_hash(&self, caller_hash: &str) -> Option<&CallerEntry> {
        self.entries
            .values()
            .find(|e| crate::auth::ct_eq(&e.expected_hash, caller_hash))
    }

    pub fn register(&mut self, caller_path: &str, caller_hash: &str) -> Result<&CallerEntry> {
        self.register_extended(&RegisterParams {
            caller_path: caller_path.to_string(),
            caller_hash: caller_hash.to_string(),
            ..RegisterParams::default()
        })
    }

    pub fn register_extended(&mut self, params: &RegisterParams) -> Result<&CallerEntry> {
        let script_sha256 =
            bind_script_sha256(params.caller_path.trim(), params.caller_hash.trim());
        self.register_extended_with_script_sha256(params, script_sha256)
    }

    /// 预计算脚本哈希入口（D5）：生产写路径在取写锁前异步读取后传入，
    /// 锁内零文件 I/O。
    pub fn register_extended_with_script_sha256(
        &mut self,
        params: &RegisterParams,
        script_sha256: String,
    ) -> Result<&CallerEntry> {
        let caller_path = params.caller_path.trim();
        let caller_hash = params.caller_hash.trim();
        if caller_path.is_empty() || caller_hash.is_empty() {
            return Err(VeilError::BadRequest {
                message: "caller_path 与 caller_hash 均必填".to_string(),
            });
        }
        // 冲突判定只看 path：同值多路径允许分别注册（对标 Python 口径）。
        // 全局 hash 唯一拒绝已删除：内容相同的双脚本可各自注册。
        if self.entries.contains_key(caller_path) {
            return Err(VeilError::Conflict {
                message: format!("调用方已注册: {caller_path}"),
            });
        }
        let entry = CallerEntry {
            caller_path: caller_path.to_string(),
            expected_hash: caller_hash.to_string(),
            script_sha256,
            enabled: false,
            revoked: false,
            auto_approve: None,
            name: params.name.trim().to_string(),
            description: params.description.trim().to_string(),
            entries: params.entries.clone(),
            allow_mode: params.allow_mode,
            old_hash: None,
            old_hash_expires_at: None,
        };
        self.entries.insert(caller_path.to_string(), entry);
        self.entries
            .get(caller_path)
            .ok_or_else(|| VeilError::Storage {
                message: "注册表写入后回读失败".to_string(),
            })
    }

    pub fn revoke(&mut self, key: &str) -> Result<&CallerEntry> {
        let entry = self.find_mut(key).ok_or_else(|| VeilError::BadRequest {
            message: format!("调用方不存在: {key}"),
        })?;
        entry.revoked = true;
        entry.enabled = false;
        Ok(entry)
    }

    pub fn approve_hash_change(
        &mut self,
        caller_path: &str,
        new_hash: &str,
    ) -> Result<&CallerEntry> {
        let script_sha256 = bind_script_sha256(caller_path, new_hash);
        self.approve_hash_change_with_script_sha256(caller_path, new_hash, script_sha256)
    }

    /// 预计算脚本哈希入口（D5）：生产写路径在取写锁前异步读取后传入。
    pub fn approve_hash_change_with_script_sha256(
        &mut self,
        caller_path: &str,
        new_hash: &str,
        script_sha256: String,
    ) -> Result<&CallerEntry> {
        let entry = self
            .entries
            .get_mut(caller_path)
            .ok_or_else(|| VeilError::BadRequest {
                message: format!("调用方不存在: {caller_path}"),
            })?;
        if !crate::auth::ct_eq(&entry.expected_hash, new_hash) {
            entry.old_hash = Some(entry.expected_hash.clone());
            entry.old_hash_expires_at = Some(now_unix_secs() + OLD_HASH_GRACE_SECS);
        }
        entry.expected_hash = new_hash.to_string();
        entry.script_sha256 = script_sha256;
        entry.revoked = false;
        entry.enabled = true;
        Ok(entry)
    }

    pub fn set_enabled(&mut self, key: &str, enabled: bool) -> Result<()> {
        let entry = self.find_mut(key).ok_or_else(|| VeilError::BadRequest {
            message: format!("调用方不存在: {key}"),
        })?;
        entry.enabled = enabled;
        if enabled {
            entry.revoked = false;
        }
        Ok(())
    }

    fn find_mut(&mut self, key: &str) -> Option<&mut CallerEntry> {
        if self.entries.contains_key(key) {
            return self.entries.get_mut(key);
        }
        let path = self
            .entries
            .iter()
            .find(|(_, e)| crate::auth::ct_eq(&e.expected_hash, key))
            .map(|(k, _)| k.clone());
        path.and_then(|k| self.entries.get_mut(&k))
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn snapshot(&self) -> Vec<CallerEntry> { self.entries.values().cloned().collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_path_conflicts_409_same_hash_multi_path_allowed() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        let err = reg.register("/s/a.sh", "h2").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
        // 同 hash 不同 path：允许分别注册（冲突只看 path）。
        let e2 = reg.register("/s/b.sh", "h1").unwrap();
        assert_eq!(e2.caller_path, "/s/b.sh");
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn new_registration_disabled_by_default() {
        let mut reg = CallerRegistry::empty();
        let e = reg.register("/s/a.sh", "h1").unwrap();
        assert!(!e.enabled && !e.revoked);
        assert_eq!(e.status_emoji(), "🔓");
    }

    #[test]
    fn atomic_save_and_integrity_check() {
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("caller_registry.json");
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.save_to(&path).unwrap();
        let loaded = CallerRegistry::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw = raw.replace('h', "x");
        std::fs::write(&path, raw).unwrap();
        assert!(CallerRegistry::load_from(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revoke_disables_entry() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.set_enabled("/s/a.sh", true).unwrap();
        reg.revoke("/s/a.sh").unwrap();
        let e = reg.lookup_by_path("/s/a.sh").unwrap();
        assert!(e.revoked && !e.enabled);
        assert_eq!(e.status_emoji(), "❎");
    }

    #[test]
    fn approve_hash_change_applies_and_enables() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.approve_hash_change("/s/a.sh", "h2").unwrap();
        let e = reg.lookup_by_path("/s/a.sh").unwrap();
        assert_eq!(e.expected_hash, "h2");
        assert!(e.enabled && !e.revoked);
        assert_eq!(e.status_emoji(), "✅");
    }

    #[test]
    fn saved_file_permissions_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-0600-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("caller_registry.json");
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extended_register_keeps_name_desc_and_allowlist() {
        let mut reg = CallerRegistry::empty();
        reg.register_extended(&RegisterParams {
            caller_path: "/s/go.sh".to_string(),
            caller_hash: "gh1".to_string(),
            name: "check-mail".to_string(),
            description: "检查邮件".to_string(),
            entries: BTreeMap::from([("网易".to_string(), vec!["授权码".to_string()])]),
            allow_mode: Some(crate::config::AutoApprove::Pending),
        })
        .unwrap();
        let e = reg.lookup_by_path("/s/go.sh").unwrap();
        assert_eq!(e.name, "check-mail");
        assert_eq!(e.description, "检查邮件");
        assert_eq!(
            e.effective_allow_mode(crate::config::AutoApprove::Allow),
            crate::config::AutoApprove::Pending
        );
    }

    #[test]
    fn missing_entry_no_db_invalid_json_and_double_revoke_idempotent() {
        let mut reg = CallerRegistry::empty();
        assert!(reg.lookup_by_path("/s/nope.sh").is_none(), "未注册缺条目");
        let err = reg.revoke("/s/nope.sh").unwrap_err();
        assert!(err.to_string().contains("调用方不存在"), "缺条目吊销须明错");
        reg.register("/s/d.sh", "h1").unwrap();
        reg.revoke("/s/d.sh").unwrap();
        reg.revoke("/s/d.sh").expect("清理双删须幂等成功");
        let e = reg.lookup_by_path("/s/d.sh").unwrap();
        assert!(e.revoked && !e.enabled);
        let missing = std::env::temp_dir().join(format!(
            "veil-reg-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let loaded = CallerRegistry::load_from(&missing.join("no.json")).unwrap();
        assert_eq!(loaded.len(), 0, "无库须兼容空表");
        std::fs::create_dir_all(&missing).unwrap();
        let bad = missing.join("bad.json");
        std::fs::write(&bad, b"{not json").unwrap();
        assert!(CallerRegistry::load_from(&bad).is_err(), "无效 JSON 须拒载");
        std::fs::remove_dir_all(&missing).ok();
    }

    #[test]
    fn integrity_serialize_failure() {
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-failint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("caller_registry.json");
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.save_to(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        FAIL_INTEGRITY.with(|f| f.set(true));
        let err = reg.save_to(&path).unwrap_err();
        assert!(err.to_string().contains("完整性"), "{err}");
        assert!(!path.with_extension("tmp").exists(), "失败不得残留 tmp");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "原文件字节不得被覆盖"
        );
        let err = CallerRegistry::load_from(&path).unwrap_err();
        assert!(err.to_string().contains("完整性"), "{err}");
        FAIL_INTEGRITY.with(|f| f.set(false));
        assert!(CallerRegistry::load_from(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn bind_script_size_cap() {
        let dir = std::env::temp_dir().join(format!(
            "veil-reg-bindcap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.sh");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(BIND_SCRIPT_MAX_BYTES + 1).unwrap();
        drop(file);
        let big_str = big.to_string_lossy().into_owned();
        let got = bind_script_sha256_async(big_str.clone(), "cap-h".to_string()).await;
        assert_eq!(
            got,
            derived_script_sha256("cap-h", &big_str),
            "超限文件须回退派生且结果与公式一致"
        );
        let small = dir.join("small.sh");
        std::fs::write(&small, b"echo hi").unwrap();
        let small_str = small.to_string_lossy().into_owned();
        let got = bind_script_sha256_async(small_str, "cap-h".to_string()).await;
        assert_eq!(got, script_sha256_of_bytes(b"echo hi"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn bind_script_path_length() {
        let too_long = format!("/nonexistent/{}.sh", "a".repeat(BIND_SCRIPT_MAX_PATH_LEN));
        let got = bind_script_sha256_async(too_long.clone(), "len-h".to_string()).await;
        assert_eq!(got, derived_script_sha256("len-h", &too_long));
        assert_eq!(bind_script_sha256(&too_long, "len-h"), got);
    }

    #[test]
    fn bind_script_relative_path() {
        let rel = "relative/scripts/job.sh";
        let abs = "/nonexistent/scripts/job.sh";
        assert_eq!(
            bind_script_sha256(rel, "rel-h"),
            derived_script_sha256("rel-h", rel),
            "相对路径未被拒绝（仅长度/大小校验，decision D5）"
        );
        assert_eq!(
            bind_script_sha256(abs, "rel-h"),
            derived_script_sha256("rel-h", abs)
        );
        assert_eq!(
            bind_script_sha256(rel, "rel-h"),
            bind_script_sha256(rel, "rel-h")
        );
    }
}
