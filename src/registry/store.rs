//! 注册表存储（B6/D6 自 `registry.rs` 拆出）：加载/原子落盘/完整性/绑定哈希。

use {
    super::entry::{CallerEntry, HashChangeOutcome, OLD_HASH_GRACE_SECS, RegisterParams},
    crate::{
        auth::sha256_hex,
        error::{Result, VeilError},
        fs_perm::ensure_0600,
    },
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, io::Write as _, path::Path},
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

fn storage_io(what: &str, e: std::io::Error) -> VeilError {
    VeilError::Storage {
        message: format!("{what}: {e}"),
    }
}

/// 纯字节原子落盘（B1/D1）：`create_dir_all` + tmp 写 + `0600`，
/// 随后 `sync_all`、rename、`0600`、父目录 `sync_all`（`C14`/D14，
/// 掉电后已确认写不丢失）；不引用 `CallerRegistry`，可在 `spawn_blocking`
/// 中于写锁外调用。
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
        std::fs::create_dir_all(parent).map_err(|e| storage_io("注册表目录创建失败", e))?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp).map_err(|e| storage_io("注册表暂存写入失败", e))?;
    file.write_all(bytes)
        .map_err(|e| storage_io("注册表暂存写入失败", e))?;
    #[cfg(test)]
    if FAIL_SYNC.with(std::cell::Cell::get) {
        let _ = std::fs::remove_file(&tmp);
        return Err(storage_io(
            "注册表 fsync 失败（测试注入）",
            std::io::Error::other("injected fsync failure"),
        ));
    }
    file.sync_all()
        .map_err(|e| storage_io("注册表 fsync 失败", e))?;
    drop(file);
    ensure_0600(&tmp);
    std::fs::rename(&tmp, path).map_err(|e| storage_io("注册表原子提交失败", e))?;
    ensure_0600(path);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| storage_io("注册表目录 fsync 失败", e))?;
    }
    Ok(())
}

// 测试钩子（仅测试，线程局部）：本线程置位后 `integrity_of` 恒返回错误（B4 故障注入）。
#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_INTEGRITY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// 测试钩子（仅测试，线程局部）：本线程置位后 `write_atomic` 模拟 fsync 失败（C14 故障注入）。
#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
        // 新格式直读；解析或完整性失败时交迁移入口识别旧形态（`C4`/D4），
        // 两者皆不匹配仍 fail-closed。
        match serde_json::from_slice::<RegistryFile>(&raw) {
            Ok(file) if file.sha256 == integrity_of(&file.entries)? => Ok(Self {
                entries: file.entries,
            }),
            _ => Self::migrate_python_registry(path),
        }
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

    /// 按展示名定位（`C5`/D5）：未吊销条目优先；因注册已拒未吊销重名，
    /// 未吊销集合内至多一条，历史已吊销同名仅在无未吊销命中时兜底。
    pub fn lookup_by_name(&self, name: &str) -> Option<&CallerEntry> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        self.entries
            .values()
            .find(|e| !e.revoked && e.name == name)
            .or_else(|| self.entries.values().find(|e| e.name == name))
    }

    /// 按 `path`/`hash`/`name` 解析规范 `caller_path`（`C3`/D3：哈希变更落定入口的
    /// `reg_id` 缺省回退 `caller_path`；`C5`/D5：按名吊销定位入口）。
    pub fn resolve_path(&self, key: &str) -> Option<String> {
        self.lookup_by_path(key)
            .map(|e| e.caller_path.clone())
            .or_else(|| self.lookup_by_hash(key).map(|e| e.caller_path.clone()))
            .or_else(|| self.lookup_by_name(key).map(|e| e.caller_path.clone()))
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
        // 注册判重口径（`F17`，`veil-oracle-followup-fix`）：全局 hash 去重已移除
        // （内容相同双脚本可各自注册）；判重仍按 `caller_path` 与未吊销 `name`——
        // path 已存在直接拒绝；`name` 非空且与任一未吊销条目重名亦拒绝
        // （`C5`/D5，已吊销条目释放其名以允许复用）。
        // `AUTH-7`：仅对**未吊销**条目拒绝重路径；已吊销路径允许复用（与已释放 `name` 语义一致），
        // 重注册条目按下方全新初始化（`enabled=false`/`revoked=false`/无旧哈希宽限）。
        if let Some(existing) = self.entries.get(caller_path)
            && !existing.revoked
        {
            return Err(VeilError::Conflict {
                message: format!("调用方已注册: {caller_path}"),
            });
        }
        let name = params.name.trim();
        if !name.is_empty() && self.entries.values().any(|e| !e.revoked && e.name == name) {
            return Err(VeilError::Conflict {
                message: format!("调用方名称已存在: {name}"),
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

    /// `AUTH-6` 回滚：删除指定 `caller_path` 条目并返回之（注册审批建单/发送失败原子回滚用）。
    pub fn remove_entry(&mut self, caller_path: &str) -> Option<CallerEntry> {
        self.entries.remove(caller_path)
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
        self.approve_hash_change_with_script_sha256(
            caller_path,
            new_hash,
            script_sha256,
            HashChangeOutcome::KeepAuto,
        )
    }

    /// 预计算脚本哈希入口（D5）：生产写路径在取写锁前异步读取后传入。
    /// `outcome`（`C3`/D3）三态：`KeepAuto` 保持 `allow_mode`、`DemoteManual`
    /// 降级 `Pending`、`Disable` 置 `enabled=false`；三态均写旧哈希宽限与
    /// `script_sha256`。
    pub fn approve_hash_change_with_script_sha256(
        &mut self,
        caller_path: &str,
        new_hash: &str,
        script_sha256: String,
        outcome: HashChangeOutcome,
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
        match outcome {
            HashChangeOutcome::KeepAuto => {
                entry.revoked = false;
                entry.enabled = true;
            }
            HashChangeOutcome::DemoteManual => {
                entry.revoked = false;
                entry.enabled = true;
                entry.allow_mode = Some(crate::config::AutoApprove::Pending);
            }
            HashChangeOutcome::Disable => {
                entry.enabled = false;
            }
        }
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
        if let Some(k) = path {
            return self.entries.get_mut(&k);
        }
        let name = self
            .entries
            .iter()
            .find(|(_, e)| !e.revoked && e.name == key);
        let name = name
            .or_else(|| self.entries.iter().find(|(_, e)| e.name == key))
            .map(|(k, _)| k.clone());
        name.and_then(|k| self.entries.get_mut(&k))
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn snapshot(&self) -> Vec<CallerEntry> { self.entries.values().cloned().collect() }
}

#[cfg(test)]
mod tests;
