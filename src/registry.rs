use {
    crate::{
        auth::sha256_hex,
        config::AutoApprove,
        error::{Result, VeilError},
    },
    serde::{Deserialize, Serialize},
    std::{collections::BTreeMap, path::Path},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerEntry {
    pub caller_path: String,
    pub expected_hash: String,
    pub script_sha256: String,
    pub enabled: bool,
    pub revoked: bool,
    #[serde(default)]
    pub auto_approve: Option<AutoApprove>,
    /// 调用方展示名（Go `name` 形态映射，缺省空）。
    #[serde(default)]
    pub name: String,
    /// 调用方描述（Go `desc`/`description` 映射，缺省空）。
    #[serde(default)]
    pub description: String,
    /// 条目到字段的授权映射（Go `entries` 形态映射；空表 = 未授权，默认拒绝）。
    #[serde(default)]
    pub entries: BTreeMap<String, Vec<String>>,
    /// 单调用方自动放行模式（Go `allow_mode` 映射；`None` 时回退 `auto_approve`/全局）。
    #[serde(default)]
    pub allow_mode: Option<AutoApprove>,
    /// 上次哈希（`approve_hash_change` 暂存，宽限期内旧哈希仍可用并通知）。
    #[serde(default)]
    pub old_hash: Option<String>,
    /// 旧哈希过期时间（unix 秒）；`None` 表示无宽限。
    #[serde(default)]
    pub old_hash_expires_at: Option<u64>,
}

/// 旧哈希宽限窗口（秒，对标 Python 3600s 语义）。
pub const OLD_HASH_GRACE_SECS: u64 = 3600;

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 注册扩展参数（网关侧做 Go 字段映射，协议不 breaking）。
#[derive(Debug, Clone, Default)]
pub struct RegisterParams {
    pub caller_path: String,
    pub caller_hash: String,
    pub name: String,
    pub description: String,
    pub entries: BTreeMap<String, Vec<String>>,
    pub allow_mode: Option<AutoApprove>,
}

impl CallerEntry {
    pub fn status_emoji(&self) -> &'static str {
        if self.revoked {
            "❎"
        } else if self.enabled {
            "✅"
        } else {
            "🔓"
        }
    }

    pub fn effective_allow_mode(&self, fallback: AutoApprove) -> AutoApprove {
        self.allow_mode.or(self.auto_approve).unwrap_or(fallback)
    }

    pub fn check_entry_allowed(&self, entry: &str, field: Option<&str>) -> bool {
        let entry = entry.trim();
        if entry.is_empty() || self.entries.is_empty() {
            return false;
        }
        match self.entries.get(entry) {
            None => false,
            Some(allowed) => match field {
                None => true,
                Some(f) => {
                    let f = f.trim();
                    if f.is_empty() {
                        return true;
                    }
                    if allowed.is_empty() {
                        return true;
                    }
                    allowed.iter().any(|a| a == f)
                }
            },
        }
    }

    pub fn matches_old_hash(&self, hash: &str) -> bool {
        match (self.old_hash.as_deref(), self.old_hash_expires_at) {
            (Some(old), Some(exp)) => {
                !old.is_empty() && crate::auth::ct_eq(old, hash) && now_unix_secs() <= exp
            }
            _ => false,
        }
    }
}

impl AutoApprove {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "true",
            Self::Deny => "false",
            Self::Pending => "none",
        }
    }

    fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "true" => Some(Self::Allow),
            "false" => Some(Self::Deny),
            "none" => Some(Self::Pending),
            _ => None,
        }
    }
}

impl serde::Serialize for AutoApprove {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AutoApprove {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::from_str_opt(raw.trim().to_lowercase().as_str())
            .ok_or_else(|| serde::de::Error::custom(format!("AUTO_APPROVE 非法: {raw:?}")))
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallerRegistry {
    entries: BTreeMap<String, CallerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryFile {
    entries: BTreeMap<String, CallerEntry>,
    sha256: String,
}

pub fn bind_script_sha256(caller_path: &str, expected_hash: &str) -> String {
    if let Ok(bytes) = std::fs::read(caller_path)
        && !bytes.is_empty()
    {
        return sha256_hex(&bytes);
    }
    sha256_hex(format!("{expected_hash}:{caller_path}").as_bytes())
}

fn integrity_of(entries: &BTreeMap<String, CallerEntry>) -> String {
    let canonical = serde_json::to_string(entries).unwrap_or_default();
    sha256_hex(canonical.as_bytes())
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
        if file.sha256 != integrity_of(&file.entries) {
            return Err(VeilError::Storage {
                message: "注册表完整性校验失败（sha256 失配），拒绝加载".to_string(),
            });
        }
        Ok(Self {
            entries: file.entries,
        })
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| VeilError::Storage {
                message: format!("注册表目录创建失败: {e}"),
            })?;
        }
        let file = RegistryFile {
            entries: self.entries.clone(),
            sha256: integrity_of(&self.entries),
        };
        let raw = serde_json::to_vec_pretty(&file).map_err(|e| VeilError::Storage {
            message: format!("注册表序列化失败: {e}"),
        })?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &raw).map_err(|e| VeilError::Storage {
            message: format!("注册表暂存写入失败: {e}"),
        })?;
        chmod_0600(&tmp);
        std::fs::rename(&tmp, path).map_err(|e| VeilError::Storage {
            message: format!("注册表原子提交失败: {e}"),
        })?;
        chmod_0600(path);
        Ok(())
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
        let caller_path = params.caller_path.trim();
        let caller_hash = params.caller_hash.trim();
        if caller_path.is_empty() || caller_hash.is_empty() {
            return Err(VeilError::BadRequest {
                message: "caller_path 与 caller_hash 均必填".to_string(),
            });
        }
        if self.entries.contains_key(caller_path) {
            return Err(VeilError::Conflict {
                message: format!("调用方已注册: {caller_path}"),
            });
        }
        if self.lookup_by_hash(caller_hash).is_some() {
            return Err(VeilError::Conflict {
                message: "调用方哈希已存在".to_string(),
            });
        }
        let entry = CallerEntry {
            caller_path: caller_path.to_string(),
            expected_hash: caller_hash.to_string(),
            script_sha256: bind_script_sha256(caller_path, caller_hash),
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

    pub fn set_entries(&mut self, key: &str, entries: BTreeMap<String, Vec<String>>) -> Result<()> {
        let entry = self.find_mut(key).ok_or_else(|| VeilError::BadRequest {
            message: format!("调用方不存在: {key}"),
        })?;
        entry.entries = entries;
        Ok(())
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
        entry.script_sha256 = bind_script_sha256(caller_path, new_hash);
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

fn chmod_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!("注册表 chmod 0600 失败: {}: {e}", path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, hash: &str) -> CallerEntry {
        CallerEntry {
            caller_path: path.to_string(),
            expected_hash: hash.to_string(),
            script_sha256: bind_script_sha256(path, hash),
            enabled: false,
            revoked: false,
            auto_approve: None,
            name: String::new(),
            description: String::new(),
            entries: BTreeMap::new(),
            allow_mode: None,
            old_hash: None,
            old_hash_expires_at: None,
        }
    }

    #[test]
    fn 三态标识映射() {
        let mut e = entry("/s/a.sh", "h1");
        assert_eq!(e.status_emoji(), "🔓");
        e.enabled = true;
        assert_eq!(e.status_emoji(), "✅");
        e.revoked = true;
        e.enabled = false;
        assert_eq!(e.status_emoji(), "❎");
    }

    #[test]
    fn 重复注册判重409() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        let err = reg.register("/s/a.sh", "h2").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::CONFLICT);
        let err2 = reg.register("/s/b.sh", "h1").unwrap_err();
        assert_eq!(err2.status_code(), axum::http::StatusCode::CONFLICT);
    }

    #[test]
    fn 新注册默认未启用() {
        let mut reg = CallerRegistry::empty();
        let e = reg.register("/s/a.sh", "h1").unwrap();
        assert!(!e.enabled && !e.revoked);
        assert_eq!(e.status_emoji(), "🔓");
    }

    #[test]
    fn 原子落盘与完整性校验() {
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
    fn 吊销后置禁用() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.set_enabled("/s/a.sh", true).unwrap();
        reg.revoke("/s/a.sh").unwrap();
        let e = reg.lookup_by_path("/s/a.sh").unwrap();
        assert!(e.revoked && !e.enabled);
        assert_eq!(e.status_emoji(), "❎");
    }

    #[test]
    fn 哈希变更审批后生效并启用() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/a.sh", "h1").unwrap();
        reg.approve_hash_change("/s/a.sh", "h2").unwrap();
        let e = reg.lookup_by_path("/s/a.sh").unwrap();
        assert_eq!(e.expected_hash, "h2");
        assert!(e.enabled && !e.revoked);
        assert_eq!(e.status_emoji(), "✅");
    }

    #[test]
    fn 未知条目字段默认拒绝() {
        let mut reg = CallerRegistry::empty();
        reg.register_extended(&RegisterParams {
            caller_path: "/s/acl.sh".to_string(),
            caller_hash: "h1".to_string(),
            name: "check-mail".to_string(),
            description: "检查邮件".to_string(),
            entries: BTreeMap::from([("网易".to_string(), vec!["授权码".to_string()])]),
            allow_mode: None,
        })
        .unwrap();
        let e = reg.lookup_by_path("/s/acl.sh").unwrap();
        assert!(e.check_entry_allowed("网易", Some("授权码")));
        assert!(e.check_entry_allowed("网易", None));
        assert!(!e.check_entry_allowed("未知条目", Some("授权码")));
        assert!(!e.check_entry_allowed("网易", Some("未授权字段")));
        assert!(!e.check_entry_allowed("", Some("授权码")));
    }

    #[test]
    fn 空授权表默认拒绝() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/empty.sh", "h9").unwrap();
        let e = reg.lookup_by_path("/s/empty.sh").unwrap();
        assert!(!e.check_entry_allowed("网易", Some("授权码")));
        assert!(!e.check_entry_allowed("网易", None));
    }

    #[test]
    fn 旧哈希宽限有效且过期失效() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/g.sh", "h1").unwrap();
        reg.approve_hash_change("/s/g.sh", "h2").unwrap();
        let e = reg.lookup_by_path("/s/g.sh").unwrap();
        assert_eq!(e.old_hash.as_deref(), Some("h1"));
        assert!(e.matches_old_hash("h1"));
        assert!(!e.matches_old_hash("hX"));
    }

    #[test]
    fn 落盘权限0600() {
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
    fn 扩展注册保留名称描述与授权映射() {
        let mut reg = CallerRegistry::empty();
        reg.register_extended(&RegisterParams {
            caller_path: "/s/go.sh".to_string(),
            caller_hash: "gh1".to_string(),
            name: "check-mail".to_string(),
            description: "检查邮件".to_string(),
            entries: BTreeMap::from([("网易".to_string(), vec!["授权码".to_string()])]),
            allow_mode: Some(AutoApprove::Pending),
        })
        .unwrap();
        let e = reg.lookup_by_path("/s/go.sh").unwrap();
        assert_eq!(e.name, "check-mail");
        assert_eq!(e.description, "检查邮件");
        assert_eq!(
            e.effective_allow_mode(AutoApprove::Allow),
            AutoApprove::Pending
        );
    }
}
