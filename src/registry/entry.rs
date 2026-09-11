//! 调用方条目定义（B6/D6 自 `registry.rs` 拆出）：条目结构、注册参数与旧哈希宽限。

use {
    super::store::now_unix_secs,
    crate::config::AutoApprove,
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
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

#[cfg(test)]
mod tests {
    use crate::registry::CallerRegistry;

    #[test]
    fn old_hash_grace_accepts_old_rejects_other() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/g.sh", "h1").unwrap();
        reg.approve_hash_change("/s/g.sh", "h2").unwrap();
        let e = reg.lookup_by_path("/s/g.sh").unwrap();
        assert_eq!(e.old_hash.as_deref(), Some("h1"));
        assert!(e.matches_old_hash("h1"));
        assert!(!e.matches_old_hash("hX"));
    }
}
