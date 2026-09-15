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
    /// 注册稳定标识（`CRD-11`）：新注册按 `caller_path` 补齐；旧格式迁移保留原
    /// `reg_id`（缺省回退 `caller_path`）。空串不序列化，保持既有文件完整性哈希不变。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reg_id: String,
}

/// 旧哈希宽限窗口（秒，对标 Python 3600s 语义）。
pub const OLD_HASH_GRACE_SECS: u64 = 3600;

/// 哈希变更落定三态（`C3`/D3）：对应 Matrix reaction 表情与等待超时。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashChangeOutcome {
    /// `🔓`：批准但保持现有 `allow_mode`（自动放行延续），兼容既有二元批准。
    #[default]
    KeepAuto,
    /// `✅`：批准并降级为人工审批模式（`allow_mode = Some(AutoApprove::Pending)`）。
    DemoteManual,
    /// `❎` 或等待超时：未获批准，禁用条目（fail-closed）。
    Disable,
}

impl HashChangeOutcome {
    /// 从 `reaction` 入参解析：缺省/空串按保持自动；`✅` 降级；`❎` 禁用；
    /// 其它非空值返回 `None`（调用方按 `400` 处理，对标 Python 显式校验）。
    pub fn from_reaction(reaction: Option<&str>) -> Option<Self> {
        match reaction.map(str::trim) {
            None | Some("") | Some("🔓") => Some(Self::KeepAuto),
            Some("✅") => Some(Self::DemoteManual),
            Some("❎") => Some(Self::Disable),
            Some(_) => None,
        }
    }
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
    use {
        super::{CallerEntry, OLD_HASH_GRACE_SECS},
        crate::registry::CallerRegistry,
    };

    fn entry_with_expiry(exp: u64) -> CallerEntry {
        CallerEntry {
            caller_path: "/s/grace.sh".to_string(),
            expected_hash: "new".to_string(),
            script_sha256: String::new(),
            enabled: true,
            revoked: false,
            auto_approve: None,
            name: String::new(),
            description: String::new(),
            entries: Default::default(),
            allow_mode: None,
            old_hash: Some("old".to_string()),
            old_hash_expires_at: Some(exp),
            reg_id: String::new(),
        }
    }

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

    #[test]
    fn old_hash_grace_window() {
        // C12/D12：Rust 真置 `now+3600` 宽限（Python 死码），宽限内旧 hash 可用、过期失效。
        let now = super::now_unix_secs();
        let entry = entry_with_expiry(now + OLD_HASH_GRACE_SECS);
        assert!(entry.matches_old_hash("old"), "宽限内旧 hash 须可用");
        assert!(
            entry.old_hash_expires_at.unwrap() - now >= OLD_HASH_GRACE_SECS - 2,
            "宽限须约 3600s"
        );
        // 边界：exp-1s（距过期 1s）仍可用。
        assert!(entry_with_expiry(now + 1).matches_old_hash("old"));
        // 边界：exp+1s（已过 1s）失效，且其它 hash 不匹配。
        assert!(!entry_with_expiry(now.saturating_sub(1)).matches_old_hash("old"));
        assert!(!entry_with_expiry(now + 1).matches_old_hash("other"));
    }
}
