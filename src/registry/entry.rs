//! 调用方条目定义（自 `registry.rs` 拆出）：条目结构、注册参数与旧哈希宽限。

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
    /// 注册稳定标识：新注册按 `caller_path` 补齐；旧格式迁移保留原
    /// `reg_id`（缺省回退 `caller_path`）。空串不序列化，保持既有文件完整性哈希不变。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reg_id: String,
    /// 授权窗口起点（unix 秒）；`None` 表示从未落定过带窗口的批准。
    ///
    /// `skip_serializing_if` 不可省：注册表完整性哈希是「反序列化 → 重序列化 →
    /// sha256」（见 `store::integrity_of`）。旧文件不含这两个键，若 `None` 也序列化
    /// 成 `null`，升级后 canonical 字节改变导致哈希失配，而迁移入口只认得远古
    /// `callers` 数组，最终 fail-closed 拒绝启动。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<u64>,
    /// 授权窗口长度（秒）；`None` 表示无期限。同 `authorized_at` 需省略 `None`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_ttl_secs: Option<u64>,
}

/// 旧哈希宽限窗口（秒，3600s）。
pub const OLD_HASH_GRACE_SECS: u64 = 3600;

/// 哈希变更落定三态：对应 Matrix reaction 表情；缺省不再是合法输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashChangeOutcome {
    /// `♾️`：批准新哈希并置为自动放行（`allow_mode = Some(AutoApprove::Allow)`）。
    ApproveAlways,
    /// `✅`：批准并降级为人工审批模式（`allow_mode = Some(AutoApprove::Pending)`）。
    DemoteManual,
    /// `❎`：未获批准，禁用条目（fail-closed）。
    Disable,
}

impl HashChangeOutcome {
    /// 从 `reaction` 入参解析：`♾️`/`♾` 持久放行、`✅` 降级、`❎` 禁用；
    /// 缺省/空串/旧解锁表情/集合外取值返回 `None`（调用方按 `400` 处理）。
    pub fn from_reaction(reaction: Option<&str>) -> Option<Self> {
        let key = reaction?.trim().replace('\u{FE0F}', "");
        match key.as_str() {
            "♾" => Some(Self::ApproveAlways),
            "✅" => Some(Self::DemoteManual),
            "❎" => Some(Self::Disable),
            _ => None,
        }
    }
}

/// 注册时对授权窗口的诉求。
///
/// 必须三态：`Absent`（未声明，取配置缺省）与 `Unbounded`（请求显式 `0`，本条
/// 永久）在归一后都是「无秒数」，若压成 `Option<u64>` 就无法区分，会把显式无期限
/// 静默改成配置窗口。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthorizationTtl {
    /// 未声明：落定时取 `[storage].authorization_ttl_secs`。
    #[default]
    Absent,
    /// 声明为无期限。
    Unbounded,
    /// 声明为指定秒数（恒 > 0，`0` 已归一为 [`Self::Unbounded`]）。
    Secs(u64),
}

impl AuthorizationTtl {
    /// 归一：`0` 视为无期限；非 0 保留秒数。
    ///
    /// `raw` 为 `None` 时返回 `fallback`（即「未声明」）。
    pub fn from_request(raw: Option<u64>) -> Self {
        match crate::registry::normalize_ttl(raw) {
            Some(secs) => Self::Secs(secs),
            None if raw.is_some() => Self::Unbounded,
            None => Self::Absent,
        }
    }

    /// 解析为落定写入的窗口长度：`Absent` 取配置缺省，其余按声明值。
    pub fn resolve(self, configured: Option<u64>) -> Option<u64> {
        match self {
            Self::Absent => configured,
            Self::Unbounded => None,
            Self::Secs(secs) => Some(secs),
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
    /// 授权窗口诉求；由 `register_caller_extended` 单点解析为落定值后写入条目。
    pub authorization_ttl: AuthorizationTtl,
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
            authorized_at: None,
            authorized_ttl_secs: None,
        }
    }

    #[test]
    fn old_hash_grace_accepts_old_rejects_other() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/g.sh", "h1").unwrap();
        reg.approve_hash_change_with_script_sha256(
            "/s/g.sh",
            "h2",
            "sha-h2".to_string(),
            super::HashChangeOutcome::ApproveAlways,
        )
        .unwrap();
        let e = reg.lookup_by_path("/s/g.sh").unwrap();
        assert_eq!(e.old_hash.as_deref(), Some("h1"));
        assert!(e.matches_old_hash("h1"));
        assert!(!e.matches_old_hash("hX"));
    }

    #[test]
    fn old_hash_grace_window() {
        // 置 `now+3600` 宽限，宽限内旧 hash 可用、过期失效。
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

#[cfg(test)]
mod ttl_field_tests {
    use super::CallerEntry;

    #[test]
    fn legacy_json_without_ttl_keys_deserializes_to_none() {
        // 旧格式（无 authorized_at / authorized_ttl_secs）须可加载，两字段为 None。
        let json = r#"{
            "caller_path": "/s/legacy.sh",
            "expected_hash": "h1",
            "script_sha256": "sha",
            "enabled": true,
            "revoked": false
        }"#;
        let entry: CallerEntry = serde_json::from_str(json).expect("旧格式须可反序列化");
        assert_eq!(entry.authorized_at, None);
        assert_eq!(entry.authorized_ttl_secs, None);
        assert!(!crate::registry::is_authorization_expired(&entry, u64::MAX));
    }

    #[test]
    fn ttl_keys_round_trip_through_json() {
        let json = r#"{
            "caller_path": "/s/ttl.sh",
            "expected_hash": "h1",
            "script_sha256": "sha",
            "enabled": true,
            "revoked": false,
            "authorized_at": 1700000000,
            "authorized_ttl_secs": 3600
        }"#;
        let entry: CallerEntry = serde_json::from_str(json).expect("含 TTL 键须可反序列化");
        assert_eq!(entry.authorized_at, Some(1_700_000_000));
        assert_eq!(entry.authorized_ttl_secs, Some(3_600));
        let back = serde_json::to_string(&entry).expect("须可序列化");
        assert!(back.contains("\"authorized_at\":1700000000"), "{back}");
        assert!(back.contains("\"authorized_ttl_secs\":3600"), "{back}");
    }
}
