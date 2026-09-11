//! 条目/字段授权判定（B6/D6 自 `registry.rs` 拆出）：`CallerEntry` 的 ACL 辅助方法。

use {super::entry::CallerEntry, crate::config::AutoApprove};

/// 授权判定：对标 Python `_registry.py` 的 entry/field 语义。
/// - `Allow`：命中授权表，放行；
/// - `TurnToApproval`：未知 entry/field，迁移期先 warn 后转 Matrix 审批（fail-closed，
///   不得默认放行；网关侧收到本判定后建单走审批链）；
/// - `Deny`：已吊销/禁用，拒绝。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allow,
    TurnToApproval { reason: String },
    Deny { reason: String },
}

impl CallerEntry {
    /// entry/field 授权判定（空表/未知一律转审，迁移期 warn 指引补注册）。
    pub fn authorize_entry(&self, entry: &str, field: Option<&str>) -> AuthorizationDecision {
        if self.revoked || !self.enabled {
            return AuthorizationDecision::Deny {
                reason: "调用方已吊销或未启用".to_string(),
            };
        }
        if !self.check_entry_allowed(entry, field) {
            let want = match field {
                Some(f) => format!("{entry}/{f}"),
                None => entry.to_string(),
            };
            tracing::warn!(
                "未知授权 {want:?}：转 Matrix 审批（迁移期），请补注册 entry/field 后重新申请"
            );
            return AuthorizationDecision::TurnToApproval {
                reason: format!("未授权 entry/field: {want}，已转审批"),
            };
        }
        AuthorizationDecision::Allow
    }

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
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::registry::{CallerRegistry, RegisterParams},
        std::collections::BTreeMap,
    };

    fn entry(path: &str, hash: &str) -> CallerEntry {
        CallerEntry {
            caller_path: path.to_string(),
            expected_hash: hash.to_string(),
            script_sha256: crate::registry::bind_script_sha256(path, hash),
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
    fn status_emoji_maps_three_states() {
        let mut e = entry("/s/a.sh", "h1");
        assert_eq!(e.status_emoji(), "🔓");
        e.enabled = true;
        assert_eq!(e.status_emoji(), "✅");
        e.revoked = true;
        e.enabled = false;
        assert_eq!(e.status_emoji(), "❎");
    }

    #[test]
    fn unknown_entry_or_field_turns_to_approval() {
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
        reg.set_enabled("/s/acl.sh", true).unwrap();
        let e = reg.lookup_by_path("/s/acl.sh").unwrap();
        assert_eq!(
            e.authorize_entry("网易", Some("授权码")),
            AuthorizationDecision::Allow
        );
        assert!(matches!(
            e.authorize_entry("未知条目", Some("授权码")),
            AuthorizationDecision::TurnToApproval { .. }
        ));
        assert!(matches!(
            e.authorize_entry("网易", Some("未授权字段")),
            AuthorizationDecision::TurnToApproval { .. }
        ));
        // 空授权表同样转审（迁移期 warn），不直接放行。
        let mut reg2 = CallerRegistry::empty();
        reg2.register("/s/empty.sh", "h9").unwrap();
        reg2.set_enabled("/s/empty.sh", true).unwrap();
        let e2 = reg2.lookup_by_path("/s/empty.sh").unwrap();
        assert!(matches!(
            e2.authorize_entry("网易", None),
            AuthorizationDecision::TurnToApproval { .. }
        ));
    }

    #[test]
    fn empty_allowlist_denies_by_default() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/empty.sh", "h9").unwrap();
        let e = reg.lookup_by_path("/s/empty.sh").unwrap();
        assert!(!e.check_entry_allowed("网易", Some("授权码")));
        assert!(!e.check_entry_allowed("网易", None));
    }
}
