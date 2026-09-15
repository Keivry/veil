//! 条目/字段授权判定（B6/D6 自 `registry.rs` 拆出）：`CallerEntry` 的 ACL 辅助方法。

use {super::entry::CallerEntry, crate::config::AutoApprove};

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
}

#[cfg(test)]
mod tests {
    use {super::*, crate::registry::CallerRegistry, std::collections::BTreeMap};

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
            reg_id: String::new(),
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
    fn empty_allowlist_denies_by_default() {
        let mut reg = CallerRegistry::empty();
        reg.register("/s/empty.sh", "h9").unwrap();
        let e = reg.lookup_by_path("/s/empty.sh").unwrap();
        assert!(!e.check_entry_allowed("网易", Some("授权码")));
        assert!(!e.check_entry_allowed("网易", None));
    }
}
