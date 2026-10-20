//! 条目/字段授权判定（自 `registry.rs` 拆出）：`CallerEntry` 的 ACL 辅助方法
//! 与授权窗口（TTL）纯函数。

use {super::entry::CallerEntry, crate::config::AutoApprove};

/// 配置与落定共用的 TTL 归一：`Some(0)` 与 `None` 同为「无期限」，
/// 保证「0 等于无期限」只有一处实现。
pub fn normalize_ttl(ttl: Option<u64>) -> Option<u64> { ttl.filter(|secs| *secs > 0) }

/// 授权到期时刻（unix 秒）：`authorized_at + authorized_ttl_secs`。
/// 任一为 `None` 则无期限（`None`）；相加饱和，恶意极端配置不会 panic。
pub fn authorization_expires_at(entry: &CallerEntry) -> Option<u64> {
    let start = entry.authorized_at?;
    let ttl = entry.authorized_ttl_secs?;
    Some(start.saturating_add(ttl))
}

/// 授权窗口是否已到期（`now >= 到期时刻`，边界即到期）。
/// 无期限条目恒为 `false`；`now_secs` 由调用方传入以保持本函数纯函数可测。
pub fn is_authorization_expired(entry: &CallerEntry, now_secs: u64) -> bool {
    authorization_expires_at(entry).is_some_and(|expires_at| now_secs >= expires_at)
}

impl CallerEntry {
    pub fn status_emoji(&self) -> &'static str {
        if self.revoked {
            "❎"
        } else if self.enabled {
            "✅"
        } else {
            "⏳"
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
            authorized_at: None,
            authorized_ttl_secs: None,
        }
    }

    #[test]
    fn status_emoji_maps_three_states() {
        let mut e = entry("/s/a.sh", "h1");
        assert_eq!(e.status_emoji(), "⏳");
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

#[cfg(test)]
mod ttl_tests {
    use {super::*, std::collections::BTreeMap};

    fn entry(authorized_at: Option<u64>, ttl: Option<u64>) -> CallerEntry {
        CallerEntry {
            caller_path: "/s/ttl.sh".to_string(),
            expected_hash: "h1".to_string(),
            script_sha256: String::new(),
            enabled: true,
            revoked: false,
            auto_approve: None,
            name: String::new(),
            description: String::new(),
            entries: BTreeMap::new(),
            allow_mode: None,
            old_hash: None,
            old_hash_expires_at: None,
            reg_id: String::new(),
            authorized_at,
            authorized_ttl_secs: ttl,
        }
    }

    #[test]
    fn normalize_ttl_treats_zero_as_unbounded() {
        assert_eq!(normalize_ttl(Some(0)), None, "0 须归一为无期限");
        assert_eq!(normalize_ttl(Some(60)), Some(60));
        assert_eq!(normalize_ttl(Some(1)), Some(1));
        assert_eq!(normalize_ttl(None), None);
    }

    #[test]
    fn expires_at_sums_start_and_ttl() {
        assert_eq!(
            authorization_expires_at(&entry(Some(1_000), Some(3_600))),
            Some(4_600)
        );
        assert_eq!(authorization_expires_at(&entry(None, Some(3_600))), None);
        assert_eq!(authorization_expires_at(&entry(Some(1_000), None)), None);
        assert_eq!(authorization_expires_at(&entry(None, None)), None);
    }

    #[test]
    fn expires_at_saturates_instead_of_panicking() {
        assert_eq!(
            authorization_expires_at(&entry(Some(u64::MAX), Some(u64::MAX))),
            Some(u64::MAX),
            "极端配置须饱和而非 panic"
        );
        assert_eq!(
            authorization_expires_at(&entry(Some(u64::MAX - 1), Some(10))),
            Some(u64::MAX)
        );
    }

    #[test]
    fn expired_at_boundary_inclusive() {
        // 边界：`now == expires_at` 即判为到期（不留 1 秒越权窗口）。
        let e = entry(Some(1_000), Some(100));
        let expires_at = authorization_expires_at(&e).unwrap();
        assert!(
            !is_authorization_expired(&e, expires_at - 1),
            "到期前 1s 仍有效"
        );
        assert!(
            is_authorization_expired(&e, expires_at),
            "now == expires_at 须判为到期"
        );
        assert!(is_authorization_expired(&e, expires_at + 1));
    }

    #[test]
    fn missing_ttl_never_expires() {
        let e = entry(Some(1_000), None);
        assert!(!is_authorization_expired(&e, u64::MAX), "无 TTL 恒不到期");
        let e = entry(None, Some(3_600));
        assert!(!is_authorization_expired(&e, u64::MAX), "无起点恒不到期");
        let e = entry(None, None);
        assert!(!is_authorization_expired(&e, u64::MAX));
    }

    #[test]
    fn zero_ttl_written_to_entry_never_expires() {
        // 即使持久化里残留 `Some(0)`，`now >= start + 0` 会立即到期——故落定路径
        // 必须经 `normalize_ttl` 归一为 `None`（见 vault_ops 落定）。此处锁定该语义差异。
        let e = entry(Some(1_000), Some(0));
        assert!(
            is_authorization_expired(&e, 1_000),
            "未归一的 ttl=0 会立即到期，故落定必须走 normalize_ttl"
        );
        assert_eq!(normalize_ttl(e.authorized_ttl_secs), None);
    }
}
