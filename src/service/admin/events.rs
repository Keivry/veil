//! 管理面事件查询纯逻辑：旧查询兼容映射 + 管理 token 等长比较
//! （handler 层实现见 `handler::admin`）。

/// 旧查询 `range` 兼容：`1h/24h/7d/30d` 映射新口径 `granularity`；未知值返回 `None`。
/// 映射等价性：`1h→five_min`、`24h→hourly`、`7d/30d→daily`，与新口径同窗查询等价。
pub fn compat_granularity_for_range(range: &str) -> Option<&'static str> {
    match range.trim().to_lowercase().as_str() {
        "1h" => Some("five_min"),
        "24h" => Some("hourly"),
        "7d" | "30d" => Some("daily"),
        _ => None,
    }
}

/// 旧 `verdict` 值兼容：大小写不敏感归一到 `allow/block/need_approval` 新口径；
/// 未知值返回 `None`（调用方忽略过滤、仅弃用标注，避免空结果误导）。
pub fn normalize_verdict_compat(verdict: &str) -> Option<&'static str> {
    match verdict.trim().to_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "approved" => Some("allow"),
        "block" | "blocked" | "deny" | "rejected" => Some("block"),
        "need_approval" | "needapproval" | "pending" | "approve" | "approval" => {
            Some("need_approval")
        }
        _ => None,
    }
}

/// 管理 token 变长比较：复用 `auth::secret_eq`（HMAC-SHA256 域分隔后比较
/// 32 字节固定 tag，恒时无早退），自研实现已删，单一实现口径。
/// 注：与凭据 Secret 共用同一域分隔 key——两者永不跨域比较，仅作等值
/// 判定，域分隔合并无安全影响；调用方 MUST NOT 用本函数比较定长哈希
/// （定长哈希用 `auth::ct_eq`）。
pub fn admin_token_eq(provided: &str, expected: &str) -> bool {
    crate::auth::secret_eq(provided, expected)
}

/// `DATA_DIR/admin_token` 文件值读取（Token 独立性第二锚点：文件值须与
/// `MATRIX_ACCESS_TOKEN` 不同，由网关启动期校验；缺失/空返回 None）。
/// D4：仅单测使用，降级为测试可见（生产无读取方）。
#[cfg(test)]
pub fn load_admin_token_file(data_dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("admin_token")).ok()?;
    let v = text.trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// 事件查询默认上限。
pub const EVENT_DEFAULT_LIMIT: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_constant_time_comparison_semantics() {
        assert!(admin_token_eq("tok-abc-123", "tok-abc-123"));
        assert!(!admin_token_eq("tok-abc-124", "tok-abc-123"));
        assert!(!admin_token_eq("short", "much-longer-expected-value"));
        assert!(!admin_token_eq("", "x"));
        assert!(admin_token_eq("", ""));
    }

    /// A18/D18：旧 `range` 键映射新 `granularity`，且三档桶跨度与旧窗口数值等价
    /// （1h=12×five_min、1d=24×hourly=288×five_min、1d=daily 单桶）。
    #[test]
    fn metrics_series_timeframe_mapping() {
        use crate::service::metrics::aggregate::{day_key, five_min_key, hour_key};
        for (range, gran) in [
            ("1h", "five_min"),
            ("24h", "hourly"),
            ("7d", "daily"),
            ("30d", "daily"),
        ] {
            assert_eq!(compat_granularity_for_range(range), Some(gran), "{range}");
        }
        let base = 1_234_567_890_i64.div_euclid(86_400) * 86_400;
        let five_in_hour: std::collections::BTreeSet<String> = (0..3_600)
            .step_by(300)
            .map(|d| five_min_key(base + d))
            .collect();
        assert_eq!(five_in_hour.len(), 12, "1h 须恰 12 个 five_min 桶");
        let hours_in_day: std::collections::BTreeSet<String> = (0..86_400)
            .step_by(3_600)
            .map(|d| hour_key(base + d))
            .collect();
        assert_eq!(hours_in_day.len(), 24, "24h 须恰 24 个 hourly 桶");
        let five_in_day: std::collections::BTreeSet<String> = (0..86_400)
            .step_by(300)
            .map(|d| five_min_key(base + d))
            .collect();
        assert_eq!(five_in_day.len(), 288, "24h 须恰 288 个 five_min 桶");
        let daily: std::collections::BTreeSet<String> = (0..86_400)
            .step_by(3_600)
            .map(|d| day_key(base + d))
            .collect();
        assert_eq!(daily.len(), 1, "24h 须恰 1 个 daily 桶");
    }

    #[test]
    fn legacy_range_maps_to_new_granularity() {
        assert_eq!(compat_granularity_for_range("1h"), Some("five_min"));
        assert_eq!(compat_granularity_for_range("24h"), Some("hourly"));
        assert_eq!(compat_granularity_for_range("7d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("30d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("24H"), Some("hourly"));
        assert_eq!(compat_granularity_for_range(" 7d "), Some("daily"));
        assert_eq!(compat_granularity_for_range("90d"), None);
        assert_eq!(compat_granularity_for_range(""), None);
    }

    #[test]
    fn legacy_verdict_normalizes_to_new_values() {
        for v in ["allow", "allowed", "pass", "approved", "ALLOW"] {
            assert_eq!(normalize_verdict_compat(v), Some("allow"), "{v}");
        }
        for v in ["block", "blocked", "deny", "rejected", "BLOCK"] {
            assert_eq!(normalize_verdict_compat(v), Some("block"), "{v}");
        }
        for v in ["need_approval", "pending", "approve", "approval"] {
            assert_eq!(normalize_verdict_compat(v), Some("need_approval"), "{v}");
        }
        assert_eq!(normalize_verdict_compat("bogus"), None);
        assert_eq!(normalize_verdict_compat(""), None);
    }

    #[test]
    fn verdict_normalization_covers_all_aliases() {
        for v in ["allow", "allowed", "pass", "approved", "ALLOW", " Pass "] {
            assert_eq!(normalize_verdict_compat(v), Some("allow"), "{v}");
        }
        for v in ["block", "blocked", "deny", "rejected", "BLOCKED"] {
            assert_eq!(normalize_verdict_compat(v), Some("block"), "{v}");
        }
        for v in [
            "need_approval",
            "needapproval",
            "pending",
            "approve",
            "approval",
        ] {
            assert_eq!(normalize_verdict_compat(v), Some("need_approval"), "{v}");
        }
        assert_eq!(normalize_verdict_compat("weird"), None);
        assert_eq!(normalize_verdict_compat(""), None);
        for r in ["1h", "24h", "7d", "30d"] {
            assert!(compat_granularity_for_range(r).is_some(), "{r}");
        }
        assert_eq!(compat_granularity_for_range("1h"), Some("five_min"));
        assert_eq!(compat_granularity_for_range("24h"), Some("hourly"));
        assert_eq!(compat_granularity_for_range("7d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("30d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("9d"), None);
    }

    #[test]
    fn admin_token_file_isolation() {
        let dir = std::env::temp_dir().join(format!("veil-admin-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_admin_token_file(&dir), None);
        std::fs::write(dir.join("admin_token"), "file-token-abc\n").unwrap();
        assert_eq!(
            load_admin_token_file(&dir).as_deref(),
            Some("file-token-abc")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn admin_token_file_empty_vs_missing_edges() {
        let dir =
            std::env::temp_dir().join(format!("veil-admin-token-edge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 缺文件：读取失败路径，fail-closed 为 None（不 panic）。
        assert_eq!(load_admin_token_file(&dir), None);
        // 空文件：空值过滤路径，fail-closed 为 None（无空串 token 旁路）。
        std::fs::write(dir.join("admin_token"), "").unwrap();
        assert_eq!(load_admin_token_file(&dir), None);
        // 纯空白文件：同空文件口径。
        std::fs::write(dir.join("admin_token"), "  \n\t\n").unwrap();
        assert_eq!(load_admin_token_file(&dir), None);
        // 首尾空白有效值：trim 后生效。
        std::fs::write(dir.join("admin_token"), "  file-token-xyz\n").unwrap();
        assert_eq!(
            load_admin_token_file(&dir).as_deref(),
            Some("file-token-xyz")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
