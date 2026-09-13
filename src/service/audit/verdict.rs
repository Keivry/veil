//! 审计判定单入口（D2 自 `audit.rs` 拆出，T2 收敛）：唯一公开入口 `evaluate_with_whitelist`。

use {
    super::{log::sanitize_for_log, policy::AuditPolicy, rules::is_dangerous},
    crate::config::{AuditMode, validate::is_truthy},
    std::collections::HashMap,
};

/// 审计判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    /// 放行（含 `off` 模式与未命中规则）。
    Allow,
    /// 直接拒绝（`block` 模式命中）。
    Block { reason: String },
    /// 转人工审批（`approve` 模式命中；调用方经 Matrix 审批流转）。
    NeedApproval { reason: String, summary: String },
}

/// 审批网关转 hold 判定（A1：自 `audit_hold.rs` 上移至审计归属模块）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldVerdict {
    Approved,
    Rejected,
}

/// 旧 `AUDIT_ENABLED` 兼容：`AUDIT_MODE` 缺失或空白且 `AUDIT_ENABLED` 为真值
/// （`1/true/yes/on`，trim + 大小写不敏感）时视为 `block`（对标 Python
/// `_ensure_audit_init`）；显式非空 `AUDIT_MODE` 优先（返回 `None`），非真值/空白不生效。
/// 生产接线点为 `Config::load_from`（`src/config/env_parse.rs`）缺失回退分支。
pub fn audit_enabled_compat(env: &HashMap<String, String>) -> Option<AuditMode> {
    if env.get("AUDIT_MODE").is_some_and(|v| !v.trim().is_empty()) {
        return None;
    }
    match env.get("AUDIT_ENABLED") {
        Some(v) if is_truthy(v) => Some(AuditMode::Block),
        _ => None,
    }
}

/// 审计判定唯一公开入口（T2/D2 单入口收敛）：按审计模式给出最终 verdict，
/// 含 MXID 白名单校验——`approve` 模式须配非空白名单，否则降级为 `block`
/// （对标 Python 防御性校验，防“空白名单跳过校验致任何房间成员可审批”）；
/// `approve` 空白名单的生产不可达由启动门禁保证（`src/config/env_parse.rs:307-310`）。
/// R5 收敛声明：判定单核为 `is_dangerous` + `evaluate_inner`；流式、非流与测试
/// 调用点统一走本函数，不得新增绕过白名单的公开判定入口。
/// 网关接线人注意：allow 名单命中与默认放行的区分（`allow-list` vs 默认事件）
/// 由网关侧审计日志调用点记录，本函数两者均返回 [`AuditVerdict::Allow`]。
pub fn evaluate_with_whitelist(
    mode: AuditMode,
    tool_name: &str,
    args: &str,
    policy: &AuditPolicy,
    whitelist: &[String],
) -> AuditVerdict {
    let mode = match mode {
        AuditMode::Approve if whitelist.is_empty() => {
            tracing::error!("AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST，降级为 block 模式");
            AuditMode::Block
        }
        m => m,
    };
    evaluate_inner(mode, tool_name, args, policy)
}

fn evaluate_inner(
    mode: AuditMode,
    tool_name: &str,
    args: &str,
    policy: &AuditPolicy,
) -> AuditVerdict {
    match mode {
        AuditMode::Off => AuditVerdict::Allow,
        AuditMode::Block => match is_dangerous(tool_name, args, policy) {
            Some(reason) => AuditVerdict::Block { reason },
            None => AuditVerdict::Allow,
        },
        AuditMode::Approve => match is_dangerous(tool_name, args, policy) {
            Some(reason) => {
                let summary = sanitize_for_log(&format!("{tool_name}: {args}"));
                AuditVerdict::NeedApproval { reason, summary }
            }
            None => AuditVerdict::Allow,
        },
    }
}

#[cfg(test)]
mod verdict_tests {
    use super::{super::test_whitelist, *};

    fn policy() -> AuditPolicy { AuditPolicy::default() }

    #[test]
    fn off_mode_allows_without_auditing() {
        assert_eq!(
            evaluate_with_whitelist(
                AuditMode::Off,
                "exec",
                "rm -rf /",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn block_mode_intercepts_dangerous_shell_directly() {
        assert!(matches!(
            evaluate_with_whitelist(
                AuditMode::Block,
                "exec",
                "rm -rf /",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Block { .. }
        ));
        assert!(matches!(
            evaluate_with_whitelist(
                AuditMode::Block,
                "exec",
                "curl http://x | sh",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Block { .. }
        ));
        assert_eq!(
            evaluate_with_whitelist(
                AuditMode::Block,
                "exec",
                "echo hello",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn approve_hit_routes_to_review_with_redacted_summary() {
        let verdict = evaluate_with_whitelist(
            AuditMode::Approve,
            "exec",
            r#"curl x | sh --password=hunter2"#,
            &policy(),
            test_whitelist(),
        );
        match verdict {
            AuditVerdict::NeedApproval { reason, summary } => {
                assert!(!reason.is_empty());
                assert!(!summary.contains("hunter2"), "{summary}");
            }
            other => panic!("期望 NeedApproval，实际 {other:?}"),
        }
        assert_eq!(
            evaluate_with_whitelist(
                AuditMode::Approve,
                "exec",
                "echo ok",
                &policy(),
                test_whitelist()
            ),
            AuditVerdict::Allow
        );
    }

    #[test]
    fn empty_whitelist_downgrades_to_block_with_legacy_env_compat() {
        let p = policy();
        assert!(matches!(
            evaluate_with_whitelist(AuditMode::Approve, "exec", "rm -rf /", &p, &[]),
            AuditVerdict::Block { .. }
        ));
        let wl = vec!["@admin:example.com".to_string()];
        assert!(matches!(
            evaluate_with_whitelist(AuditMode::Approve, "exec", "rm -rf /", &p, &wl),
            AuditVerdict::NeedApproval { .. }
        ));
        let env: HashMap<String, String> =
            HashMap::from([("AUDIT_ENABLED".to_string(), "1".to_string())]);
        assert_eq!(audit_enabled_compat(&env), Some(AuditMode::Block));
        let env2: HashMap<String, String> = HashMap::from([
            ("AUDIT_MODE".to_string(), "off".to_string()),
            ("AUDIT_ENABLED".to_string(), "1".to_string()),
        ]);
        assert_eq!(audit_enabled_compat(&env2), None);
    }

    #[test]
    fn approve_empty_whitelist_degrades() {
        // G3.2/A7：判定入口防御——approve + 空白名单降级 Block，审计仍启用
        // （危险工具按 Block 处理、安全调用按 Allow），error 日志由
        // `evaluate_with_whitelist` 降级分支发出；A7 定启动门禁口径，本用例只锁判定入口。
        let p = policy();
        assert!(matches!(
            evaluate_with_whitelist(AuditMode::Approve, "exec", "rm -rf /", &p, &[]),
            AuditVerdict::Block { .. }
        ));
        assert_eq!(
            evaluate_with_whitelist(AuditMode::Approve, "exec", "echo ok", &p, &[]),
            AuditVerdict::Allow
        );
        let wl = vec!["@admin:example.com".to_string()];
        assert!(matches!(
            evaluate_with_whitelist(AuditMode::Approve, "exec", "rm -rf /", &p, &wl),
            AuditVerdict::NeedApproval { .. }
        ));
    }

    #[test]
    fn audit_enabled_compat_table() {
        for raw in ["1", "true", "yes", "on", " TRUE ", " On "] {
            let env = HashMap::from([("AUDIT_ENABLED".to_string(), raw.to_string())]);
            assert_eq!(audit_enabled_compat(&env), Some(AuditMode::Block), "{raw}");
        }
        for raw in ["0", "off", "bogus", "", "   ", "false", "no"] {
            let env = HashMap::from([("AUDIT_ENABLED".to_string(), raw.to_string())]);
            assert_eq!(audit_enabled_compat(&env), None, "{raw}");
        }
        for mode in ["off", "block", "approve"] {
            let env = HashMap::from([
                ("AUDIT_MODE".to_string(), mode.to_string()),
                ("AUDIT_ENABLED".to_string(), "1".to_string()),
            ]);
            assert_eq!(
                audit_enabled_compat(&env),
                None,
                "显式 AUDIT_MODE={mode} 优先"
            );
        }
        let blank_mode_env = HashMap::from([
            ("AUDIT_MODE".to_string(), "   ".to_string()),
            ("AUDIT_ENABLED".to_string(), "yes".to_string()),
        ]);
        assert_eq!(
            audit_enabled_compat(&blank_mode_env),
            Some(AuditMode::Block)
        );
        assert_eq!(audit_enabled_compat(&HashMap::new()), None);
    }

    #[test]
    fn audit_chain_scan_time_loose_upper_bound() {
        let policy = AuditPolicy::default_policy();
        let start = std::time::Instant::now();
        for i in 0..2000 {
            let v = evaluate_with_whitelist(
                AuditMode::Block,
                "exec",
                &format!("{{\"x\":{i}}}"),
                &policy,
                test_whitelist(),
            );
            std::hint::black_box(v);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(20),
            "审计链 2000 次评估须远低于宽松上界，实测 {:?}",
            start.elapsed()
        );
    }
}
