//! 审计性能上限锚（B2）：原 `audit_perf_test` 6 用例等价移植。
//!
//! 映射：
//! 1. `small_benign_allow_fast` ↔ 小体良性放行耗时
//! 2. `large_benign_1mb_bounded` ↔ 1MB 大体良性耗时上限
//! 3. `large_dangerous_tail_blocked` ↔ 大体尾部危险载荷仍拦截且有界
//! 4. `empty_body_allow` ↔ 空体边缘（判定正确）
//! 5. `near_8mb_ceiling_bounded` ↔ 8MB 上限附近体耗时上限
//! 6. `approve_dangerous_verdict_shape` ↔ 危险输入 verdict 形态正确
//!
//! 上界取宽松值（只防数量级退化，不卡精确墙钟，CI 慢机不红）。

use {
    std::time::{Duration, Instant},
    veil::{
        config::AuditMode,
        service::audit::{AuditPolicy, AuditVerdict, evaluate_with_whitelist},
    },
};

/// T2/D2：测试统一以非空白名单提供；空白名单降级语义由 verdict 单测锁定。
fn test_whitelist() -> &'static [String] {
    static TEST_WHITELIST: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    TEST_WHITELIST.get_or_init(|| vec!["@admin:example.com".to_string()])
}

fn policy() -> AuditPolicy { AuditPolicy::default_policy() }

fn assert_bounded(elapsed: Duration, bound: Duration, case: &str) {
    assert!(
        elapsed <= bound,
        "{case}: 耗时 {elapsed:?} 超出宽松上界 {bound:?}（数量级退化）"
    );
}

#[test]
fn small_benign_allow_fast() {
    let start = Instant::now();
    let verdict = evaluate_with_whitelist(
        AuditMode::Block,
        "exec",
        "echo hello",
        &policy(),
        test_whitelist(),
    );
    let elapsed = start.elapsed();
    assert_eq!(verdict, AuditVerdict::Allow);
    assert_bounded(elapsed, Duration::from_secs(1), "small_benign");
}

#[test]
fn large_benign_1mb_bounded() {
    let body = "echo ok\n".repeat(128 * 1024);
    assert!(body.len() >= 1024 * 1024, "实际 {}", body.len());
    let start = Instant::now();
    let verdict =
        evaluate_with_whitelist(AuditMode::Block, "exec", &body, &policy(), test_whitelist());
    let elapsed = start.elapsed();
    assert_eq!(verdict, AuditVerdict::Allow);
    assert_bounded(elapsed, Duration::from_secs(5), "large_benign_1mb");
}

#[test]
fn large_dangerous_tail_blocked() {
    let mut body = "echo ok\n".repeat(128 * 1024);
    body.push_str("; rm -rf /");
    let start = Instant::now();
    let verdict =
        evaluate_with_whitelist(AuditMode::Block, "exec", &body, &policy(), test_whitelist());
    let elapsed = start.elapsed();
    assert!(matches!(verdict, AuditVerdict::Block { .. }), "{verdict:?}");
    assert_bounded(elapsed, Duration::from_secs(5), "large_dangerous_tail");
}

#[test]
fn empty_body_allow() {
    let start = Instant::now();
    let verdict =
        evaluate_with_whitelist(AuditMode::Block, "exec", "", &policy(), test_whitelist());
    let elapsed = start.elapsed();
    assert_eq!(verdict, AuditVerdict::Allow);
    assert_bounded(elapsed, Duration::from_secs(1), "empty_body");
}

#[test]
fn near_8mb_ceiling_bounded() {
    // 8MB 上限附近体（8MiB - 1KiB），只锚数量级不卡墙钟。
    let body = "x".repeat(8 * 1024 * 1024 - 1024);
    let start = Instant::now();
    let verdict =
        evaluate_with_whitelist(AuditMode::Block, "exec", &body, &policy(), test_whitelist());
    let elapsed = start.elapsed();
    assert_eq!(verdict, AuditVerdict::Allow);
    assert_bounded(elapsed, Duration::from_secs(15), "near_8mb_ceiling");
}

#[test]
fn approve_dangerous_verdict_shape() {
    let start = Instant::now();
    let verdict = evaluate_with_whitelist(
        AuditMode::Approve,
        "exec",
        "rm -rf /",
        &policy(),
        test_whitelist(),
    );
    let elapsed = start.elapsed();
    match verdict {
        AuditVerdict::NeedApproval { reason, summary } => {
            assert!(!reason.is_empty());
            assert!(!summary.is_empty());
        }
        other => panic!("期望 NeedApproval，实际 {other:?}"),
    }
    assert_bounded(elapsed, Duration::from_secs(1), "approve_shape");
}
