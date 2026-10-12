//! `matrix::branch` 单测（自 `branch.rs` 外迁；测试名与断言不变）。

use super::*;

#[test]
fn whitelist_exact_match_rejects_forged_members() {
    let wl = vec!["@admin:example.com".to_string()];
    assert!(is_mxid_allowed("@admin:example.com", &wl));
    assert!(!is_mxid_allowed("@ghost:example.com", &wl));
    assert!(!is_mxid_allowed("@admin:example.com.evil.com", &wl));
    assert!(!is_mxid_allowed("evil-@admin:example.comX", &wl));
    assert!(!is_mxid_allowed("@ADMIN:example.com", &wl));
    assert!(!is_mxid_allowed("@admin:example.com ", &wl));
}

#[test]
fn is_mxid_allowed_empty_whitelist_no_filter() {
    // 空白名单＝不过滤；非空名单成员放行、非成员拒绝。
    assert!(
        is_mxid_allowed("@anyone:example.com", &[]),
        "空白名单不过滤"
    );
    let wl = vec!["@admin:example.com".to_string()];
    assert!(is_mxid_allowed("@admin:example.com", &wl));
    assert!(!is_mxid_allowed("@ghost:example.com", &wl));
}

#[test]
fn invalid_whitelist_member_rejected_at_startup() {
    assert!(validate_whitelist_mxids(&["@admin:example.com".to_string()]).is_ok());
    assert!(validate_whitelist_mxids(&["@keivry@matrix.example".to_string()]).is_err());
    assert!(validate_whitelist_mxids(&["admin:example.com".to_string()]).is_err());
    assert!(validate_whitelist_mxids(&["@a: b".to_string()]).is_err());
}

#[test]
fn is_valid_mxid_equivalence() {
    // 合并为单一实现后判定须与合并前两份副本逐例等价。
    let cases = [
        ("@admin:example.com", true),
        ("@keivry:matrix.example.org", true),
        ("@a.b-c_d:x.y", true),
        ("@a@b:c", false),
        ("@keivry@matrix.example", false),
        ("admin:example.com", false),
        ("@a:", false),
        ("@:b", false),
        ("@a b:c", false),
        ("@a:b:c", false),
        ("", false),
        ("@", false),
    ];
    for (s, expected) in cases {
        assert_eq!(is_valid_mxid(s), expected, "单一实现判定漂移: {s:?}");
        assert_eq!(
            validate_whitelist_mxids(&[s.to_string()]).is_ok(),
            expected,
            "Matrix 门禁复用同一实现: {s:?}"
        );
    }
}

#[test]
fn backoff_grows_exponentially_capped_at_60s() {
    assert_eq!(sync_backoff_secs(0), 1);
    assert_eq!(sync_backoff_secs(1), 2);
    assert_eq!(sync_backoff_secs(5), 32);
    assert_eq!(sync_backoff_secs(6), 60);
    assert_eq!(sync_backoff_secs(100), 60);
}

#[test]
fn sync_request_timeout_outlives_long_poll_window() {
    // 客户端总超时须严格大于服务端长轮询窗口（服务端窗口到点后还要叠加 RTT 才返回）；
    // 两者相等即空闲窗口恒被客户端先截断，落成假失败 + 退避噪声。
    let t = sync_request_timeout();
    assert_eq!(
        t,
        std::time::Duration::from_millis(SYNC_TIMEOUT_MS + SYNC_TIMEOUT_MARGIN_MS)
    );
    assert!(
        t > std::time::Duration::from_millis(SYNC_TIMEOUT_MS),
        "sync per-request 超时须严格大于长轮询窗口"
    );
}

#[test]
fn sync_token_persist_roundtrip() {
    let dir = std::env::temp_dir().join(format!(
        "veil-sync-token-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let path = dir.join("sync_token");
    assert_eq!(load_since_token(&path), None);
    assert!(save_since_token(&path, "s123_456"));
    assert_eq!(load_since_token(&path).as_deref(), Some("s123_456"));
    assert!(save_since_token(&path, "s789_000"));
    assert_eq!(load_since_token(&path).as_deref(), Some("s789_000"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unknown_emoji_and_branch_map_to_noop() {
    assert_eq!(reaction_to_decision(MatrixBranch::Credential, "👍"), None);
    assert_eq!(reaction_to_decision(MatrixBranch::Unknown, "✅"), None);
    assert_eq!(reaction_to_decision(MatrixBranch::Credential, "🔓"), None);
    assert_eq!(
        reaction_to_decision(MatrixBranch::Register, "🔓"),
        Some((true, true))
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Audit, "✅"),
        Some((true, false))
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Audit, "❎"),
        Some((false, false))
    );
}

#[test]
fn text_commands_parse_three_instructions() {
    assert_eq!(parse_text_command("lock proxy"), TextCommand::Lock);
    assert_eq!(parse_text_command("  LOCK  "), TextCommand::Lock);
    assert_eq!(parse_text_command("status"), TextCommand::Status);
    assert_eq!(parse_text_command("forget secrets"), TextCommand::Forget);
    assert_eq!(parse_text_command("hello"), TextCommand::Unknown);
}

#[test]
fn five_branches_map_and_identify() {
    assert_eq!(MatrixBranch::from_reason("unlock"), MatrixBranch::Unlock);
    assert_eq!(
        MatrixBranch::from_reason("注册审批"),
        MatrixBranch::Register
    );
    // 常规吊销复用 `Register` 分支的三态映射（`from_reason` 须识别）。
    assert_eq!(
        MatrixBranch::from_reason("revoke审批"),
        MatrixBranch::Register
    );
    assert_eq!(
        MatrixBranch::from_reason("吊销审批"),
        MatrixBranch::Register
    );
    assert_eq!(
        MatrixBranch::from_reason("hash-change"),
        MatrixBranch::HashChange
    );
    assert_eq!(
        MatrixBranch::from_reason("凭据下发"),
        MatrixBranch::Credential
    );
    assert_eq!(MatrixBranch::from_reason("audit-hold"), MatrixBranch::Audit);
    assert_eq!(MatrixBranch::from_reason("加急转交"), MatrixBranch::Unknown);
    assert!(!MatrixBranch::Unknown.is_known());
    assert_eq!(MatrixBranch::Audit.status_emoji_approved(), "✅");
    assert_eq!(MatrixBranch::Audit.status_emoji_rejected(), "❎");
    assert_eq!(MatrixBranch::Audit.status_emoji_pending(), "🔓");
}
