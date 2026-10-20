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
fn reaction_actions_are_global_and_fe0f_insensitive() {
    use ReactionAction::{Approve, ApproveAlways, NotAccepted, NotAnOrderBranch, Reject};
    assert_eq!(
        reaction_to_decision(MatrixBranch::Register, "♾"),
        ApproveAlways
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Register, "♾️"),
        ApproveAlways
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Command, "♾️"),
        ApproveAlways
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Revoke, "♾️"),
        NotAccepted
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Credential, "♾️"),
        NotAccepted
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Audit, "♾️"),
        NotAnOrderBranch
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::HashChange, "✅"),
        NotAnOrderBranch
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Register, "🔓"),
        NotAccepted
    );
    assert_eq!(reaction_to_decision(MatrixBranch::Register, "✅"), Approve);
    assert_eq!(reaction_to_decision(MatrixBranch::Revoke, "❎"), Reject);
    assert!(is_known_reaction("♾"));
    assert!(is_known_reaction("♾️"));
    assert!(!is_known_reaction("🔓"));
    assert!(!is_known_reaction("👍"));
}

#[test]
fn presets_and_pending_status_decoupled_from_reactions() {
    assert_eq!(
        MatrixBranch::Register.reaction_presets(),
        &[REACTION_APPROVE, REACTION_APPROVE_ALWAYS, REACTION_REJECT]
    );
    assert_eq!(
        MatrixBranch::Revoke.reaction_presets(),
        &[REACTION_APPROVE, REACTION_REJECT]
    );
    assert_eq!(
        MatrixBranch::Credential.reaction_presets(),
        &[REACTION_APPROVE, REACTION_REJECT]
    );
    assert!(
        MatrixBranch::HashChange.reaction_presets().is_empty(),
        "HashChange 仅为分类标签，不得预置 reaction"
    );
    assert!(
        MatrixBranch::Audit.reaction_presets().is_empty(),
        "Audit 仅为分类标签，不得预置 reaction"
    );
    for branch in [
        MatrixBranch::Register,
        MatrixBranch::Revoke,
        MatrixBranch::Credential,
        MatrixBranch::Audit,
    ] {
        assert_eq!(branch.status_emoji_pending(), "⏳");
    }
}

#[test]
fn from_reason_routes_revoke_and_rejects_unlock() {
    assert!(MatrixBranch::from_reason("unlock credential").is_err());
    assert!(MatrixBranch::from_reason("解锁凭据").is_err());
    assert_eq!(
        MatrixBranch::from_reason("revoke caller").unwrap(),
        MatrixBranch::Revoke
    );
    assert_eq!(
        MatrixBranch::from_reason("吊销 x").unwrap(),
        MatrixBranch::Revoke
    );
    assert_eq!(
        MatrixBranch::from_reason("注册审批").unwrap(),
        MatrixBranch::Register
    );
    assert_eq!(
        MatrixBranch::from_reason("hash-change").unwrap(),
        MatrixBranch::HashChange
    );
    assert_eq!(
        MatrixBranch::from_reason("hash_mismatch").unwrap(),
        MatrixBranch::Credential,
        "凭据取用的 hash_mismatch 原因串不得被分类为 HashChange 建单标签"
    );
    assert_eq!(
        MatrixBranch::from_reason("凭据下发").unwrap(),
        MatrixBranch::Credential
    );
    assert_eq!(
        MatrixBranch::from_reason("command_invoke").unwrap(),
        MatrixBranch::Command
    );
    assert_eq!(
        MatrixBranch::from_reason("audit-hold").unwrap(),
        MatrixBranch::Audit
    );
    assert_eq!(
        MatrixBranch::from_reason("加急转交").unwrap(),
        MatrixBranch::Unknown
    );
    assert!(!MatrixBranch::Unknown.is_known());
    assert!(!MatrixBranch::HashChange.is_matrix_order_branch());
    assert!(!MatrixBranch::Audit.is_matrix_order_branch());
    assert!(MatrixBranch::Revoke.is_matrix_order_branch());
    assert_eq!(MatrixBranch::Audit.status_emoji_approved(), "✅");
    assert_eq!(MatrixBranch::Audit.status_emoji_rejected(), "❎");
}

#[test]
fn from_reason_prioritizes_hash_mismatch_over_register() {
    assert_eq!(
        MatrixBranch::from_reason("hash_mismatch :: /s/register-foo.sh").unwrap(),
        MatrixBranch::Credential,
        "含 register 字样的凭据类原因串须先命中 hash_mismatch"
    );
    assert_eq!(
        MatrixBranch::from_reason("hash mismatch register").unwrap(),
        MatrixBranch::Credential,
        "hash mismatch 变体同样优先于 register"
    );
    assert_eq!(
        MatrixBranch::from_reason("register caller").unwrap(),
        MatrixBranch::Register
    );
    assert!(MatrixBranch::from_reason("unlock credential").is_err());
    assert!(MatrixBranch::from_reason("解锁 凭据").is_err());
    assert_eq!(
        MatrixBranch::from_reason("revoke caller").unwrap(),
        MatrixBranch::Revoke
    );
    assert_eq!(
        MatrixBranch::from_reason("吊销 x").unwrap(),
        MatrixBranch::Revoke
    );
}

#[test]
fn command_branch_three_state_reactions() {
    assert_eq!(
        reaction_to_decision(MatrixBranch::Command, REACTION_APPROVE),
        ReactionAction::Approve,
        "✅ 批准一次"
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Command, REACTION_REJECT),
        ReactionAction::Reject,
        "❎ 拒绝"
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Command, REACTION_APPROVE_ALWAYS),
        ReactionAction::ApproveAlways,
        "♾️ 批准并持久化 accept-always"
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
