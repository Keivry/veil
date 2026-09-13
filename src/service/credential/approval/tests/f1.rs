use {
    crate::{
        registry::RegisterParams,
        service::{
            credential::{
                approval::{submit_pending, submit_pending_with_branch},
                handle_credential,
                register_caller,
                register_caller_with_approval,
                revoke_caller_with_approval,
                test_support::*,
            },
            matrix::{MatrixBranch, ReactionInput, ReactionOutcome, ResolveOutcome},
        },
    },
    axum::http::StatusCode,
};

#[tokio::test]
async fn approval_send_failure_fail_closed() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    // 凭据路径：tracked 发送失败须 403 且不建单。
    let state = cred_state_with_sink(&env, InjectSink::failing());
    enrolled_with_entries(
        &state,
        "/s/down.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/down.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0, "发送失败不得建内存侧票");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "发送失败不得建矩阵侧票"
    );

    // 注册路径
    let state = cred_state_with_sink(&env, InjectSink::failing());
    let params = RegisterParams {
        caller_path: "/s/reg-fail.sh".to_string(),
        caller_hash: "h-reg-fail".to_string(),
        name: "reg-fail".to_string(),
        description: String::new(),
        entries: TestMap::new(),
        allow_mode: None,
    };
    let err = register_caller_with_approval(&state, &params, "fail-src")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0);
    assert_eq!(state.approval.pending_len().await, 0);

    // 吊销路径
    let state = cred_state_with_sink(&env, InjectSink::failing());
    register_caller(&state, "/s/rev-fail.sh", "h-rev", "fail-src")
        .await
        .unwrap();
    let err = revoke_caller_with_approval(&state, "/s/rev-fail.sh")
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0);
    assert_eq!(state.approval.pending_len().await, 0);
}

#[tokio::test]
async fn approval_pending_uses_real_event_id() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    let event_id = submit_pending(
        &state,
        "/s/real.sh:h",
        "hash_mismatch",
        "网易",
        Some("授权码"),
    )
    .await
    .unwrap();
    assert!(
        event_id.starts_with("$test-event-"),
        "pending 键须为注入 sink 的真实 id，实得 {event_id}"
    );
    assert_eq!(state.pending.len(), 1);
    assert_eq!(
        state.approval.pending_event_ids().await,
        vec![event_id.clone()],
        "矩阵侧 pending 键须等于真实 id"
    );
    assert_eq!(
        state
            .approval
            .resolve(&event_id, "@admin:example.com", true)
            .await,
        ResolveOutcome::Applied(true)
    );
}

#[tokio::test]
async fn audit_branch_pending_uses_real_event_id() {
    // R3：本测试覆盖「通用 `MatrixBranch::Audit` 经 tracked 发送取真实 id 建单」的能力，
    // 非生产 `audit-hold` 路径——生产 audit-hold（`src/handler/llm/pump/spawn.rs`）仅写内存
    // `audit_pending`，不建 Matrix 审批票（README §6.4，spec「审批建单路径白名单」）。
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    let event_id = submit_pending_with_branch(
        &state,
        "audit-hold-0-shell",
        "audit-hold: rm -rf /",
        MatrixBranch::Audit,
        "",
        None,
    )
    .await
    .unwrap();
    assert!(
        event_id.starts_with("$test-event-"),
        "Audit 分支建单须用真实 id，实得 {event_id}"
    );
    assert_eq!(
        state.approval.pending_event_ids().await,
        vec![event_id.clone()]
    );
    let reaction = ReactionInput {
        target_event_id: event_id,
        key: "✅".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        state
            .approval
            .on_reaction(&reaction, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: false
        }
    );
}

#[tokio::test]
async fn approval_reaction_three_state_and_timeout() {
    use std::time::Duration;
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    let approve_id = submit_pending_with_branch(
        &state,
        "/s/a.sh:h",
        "hash_mismatch",
        MatrixBranch::Credential,
        "网易",
        Some("授权码"),
    )
    .await
    .unwrap();
    let reject_id = submit_pending_with_branch(
        &state,
        "/s/b.sh:h",
        "hash_mismatch",
        MatrixBranch::Credential,
        "网易",
        Some("授权码"),
    )
    .await
    .unwrap();
    let auto_id = submit_pending_with_branch(
        &state,
        "/s/c.sh",
        "register审批",
        MatrixBranch::Register,
        "",
        None,
    )
    .await
    .unwrap();
    for id in [&approve_id, &reject_id, &auto_id] {
        assert!(id.starts_with("$test-event-"), "三态均以真实 id 为键");
    }
    let reaction = |id: &str, key: &str| ReactionInput {
        target_event_id: id.to_string(),
        key: key.to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        state
            .approval
            .on_reaction(
                &reaction(&approve_id, "✅"),
                "@bot:example.com",
                "!r:example.com",
                1000
            )
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: false
        }
    );
    assert_eq!(
        state
            .approval
            .on_reaction(
                &reaction(&reject_id, "❎"),
                "@bot:example.com",
                "!r:example.com",
                1000
            )
            .await,
        ReactionOutcome::Applied {
            approved: false,
            auto: false
        }
    );
    assert_eq!(
        state
            .approval
            .on_reaction(
                &reaction(&auto_id, "🔓"),
                "@bot:example.com",
                "!r:example.com",
                1000
            )
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: true
        }
    );
    let timeout_id = submit_pending_with_branch(
        &state,
        "/s/d.sh:h",
        "hash_mismatch",
        MatrixBranch::Credential,
        "网易",
        Some("授权码"),
    )
    .await
    .unwrap();
    assert_eq!(
        state
            .approval
            .ask(&timeout_id, Duration::from_millis(80))
            .await,
        None,
        "无回复须超时按拒绝"
    );
    assert_eq!(
        state
            .approval
            .on_reaction(
                &reaction("$unknown-real", "✅"),
                "@bot:example.com",
                "!r:example.com",
                1000
            )
            .await,
        ReactionOutcome::Ignored("event id 无精确匹配"),
        "未知 id 不得落定"
    );
}
