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
            matrix::{
                CallerIdentity,
                MatrixBranch,
                ReactionInput,
                ReactionOutcome,
                ResolveOutcome,
                TicketContext,
            },
        },
    },
    axum::http::StatusCode,
};

fn ticket<'a>(branch: MatrixBranch, reason: &'a str, path: &'a str) -> TicketContext<'a> {
    TicketContext {
        branch,
        subject: "网易",
        caller: CallerIdentity {
            path,
            name: None,
            desc: None,
            enrolled: false,
        },
        reason,
        facts: &[],
    }
}

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
        authorization_ttl: crate::registry::AuthorizationTtl::Absent,
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
        &ticket(MatrixBranch::Credential, "hash_mismatch", "/s/real.sh"),
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
async fn audit_and_hash_labels_never_create_tickets() {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    for (key, reason, branch) in [
        (
            "audit-hold-0-shell",
            "audit-hold: rm -rf /",
            MatrixBranch::Audit,
        ),
        (
            "hash-change-0-shell",
            "hash-change",
            MatrixBranch::HashChange,
        ),
    ] {
        let err = submit_pending_with_branch(&state, key, &ticket(branch, reason, "/s/label.sh"))
            .await
            .expect_err("分类标签不得建票");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert!(
            state.approval.pending_event_ids().await.is_empty(),
            "{branch:?} 不得产生 Matrix 票"
        );
        let err = submit_pending(&state, key, &ticket(branch, reason, "/s/label.sh"))
            .await
            .expect_err("原因串分类得到的标签不得建票");
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert!(state.approval.pending_event_ids().await.is_empty());
    }
}

#[tokio::test]
async fn approval_reaction_three_state_and_timeout() {
    use std::time::Duration;
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    let approve_id = submit_pending_with_branch(
        &state,
        "/s/a.sh:h",
        &ticket(MatrixBranch::Credential, "hash_mismatch", "/s/a.sh"),
    )
    .await
    .unwrap();
    let reject_id = submit_pending_with_branch(
        &state,
        "/s/b.sh:h",
        &ticket(MatrixBranch::Credential, "hash_mismatch", "/s/b.sh"),
    )
    .await
    .unwrap();
    let auto_id = submit_pending_with_branch(
        &state,
        "/s/c.sh",
        &ticket(MatrixBranch::Register, "register", "/s/c.sh"),
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
            always: false
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
            always: false
        }
    );
    assert_eq!(
        state
            .approval
            .on_reaction(
                &reaction(&auto_id, "♾️"),
                "@bot:example.com",
                "!r:example.com",
                1000
            )
            .await,
        ReactionOutcome::Applied {
            approved: true,
            always: true
        }
    );
    let timeout_id = submit_pending_with_branch(
        &state,
        "/s/d.sh:h",
        &ticket(MatrixBranch::Credential, "hash_mismatch", "/s/d.sh"),
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
        ReactionOutcome::Silent("event id 无精确匹配"),
        "未知 id 不得落定"
    );
}
