#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../approval.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "approval.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "approval/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}

mod async202;
mod decision_cap;
mod f1;

use {
    super::*,
    crate::{
        approval::PendingRecord,
        service::{
            credential::{
                approve_hash_change,
                emergency_revoke,
                handle_credential,
                register_caller,
                revoke_caller,
                test_support::*,
            },
            matrix::MatrixBranch,
        },
    },
    axum::http::StatusCode,
};

#[tokio::test]
async fn enrolled_hash_tamper_turns_to_approval_202() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "goodhash", "test-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/a.sh", true)
        .unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.pending.len(), 1);
}

#[tokio::test]
async fn auto_approve_false_rejects_403() {
    let env = cred_env(&[("AUTO_APPROVE", "false")]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "goodhash", "test-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/a.sh", true)
        .unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("goodhash", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn auto_approve_none_turns_to_202() {
    let env = cred_env(&[("AUTO_APPROVE", "none")]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("fresh", "/s/fresh.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
}

#[tokio::test]
async fn credential_only_entry_approve_blocked_forbidden() {
    let env = cred_env(&[("VEIL_ENTRY_MODE", "credential-only")]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "h1", "test-src")
        .await
        .unwrap();
    let err = approve_hash_change(
        &state,
        "/s/a.sh",
        "h2",
        crate::registry::HashChangeOutcome::KeepAuto,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn emergency_revoke_exemptions_and_approval_flow() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "h1", "src-a")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/a.sh", true)
        .unwrap();
    let view = emergency_revoke(
        &state,
        "/s/a.sh",
        Some("observability-admin-token-0123456789"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(view.status, "❎");
    register_caller(&state, "/s/b.sh", "h2", "src-b")
        .await
        .unwrap();
    let err = emergency_revoke(&state, "/s/b.sh", None, Some("203.0.113.9"))
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
}

#[tokio::test]
async fn approval_ticket_uses_matrix_gateway_with_split_timeouts() {
    use std::time::Duration;
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let state = cred_state(&env);
    assert_eq!(state.approval.pending_len().await, 0);
    register_caller(&state, "/s/w.sh", "goodhash", "wire-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/w.sh", true)
        .unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/w.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.pending.len(), 1);
    assert_eq!(state.approval.pending_len().await, 1);
    assert_eq!(
        state.approval.credential_timeout(),
        Duration::from_secs(300)
    );
    assert_eq!(state.approval.audit_timeout(), Duration::from_secs(90));
    state.approval.submit("$wire-ev").await;
    state
        .approval
        .resolve("$wire-ev", "@admin:example.com", true)
        .await;
    let _ = state.approval.submit("$wire-ev2").await;
    assert_eq!(
        await_credential_approval(&state, "$wire-ev").await,
        Some(true)
    );
    assert_eq!(
        state
            .approval
            .ask("$wire-ev2", Duration::from_millis(50))
            .await,
        None
    );
    assert_eq!(state.approval.pending_len().await, 2);
}

#[tokio::test]
async fn audit_ask_uses_audit_timeout() {
    let mut env = cred_env(&[]);
    env.insert("AUDIT_TIMEOUT".to_string(), "1".to_string());
    let state = cred_state(&env);
    assert_eq!(
        state.approval.audit_timeout(),
        std::time::Duration::from_secs(1)
    );
    state.approval.submit("$audit-ev").await;
    assert_eq!(
        await_audit_approval(&state, "$audit-ev-missing").await,
        None
    );
    assert_eq!(state.approval.pending_len().await, 1);
}

#[tokio::test]
async fn hash_tamper_turns_to_approval_202_with_notify() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/tamper.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/tamper.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.pending.len(), 1);
}

#[tokio::test]
async fn old_hash_within_grace_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/grace.sh",
        "h1",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .approve_hash_change("/s/grace.sh", "h2")
        .unwrap();
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h1", "/s/grace.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
}

#[tokio::test]
async fn revoked_caller_hash_mismatch_still_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    register_caller(&state, "/s/r.sh", "goodhash", "rev-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/r.sh", true)
        .unwrap();
    revoke_caller(&state, "/s/r.sh").await.unwrap();
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/r.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert!(state.pending.is_empty());
}

#[tokio::test]
async fn blocking_mode_approval_returns_credential_for_same_request() {
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    register_caller(&state, "/s/b.sh", "goodhash", "blk-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/b.sh", true)
        .unwrap();
    let worker = state.clone();
    let handle = tokio::spawn(async move {
        handle_credential(
            &worker,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/b.sh", None),
        )
        .await
    });
    let event_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let ids = state.approval.pending_event_ids().await;
            if let Some(id) = ids.into_iter().next() {
                return id;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("阻塞模须先建单");
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("阻塞问询须在批准后返回")
        .expect("任务不崩")
        .expect("批准后同请求须返回凭据");
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
}

#[tokio::test]
async fn blocked_timeout_403() {
    // 11.2/G11：`CREDENTIAL_BLOCK_WAIT=1` 阻塞超时按拒绝返回 403（非 Python 408），
    // 且请求不悬挂（外部 10s 守护；配置超时收紧至 1s 以快速验证）。断言可观察状态码与清票副作用。
    use {
        crate::{
            config::Config,
            state::{AppState, SqliteOutcome},
        },
        std::{path::PathBuf, sync::Arc},
    };
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let mut config = Config::load_from(&env).unwrap();
    config.credential_approval_timeout_secs = 1;
    let state = inject_sink(
        AppState::new(
            config,
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked())),
        InjectSink::success(),
    );
    register_caller(&state, "/s/blocked.sh", "goodhash", "blk-to-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/blocked.sh", true)
        .unwrap();
    let worker = state.clone();
    let handle = tokio::spawn(async move {
        handle_credential(
            &worker,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/blocked.sh", None),
        )
        .await
    });
    // 刻意不 resolve：1s 后阻塞问询超时，须按拒绝返回 403。
    let err = tokio::time::timeout(std::time::Duration::from_secs(10), handle)
        .await
        .expect("阻塞超时须在配置超时后返回，不得悬挂")
        .expect("任务不崩")
        .expect_err("超时须按拒绝返回错误");
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        VeilError::Auth { message } => assert!(message.contains("超时"), "{message}"),
        other => panic!("阻塞超时须为 Auth/403，得 {other:?}"),
    }
    assert_eq!(state.pending.len(), 0, "超时后内存侧即时清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "超时后矩阵侧即时清零"
    );
}

async fn wait_event_id(state: &impl AppStateParts) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(id) = state
                .approval()
                .pending_event_ids()
                .await
                .into_iter()
                .next()
            {
                return id;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("审批须先建单")
}

#[tokio::test]
async fn pending_tables_atomic_cleanup() {
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    for (path, hash) in [("/s/atomic-a.sh", "ha"), ("/s/atomic-b.sh", "hb")] {
        register_caller(&state, path, hash, &format!("atomic-src-{path}"))
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled(path, true)
            .unwrap();
    }

    let worker = state.clone();
    let handle = tokio::spawn(async move {
        handle_credential(
            &worker,
            &headers("gethash", Some("s3cr3t")),
            &body("bad-a", "/s/atomic-a.sh", None),
        )
        .await
    });
    let event_id = wait_event_id(&state).await;
    assert_eq!(state.pending.len(), 1, "建单后内存侧应有 1 票");
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    let out = handle.await.unwrap().unwrap();
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
    assert_eq!(state.pending.len(), 0, "批准后内存侧即时清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "批准后矩阵侧即时清零"
    );

    let worker = state.clone();
    let handle = tokio::spawn(async move {
        handle_credential(
            &worker,
            &headers("gethash", Some("s3cr3t")),
            &body("bad-b", "/s/atomic-b.sh", None),
        )
        .await
    });
    let event_id = wait_event_id(&state).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", false)
        .await;
    let err = handle.await.unwrap().unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0, "拒绝后内存侧即时清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "拒绝后矩阵侧即时清零"
    );

    state
        .pending
        .insert(PendingRecord::new("/s/timeout.sh:h", "hash_mismatch"));
    state
        .approval
        .submit_branch("$timeout-ev", MatrixBranch::Credential)
        .await;
    let err = settle_approval(
        &state,
        "/s/timeout.sh:h",
        "$timeout-ev",
        None,
        "网易",
        Some("授权码"),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0, "超时后内存侧即时清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "超时后矩阵侧即时清零"
    );
}

#[tokio::test]
async fn approval_message_context() {
    let state = cred_state(&cred_env(&[]));
    let bot = matrix::MatrixBot::with_client(
        state.config().homeserver.clone(),
        state.config().room_id.clone(),
        state.config().matrix_access_token.clone(),
        state.http_client().as_ref().clone(),
    );
    let summary = approval_summary("hash_mismatch", "/s/job.sh:abc123", "网易", Some("授权码"));
    let text = bot.format_approval(MatrixBranch::Credential, None, &summary);
    assert!(text.contains("hash_mismatch"), "{text}");
    assert!(text.contains("/s/job.sh"), "{text}");
    assert!(text.contains("网易"), "{text}");
    assert!(text.contains("授权码"), "{text}");
    assert!(
        !text.contains("s3cr3t"),
        "部署 Secret 不得出现在消息: {text}"
    );

    let no_field = approval_summary("auto_approve_none", "/s/job.sh:abc", "网易", None);
    assert!(no_field.contains("网易"), "{no_field}");
    assert!(!no_field.contains("授权码"), "{no_field}");
    let blank_field = approval_summary("auto_approve_none", "/s/job.sh:abc", "网易", Some(""));
    assert_eq!(blank_field, no_field, "空字段应省略为条目形态");
    let no_entry = approval_summary("emergency_revoke转常规审批", "/s/job.sh", "", None);
    assert_eq!(no_entry, "emergency_revoke转常规审批 :: /s/job.sh");
}

#[tokio::test]
async fn unlock_timeout_single_ask() {
    // 5.1/G5：超时按拒绝（Auth）；并发同键仅一次问询且结果复用。
    use std::time::Duration;
    let state = cred_state(&cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]));
    let err = settle_approval(
        &state,
        "/s/unlock-to:h",
        "$unlock-to",
        None,
        "网易",
        Some("授权码"),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        VeilError::Auth { message } => assert!(message.contains("超时"), "{message}"),
        other => panic!("超时须鉴权拒绝，实得: {other:?}"),
    }
    assert!(
        state
            .approval
            .submit_branch("$unlock-one", MatrixBranch::Credential)
            .await
    );
    assert!(
        !state
            .approval
            .submit_branch("$unlock-one", MatrixBranch::Credential)
            .await,
        "并发二次登记不得再问询"
    );
    assert_eq!(state.approval.pending_len().await, 1, "并发须恰一问询");
    state
        .approval
        .resolve("$unlock-one", "@admin:example.com", true)
        .await;
    let (a, b) = tokio::join!(
        state.approval.ask("$unlock-one", Duration::from_secs(1)),
        state.approval.ask("$unlock-one", Duration::from_secs(1))
    );
    assert_eq!((a, b), (Some(true), Some(true)), "并发问询须复用同一结果");
}

#[tokio::test]
async fn raw_context_and_tracked_send_failure() {
    // 5.2/G5 + F1：终端直调 raw 拒绝；脚本上下文 raw 放行原文；tracked 发送失败 fail-closed。
    let state = cred_state(&cred_env(&[]));
    let mut direct = body("gethash", "/s/raw-direct.sh", None);
    direct.token = Some(false);
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &direct)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        VeilError::Auth { message } => {
            assert!(message.contains("终端直接调用"), "{message}");
        }
        other => panic!("终端直调 raw 须鉴权拒绝，实得: {other:?}"),
    }
    let state = cred_state(&cred_env(&[]));
    enroll_allow(&state, "/s/raw-script.sh", "raw-script-h").await;
    let mut script = body("raw-script-h", "/s/raw-script.sh", None);
    script.token = Some(false);
    let out = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &script)
        .await
        .unwrap();
    assert_eq!(
        credential_value(&out),
        "__MOCK_CRED_网易-授权码__",
        "脚本上下文 raw 须返回原文"
    );
    let state = cred_state_with_sink(
        &cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]),
        InjectSink::failing(),
    );
    let err = submit_pending(
        &state,
        "/s/ask-fail.sh:h",
        "hash_mismatch",
        "网易",
        Some("授权码"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(
        state.pending.len(),
        0,
        "发送失败须 fail-closed 不建内存侧票"
    );
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "发送失败须 fail-closed 不建矩阵侧票"
    );
}

#[tokio::test]
async fn pending_both_tables_cleanup() {
    // 5.3/G5：拒绝/超时/ask 失败三终态后内存侧与矩阵侧 pending 两表清理一致。
    let state = cred_state(&cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]));
    let cases = [
        ("/s/c-rej.sh:h", "$c-rej", Some(false)),
        ("/s/c-to.sh:h", "$c-to", None),
        ("/s/c-fail.sh:h", "$c-fail", None),
    ];
    for (key, event_id, decision) in cases {
        state
            .pending
            .insert(PendingRecord::new(key, "hash_mismatch"));
        state
            .approval
            .submit_branch(event_id, MatrixBranch::Credential)
            .await;
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.approval.pending_len().await, 1);
        let err = settle_approval(
            &state,
            key,
            event_id,
            decision,
            "网易",
            Some("授权码"),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(
            state.pending.len(),
            state.approval.pending_len().await,
            "两表计数须一致"
        );
        assert_eq!(state.pending.len(), 0, "终态后两表须即时清零");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emergency_revoke_auto_reaction_rejected() {
    // T1/D1：紧急吊销转常规审批的 `🔓` 不得执行吊销——重试 403、条目原状。
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let key = "/s/em-auto.sh";
    register_caller(&state, key, "em-auto-h", "em-auto-src")
        .await
        .unwrap();
    state.registry.write().await.set_enabled(key, true).unwrap();
    let err = emergency_revoke(&state, key, None, Some("203.0.113.9"))
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;
    let input = crate::service::matrix::ReactionInput {
        target_event_id: event_id,
        key: "🔓".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    let outcome = state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    assert!(
        matches!(
            outcome,
            crate::service::matrix::ReactionOutcome::Applied {
                approved: true,
                auto: true
            }
        ),
        "🔓 须按自动放行落定: {outcome:?}"
    );
    let pending_key = format!("revoke:{key}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while credential_decision_slot(&state, &pending_key) != Some(DecisionSlot::Denied) {
        assert!(
            std::time::Instant::now() < deadline,
            "🔓 落定后决策表须为拒绝，实得 {:?}",
            credential_decision_slot(&state, &pending_key)
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let denied = emergency_revoke(&state, key, None, Some("203.0.113.9"))
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), StatusCode::FORBIDDEN);
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path(key).unwrap();
    assert!(entry.enabled && !entry.revoked, "🔓 不得吊销，条目须原状");
}

#[tokio::test]
async fn pending_count_zeroes_on_terminal_state() {
    // AUTH-9 回归：终态清理同批清内存/矩阵票，health.pending 即时归零。
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    state
        .pending
        .insert(PendingRecord::new("/s/zero:h", "hash_mismatch"));
    assert_eq!(crate::service::credential::health_status(&state).pending, 1);
    clear_terminal_pending(&state, "/s/zero:h", "$evt-zero").await;
    assert_eq!(
        crate::service::credential::health_status(&state).pending,
        0,
        "终态须即时归零 health.pending"
    );
}
