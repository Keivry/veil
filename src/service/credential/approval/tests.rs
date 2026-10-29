#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("approval.rs", include_str!("../approval.rs"));
    crate::test_support::file_len_under_800_or_split("approval/tests.rs", include_str!("tests.rs"));
}

mod async202;
mod decision_cap;
mod event_id_binding;
mod grace;
mod preseed;
mod ticket_copy;

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

/// 测试 sink：仅统计 tracked 发送次数，其余无副作用。
#[derive(Debug, Default)]
struct TrackedCountingSink {
    tracked: std::sync::atomic::AtomicUsize,
}

impl TrackedCountingSink {
    fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(Self::default()) }

    fn tracked(&self) -> usize { self.tracked.load(std::sync::atomic::Ordering::SeqCst) }
}

impl crate::service::matrix::NotificationSink for TrackedCountingSink {
    fn send_text(
        &self,
        _text: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn send_text_tracked(
        &self,
        _text: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + '_>> {
        self.tracked
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async { Some("$should-not-send".to_string()) })
    }
}

/// Matrix 关闭（三要素缺失）时审批 fail-closed：指名缺失键、不触 tracked 发送、不建票。
#[tokio::test]
async fn matrix_disabled_approval_fails_closed_before_tracked_send() {
    let mut env = cred_env(&[]);
    env.remove("HOMESERVER");
    env.remove("ROOM_ID");
    env.remove("MATRIX_ACCESS_TOKEN");
    let sink = TrackedCountingSink::new();
    let state = cred_state_with_sink(&env, sink.clone());
    assert!(!state.config().matrix_enabled(), "三要素缺失须关闭 Matrix");

    let err = submit_pending(
        &state,
        "/s/no-matrix.sh:h",
        &matrix::TicketContext {
            branch: MatrixBranch::Credential,
            subject: "网易 / 授权码",
            caller: matrix::CallerIdentity {
                path: "/s/no-matrix.sh",
                name: None,
                desc: None,
                enrolled: false,
            },
            reason: "hash_mismatch",
            facts: &[],
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        VeilError::Auth { message } => {
            assert!(message.contains("Matrix 未配置（缺"), "{message}");
            assert!(message.contains("审批功能已关闭，按拒绝处理"), "{message}");
            for key in ["HOMESERVER", "ROOM_ID", "MATRIX_ACCESS_TOKEN"] {
                assert!(message.contains(key), "须指名缺失键 {key}: {message}");
            }
        }
        other => panic!("须鉴权拒绝，实得: {other:?}"),
    }
    assert_eq!(sink.tracked(), 0, "Matrix 关闭时不得尝试 tracked 发送");
    assert_eq!(state.pending.len(), 0, "不得建内存侧票");
    assert_eq!(state.approval.pending_len().await, 0, "不得建矩阵侧票");
}

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
async fn full_entry_approve_allowed() {
    // full 入口下 approve 不被入口模式阻断。
    let env = cred_env(&[("VEIL_ENTRY_MODE", "full")]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "h1", "test-src")
        .await
        .unwrap();
    let view = approve_hash_change(
        &state,
        "/s/a.sh",
        "h2",
        crate::registry::HashChangeOutcome::ApproveAlways,
    )
    .await
    .expect("full 下 approve 不得被入口模式阻断");
    assert_eq!(
        view.status, "⏳",
        "须进入待审批流转（与 full 同效），而非被入口模式拒绝"
    );
}

#[tokio::test]
async fn llm_only_entry_approve_blocked_forbidden() {
    // llm_only 凭据面整体不可用，approve 仍须阻断。
    let env = cred_env(&[("VEIL_ENTRY_MODE", "llm_only")]);
    let state = cred_state(&env);
    register_caller(&state, "/s/a.sh", "h1", "test-src")
        .await
        .unwrap();
    let err = approve_hash_change(
        &state,
        "/s/a.sh",
        "h2",
        crate::registry::HashChangeOutcome::ApproveAlways,
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
    )
    .await
    .unwrap();
    assert_eq!(view.status, "❎");
    register_caller(&state, "/s/b.sh", "h2", "src-b")
        .await
        .unwrap();
    let err = emergency_revoke(&state, "/s/b.sh", None).await.unwrap_err();
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
    env.insert("AUDIT_TIMEOUT_SECS".to_string(), "1".to_string());
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
        .approve_hash_change_with_script_sha256(
            "/s/grace.sh",
            "h2",
            "sha-h2".to_string(),
            crate::registry::HashChangeOutcome::ApproveAlways,
        )
        .unwrap();
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h1", "/s/grace.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
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
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn blocked_timeout_403() {
    // `CREDENTIAL_BLOCK_WAIT=1` 阻塞超时按拒绝返回 403，
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
    assert!(credential_value(&out).starts_with("__CRED_"));
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
        &CredentialApproval::new(
            "/s/timeout.sh:h",
            "/s/timeout.sh",
            "hash_mismatch",
            "网易",
            Some("授权码"),
            false,
        ),
        "$timeout-ev",
        None,
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
    let facts = hash_change_fact("sha256:50f7f169d22f9acad", "sha256:d58c1f7a00112233");
    let ctx = matrix::TicketContext {
        branch: MatrixBranch::Credential,
        subject: &credential_subject("网易", Some("授权码")),
        caller: matrix::CallerIdentity {
            path: "/s/job.sh",
            name: Some("构建脚本"),
            desc: None,
            enrolled: true,
        },
        reason: "hash_mismatch",
        facts: &facts,
    };
    let text = bot.format_notice(&ctx, None);
    assert!(text.contains("脚本哈希已变更"), "{text}");
    assert!(!text.contains("hash_mismatch"), "{text}");
    assert!(text.contains("/s/job.sh"), "{text}");
    assert!(text.contains("构建脚本"), "{text}");
    assert!(text.contains("网易 / 授权码"), "{text}");
    assert!(text.contains("50f7f169 → d58c1f7a"), "{text}");
    assert!(!text.contains("sha256:"), "{text}");
    assert!(
        !text.contains("s3cr3t"),
        "部署 Secret 不得出现在消息: {text}"
    );
    assert!(!text.contains("!r:example.com"), "正文不得含房间号: {text}");

    assert_eq!(credential_subject("网易", None), "网易");
    assert_eq!(credential_subject("网易", Some("")), "网易", "空字段应省略");
    assert_eq!(credential_subject("网易", Some("授权码")), "网易 / 授权码");

    let plain = matrix::TicketContext {
        branch: MatrixBranch::Credential,
        subject: "网易",
        caller: matrix::CallerIdentity {
            path: "/s/job.sh",
            name: None,
            desc: None,
            enrolled: false,
        },
        reason: "auto_approve_none",
        facts: &[],
    };
    let plain_text = bot.format_ticket(&plain);
    assert!(plain_text.contains("（未注册）"), "{plain_text}");
    assert!(plain_text.contains("人工审批模式"), "{plain_text}");
    assert!(!plain_text.contains("sha256:"), "{plain_text}");
    for hash in ["50f7f169", "d58c1f7a"] {
        assert!(!plain_text.contains(hash), "{plain_text}");
    }
}

#[tokio::test]
async fn credential_timeout_single_ask() {
    // 超时按拒绝（Auth）；并发同键仅一次问询且结果复用。
    use std::time::Duration;
    let state = cred_state(&cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]));
    let err = settle_approval(
        &state,
        &CredentialApproval::new(
            "/s/cred-timeout:h",
            "/s/cred-timeout",
            "auto_approve_none",
            "网易",
            Some("授权码"),
            false,
        ),
        "$cred-timeout",
        None,
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
            .submit_branch("$cred-concurrent", MatrixBranch::Credential)
            .await
    );
    assert!(
        !state
            .approval
            .submit_branch("$cred-concurrent", MatrixBranch::Credential)
            .await,
        "并发二次登记不得再问询"
    );
    assert_eq!(state.approval.pending_len().await, 1, "并发须恰一问询");
    state
        .approval
        .resolve("$cred-concurrent", "@admin:example.com", true)
        .await;
    let (a, b) = tokio::join!(
        state
            .approval
            .ask("$cred-concurrent", Duration::from_secs(1)),
        state
            .approval
            .ask("$cred-concurrent", Duration::from_secs(1))
    );
    assert_eq!((a, b), (Some(true), Some(true)), "并发问询须复用同一结果");
}

#[tokio::test]
async fn raw_context_and_tracked_send_failure() {
    // 终端直调 raw 拒绝；脚本上下文 raw 放行原文；tracked 发送失败 fail-closed。
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
        &matrix::TicketContext {
            branch: MatrixBranch::Credential,
            subject: "网易 / 授权码",
            caller: matrix::CallerIdentity {
                path: "/s/ask-fail.sh",
                name: None,
                desc: None,
                enrolled: false,
            },
            reason: "hash_mismatch",
            facts: &[],
        },
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
    // 拒绝/超时/ask 失败三终态后内存侧与矩阵侧 pending 两表清理一致。
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
            &CredentialApproval::new(
                key,
                "/s/cap.sh",
                "hash_mismatch",
                "网易",
                Some("授权码"),
                false,
            ),
            event_id,
            decision,
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
async fn emergency_revoke_always_reaction_not_settled() {
    // 紧急吊销转常规审批的 `♾️` 不受理——票保持未决、重试仍 202、条目原状。
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let key = "/s/em-auto.sh";
    register_caller(&state, key, "em-auto-h", "em-auto-src")
        .await
        .unwrap();
    state.registry.write().await.set_enabled(key, true).unwrap();
    let err = emergency_revoke(&state, key, None).await.unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;
    let input = crate::service::matrix::ReactionInput {
        target_event_id: event_id,
        key: "♾️".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    let outcome = state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    assert!(
        matches!(outcome, crate::service::matrix::ReactionOutcome::Notify(_)),
        "♾️ 在吊销分支须回执而不落定: {outcome:?}"
    );
    let pending_key = format!("revoke:{key}");
    assert_eq!(
        credential_decision_slot(&state, &pending_key),
        Some(DecisionSlot::Pending),
        "不受理后票须保持未决"
    );
    let retried = emergency_revoke(&state, key, None).await.unwrap_err();
    assert_eq!(
        retried.status_code(),
        StatusCode::ACCEPTED,
        "重试仍为 202 + E_PENDING"
    );
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path(key).unwrap();
    assert!(entry.enabled && !entry.revoked, "♾️ 不得吊销，条目须原状");
}

#[tokio::test]
async fn pending_count_zeroes_on_terminal_state() {
    // 回归：终态清理同批清内存/矩阵票，health.pending 即时归零。
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
