use {
    super::super::{
        BeginOutcome,
        CredentialDecision,
        DecisionSlot,
        approval_async_202,
        credential_decision_slot,
        record_credential_decision,
    },
    crate::{
        config::Config,
        error::{Result, VeilError},
        keepass::{CustomProp, EntrySnapshot, KeePassBackend},
        service::credential::{handle_credential, test_support::*},
        state::{AppState, SqliteOutcome},
    },
    axum::http::StatusCode,
    std::{
        future::Future,
        path::PathBuf,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    },
};

async fn wait_event_id(state: &AppState) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(id) = state.approval.pending_event_ids().await.into_iter().next() {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("审批须先建单")
}

async fn wait_slot(key: &str, want: DecisionSlot) {
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if credential_decision_slot(key) == Some(want) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(reached, "决策表未在超时内落定 {key}: {want:?}");
}

async fn clear_rate(state: &AppState) { state.credential_hits.lock().await.clear(); }

fn async_state() -> AppState {
    cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]))
}

fn timeout_state() -> AppState {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    let mut config = Config::load_from(&env).expect("测试 config 可加载");
    config.credential_approval_timeout_secs = 1;
    inject_sink(
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
    )
}

#[tokio::test]
async fn async_202_decision_table() {
    let (k_ok, k_no, k_to) = ("/s/dec-ok.sh:h", "/s/dec-no.sh:h", "/s/dec-to.sh:h");
    {
        let mut table = super::super::decisions().lock().expect("决策表锁可获取");
        assert_eq!(table.begin(k_ok), BeginOutcome::Reserved);
        assert_eq!(table.slot(k_ok), Some(DecisionSlot::Pending), "占位即未决");
        assert_eq!(
            table.begin(k_ok),
            BeginOutcome::Busy,
            "未决重试须复用不建单"
        );
        table.resolve(k_ok, Some(true));
        assert_eq!(table.slot(k_ok), Some(DecisionSlot::Approved));
        assert_eq!(
            table.begin(k_ok),
            BeginOutcome::Decided(CredentialDecision::Approved)
        );
        assert_eq!(
            table.slot(k_ok),
            Some(DecisionSlot::Approved),
            "S3：begin 只读不消费，动作成功后才消费"
        );
        assert!(table.consume(k_ok), "动作成功后显式消费");
        assert_eq!(table.slot(k_ok), None, "消费后清除");

        table.begin(k_no);
        table.resolve(k_no, Some(false));
        assert_eq!(table.slot(k_no), Some(DecisionSlot::Denied));
        table.begin(k_to);
        table.resolve(k_to, None);
        assert_eq!(table.slot(k_to), Some(DecisionSlot::TimedOut));
    }

    let state = async_state();
    enrolled_with_entries(
        &state,
        "/s/dec-wait.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let key = "/s/dec-wait.sh:badhash";
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/dec-wait.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_slot(key, DecisionSlot::Approved).await;
}

#[tokio::test]
async fn async_202_retry_reuses_ticket() {
    let state = async_state();
    enrolled_with_entries(
        &state,
        "/s/reuse.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let request = || body("badhash", "/s/reuse.sh", None);

    let first = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &request())
        .await
        .unwrap_err();
    assert_eq!(first.status_code(), StatusCode::ACCEPTED);
    let event_before = wait_event_id(&state).await;
    assert_eq!(state.pending.len(), 1);

    clear_rate(&state).await;
    let second = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &request())
        .await
        .unwrap_err();
    assert_eq!(
        second.status_code(),
        StatusCode::ACCEPTED,
        "未决重试须 202 复用"
    );
    assert_eq!(state.pending.len(), 1, "重试不得重复插入内存 pending");
    assert_eq!(
        state.approval.pending_event_ids().await,
        vec![event_before],
        "重试不得叠加 Matrix 票/消息"
    );
}

#[tokio::test]
async fn async_202_e2e_approve_returns_credential() {
    let state = async_state();
    enrolled_with_entries(
        &state,
        "/s/e2e-ok.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let key = "/s/e2e-ok.sh:badhash";
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-ok.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_slot(key, DecisionSlot::Approved).await;

    clear_rate(&state).await;
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-ok.sh", None),
    )
    .await
    .unwrap();
    assert!(
        credential_value(&out).starts_with("__VG_CRED_"),
        "批准后重试须返回凭据: {out}"
    );
    assert_eq!(state.pending.len(), 0, "终态后内存侧 pending 即时清零");
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "终态后矩阵侧 pending 即时清零"
    );
}

#[tokio::test]
async fn async_202_e2e_deny_returns_403() {
    let state = async_state();
    enrolled_with_entries(
        &state,
        "/s/e2e-no.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let key = "/s/e2e-no.sh:badhash";
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-no.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", false)
        .await;
    wait_slot(key, DecisionSlot::Denied).await;

    clear_rate(&state).await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-no.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        crate::error::VeilError::Auth { message } => assert!(message.contains("拒绝"), "{message}"),
        other => panic!("拒绝须为鉴权 403，实得: {other:?}"),
    }
    assert_eq!(state.pending.len(), 0);
}

#[tokio::test]
async fn async_202_e2e_still_pending_returns_202() {
    let state = async_state();
    enrolled_with_entries(
        &state,
        "/s/e2e-pd.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let first = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-pd.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(first.status_code(), StatusCode::ACCEPTED);
    let event_id = wait_event_id(&state).await;

    clear_rate(&state).await;
    let second = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-pd.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(second.status_code(), StatusCode::ACCEPTED, "未决重试须 202");
    assert_eq!(state.approval.pending_len().await, 1, "未决不得重复建单");
    assert_eq!(
        state.approval.pending_event_ids().await,
        vec![event_id],
        "复用既有真实 event id"
    );
}

#[tokio::test]
async fn async_202_e2e_timeout_returns_403() {
    let state = timeout_state();
    enrolled_with_entries(
        &state,
        "/s/e2e-to.sh",
        "goodhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let key = "/s/e2e-to.sh:badhash";
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-to.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::ACCEPTED);
    wait_slot(key, DecisionSlot::TimedOut).await;

    clear_rate(&state).await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("badhash", "/s/e2e-to.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    match &err {
        crate::error::VeilError::Auth { message } => assert!(message.contains("超时"), "{message}"),
        other => panic!("超时须按拒绝 403，实得: {other:?}"),
    }
    assert_eq!(state.pending.len(), 0);
    assert_eq!(state.approval.pending_len().await, 0);
}

#[derive(Debug)]
struct FlakyKeePass {
    remaining_failures: AtomicUsize,
}

impl FlakyKeePass {
    fn new(fail_times: usize) -> Self {
        Self {
            remaining_failures: AtomicUsize::new(fail_times),
        }
    }
}

impl KeePassBackend for FlakyKeePass {
    fn is_unlocked(&self) -> bool { true }

    fn fetch_entry(
        &self,
        title: String,
    ) -> Pin<Box<dyn Future<Output = Result<EntrySnapshot>> + Send + '_>> {
        Box::pin(async move {
            if self.remaining_failures.load(Ordering::SeqCst) > 0 {
                self.remaining_failures.fetch_sub(1, Ordering::SeqCst);
                return Err(VeilError::Unavailable {
                    message: "KeePass 未解锁（瞬时）".to_string(),
                });
            }
            Ok(EntrySnapshot {
                title: title.clone(),
                username: format!("{title}-user"),
                password: "p".to_string(),
                url: String::new(),
                custom: vec![CustomProp {
                    name: "授权码".to_string(),
                    value: format!("__MOCK_CRED_{title}-授权码__"),
                    protected: true,
                }],
            })
        })
    }
}

fn flaky_state(fail_times: usize) -> AppState {
    let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
    inject_sink(
        AppState::new(
            Config::load_from(&env).expect("测试 config 可加载"),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(FlakyKeePass::new(fail_times))),
        InjectSink::success(),
    )
}

#[tokio::test]
async fn approved_decision_fetch_failure_retry() {
    let state = flaky_state(1);
    let key = "/s/fetch-retry.sh:badhash";
    record_credential_decision(key, Some(true));
    assert_eq!(credential_decision_slot(key), Some(DecisionSlot::Approved));

    let err = approval_async_202(&state, key, "hash_mismatch", "网易", Some("授权码"), false)
        .await
        .unwrap_err();
    assert_eq!(
        err.status_code(),
        StatusCode::SERVICE_UNAVAILABLE,
        "首次取库失败须透传 503"
    );
    assert_eq!(
        credential_decision_slot(key),
        Some(DecisionSlot::Approved),
        "取库失败后决策槽位仍为 Approved"
    );

    let out = approval_async_202(&state, key, "hash_mismatch", "网易", Some("授权码"), false)
        .await
        .expect("重试成功返回凭据");
    assert!(credential_value(&out).starts_with("__MOCK_CRED_"));
    assert_eq!(credential_decision_slot(key), None, "成功后决策被消费");
}

#[tokio::test]
async fn approved_decision_not_lost_on_fetch_error() {
    let state = flaky_state(2);
    let key = "/s/fetch-lost.sh:badhash";
    record_credential_decision(key, Some(true));

    for attempt in 0..2 {
        let err = approval_async_202(&state, key, "hash_mismatch", "网易", Some("授权码"), false)
            .await
            .unwrap_err();
        assert_eq!(
            err.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "第 {attempt} 次瞬时失败"
        );
        assert_eq!(
            credential_decision_slot(key),
            Some(DecisionSlot::Approved),
            "失败不得丢批准（第 {attempt} 次）"
        );
    }

    let out = approval_async_202(&state, key, "hash_mismatch", "网易", Some("授权码"), false)
        .await
        .expect("第三次取库成功");
    assert!(credential_value(&out).starts_with("__MOCK_CRED_"));
    assert_eq!(credential_decision_slot(key), None, "成功即消费");

    let after = approval_async_202(&state, key, "hash_mismatch", "网易", Some("授权码"), false)
        .await
        .unwrap_err();
    assert_eq!(
        after.status_code(),
        StatusCode::ACCEPTED,
        "消费后重试不得复用批准，须重新建单 202"
    );
    assert_eq!(state.pending.len(), 1, "消费后重试须新建 pending");
}
