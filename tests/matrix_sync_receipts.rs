//! Matrix 审批回执端到端：真实 `spawn_sync_loop` + 本地 mock homeserver。
//!
//! 覆盖 tasks 7.3 的 reaction 人工验收口径（无真实房间时的可复现等价）：
//! - 注册 / 命令票收到 `♾️` → 落定批准 + 持久放行（`always=true`）；
//! - 吊销票收到 `♾️` → 回执"未被受理"，票保持未决（D12 关键回归点）；
//! - 凭据票收到 `♾️` → 回执且票未决；
//! - 已退役的 `🔓` → 说明性回执（含可用表情），任何票状态不变；
//! - 四类建单消息各自携带本分支图例，受理集外的表情不出现在图例里。
//!
//! 与单测的区别：本文件走 whoami → 长轮询 sync → reaction 分发 → 回执发送
//! 的完整生产接线，验证回执文本确实经过 `MatrixBot::send_text` 落进房间。

mod common;

use {
    axum::{
        Router,
        extract::{Path, State},
        http::StatusCode,
        response::IntoResponse,
        routing::{any, get, put},
    },
    serde_json::{Value, json},
    std::{
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    },
    veil::service::matrix::{
        FixedCleanup,
        GatewayCleanup,
        LockCleanupReport,
        MatrixApproval,
        MatrixBot,
        MatrixBranch,
        ReactionOutcome,
    },
};

/// mock homeserver 的共享状态：sync 首轮返回的 reaction 事件 + 收到的消息正文。
#[derive(Clone, Default)]
struct MockMatrix {
    events: Arc<Mutex<Vec<Value>>>,
    sent: Arc<Mutex<Vec<String>>>,
    sync_calls: Arc<Mutex<u64>>,
    /// 前 N 次 whoami 返回 500（用于验证退避重试后恢复）。
    whoami_fail_first: Arc<Mutex<u64>>,
}

impl MockMatrix {
    fn sent_texts(&self) -> Vec<String> { self.sent.lock().unwrap().clone() }

    /// 轮询等待某条回执出现（含子串匹配），超时即失败并打印已收正文。
    async fn wait_for(&self, needle: &str) -> String {
        for _ in 0..200 {
            if let Some(hit) = self
                .sent_texts()
                .into_iter()
                .find(|text| text.contains(needle))
            {
                return hit;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "未收到含 {needle:?} 的回执；已收正文: {:?}",
            self.sent_texts()
        );
    }
}

fn reaction(target: &str, key: &str, sender: &str, ts: u64) -> Value {
    json!({
        "type": "m.reaction",
        "sender": sender,
        "origin_server_ts": ts,
        "content": {
            "m.relates_to": {"event_id": target, "key": key, "rel_type": "m.annotation"}
        }
    })
}

fn text_event(body: &str, sender: &str, ts: u64) -> Value {
    json!({
        "type": "m.room.message",
        "sender": sender,
        "origin_server_ts": ts,
        "content": {"msgtype": "m.text", "body": body}
    })
}

/// 记录指令清理调用的网关桩：非成员指令若被执行，计数与 secret 数会变化。
#[derive(Default)]
struct RecordingCleanup {
    lock_cleanup_calls: AtomicUsize,
    forget_cleanup_calls: AtomicUsize,
    secrets: AtomicUsize,
}

impl GatewayCleanup for RecordingCleanup {
    fn keepass_unlocked(&self) -> bool { true }

    fn vault_len(&self) -> usize { self.secrets.load(Ordering::SeqCst) }

    fn lock_cleanup(&self) -> LockCleanupReport {
        self.lock_cleanup_calls.fetch_add(1, Ordering::SeqCst);
        LockCleanupReport::default()
    }

    fn forget_cleanup(&self) -> usize {
        self.forget_cleanup_calls.fetch_add(1, Ordering::SeqCst);
        0
    }
}

async fn whoami(State(mock): State<MockMatrix>) -> impl IntoResponse {
    let mut left = mock.whoami_fail_first.lock().unwrap();
    if *left > 0 {
        *left -= 1;
        return (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({}))).into_response();
    }
    axum::Json(json!({"user_id": "@bot:example.com"})).into_response()
}

async fn sync(State(mock): State<MockMatrix>) -> impl IntoResponse {
    let mut calls = mock.sync_calls.lock().unwrap();
    *calls += 1;
    // 首轮下发 reaction，之后不再重复（避免同一票被反复投递）。
    let events = if *calls == 1 {
        mock.events.lock().unwrap().clone()
    } else {
        Vec::new()
    };
    axum::Json(json!({
        "next_batch": format!("s{}", *calls),
        "rooms": {"join": {"!r:example.com": {"timeline": {"events": events}}}}
    }))
}

async fn send_message(
    State(mock): State<MockMatrix>,
    Path((_room, _kind, _txn)): Path<(String, String, String)>,
    body: String,
) -> impl IntoResponse {
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    if let Some(text) = parsed.get("body").and_then(Value::as_str) {
        mock.sent.lock().unwrap().push(text.to_string());
    }
    (StatusCode::OK, axum::Json(json!({"event_id": "$mock-msg"})))
}

async fn send_reaction() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(json!({"event_id": "$mock-react"})),
    )
}

/// 启动 mock homeserver 并返回 `(base_url, 共享状态, JoinHandle)`。
async fn serve_mock(events: Vec<Value>) -> (String, MockMatrix, tokio::task::JoinHandle<()>) {
    let mock = MockMatrix {
        events: Arc::new(Mutex::new(events)),
        ..MockMatrix::default()
    };
    let app = Router::new()
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        .route("/_matrix/client/v3/sync", get(sync))
        .route(
            "/_matrix/client/v3/rooms/{room}/send/{kind}/{txn}",
            put(send_message),
        )
        .route(
            "/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}",
            any(send_reaction),
        )
        .with_state(mock.clone());
    let (base, handle) = common::serve(app).await;
    (base, mock, handle)
}

fn temp_token_file(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "veil-mx-receipts-{}-{tag}.token",
        std::process::id()
    ))
}

/// 五张票（注册/命令/吊销/凭据/旧表情）在一次 sync 中同时投递，逐条校验回执与落定语义。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_ticket_kinds_receipts_and_settlement() {
    let events = vec![
        reaction("$t-reg", "♾️", "@admin:example.com", 2000),
        reaction("$t-cmd", "♾️", "@admin:example.com", 2001),
        reaction("$t-rev", "♾️", "@admin:example.com", 2002),
        reaction("$t-cred", "♾️", "@admin:example.com", 2003),
        reaction("$t-legacy", "🔓", "@admin:example.com", 2004),
    ];
    let (homeserver, mock, server) = serve_mock(events).await;
    let approval = Arc::new(MatrixApproval::new(
        vec!["@admin:example.com".to_string()],
        90,
    ));
    for (event_id, branch) in [
        ("$t-reg", MatrixBranch::Register),
        ("$t-cmd", MatrixBranch::Command),
        ("$t-rev", MatrixBranch::Revoke),
        ("$t-cred", MatrixBranch::Credential),
        ("$t-legacy", MatrixBranch::Register),
    ] {
        assert!(
            approval.submit_branch(event_id, branch).await,
            "建单须成功: {event_id}"
        );
    }

    let token_file = temp_token_file("four");
    let bot = MatrixBot::new(
        homeserver,
        "!r:example.com".to_string(),
        "syt_test".to_string(),
    );
    let handle = bot.spawn_sync_loop(
        Arc::clone(&approval),
        Arc::new(FixedCleanup {
            unlocked: true,
            secrets: 0,
        }),
        token_file.clone(),
        0,
    );

    // 注册票 `♾️`：落定批准并持久放行。
    mock.wait_for("$t-reg").await;
    assert_eq!(
        approval.decision("$t-reg").await,
        Some(Some(true)),
        "注册票 ♾️ 须落定批准"
    );
    assert_eq!(
        approval.applied_always("$t-reg").await,
        Some(true),
        "注册票 ♾️ 须标记持久放行"
    );

    // 命令票 `♾️`：落定批准并持久放行（accept-always 载体）。
    let cmd_receipt = mock.wait_for("$t-cmd").await;
    assert!(
        cmd_receipt.contains("持久放行"),
        "命令票 ♾️ 须回执持久放行: {cmd_receipt}"
    );
    assert_eq!(
        approval.decision("$t-cmd").await,
        Some(Some(true)),
        "命令票 ♾️ 须落定批准"
    );
    assert_eq!(
        approval.applied_always("$t-cmd").await,
        Some(true),
        "命令票 ♾️ 须标记持久放行"
    );

    // 吊销票 `♾️`：不受理，票保持未决（D12 关键回归点）。
    let revoke_receipt = mock.wait_for("$t-rev").await;
    assert!(
        revoke_receipt.contains("未被受理"),
        "吊销票 ♾️ 须收到不受理回执: {revoke_receipt}"
    );
    assert_eq!(
        approval.decision("$t-rev").await,
        Some(None),
        "吊销票 ♾️ 不得落定"
    );

    // 凭据票 `♾️`：不受理，票保持未决。
    let cred_receipt = mock.wait_for("$t-cred").await;
    assert!(
        cred_receipt.contains("未被受理"),
        "凭据票 ♾️ 须收到不受理回执: {cred_receipt}"
    );
    assert_eq!(
        approval.decision("$t-cred").await,
        Some(None),
        "凭据票 ♾️ 不得落定"
    );

    // 已退役 `🔓`：说明性回执（列出可用表情），票状态不变。
    let legacy_receipt = mock.wait_for("$t-legacy").await;
    assert!(
        legacy_receipt.contains("未知表情") && legacy_receipt.contains("♾️"),
        "🔓 须收到含合法取值的说明性回执: {legacy_receipt}"
    );
    assert_eq!(
        approval.decision("$t-legacy").await,
        Some(None),
        "🔓 不得改变任何票状态"
    );

    handle.abort();
    server.abort();
    std::fs::remove_file(&token_file).ok();
}

/// 非白名单成员的文本指令整批丢弃：无任何回执、pending 与 secret 映射不变。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_member_text_commands_dropped_without_any_receipt() {
    let events = vec![
        text_event("lock", "@intruder:example.com", 2000),
        text_event("status", "@intruder:example.com", 2001),
        text_event("forget secrets", "@intruder:example.com", 2002),
        text_event("Lock", "@intruder:example.com", 2003),
        text_event("status", "@admin:example.com", 2004),
        // 成员发送未知文本同样无回执：指令词表不构成探测通道。
        text_event("hello", "@admin:example.com", 2005),
    ];
    let (homeserver, mock, server) = serve_mock(events).await;
    let approval = Arc::new(MatrixApproval::new(
        vec!["@admin:example.com".to_string()],
        90,
    ));
    assert!(
        approval
            .submit_branch("$t-pending", MatrixBranch::Register)
            .await,
        "建单须成功"
    );

    let cleanup = Arc::new(RecordingCleanup {
        secrets: AtomicUsize::new(3),
        ..RecordingCleanup::default()
    });
    let cleanup_handle: Arc<dyn GatewayCleanup> = cleanup.clone();
    let token_file = temp_token_file("whitelist-text");
    let bot = MatrixBot::new(
        homeserver,
        "!r:example.com".to_string(),
        "syt_test".to_string(),
    );
    let handle = bot.spawn_sync_loop(Arc::clone(&approval), cleanup_handle, token_file.clone(), 0);

    let receipt = mock.wait_for("主密码缓存").await;
    assert!(receipt.contains("待审批: 1"), "{receipt}");
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(
        mock.sent_texts().len(),
        1,
        "仅白名单成员 status 有回执，非成员文本一律无回执: {:?}",
        mock.sent_texts()
    );
    assert_eq!(
        approval.decision("$t-pending").await,
        Some(None),
        "非成员 lock 不得把 pending 按拒绝落定"
    );
    assert_eq!(
        cleanup.lock_cleanup_calls.load(Ordering::SeqCst),
        0,
        "非成员 lock 不得触发清理"
    );
    assert_eq!(
        cleanup.forget_cleanup_calls.load(Ordering::SeqCst),
        0,
        "非成员 forget 不得触发清理"
    );
    assert_eq!(
        cleanup.secrets.load(Ordering::SeqCst),
        3,
        "非成员 forget 不得清空 secret 映射"
    );

    handle.abort();
    server.abort();
    std::fs::remove_file(&token_file).ok();
}

/// whoami 失败（mock 返回非 200）时 fail-closed：全部 reaction 丢弃、无回执、票全未决。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoami_failure_discards_all_reactions() {
    let events = vec![
        reaction("$t-a", "✅", "@admin:example.com", 2000),
        reaction("$t-b", "♾️", "@admin:example.com", 2001),
    ];
    // whoami 相只复用 mock 的收件箱与事件投递，homeserver 由下面的 failing 路由承载。
    let (_homeserver, mock, server) = serve_mock(events).await;
    let approval = Arc::new(MatrixApproval::new(
        vec!["@admin:example.com".to_string()],
        90,
    ));
    for event_id in ["$t-a", "$t-b"] {
        approval
            .submit_branch(event_id, MatrixBranch::Register)
            .await;
    }

    // 覆盖 whoami 路由为 500，使 Bot 拿不到自身 MXID。
    let failing = Router::new()
        .route(
            "/_matrix/client/v3/account/whoami",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .route("/_matrix/client/v3/sync", get(sync))
        .route(
            "/_matrix/client/v3/rooms/{room}/send/{kind}/{txn}",
            put(send_message),
        )
        .route(
            "/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}",
            any(send_reaction),
        )
        .with_state(mock.clone());
    let (failing_base, failing_handle) = common::serve(failing).await;

    let token_file = temp_token_file("whoami");
    let bot = MatrixBot::new(
        failing_base,
        "!r:example.com".to_string(),
        "syt_test".to_string(),
    );
    let handle = bot.spawn_sync_loop(
        Arc::clone(&approval),
        Arc::new(FixedCleanup {
            unlocked: true,
            secrets: 0,
        }),
        token_file.clone(),
        0,
    );

    // 给 sync 环若干轮机会后断言：无回执、票仍待审。
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        mock.sent_texts().is_empty(),
        "whoami 失败须 fail-closed，不得发回执: {:?}",
        mock.sent_texts()
    );
    assert_eq!(approval.decision("$t-a").await, Some(None));
    assert_eq!(approval.decision("$t-b").await, Some(None));

    handle.abort();
    failing_handle.abort();
    server.abort();
    std::fs::remove_file(&token_file).ok();
}

/// 分支不受理与未知表情的回执文案互不相同（避免审批人误判）。
#[tokio::test]
async fn receipt_copy_distinguishes_not_accepted_from_unknown() {
    let approval = MatrixApproval::new(vec!["@admin:example.com".to_string()], 90);
    approval.submit_branch("$t-rev", MatrixBranch::Revoke).await;
    approval
        .submit_branch("$t-reg", MatrixBranch::Register)
        .await;
    let input = |target: &str, key: &str| veil::service::matrix::ReactionInput {
        target_event_id: target.to_string(),
        key: key.to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    let not_accepted = approval
        .on_reaction(
            &input("$t-rev", "♾️"),
            "@bot:example.com",
            "!r:example.com",
            1000,
        )
        .await;
    let unknown = approval
        .on_reaction(
            &input("$t-reg", "🔓"),
            "@bot:example.com",
            "!r:example.com",
            1000,
        )
        .await;
    let text = |outcome: ReactionOutcome| match outcome {
        ReactionOutcome::Notify(reason) => reason.to_string(),
        other => panic!("须为 Notify 回执: {other:?}"),
    };
    let not_accepted = text(not_accepted);
    let unknown = text(unknown);
    assert!(not_accepted.contains("不受理"), "{not_accepted}");
    assert!(unknown.contains("未知表情"), "{unknown}");
    assert_ne!(not_accepted, unknown);
}

/// 四类建单消息各自带本分支图例；吊销票图例不含 `♾️`（不受理时不诱导点选）。
#[test]
fn ticket_legends_name_each_branch_action() {
    let bot = MatrixBot::new(
        "https://m.example.com".to_string(),
        "!r:example.com".to_string(),
        "tok".to_string(),
    );
    for (branch, needles) in [
        (
            MatrixBranch::Register,
            vec!["激活", "激活并持久放行", "吊销"],
        ),
        (
            MatrixBranch::Command,
            vec!["批准本次", "批准并持久放行", "拒绝"],
        ),
        (MatrixBranch::Revoke, vec!["执行吊销", "不吊销"]),
        (MatrixBranch::Credential, vec!["批准本次", "拒绝"]),
    ] {
        let ticket = bot.format_ticket(branch, "摘要");
        assert!(ticket.contains("可选反应"), "{branch:?} 缺图例: {ticket}");
        for needle in needles {
            assert!(
                ticket.contains(needle),
                "{branch:?} 图例缺 {needle:?}: {ticket}"
            );
        }
    }
    let revoke_ticket = bot.format_ticket(MatrixBranch::Revoke, "吊销 :: /s/a.sh");
    assert!(
        !revoke_ticket.contains('♾'),
        "吊销票图例不得出现 ♾️: {revoke_ticket}"
    );
    let credential_ticket = bot.format_ticket(MatrixBranch::Credential, "取用 :: 网易");
    assert!(
        !credential_ticket.contains('♾'),
        "凭据票图例不得出现 ♾️: {credential_ticket}"
    );
}

/// whoami 启动瞬间失败后必须能自愈：退避重试成功前 fail-closed 丢弃，
/// 恢复后同一 sync 循环继续落定 reaction（回归 7.3 期间发现的可用性缺陷）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoami_recovers_and_resumes_settling() {
    let events = vec![reaction("$t-late", "✅", "@admin:example.com", 2000)];
    let mock = MockMatrix {
        // 前两次 whoami 失败，第三次起成功。
        whoami_fail_first: Arc::new(Mutex::new(2)),
        ..MockMatrix::default()
    };
    *mock.events.lock().unwrap() = events;
    let app = Router::new()
        .route("/_matrix/client/v3/account/whoami", get(whoami))
        .route("/_matrix/client/v3/sync", get(sync))
        .route(
            "/_matrix/client/v3/rooms/{room}/send/{kind}/{txn}",
            put(send_message),
        )
        .route(
            "/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}",
            any(send_reaction),
        )
        .with_state(mock.clone());
    let (base, server) = common::serve(app).await;

    let approval = Arc::new(MatrixApproval::new(
        vec!["@admin:example.com".to_string()],
        90,
    ));
    approval
        .submit_branch("$t-late", MatrixBranch::Register)
        .await;

    let token_file = temp_token_file("whoami-recover");
    let bot = MatrixBot::new(base, "!r:example.com".to_string(), "syt_test".to_string());
    let handle = bot.spawn_sync_loop(
        Arc::clone(&approval),
        Arc::new(FixedCleanup {
            unlocked: true,
            secrets: 0,
        }),
        token_file.clone(),
        0,
    );

    // 退避首轮 1s、次轮 2s，故给足 6s 窗口观察恢复后落定。
    let settled = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if approval.decision("$t-late").await == Some(Some(true)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "whoami 恢复后须继续落定 reaction；当前 decision={:?}",
        approval.decision("$t-late").await
    );

    handle.abort();
    server.abort();
    std::fs::remove_file(&token_file).ok();
}
