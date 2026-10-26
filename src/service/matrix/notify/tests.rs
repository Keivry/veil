//! `matrix::notify` 单测（自 `notify.rs` 外迁；测试名与断言不变）。

use {
    super::*,
    crate::service::matrix::{MatrixBranch, ticket::CallerIdentity},
    std::sync::atomic::{AtomicBool, Ordering},
    tokio::sync::Notify,
};

#[derive(Debug)]
struct FakeSink {
    sent: Arc<AtomicU64>,
    open: Arc<AtomicBool>,
    gate: Arc<Notify>,
}

impl FakeSink {
    fn new(open: bool) -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(0)),
            open: Arc::new(AtomicBool::new(open)),
            gate: Arc::new(Notify::new()),
        }
    }

    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.gate.notify_waiters();
    }

    fn sent(&self) -> u64 { self.sent.load(Ordering::SeqCst) }
}

impl NotificationSink for FakeSink {
    fn send_text(&self, _text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            while !self.open.load(Ordering::SeqCst) {
                self.gate.notified().await;
            }
            self.sent.fetch_add(1, Ordering::SeqCst);
        })
    }
}

fn dummy_bot() -> Arc<MatrixBot> {
    Arc::new(MatrixBot::new(
        "https://matrix.example.com".to_string(),
        "!r:example.com".to_string(),
        "syt_x".to_string(),
    ))
}

async fn wait_sent(sink: &FakeSink, expected: u64) {
    for _ in 0..100 {
        if sink.sent() == expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn notification_spool_bounded() {
    let sink = Arc::new(FakeSink::new(false));
    let spool = NotificationSpool::with_sink(dummy_bot(), sink.clone(), 1);
    spool.start();
    let mut accepted: u64 = 0;
    for i in 0..5 {
        if spool.notify_text(format!("n{i}")) {
            accepted += 1;
        }
    }
    assert!(
        accepted <= spool.capacity() as u64 + 1,
        "有界队列不得无界接收，accepted={accepted}"
    );
    assert!(
        spool.dropped_count() >= 5 - accepted,
        "满队列须计数丢弃，dropped={}",
        spool.dropped_count()
    );
    sink.release();
    wait_sent(&sink, accepted).await;
    assert_eq!(sink.sent(), accepted, "入队通知须全部送达");
    spool.shutdown();
}

#[tokio::test]
async fn notification_spool_reuse() {
    let sink = Arc::new(FakeSink::new(true));
    let spool = NotificationSpool::with_sink(dummy_bot(), sink.clone(), 8);
    spool.start();
    spool.start();
    assert!(spool.is_started(), "重复 start 须保持单一消费者");
    for i in 0..6 {
        assert!(spool.notify_text(format!("m{i}")), "容量内投递须入队");
    }
    wait_sent(&sink, 6).await;
    assert_eq!(sink.sent(), 6, "多次通知经单一消费者送达一次");
    assert_eq!(spool.dropped_count(), 0, "容量内不得丢弃");
    // 复用同一 Bot 格式化，不新建实例。
    let text = spool.format_notice(
        &TicketContext {
            branch: MatrixBranch::Credential,
            subject: "网易",
            caller: CallerIdentity {
                path: "/s/a.sh",
                name: None,
                desc: None,
                enrolled: false,
            },
            reason: "hash_mismatch",
            facts: &[],
        },
        Some(false),
    );
    assert!(
        text.contains("凭据取用失败") && text.contains("❎"),
        "格式化经 spool 单一 Bot: {text}"
    );
    spool.shutdown();
}

#[tokio::test]
async fn notification_spool_lifecycle() {
    let sink = Arc::new(FakeSink::new(true));
    let spool = NotificationSpool::with_sink(dummy_bot(), sink.clone(), 4);
    assert!(!spool.is_started(), "启动前无消费者");
    assert_eq!(spool.capacity(), 4);
    spool.start();
    assert!(spool.is_started(), "启动后消费者可跟踪");
    spool.start();
    assert!(spool.is_started(), "重复启动仍为同一消费者");
    spool.shutdown();
    assert!(!spool.is_started(), "停机后消费者停止");
}

#[tokio::test]
async fn notification_sink_default_tracked() {
    let sink = FakeSink::new(true);
    let tracked = NotificationSink::send_text_tracked(&sink, "x".to_string()).await;
    assert_eq!(tracked, None, "默认 tracked 须返回 None");
    assert_eq!(sink.sent(), 1, "默认 tracked 须回退完成 send_text");
}

#[tokio::test]
async fn noop_sink_is_fail_closed_and_benign() {
    let sink = NoopSink;
    NotificationSink::send_text(&sink, "x".to_string()).await;
    assert_eq!(
        NotificationSink::send_text_tracked(&sink, "x".to_string()).await,
        None,
        "no-op tracked 须返回 None（fail-closed）"
    );
    assert!(
        NotificationSink::send_reaction(&sink, "$e", "✅").await,
        "no-op reaction 默认 true，不产生噪声告警"
    );
}

#[tokio::test]
async fn matrix_bot_tracked_returns_real_id() {
    let app = axum::Router::new()
        .fallback(|| async { axum::Json(serde_json::json!({"event_id": "$real-event-id"})) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let bot = MatrixBot::new(
        format!("http://{addr}"),
        "!r:example.com".to_string(),
        "syt_x".to_string(),
    );
    let direct = bot.send_text("hello").await.expect("直连发送须成功");
    assert_eq!(direct, "$real-event-id");
    let tracked = NotificationSink::send_text_tracked(&bot, "hello".to_string()).await;
    assert_eq!(
        tracked.as_deref(),
        Some(direct.as_str()),
        "tracked 须等于 bot.rs 返回的真实 id"
    );
    server.abort();

    let down = MatrixBot::new(
        "http://127.0.0.1:9".to_string(),
        "!r:example.com".to_string(),
        "syt_x".to_string(),
    );
    assert!(
        NotificationSink::send_text_tracked(&down, "hello".to_string())
            .await
            .is_none(),
        "发送失败须返回 None 且不 panic"
    );
}
