//! H10/D10：失败/审批通知统一有界 spool。
//!
//! 单例 `MatrixBot`（进程内复用，不再每失败 `MatrixBot::with_client` 新建）+
//! 有界 `tokio::sync::mpsc` 队列 + 常驻消费者（`JoinHandle` 由本结构持有，
//! 停机 `shutdown` abort 口径明确）。`notify_text` 走 `try_send`，满队列或
//! 消费者已停即丢弃并计数 + warn，不阻塞请求热路径（best-effort 语义不变）。

use {
    super::{MatrixBot, MatrixBranch},
    std::{
        fmt,
        future::Future,
        pin::Pin,
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    },
    tokio::{sync::mpsc, task::JoinHandle},
};

/// 通知队列默认容量（有界，防故障风暴放大）。
pub const NOTIFICATION_QUEUE_CAPACITY: usize = 128;

/// 异步发送 sink：生产为 `MatrixBot`，测试注入 fake 以验证有界/丢弃/生命周期。
pub trait NotificationSink: Send + Sync + fmt::Debug + 'static {
    /// best-effort 发送一条文本；失败由实现内部 warn，不向上传播。
    fn send_text(&self, text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// `F1` tracked 发送：返回真实 Matrix event id，供审批建单以其为 pending 键。
    /// 默认实现回退 [`Self::send_text`] 并返回 `None`，保持 spool/事件环 best-effort 语义。
    fn send_text_tracked(
        &self,
        text: String,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(async move {
            self.send_text(text).await;
            None
        })
    }

    /// `CRD-5` best-effort 预置 reaction：返回是否已发送（`false` 由调用方记 warn，不阻断建单）。
    /// 默认 no-op 返回 `true`，使无 reaction 能力的 sink 不产生噪声告警。
    fn send_reaction<'a>(
        &'a self,
        event_id: &'a str,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let _ = (event_id, key);
            true
        })
    }
}

impl NotificationSink for MatrixBot {
    fn send_text(&self, text: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if let Err(err) = MatrixBot::send_text(self, &text).await {
                tracing::warn!("通知发送失败（best-effort 丢弃）: {err:#}");
            }
        })
    }

    fn send_text_tracked(
        &self,
        text: String,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        Box::pin(async move {
            match MatrixBot::send_text(self, &text).await {
                Ok(event_id) if !event_id.is_empty() => Some(event_id),
                Ok(_) => {
                    tracing::warn!("tracked 通知发送成功但未返回 event_id，按 None 处理");
                    None
                }
                Err(err) => {
                    tracing::warn!("tracked 通知发送失败: {err:#}");
                    None
                }
            }
        })
    }

    fn send_reaction<'a>(
        &'a self,
        event_id: &'a str,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match MatrixBot::send_reaction(self, event_id, key).await {
                Ok(()) => true,
                Err(err) => {
                    tracing::warn!("审批预置 reaction 发送失败（仅告警，不阻断）: {err:#}");
                    false
                }
            }
        })
    }
}

/// 有界通知 spool：单 Bot + 有界队列 + 常驻消费者。
pub struct NotificationSpool {
    bot: Arc<MatrixBot>,
    capacity: usize,
    tx: mpsc::Sender<String>,
    rx: Mutex<Option<mpsc::Receiver<String>>>,
    sink: Arc<dyn NotificationSink>,
    dropped: Arc<AtomicU64>,
    consumer: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for NotificationSpool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotificationSpool")
            .field("capacity", &self.capacity)
            .field("dropped", &self.dropped_count())
            .field("started", &self.is_started())
            .finish()
    }
}

impl NotificationSpool {
    /// 生产入口：单一 `Arc<MatrixBot>` 同时作为发送 sink 与格式化源。
    pub fn new(bot: Arc<MatrixBot>, capacity: usize) -> Self {
        let sink: Arc<dyn NotificationSink> = bot.clone();
        Self::with_sink(bot, sink, capacity)
    }

    /// 可注入 sink（测试用）：`bot` 仅承担 `format_approval`，发送走 `sink`。
    pub fn with_sink(
        bot: Arc<MatrixBot>,
        sink: Arc<dyn NotificationSink>,
        capacity: usize,
    ) -> Self {
        let capacity = capacity.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            bot,
            capacity,
            tx,
            rx: Mutex::new(Some(rx)),
            sink,
            dropped: Arc::new(AtomicU64::new(0)),
            consumer: Mutex::new(None),
        }
    }

    pub fn capacity(&self) -> usize { self.capacity }

    /// 审批正文格式化（复用单一 Bot，无新建实例）。
    pub fn format_approval(
        &self,
        branch: MatrixBranch,
        approved: Option<bool>,
        summary: &str,
    ) -> String {
        self.bot.format_approval(branch, approved, summary)
    }

    /// `F1` 审批建单专用 tracked 发送：直接 `await` sink 取真实 event id，`None` 即发送失败。
    /// 与 [`Self::notify_text`]（有界 spool、best-effort、满即丢弃计数）路由不同——审批需回执，
    /// 失败由调用方 fail-closed。
    pub async fn send_tracked(&self, text: String) -> Option<String> {
        self.sink.send_text_tracked(text).await
    }

    /// `CRD-5`：建单后预置 reaction（best-effort；`false` 由调用方 warn，不阻断建单）。
    pub async fn send_reaction(&self, event_id: &str, key: &str) -> bool {
        self.sink.send_reaction(event_id, key).await
    }

    /// 非阻塞投递：满队列/已停即丢弃并计数 + warn，返回是否入队。
    pub fn notify_text(&self, text: String) -> bool {
        match self.tx.try_send(text) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.record_drop("通知队列已满");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.record_drop("通知消费者已停止");
                false
            }
        }
    }

    fn record_drop(&self, reason: &str) {
        let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!("{reason}，丢弃通知（累计 {n} 条，容量 {}）", self.capacity);
    }

    pub fn dropped_count(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }

    /// 启动常驻消费者（幂等）：须在 tokio 运行期内调用（`main` 启动期 / 测试）。
    pub fn start(&self) {
        let mut consumer = self.consumer.lock().unwrap_or_else(|e| e.into_inner());
        if consumer.is_some() {
            return;
        }
        let rx = self.rx.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(mut rx) = rx else { return };
        let sink = Arc::clone(&self.sink);
        *consumer = Some(tokio::spawn(async move {
            while let Some(text) = rx.recv().await {
                sink.send_text(text).await;
            }
        }));
    }

    /// 消费者是否在运行（测试生命周期口径）。
    pub fn is_started(&self) -> bool {
        self.consumer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// 停机口径：abort 常驻消费者（剩余队列丢弃，best-effort 语义）。
    pub fn shutdown(&self) {
        let handle = self
            .consumer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handle) = handle {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
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
        let text = spool.format_approval(MatrixBranch::Credential, Some(false), "KeePass 失败");
        assert!(text.contains("[凭据]"), "格式化经 spool 单一 Bot: {text}");
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
}
