//! NonDialog 命中 `params` 声明的豁免路径：参数被忽略、请求体字节保真、
//! 告警恰一次（去重可验，task 4.3）。

use {
    super::super::{NondialogCtx, serve_nondialog_passthrough},
    crate::{
        config::{ParamOverrides, ParamProtocol, UpstreamOverrides},
        service::llm_gateway::{GatewayMetrics, Protocol},
    },
    axum::http::HeaderMap,
    std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    },
};

/// 声明 `params.chat` 的覆盖（NonDialog 须忽略）。
fn overrides_with_params() -> UpstreamOverrides {
    let rules = ParamOverrides {
        default: BTreeMap::new(),
        r#override: [("temperature".to_string(), serde_json::json!(0.7))]
            .into_iter()
            .collect(),
        drop: Vec::new(),
    };
    UpstreamOverrides {
        headers: HeaderMap::with_capacity(0),
        params: BTreeMap::from([(ParamProtocol::Chat, rules)]),
        override_existing: true,
        user_agent: None,
        drop_headers: Vec::new(),
    }
}

/// 捕获完整请求（头 + `content-length` 体）的回环上游：回固定 JSON，
/// 原始请求字节经共享句柄交回测试。
async fn capture_loopback(
    resp_body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<u8>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/models",
        listener.local_addr().expect("回环地址须可读")
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = captured.clone();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = Vec::new();
            let mut chunk = [0u8; 16384];
            loop {
                let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut chunk))
                        .await
                else {
                    break;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(header_end) = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|pos| pos + 4)
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                let declared = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if declared == 0 || buf.len() >= header_end + declared {
                    break;
                }
            }
            sink.lock().expect("捕获锁不得中毒").extend_from_slice(&buf);
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&resp_body).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, captured, handle)
}

/// 捕获事件 `message` 字段的订阅者（断言豁免 warn 文案与去重）。
#[derive(Clone, Default)]
struct MessageCapture(Arc<Mutex<Vec<String>>>);

struct MessageVisitor<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for MessageVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0.push(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        }
    }
}

impl tracing::Subscriber for MessageCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut lines = self.0.lock().expect("捕获锁不得中毒");
        event.record(&mut MessageVisitor(&mut lines));
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn nondialog_params_ignored_warns_once_and_keeps_bytes() {
    // 进程级 warn 去重位与并行用例共享：持锁串行至断言结束（先持锁再复位）。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    crate::handler::llm::nonstream::reset_nondialog_params_ignored_warning();
    let capture = MessageCapture::default();
    let subscriber = capture.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("测试运行时须可构造");
        let (url, captured, server) = rt.block_on(capture_loopback(b"{}".to_vec()));
        let overrides = overrides_with_params();
        let client = reqwest::Client::new();
        let metrics = Arc::new(GatewayMetrics::default());
        let client_body = br#"{"probe":"nondialog-params-original"}"#.to_vec();
        crate::test_support::with_capture_subscriber(subscriber, || {
            // 两次请求：第一次记 warn，第二次不得重复（去重位已置位）。
            for _ in 0..2 {
                let ctx = NondialogCtx {
                    protocol: Protocol::NonDialog,
                    metrics: &metrics,
                    overrides: Some(&overrides),
                    expand: crate::handler::llm::test_support::no_expand(),
                };
                let resp = rt.block_on(serve_nondialog_passthrough(
                    &client,
                    reqwest::Method::POST,
                    &url,
                    HeaderMap::new(),
                    client_body.clone(),
                    ctx,
                ));
                assert_eq!(resp.status(), axum::http::StatusCode::OK);
            }
        });
        let raw = captured.lock().expect("捕获锁不得中毒").clone();
        assert!(
            raw.windows(client_body.len())
                .any(|window| window == client_body.as_slice()),
            "NonDialog 请求体须逐字节等于客户端原文"
        );
        server.abort();
    });
    handle.join().expect("测试线程不得 panic");
    let messages = capture.0.lock().expect("捕获锁不得中毒").clone();
    let hits: Vec<&String> = messages
        .iter()
        .filter(|message| message.contains("NonDialog") && message.contains("params"))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "命中 params 的 NonDialog 请求须恰一次 warn（去重）: {messages:?}"
    );
}
