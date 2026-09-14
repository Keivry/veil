//! RUN-4 回归：上游读取失败可观测（warn + 指标）且对外语义不变。

use {
    super::{BoundedBody, read_bounded_body},
    crate::{
        config::NONSTREAM_MAX_BYTES_DEFAULT,
        service::llm_gateway::{EmptyAction, GatewayMetrics, Protocol, classify_empty},
    },
    axum::http::StatusCode,
};

#[tokio::test]
async fn upstream_read_error_logged() {
    let client = reqwest::Client::new();
    let (url, server) = broken_body_server().await;
    let up = client
        .post(&url)
        .body("{}")
        .send()
        .await
        .expect("须先拿到响应头");
    let metrics = GatewayMetrics::default();
    let result = read_bounded_body(up, NONSTREAM_MAX_BYTES_DEFAULT, &metrics).await;
    server.abort();
    assert!(
        matches!(result, BoundedBody::Complete(b) if b.is_empty()),
        "读取失败须退化为空体"
    );
    assert_eq!(
        metrics.upstream_read_error_count(),
        1,
        "读取失败须累加可观测计数"
    );
    let src = include_str!("../nonstream.rs");
    assert!(
        src.contains("上游响应体读取失败，退化为空体"),
        "须记含错误与已读字节的 warn"
    );
    assert!(src.contains("read_bytes"));
}

#[tokio::test]
async fn upstream_read_error_semantics_unchanged() {
    let client = reqwest::Client::new();
    let (url, server) = broken_body_server().await;
    let up = client
        .post(&url)
        .body("{}")
        .send()
        .await
        .expect("须先拿到响应头");
    let metrics = GatewayMetrics::default();
    let bytes = match read_bounded_body(up, NONSTREAM_MAX_BYTES_DEFAULT, &metrics).await {
        BoundedBody::Complete(b) => b,
        BoundedBody::Oversize => panic!("读取失败不得判超限"),
    };
    server.abort();
    assert_eq!(
        classify_empty(true, bytes.len(), false, 200),
        EmptyAction::NonStreamTo502,
        "对外仍走既有空体分类路径"
    );
    let resp = super::super::empty_body_response(Protocol::Chat);
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "对外仍为既有 502 E_EMPTY_BODY，无新错误码"
    );
}

async fn broken_body_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("地址可读")
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\nconnection: close\r\n\r\n";
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(b"{\"partial\"").await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}
