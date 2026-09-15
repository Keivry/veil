//! N1/D10 非流错误状态 + SSE 内容类型回归：`status>=400` 不再被 `looks_sse`
//! 分支改写为 200 假流，错误状态与正文字节一律透传（拆分见测试外迁模板）。

use {
    super::{loopback_server, test_ctx},
    crate::{
        handler::llm::nonstream::{NonstreamOutcome, serve_nonstream},
        service::llm_gateway::Protocol,
    },
};

async fn run(
    status: u16,
    body: Vec<u8>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let client = reqwest::Client::new();
    let (url, server) = loopback_server(status, "text/event-stream", body).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx(Protocol::Chat),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误状态 + SSE 内容类型须直接响应而非转流（不得合成 200 假流）");
    };
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读")
        .to_vec();
    (status, headers, bytes)
}

#[tokio::test]
async fn nonstream_4xx_sse_passthrough() {
    // N1/D10：上游 429 + `text/event-stream` 保状态与正文字节，不伪造 200 流。
    let body = b"data: {\"error\":\"rate limited\"}\n\n".to_vec();
    let (status, headers, bytes) = run(429, body.clone()).await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "状态须保留"
    );
    assert_eq!(bytes, body, "正文字节须逐字节保留");
    assert_eq!(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream"),
        "内容类型须保留"
    );
}

#[tokio::test]
async fn nonstream_error_sse_status_preserved() {
    // N1/D10：上游 500 + 疑似 SSE 正文不改写为 200，状态码保留。
    let body = b"data: {\"type\":\"error\",\"message\":\"boom\"}\n\n".to_vec();
    let (status, _headers, bytes) = run(500, body.clone()).await;
    assert_eq!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "500 不得被改写为 200"
    );
    assert_ne!(status, axum::http::StatusCode::OK);
    assert_eq!(bytes, body, "正文字节须逐字节保留");
}

#[tokio::test]
async fn nonstream_error_sse_empty_body() {
    // N1/D10：上游 500 + SSE 内容类型 + 空体——状态码保留，不合成 502/200。
    let (status, _headers, bytes) = run(500, Vec::new()).await;
    assert_eq!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "空体状态码须保留"
    );
    assert_ne!(status, axum::http::StatusCode::OK);
    assert_ne!(status, axum::http::StatusCode::BAD_GATEWAY);
    assert!(bytes.is_empty(), "空体须保持为空");
}
