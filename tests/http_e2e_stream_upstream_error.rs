//! S6/D7 流式上游错误状态透传 E2E：`stream:true` 请求命中上游 `status>=400`
//! 或 2xx 非 `text/event-stream` 正文时，网关按非流口径保状态保正文透传，
//! 不改写为 200 SSE 假流；超限非错误体走 502 `response_too_large`。
//! 全部夹具为合成数据，无真实 PII。

use common::{serve, test_app_db};

mod common;

/// 固定状态码/内容类型/体的 mock 上游（无 SSE 形态）。
async fn mock_upstream(
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move || {
            let body = body.clone();
            async move {
                use axum::response::IntoResponse;
                let status = axum::http::StatusCode::from_u16(status).unwrap();
                if content_type.is_empty() {
                    (status, body).into_response()
                } else {
                    (
                        status,
                        [(axum::http::header::CONTENT_TYPE, content_type)],
                        body,
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

const CHAT_STREAM_BODY: &str =
    "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}";

async fn post_stream_true(base: &str) -> (u16, reqwest::header::HeaderMap, Vec<u8>) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(CHAT_STREAM_BODY)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp.bytes().await.unwrap().to_vec();
    (status, headers, bytes)
}

fn content_type(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn stream_upstream_error_passthrough() {
    // 500 JSON / 500 HTML / 500 空体：状态与正文字节逐字节一致，不入 SSE 泵。
    let json_err = br#"{"error":{"message":"upstream boom","type":"server_error"}}"#.to_vec();
    let html_err = b"<html><body>500 Internal Server Error</body></html>".to_vec();
    let cases: [(&str, &str, Vec<u8>); 3] = [
        (
            "/tmp/veil-e2e-s6-json.sqlite",
            "application/json",
            json_err.clone(),
        ),
        (
            "/tmp/veil-e2e-s6-html.sqlite",
            "text/html",
            html_err.clone(),
        ),
        (
            "/tmp/veil-e2e-s6-empty.sqlite",
            "application/json",
            Vec::new(),
        ),
    ];
    for (db, ct, body) in cases {
        let (upstream, uhandle) = mock_upstream(500, ct, body.clone()).await;
        let (base, handle) = serve(test_app_db(&[("LLM_UPSTREAM", upstream.as_str())], db)).await;
        let (status, headers, got) = post_stream_true(&base).await;
        assert_eq!(status, 500, "上游错误状态须保原码（ct={ct}）");
        assert_eq!(got, body, "上游错误正文字节须逐字节一致（ct={ct}）");
        assert!(
            !content_type(&headers).contains("text/event-stream"),
            "错误状态不得改写为 SSE 假流（ct={ct}）"
        );
        assert_eq!(
            headers.get("x-veil-protocol").and_then(|v| v.to_str().ok()),
            Some("chat"),
            "透传须标注协议（ct={ct}）"
        );
        handle.abort();
        uhandle.abort();
    }
}

#[tokio::test]
async fn stream_upstream_non_sse_body() {
    // 2xx 非 text/event-stream：正文原样透传，不改写为 200 SSE 假流。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"plain"}}],"usage":{}}"#.to_vec();
    let (upstream, uhandle) = mock_upstream(200, "application/json", up_body.clone()).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-s6-nonsse.sqlite",
    ))
    .await;
    let (status, headers, got) = post_stream_true(&base).await;
    assert_eq!(status, 200, "2xx 非 SSE 保原状态");
    assert_eq!(got, up_body, "2xx 非 SSE 正文字节须逐字节一致");
    assert!(
        content_type(&headers).contains("application/json"),
        "内容类型须保留上游 application/json"
    );
    assert!(
        !content_type(&headers).contains("text/event-stream"),
        "不得改写为 text/event-stream"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn stream_upstream_non_sse_oversize_returns_502() {
    // 非错误（2xx）非 SSE 正文超 NONSTREAM_MAX_BYTES ⇒ 502 response_too_large。
    let up_body = vec![b'x'; 64];
    let (upstream, uhandle) = mock_upstream(200, "application/json", up_body).await;
    let (base, handle) = serve(test_app_db(
        &[
            ("LLM_UPSTREAM", upstream.as_str()),
            ("NONSTREAM_MAX_BYTES", "8"),
        ],
        "/tmp/veil-e2e-s6-oversize.sqlite",
    ))
    .await;
    let (status, _headers, got) = post_stream_true(&base).await;
    assert_eq!(status, 502, "超限非错误体须 502");
    let text = String::from_utf8_lossy(&got);
    assert!(
        text.contains("response_too_large"),
        "超限体须为 response_too_large: {text}"
    );
    handle.abort();
    uhandle.abort();
}
