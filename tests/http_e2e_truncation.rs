//! 上游中途断流 E2E（§8.1/D6）：mock 上游真 HTTP，发送部分 SSE 分片后直接结束
//! 响应（不断链语义），断言下游 200、已透传分片保留、无伪造成功 `stop`、无合成
//! 阻断帧；Chat 按 D6 补恰一 `data: [DONE]` 传输层终止。

use common::{serve, test_app_router};

mod common;

/// 中途断流的上游：两个数据分片后直接结束流，不发 `[DONE]`。
async fn mock_upstream_truncated() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|| async {
            let frames = [
                "data: {\"choices\":[{\"delta\":{\"content\":\"截断前分片甲\"}}]}\n\n".to_string(),
                "data: {\"choices\":[{\"delta\":{\"content\":\"截断前分片乙\"}}]}\n\n".to_string(),
            ];
            let stream = async_stream::stream! {
                // 首分片拆两次写，顺带覆盖跨包重组路径（按字符边界拆，不切断 UTF-8）。
                let mid = frames[0].floor_char_boundary(frames[0].len() / 2);
                yield Ok::<_, anyhow::Error>(bytes::Bytes::from(frames[0].as_bytes()[..mid].to_vec()));
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                yield Ok::<_, anyhow::Error>(bytes::Bytes::from(frames[0].as_bytes()[mid..].to_vec()));
                yield Ok::<_, anyhow::Error>(bytes::Bytes::from(frames[1].clone()));
            };
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                axum::body::Body::from_stream(stream),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

async fn post_stream(
    base: &str,
    client: &reqwest::Client,
) -> (u16, String, reqwest::header::HeaderMap) {
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body("{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = tokio::time::timeout(std::time::Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    (status, body, headers)
}

#[tokio::test]
async fn truncated_chat_backfills_single_done_keeps_fragments() {
    let (upstream, uhandle) = mock_upstream_truncated().await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();
    let (status, body, headers) = post_stream(&base, &client).await;
    assert_eq!(status, 200);
    assert!(
        headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/event-stream"),
        "下游仍须为 SSE 形态"
    );
    assert!(body.contains("截断前分片甲"), "已透传分片不得丢失: {body}");
    assert!(body.contains("截断前分片乙"), "已透传分片不得丢失: {body}");
    assert!(
        !body.contains("[blocked:"),
        "开环截断不得合成阻断帧: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "chat 截断不得伪造成功终止: {body}"
    );
    assert_eq!(
        body.matches("data: [DONE]").count(),
        1,
        "D6：Chat 中途断流须补恰一 [DONE] 传输层终止: {body}"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn truncated_slow_audit_backfills_single_done() {
    let (upstream, uhandle) = mock_upstream_truncated().await;
    let (base, handle) = serve(test_app_router(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("AUDIT_MODE", "block"),
    ]))
    .await;
    let client = reqwest::Client::new();
    let (status, body, _) = post_stream(&base, &client).await;
    assert_eq!(status, 200);
    assert!(body.contains("截断前分片甲"), "{body}");
    assert!(body.contains("截断前分片乙"), "{body}");
    assert!(!body.contains("[blocked:"), "{body}");
    assert_eq!(body.matches("data: [DONE]").count(), 1, "{body}");
    handle.abort();
    uhandle.abort();
}
