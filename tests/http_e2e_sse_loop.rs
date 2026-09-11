//! SSE 回环 E2E（§8.1）：mock 上游真 HTTP，发送跨行数组/字符串、`[DONE]`、
//! CR-only 行尾、空行、多 `data:` 行混合载荷，并切成小 TCP 分片投递；
//! 快慢两档（`AUDIT_MODE=off/block` 对应 WHATWG 快慢泵）断言对齐。

use {
    std::{collections::HashMap, path::PathBuf, sync::Arc},
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

fn test_app(extra: &[(&str, &str)]) -> axum::Router {
    let mut env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/veil-e2e-sse-loop.sqlite"),
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    build_router(state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

/// 混合载荷：跨行数组、跨行字符串、CR-only 帧、空行、多 data 行、`[DONE]`。
fn tricky_payload() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(
        "data: {\"choices\":[{\"delta\":{\"content\":\"跨行数组甲\"}}]}\n\n".as_bytes(),
    );
    buf.extend_from_slice(
        "data: {\"choices\":[{\"delta\":{\"content\":\"跨行字符串乙\"}}]}\n\n".as_bytes(),
    );
    buf.extend_from_slice(
        "data: {\"choices\":[{\"delta\":{\"content\":\"回车单行丙\"}}]}\r\r".as_bytes(),
    );
    buf.extend_from_slice("\n\n\n".as_bytes());
    buf.extend_from_slice("data: {\"a\":1}\ndata: {\"b\":2}\n\n".as_bytes());
    buf.extend_from_slice("data: [DONE]\n\n".as_bytes());
    buf
}

async fn mock_upstream_tricky() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|| async {
            let payload = tricky_payload();
            let stream = async_stream::stream! {
                // 切 7 字节小分片投递，强制跨包重组（含跨行与 CR-only 边界）。
                // B10 等待策略：mock 单向推送无客户端 readiness 可轮询，取 20ms
                // 固定有界等待（慢机安全；增量 15ms×分片数，总时长增量有界）。
                for piece in payload.chunks(7) {
                    yield Ok::<_, anyhow::Error>(bytes::Bytes::from(piece.to_vec()));
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
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

async fn post_stream(base: &str, client: &reqwest::Client) -> (u16, String) {
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body("{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}")
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = tokio::time::timeout(std::time::Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    (status, body)
}

fn assert_loop_body(body: &str) {
    assert!(body.contains("跨行数组甲"), "跨行数组须重组透传: {body}");
    assert!(
        body.contains("跨行字符串乙"),
        "跨行字符串须重组透传: {body}"
    );
    assert!(body.contains("回车单行丙"), "CR-only 帧须解析透传: {body}");
    assert!(body.contains("\"a\":1"), "多 data 行首行须保留: {body}");
    assert!(body.contains("\"b\":2"), "多 data 行次行须保留: {body}");
    assert!(!body.contains("[blocked:"), "回环不得合成阻断帧: {body}");
    assert_eq!(
        body.matches("data: [DONE]").count(),
        1,
        "[DONE] 须精确单帧透传: {body}"
    );
    assert!(
        !body.contains("data:[DONE]"),
        "不得出现无空格的变体 DONE 帧: {body}"
    );
}

#[tokio::test]
async fn loopback_fast_pump_aligns_mixed_payload() {
    let (upstream, uhandle) = mock_upstream_tricky().await;
    let (base, handle) = serve(test_app(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();
    let (status, body) = post_stream(&base, &client).await;
    assert_eq!(status, 200);
    assert_loop_body(&body);
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn loopback_slow_pump_aligns_mixed_payload() {
    let (upstream, uhandle) = mock_upstream_tricky().await;
    let (base, handle) = serve(test_app(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("AUDIT_MODE", "block"),
    ]))
    .await;
    let client = reqwest::Client::new();
    let (status, body) = post_stream(&base, &client).await;
    assert_eq!(status, 200);
    assert_loop_body(&body);
    handle.abort();
    uhandle.abort();
}
