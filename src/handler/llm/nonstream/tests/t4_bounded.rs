//! T4/D4 非流响应体有界读取测试：`content-length` 预检（不读 body）、分块累计
//! 超限即 502、边界 `len == cap` 放行与 `status>=400` 超限错误体透传不改写。
//! 归属拆分：`nonstream/tests.rs` 触 800 红线后按测试外迁模板独立成子模块。

use {
    super::{loopback_server, test_ctx},
    crate::{
        handler::llm::nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        service::llm_gateway::Protocol,
    },
    std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn ctx_with_cap(protocol: Protocol, cap: usize) -> NonstreamCtx {
    NonstreamCtx {
        nonstream_max_bytes: cap,
        ..test_ctx(protocol)
    }
}

async fn read_body(resp: axum::http::Response<axum::body::Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读")
        .to_vec()
}

/// T4 预检 mock：声明 `declared` 字节 `content-length`，仅在客户端**仍在等待
/// body** 时才投递实际 body 并计数；客户端提前关闭（预检命中）则计数保持 0。
async fn mock_declared_length_no_body(
    declared: usize,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let served = Arc::new(AtomicUsize::new(0));
    let served_task = served.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {declared}\r\nconnection: close\r\n\r\n"
            );
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            let _ = sock.flush().await;
            // 250ms 内客户端关闭 ⇒ 预检命中（未读 body）；否则客户端在等 body。
            let mut probe = [0u8; 1];
            let closed =
                tokio::time::timeout(std::time::Duration::from_millis(250), sock.read(&mut probe))
                    .await;
            if !matches!(closed, Ok(Ok(0))) {
                let body = b"{\"id\":\"x\"}";
                if sock.write_all(body).await.is_ok() {
                    served_task.fetch_add(body.len(), Ordering::SeqCst);
                }
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, served, handle)
}

/// T4 分块 mock：`transfer-encoding: chunked` 投递 `body`（无 `content-length`）。
async fn mock_chunked(body: Vec<u8>, chunk_size: usize) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            for chunk in body.chunks(chunk_size) {
                let frame = format!("{:x}\r\n", chunk.len());
                if sock.write_all(frame.as_bytes()).await.is_err()
                    || sock.write_all(chunk).await.is_err()
                    || sock.write_all(b"\r\n").await.is_err()
                {
                    break;
                }
                let _ = sock.flush().await;
            }
            let _ = sock.write_all(b"0\r\n\r\n").await;
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

#[tokio::test]
async fn nonstream_oversize_content_length_precheck() {
    // T4/D4：声明超限 → 立即 502 `response_too_large`，上游 body 未被读取（计数 0）。
    let client = reqwest::Client::new();
    let (url, served, server) = mock_declared_length_no_body(1_000_000).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, 16),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("预检须直接响应而非转流");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    let body = read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).expect("超限体须为 JSON");
    assert_eq!(v["error"]["type"], "response_too_large");
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "声明超限时上游 body 不得被读取"
    );
}

#[tokio::test]
async fn nonstream_oversize_chunked_bounded_read() {
    // T4/D4：分块（无 content-length）累计超限即 502，不先全量缓存。
    let client = reqwest::Client::new();
    let up_body = vec![b'y'; 4096];
    let (url, server) = mock_chunked(up_body, 256).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, 16),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("分块超限须直接响应而非转流");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    let body = read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).expect("超限体须为 JSON");
    assert_eq!(v["error"]["type"], "response_too_large");
}

#[tokio::test]
async fn nonstream_oversize_non_json_200() {
    // T14/D12：200 非 JSON 体严格超限（`len > cap`，cap 取默认 8MB）→ 502
    // `response_too_large`；超限判定先于空体/非 JSON 502，不得落 `E_EMPTY_BODY`。
    let client = reqwest::Client::new();
    let cap = crate::config::NONSTREAM_MAX_BYTES_DEFAULT;
    let up_body = vec![b'x'; cap + 1];
    let (url, server) = mock_chunked(up_body, 1 << 20).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, cap),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("非 JSON 超限须直接响应而非转流");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    let body = read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).expect("超限体须为 JSON");
    assert_eq!(
        v["error"]["type"], "response_too_large",
        "非 JSON 200 超限须走超限 502，不得落空体分支"
    );
    assert!(
        v["error"].get("code").is_none(),
        "超限体不得携带空体错误码 E_EMPTY_BODY"
    );
}

#[tokio::test]
async fn nonstream_bounded_read_boundary() {
    // T4.2 边界 A：无 content-length 分块恰好 `len == cap` 放行（200）。
    let client = reqwest::Client::new();
    let upstream =
        br#"{"id":"x","model":"m","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let cap = upstream.len();
    let (url, server) = mock_chunked(upstream.clone(), 8).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, cap),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("边界放行须直接响应");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "len == cap 须放行"
    );
    let got: serde_json::Value =
        serde_json::from_slice(&read_body(resp).await).expect("放行体须为 JSON");
    let want: serde_json::Value = serde_json::from_slice(&upstream).unwrap();
    assert_eq!(got, want, "等于上限不得触发超限体");

    // T4.2 边界 B：`status>=400` 超限错误体按 N2/D6 透传，不改写为 502。
    let err_body = format!("busy: {}", "x".repeat(256)).into_bytes();
    let (url, server) = loopback_server(503, "text/plain", err_body.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx_with_cap(Protocol::Chat, 1),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误体须直接响应");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "错误状态超限不改写"
    );
    assert_eq!(
        read_body(resp).await.as_slice(),
        err_body.as_slice(),
        "错误体字节须透传"
    );
}
