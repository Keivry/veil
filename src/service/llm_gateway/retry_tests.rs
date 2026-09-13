//! `T13`/D11 拿头前瞬断重试分类测试：`is_request` 扩宽后单次瞬断可恢复、持续瞬断
//! 恒有界（初次 + 最多 3 次退避），而拿头后（`send()` 已返回 `Ok`）的中段断连
//! 不重试（fail-closed 收尾由调用方承载）。触 800 红线后按测试外迁模板独立成子模块。

use {
    super::*,
    std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    },
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    },
};

/// 每次连接先读走请求，再交 `serve` 决定响应/断开；返回监听 URL 与连接计数句柄。
async fn spawn_mock<F>(serve: F) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)
where
    F: Fn(usize, TcpStream) -> tokio::task::JoinHandle<()> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let handle = tokio::spawn(async move {
        let serve = Arc::new(serve);
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            drop(serve(n, sock));
        }
    });
    (url, accepted, handle)
}

#[tokio::test]
async fn retry_request_layer_transient() {
    // T13/D11：首次拿头前瞬断（`is_request`，非 connect/timeout）经一档退避后成功。
    let (url, accepted, server) = spawn_mock(|n, mut sock| {
        tokio::spawn(async move {
            if n == 0 {
                // 首次：读走请求后关闭，reqwest 归类为请求层瞬断（`is_request`）。
                return;
            }
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        })
    })
    .await;
    let client = reqwest::Client::new();
    let start = Instant::now();
    let resp = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await
    .expect("首次 is_request 瞬断后须退避重试成功");
    let elapsed = start.elapsed();
    server.abort();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "首次瞬断 + 一次重试 = 2 次连接（重试计数 1）"
    );
    assert!(
        elapsed >= Duration::from_millis(500),
        "须走一档 500ms 退避，实测 {elapsed:?}"
    );
}

#[tokio::test]
async fn retry_bounded_three_attempts() {
    // T13/D11：持续拿头前瞬断时最多 3 次退避（初次 + 3 = 4 次请求）后按网关错误返回。
    let (url, accepted, server) = spawn_mock(|_n, sock| {
        // 每次：读走请求后立即关闭，制造持续拿头前瞬断。
        tokio::spawn(async move { drop(sock) })
    })
    .await;
    let client = reqwest::Client::new();
    let start = Instant::now();
    let err = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await
    .expect_err("持续瞬断须返回网关错误");
    let elapsed = start.elapsed();
    server.abort();
    assert!(!err.to_string().is_empty());
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        MAX_RETRY_ATTEMPTS + 1,
        "初次 + 最多 3 次重试 = 4 次连接，无无限重试"
    );
    assert!(
        elapsed >= Duration::from_millis(3500),
        "退避 500+1000+2000 须走完，实测 {elapsed:?}"
    );
}

#[tokio::test]
async fn midstream_reset_no_retry() {
    // T13.2/D11：已拿到响应头（`send()` 返回 `Ok`）后上游断连，不重试；
    // 中段断连由调用方 fail-closed 收尾（此处断言读体报错，不发生第二次连接）。
    let (url, accepted, server) = spawn_mock(|_n, mut sock| {
        tokio::spawn(async move {
            // 完整响应头（声明 100000 字节）后只投递 8 字节即关闭 ⇒ 拿头后中段断连。
            let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\nconnection: close\r\n\r\n";
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(b"partial!").await;
            let _ = sock.flush().await;
            drop(sock);
        })
    })
    .await;
    let client = reqwest::Client::new();
    let start = Instant::now();
    let resp = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await
    .expect("拿到响应头后须返回 Ok，不得转 Err 重试");
    let elapsed = start.elapsed();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "拿头后中段断连不得发起重试"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "拿头后断连不得走退避，实测 {elapsed:?}"
    );
    assert!(
        resp.bytes().await.is_err(),
        "中段断连读体须报错（fail-closed 由调用方收尾）"
    );
    server.abort();
}
