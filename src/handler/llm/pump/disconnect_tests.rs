//! D3/ARH-1 断连中止回归：客户端断开后中止上游读取并回收泵任务，
//! 不等于继续拉取 `chunk()`；终端恰一语义不被破坏。

use {
    super::{StreamPumpCtx, spawn::spawn_stream_pump},
    crate::{
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{block_inject, llm_gateway::Protocol},
    },
    std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    },
};

/// 无限 SSE 上游：连接建立后持续投递 content 帧直到写入失败（下游关闭），
/// 写入失败时置 `closed`，供「上游连接被关闭」断言。
async fn infinite_sse_server() -> (String, tokio::task::JoinHandle<()>, Arc<AtomicBool>) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let head =
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
            if sock.write_all(head.as_bytes()).await.is_err() {
                flag.store(true, Ordering::SeqCst);
                continue;
            }
            let frame = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n";
            loop {
                if sock.write_all(frame).await.is_err() {
                    flag.store(true, Ordering::SeqCst);
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    });
    (url, handle, closed)
}

fn chat_ctx() -> StreamPumpCtx {
    let (scope, vault, detector) = fresh_arcs();
    pump_ctx(Protocol::Chat, scope, vault, detector)
}

#[tokio::test]
async fn disconnect_aborts_upstream_read() {
    // D3/ARH-1：下游断开后外层循环须跳出，泵任务在有限时间内结束（中止上游读取）。
    let (url, server, _closed) = infinite_sse_server().await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
    let handle = spawn_stream_pump(upstream, tx, chat_ctx());
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(rx);
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("断连后泵任务须在有限时间内结束（中止上游读取）");
    assert!(outcome.is_ok(), "泵任务不得 panic");
    server.abort();
}

#[tokio::test]
async fn disconnect_closes_upstream_connection() {
    // D3/ARH-1：断连回收泵任务后上游连接被关闭，mock 上游观察到写入失败。
    let (url, server, closed) = infinite_sse_server().await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
    let handle = spawn_stream_pump(upstream, tx, chat_ctx());
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("断连后泵任务须结束")
        .expect("泵任务不得 panic");
    let observed = tokio::time::timeout(Duration::from_secs(2), async {
        while !closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "断连后上游连接须被关闭（mock 观察到写入失败）"
    );
    server.abort();
}

#[tokio::test]
async fn disconnect_terminal_exactly_once() {
    // 正常收尾：Chat 终端恰一。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (outcome, frames) = collect_pump(upstream, chat_ctx()).await;
    assert!(outcome.terminal_injected, "正常收尾须有终端");
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "正常收尾终端恰一"
    );
    server.abort();

    // 断连即中止：下游在终端前断开，泵任务结束且已收帧无重复终端。
    let sse2 = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"b\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url2, server2) = loopback_server(200, "text/event-stream", sse2).await;
    let upstream2 = reqwest::Client::new()
        .get(&url2)
        .send()
        .await
        .expect("回环上游须可达");
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let handle = spawn_stream_pump(upstream2, tx, chat_ctx());
    let mut frames = Vec::new();
    if let Ok(Some(f)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
        frames.push(f);
    }
    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("断连后泵任务须在规定时间内结束")
        .expect("泵任务不得 panic");
    assert!(
        block_inject::terminal_count(&frames, "chat") <= 1,
        "断连不得产生重复终端: {frames:?}"
    );
    server2.abort();
}
