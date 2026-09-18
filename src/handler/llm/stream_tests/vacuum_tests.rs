//! 真空流/心跳帧终端 E2E（自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {super::*, crate::handler::llm::pump::should_synthesize_empty_stream};

#[tokio::test]
async fn vacuum_stream_chat_synthesizes_single_done() {
    // P2/D2：chat 零字节零残余时补恰一 `data: [DONE]`（不伪造内容/usage），
    // 下游可解析收尾；终端标记落位。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "真空流恰一 [DONE]: {joined}"
    );
    assert!(!joined.contains("\"delta\""), "不得伪造内容帧: {joined}");
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    assert!(outcome.terminal_injected, "终端标记须落位");
    server.abort();
}

#[tokio::test]
async fn vacuum_stream_responses_still_synthesizes_failed() {
    // C8 真空流 E2E 对照：responses 零字节时仍合成 failed 终端（失败语义）。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "responses 真空流须合成 failed 终端");
    assert!(
        joined.contains("response.failed"),
        "须含 failed 终端: {joined}"
    );
    assert!(
        !joined.contains("response.completed"),
        "不得伪造完成: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn empty_data_heartbeat_frames_dropped_not_forwarded() {
    // L17 + P2：纯空 `data:` 心跳（`event:` 独占帧 / 空 data 帧）不得透传；
    // 空帧不计入 `any_frame_sent`，chat 真空守门仍补恰一 `[DONE]` 收尾。
    // 注：裸 `data:\n\n` 由解析器直接过滤，本分支覆盖带 `event:` 的空帧形态。
    let up_body = b"event: ping\n\nevent: message\ndata:\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", up_body).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert!(
        !joined.contains("event: ping") && !joined.contains("event: message"),
        "空心跳帧不得透传: {joined}"
    );
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "空心跳流仍走真空守门补 [DONE]: {joined}"
    );
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    assert!(outcome.terminal_injected, "终端标记须落位");
    server.abort();
}

#[tokio::test]
async fn comment_only_heartbeat_does_not_gate_empty_synthesis_e11() {
    // E11/D6：纯 `:` 注释心跳透传但不置位 `any_frame_sent`；
    // responses 纯心跳仍合成 failed 终端（守门
    // `should_synthesize_empty_stream(false,false,false)` 为真）。
    assert!(should_synthesize_empty_stream(false, false, false));
    let up_body = b": ping\n\n: keepalive\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", up_body).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(joined.contains(": ping"), "注释帧须透传: {joined}");
    assert!(
        joined.contains("response.failed"),
        "纯心跳流仍须合成终端: {joined}"
    );
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    server.abort();
}
