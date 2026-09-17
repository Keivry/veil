//! R5-01/D2：非 Chat `data: [DONE]` 非事件回归（自 `stream_tests.rs` 拆出守 800 行红线）。

use {
    crate::{
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            block_inject,
            llm_gateway::{GatewayMetrics, Protocol},
        },
    },
    std::sync::Arc,
};

#[tokio::test]
async fn non_chat_done_is_non_event_official_terminal_flows() {
    // R5-01/D2：`data: [DONE]` 仅 Chat 为终端标记；非 Chat 视为非事件（不置终端、
    // 不透出），官方终端照常产出，下游无 `[DONE]` 且终端恰一。
    let client = reqwest::Client::new();

    // ① Responses：[DONE] 在前、无官方终端 → 合成恰一 response.failed，下游无 [DONE]。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"hi\"}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "非 Chat 不得透出 [DONE]: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "须恰一官方终端: {joined}"
    );
    assert!(joined.contains("response.failed"), "缺合成终端: {joined}");

    // ② Anthropic：[DONE] 在前、message_stop 在后 → message_stop 照常透出恰一。
    let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"claude\"}}\n\ndata: [DONE]\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_o, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Anthropic 不得透出 [DONE]: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_stop\"").count(),
        1,
        "官方 message_stop 须恰一且不被 [DONE] 抑制: {joined}"
    );
    assert_eq!(
        metrics.sse_event_total(),
        2,
        "message_start + message_stop 各计 1；[DONE] 非事件不计（已声明计数变更）"
    );

    // ③ Responses：官方终端在前、[DONE] 在后 → 官方终端恰一、无 [DONE]。
    let sse = b"data: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":{\"id\":\"r1\",\"status\":\"completed\",\"output\":[]}}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "终端后 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        joined.matches("response.completed").count(),
        1,
        "官方终端须恰一: {joined}"
    );
}

#[tokio::test]
async fn done_only_stream_is_vacuum_for_non_chat_chat_terminal_unchanged() {
    // Oracle weak-test ④：上游唯一载荷为 `data: [DONE]` 的真空流——非 Chat 视 `[DONE]`
    // 为非事件、零有效帧，走真空流最小终止；Chat 仍以 `[DONE]` 为终端原样透出。
    let client = reqwest::Client::new();
    let sse = b"data: [DONE]\n\n".to_vec();

    // ① Responses：下游无 [DONE]，恰一 failed 家族终端。
    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Responses 真空 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 须恰一 failed 家族终端: {joined}"
    );
    assert!(
        joined.contains("response.failed"),
        "缺 response.failed: {joined}"
    );
    assert!(
        !joined.contains("response.completed") && !joined.contains("response.incomplete"),
        "不得合成 completed/incomplete: {joined}"
    );

    // ② Anthropic：下游无 [DONE]，最小 message_start + message_stop。
    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let joined = frames.join("");
    assert!(
        !joined.contains("[DONE]"),
        "Anthropic 真空 [DONE] 不得透出: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_start\"").count(),
        1,
        "Anthropic 须恰一 message_start: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_stop\"").count(),
        1,
        "Anthropic 须恰一 message_stop: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        1,
        "Anthropic 终端恰一: {joined}"
    );
    assert!(
        !joined.contains("content_block"),
        "真空流不得含 content_block_*: {joined}"
    );

    // ③ Chat：`[DONE]` 仍为终端标记，原样透出恰一。
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_o, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    server.abort();
    let joined = frames.join("");
    assert!(
        joined.contains("data: [DONE]"),
        "Chat 须原样透出 [DONE] 终端: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 终端恰一: {joined}"
    );
}
