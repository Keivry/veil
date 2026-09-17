//! R5-14/D5 流式 fail-closed 与 R5-09/D10 流式写回失败计数（sibling，守 800 行红线）。

use {
    crate::{
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            block_inject,
            llm_gateway::{GatewayMetrics, Protocol},
            redaction::{ConversationKey, PreviousResponseMap, Scope},
        },
    },
    std::sync::Arc,
};

fn conversation_scope() -> Arc<Scope> {
    Arc::new(Scope::new().with_conversation(
        ConversationKey::for_test("test-conversation-key"),
        "tenant-fp".to_string(),
        Arc::<[u8]>::from(&b"secret"[..]),
        Arc::new(PreviousResponseMap::new(8)),
    ))
}

#[tokio::test]
async fn streaming_pii_unavailable_rejects_with_block_frames_no_plaintext() {
    // R5-14/D5：响应侧熵源故障——复用阻断臂，下发协议阻断帧且不外泄未脱敏明文。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"call 13812345678\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    scope.pii_scope().force_entropy_failure(true);
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope.clone(), vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(scope.pii_unavailable(), "熵源故障须置失败信号");
    assert!(outcome.block_injected, "须走阻断臂: {joined}");
    assert!(
        !joined.contains("13812345678"),
        "不得外泄未脱敏明文: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "须恰一协议阻断终端: {joined}"
    );
}

#[tokio::test]
async fn streaming_writeback_miss_counts_once_on_responses_terminal_without_id() {
    // R5-09/D10：`conversation` 模式 Responses 终端无 id → 恰计一次；
    // 缺写回上下文（`request` 模式）同形流 → 恒 0（不误计）。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"hi\"}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"\",\"status\":\"completed\",\"output\":[]}}\n\n".to_vec();

    let (url, server) = loopback_server(200, "text/event-stream", sse.clone()).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (_scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, conversation_scope(), vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        1,
        "conversation + Responses 终端缺 id 须恰计一次"
    );

    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, _frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "无写回上下文 MUST NOT 计入"
    );
}
