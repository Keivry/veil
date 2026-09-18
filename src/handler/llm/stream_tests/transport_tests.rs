//! S5/D5 + D6/S11 传输错误与中途断流终端矩阵（自 `stream_tests.rs` 拆出，
//! 测试名与断言不变）。

use {super::*, crate::service::block_inject};

#[tokio::test]
async fn stream_transport_error_observed() {
    // S5/D5：`chunk()` 返回 `Err` 时须记 warn + 截断观测，不静默按 EOF 退出；
    // Chat 按 D6 补恰一 `[DONE]` 收尾。
    let body = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\xe7\x94\xb2\"}}]}\n\n"
        .to_vec();
    let (url, server) = broken_body_server("text/event-stream", body.len() + 128, body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(joined.contains('甲'), "已收分片须保留: {joined}");
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "传输错误须按 Chat 策略补恰一 [DONE]: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "chunk Err 须置截断观测（open_ended）"
    );
    server.abort();
}

#[tokio::test]
async fn midstream_truncation_terminal_matrix() {
    // D6/S11：三协议中途断流（chunk Err）终端口径矩阵。
    // Chat 补恰一 [DONE]（open_ended）；Anthropic 不合成 message_stop（open_ended）；
    // Responses 合成恰一 response.failed（synthesized_failed）。
    let chat = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"\xe7\x94\xb2\"}}]}\n\n"
        .to_vec();
    let (url, server) = broken_body_server("text/event-stream", chat.len() + 128, chat).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 断流须补恰一 [DONE]: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "Chat 记 open_ended"
    );
    server.abort();

    let anthropic = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\xe7\x94\xb2\"}}\n\n".to_vec();
    let (url, server) =
        broken_body_server("text/event-stream", anthropic.len() + 128, anthropic).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        0,
        "Anthropic 断流不得合成 message_stop: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "Anthropic 记 open_ended"
    );
    server.abort();

    let responses = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"\xe7\x94\xb2\"}\n\n".to_vec();
    let (url, server) =
        broken_body_server("text/event-stream", responses.len() + 128, responses).await;
    let upstream = reqwest::Client::new().get(&url).send().await.unwrap();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 断流须合成恰一 response.failed: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.truncated_count("synthesized_failed"),
        1,
        "Responses 记 synthesized_failed"
    );
    server.abort();
}
