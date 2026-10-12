//! 流泵终端收尾单测（自 `terminal_carry.rs` 拆出；测试名与断言不变）。
//!
//! 覆盖干净/异常 EOF 的 `open_ended` 记账、Chat 错误帧即终端语义、
//! Anthropic 中途断流不合成终止，以及超硬上限 fail-closed 合成协议终止帧。

use super::*;

#[tokio::test]
async fn clean_eof_not_open_ended() {
    // 有 finish_reason 无 [DONE] 的干净 EOF 不记 open_ended。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
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
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "干净收尾仍补恰一 [DONE]: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        0,
        "有 finish_reason 不得记 open_ended"
    );
    server.abort();
}

#[tokio::test]
async fn abnormal_eof_still_open_ended() {
    // 无成功收尾信号（无 finish_reason、无 [DONE]）的异常 EOF 仍记 open_ended。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
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
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "异常收尾仍补恰一 [DONE]: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "无 finish_reason 的异常 EOF 须记 open_ended"
    );
    server.abort();
}

async fn run_chat_error_stream(
    sse: &'static [u8],
) -> (
    crate::handler::llm::pump::PumpOutcome,
    Vec<String>,
    Arc<GatewayMetrics>,
) {
    let (url, server) = loopback_server(200, "text/event-stream", sse.to_vec()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (outcome, frames, metrics)
}

#[tokio::test]
async fn chat_error_frame_is_terminal() {
    // 错误载荷帧即终端——本帧作为终端帧透出，其后数据帧被终端守卫
    // 丢弃、流末不补 [DONE]；`choices` 内 `error` 的正常形态不误伤。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}

data: {"error":{"message":"rate limited","type":"server_error"}}

data: {"error":{"message":"late error"}}

data: {"choices":[{"index":0,"delta":{"content":"late"}}]}

"#;
    let (outcome, frames, _metrics) = run_chat_error_stream(sse).await;
    let joined = frames.join("");
    assert!(
        joined.contains("rate limited"),
        "首个错误帧须作终端帧透出: {joined}"
    );
    assert!(
        !joined.contains("late error"),
        "终端后重复错误帧不得透出: {joined}"
    );
    assert!(!joined.contains("late"), "终端后数据帧不得透出: {joined}");
    assert_eq!(
        crate::service::block_inject::terminal_count(&frames, "chat"),
        0,
        "错误帧即终端，不得再补 [DONE]: {joined}"
    );
    assert!(!outcome.block_injected);
}

#[tokio::test]
async fn chat_error_frame_no_done_no_open_ended() {
    // 错误帧终端不进入断流收尾——不补 [DONE]、不记
    // `open_ended`（观测为 `upstream_error`）。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}

data: {"error":{"message":"boom"}}

"#;
    let (_, frames, metrics) = run_chat_error_stream(sse).await;
    let joined = frames.join("");
    assert!(!joined.contains("data: [DONE]"), "不得补 [DONE]: {joined}");
    assert_eq!(
        metrics.truncated_count("open_ended"),
        0,
        "错误终端不得记 open_ended"
    );
    assert_eq!(metrics.truncated_count("upstream_error"), 1);
}

#[tokio::test]
async fn chat_error_frame_upstream_error() {
    // 新态 `upstream_error` 落 metrics 分标签计数，四态白名单口径
    // 与 `llm_gateway` 既有口径一致（四态之外不落该指标）。
    use crate::service::sse::TruncatedMode;
    assert_eq!(TruncatedMode::SilentDiscard.as_str(), "silent_discard");
    assert_eq!(TruncatedMode::OpenEnded.as_str(), "open_ended");
    assert_eq!(
        TruncatedMode::SynthesizedFailed.as_str(),
        "synthesized_failed"
    );
    assert_eq!(TruncatedMode::UpstreamError.as_str(), "upstream_error");
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}

data: {"error":{"message":"upstream broken"}}

"#;
    let (_, frames, metrics) = run_chat_error_stream(sse).await;
    assert_eq!(
        metrics.truncated_count("upstream_error"),
        1,
        "新态须落 metrics 分标签计数"
    );
    assert_eq!(
        metrics.truncated_count("open_ended") + metrics.truncated_count("synthesized_failed"),
        0,
        "四态互斥：同一流不得再落其他截断态"
    );
    let joined = frames.join("");
    assert!(joined.contains("upstream broken") && !joined.contains("[DONE]"));
}

#[tokio::test]
async fn anthropic_midstream_eof_no_message_stop() {
    // Anthropic 中途断流（已发内容帧后异常 EOF）仅记 `open_ended`，
    // 不合成 `message_stop` 或任何终端数据帧（真空流最小终止不适用于此）。
    let sse = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(joined.contains("hi"), "内容帧须保留: {joined}");
    assert!(
        !joined.contains("message_stop"),
        "中途断流不得合成 message_stop: {joined}"
    );
    assert_eq!(
        crate::service::block_inject::terminal_count(&frames, "anthropic"),
        0,
        "不得合成任何终端数据帧"
    );
    assert_eq!(metrics.truncated_count("open_ended"), 1);
    assert_eq!(metrics.truncated_count("upstream_error"), 0);
}

#[tokio::test]
async fn over_hard_cap_stream_synthesizes_chat_terminal() {
    // 泵级：超可配硬上限的未终结行尾 → fail-closed，收尾按协议合成恰一 `[DONE]`，
    // 记 `open_ended` 观测，不交付任何半帧（此前仅 parser 级覆盖）。
    let cap = 1024usize;
    let body = format!("data: {}", "x".repeat(cap * 2)).into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.sse_frame_hard_bytes = cap;
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(!joined.contains("xxxx"), "不得交付超硬限半帧: {joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "须合成恰一 [DONE]: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "须记 open_ended 观测"
    );
}

#[tokio::test]
async fn over_hard_cap_stream_synthesizes_responses_terminal() {
    // 泵级 Responses：超硬上限 fail-closed → 合成协议终止帧并记 `synthesized_failed` 观测。
    let cap = 1024usize;
    let body = format!("data: {}", "y".repeat(cap * 2)).into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.sse_frame_hard_bytes = cap;
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    let joined = frames.join("");
    assert!(!joined.contains("yyyy"), "不得交付超硬限半帧: {joined}");
    assert!(
        joined.contains("response.failed"),
        "Responses 须合成 response.failed: {joined}"
    );
    assert_eq!(
        metrics.truncated_count("synthesized_failed"),
        1,
        "须记 synthesized_failed 观测"
    );
}
