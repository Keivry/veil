//! P3 流式任务回归（2.24/2.27/2.28）：终端真实 index、opaque carry 与干净收尾判定。

use {
    super::event::{is_anthropic_opaque_event, is_anthropic_thinking_event},
    crate::{
        config::AuditMode,
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::llm_gateway::{GatewayMetrics, Protocol},
    },
    serde_json::Value,
    std::sync::Arc,
};

#[tokio::test]
async fn anthropic_terminal_block_real_index() {
    // MSP-3/2.27：终端最终审计阻断 Anthropic 时用真实 content block index，
    // 多块流不再硬编码 0 导致错位。
    let sse = br#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a","name":"run","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"b","name":"exec","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Block;
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "终端最终审计须注入阻断帧: {joined}");
    assert!(
        joined.contains("\"index\":1"),
        "阻断帧须用真实 index 1: {joined}"
    );
    assert!(
        !joined.contains("\"index\":0"),
        "不得硬编码 index 0: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn opaque_branch_token_carry() {
    // MSP-4/2.28：thinking 明文 opaque 增量接入 TokenCarry，跨帧切开的凭证 token
    // 缝合后经还原路径还原为明文。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let (head, tail) = token.split_at(8);
    let sse = format!(
        r#"event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{head}"}}}}

event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{tail}"}}}}

event: message_stop
data: {{"type":"message_stop"}}

"#
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    assert!(
        joined.contains("my-secret-001"),
        "thinking 跨帧 token 须缝合还原: {joined}"
    );
    assert!(!joined.contains(&token), "token 不得残留: {joined}");
    server.abort();
}

#[test]
fn opaque_fallback_declared() {
    // MSP-4/2.28：signature/redacted 密文载体按 fail-closed 声明不接 carry。
    for raw in [
        r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"abc"}}"#,
        r#"{"type":"redacted_thinking","redacted_data":"abc"}"#,
        r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":"sig"}}"#,
    ] {
        let v: Value = serde_json::from_str(raw).expect("构造 JSON");
        assert!(is_anthropic_opaque_event(&v), "须为 opaque: {raw}");
        assert!(
            !is_anthropic_thinking_event(&v),
            "密文/签名载体不接 carry: {raw}"
        );
    }
    let thinking: Value = serde_json::from_str(
        r#"{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"x"}}"#,
    )
    .expect("构造 JSON");
    assert!(
        is_anthropic_thinking_event(&thinking),
        "thinking 明文可缝合"
    );
}

#[tokio::test]
async fn clean_eof_not_open_ended() {
    // CHC-5/2.24：有 finish_reason 无 [DONE] 的干净 EOF 不记 open_ended。
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
    // CHC-5/2.24：无成功收尾信号（无 finish_reason、无 [DONE]）的异常 EOF 仍记 open_ended。
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
