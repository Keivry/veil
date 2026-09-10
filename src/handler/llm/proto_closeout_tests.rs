//! 协议面 closeout 集成单测（`veil-llm-proto-closeout` B1-B8）：空流/缺 [DONE]/错误终端/
//! message_delta 一致性/断序容忍/Responses 用量。辅助函数复用 `super::stream_tests`
//! （`#[cfg(test)]` 门控，见 `mod.rs` 声明）。

use {
    super::{
        pump::StreamPumpCtx,
        stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
    },
    crate::{
        config::AuditMode,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    std::{path::PathBuf, sync::Arc},
};

/// 与 [`pump_ctx`] 同构，但回传可读的 `GatewayMetrics`（断言截断/计数用）。
fn tracked_ctx(
    protocol: Protocol,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> (StreamPumpCtx, Arc<GatewayMetrics>) {
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(protocol, scope, vault, detector);
    ctx.gateway_metrics = metrics.clone();
    (ctx, metrics)
}

#[tokio::test]
async fn vacuum_stream_anthropic_stays_open_ended_without_message_stop() {
    // B2.1：Anthropic 真空流对齐 chat——零合成帧、无 message_stop，仅记 open_ended。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, metrics) = tracked_ctx(Protocol::Anthropic, scope, vault, detector);
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    assert!(frames.is_empty(), "Anthropic 真空流须零合成帧: {frames:?}");
    let joined = frames.join("");
    assert!(
        !joined.contains("message_stop"),
        "不得合成 message_stop: {joined}"
    );
    assert!(!joined.contains("content_block_stop"), "不得合成块终止");
    assert!(!outcome.block_injected, "真空 open-ended 不得注阻断帧");
    assert!(!outcome.terminal_injected, "无帧发出时不得标记终端已注入");
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "须记 open_ended 可观测"
    );
    server.abort();
}

#[tokio::test]
async fn vacuum_stream_three_protocol_e2e_comparison() {
    // B2.2：三协议空流 e2e 对照——chat/anthropic 零帧且正常关闭；responses 恰一 failed。
    for proto in [Protocol::Chat, Protocol::Anthropic] {
        let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (ctx, metrics) = tracked_ctx(proto, scope, vault, detector);
        let (outcome, frames) = collect_pump(upstream, ctx).await;
        assert!(frames.is_empty(), "{proto:?} 真空流须零帧: {frames:?}");
        assert!(!outcome.terminal_injected, "{proto:?} 不得标记终端已注入");
        assert_eq!(
            metrics.truncated_count("open_ended"),
            1,
            "{proto:?} 须记 open_ended"
        );
        server.abort();
    }
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, metrics) = tracked_ctx(Protocol::Responses, scope, vault, detector);
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.failed"))
            .count(),
        1,
        "responses 真空流恰一 failed: {frames:?}"
    );
    assert!(!frames.join("").contains("response.completed"));
    assert!(outcome.terminal_injected, "responses 合成 failed 须落位");
    assert_eq!(metrics.truncated_count("synthesized_failed"), 1);
    server.abort();
}

#[tokio::test]
async fn chat_finish_reason_without_done_marks_open_ended_without_synthesis() {
    // B3.2：Chat 已见 finish_reason:"stop" 后 EOF 无 [DONE] → open_ended，零合成帧。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, metrics) = tracked_ctx(Protocol::Chat, scope, vault, detector);
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(joined.contains("hi"), "内容帧须透传: {joined}");
    assert!(joined.contains("\"finish_reason\":\"stop\""));
    assert!(!joined.contains("[DONE]"), "不得合成 [DONE]: {joined}");
    assert!(
        !joined.contains("empty-stream"),
        "不得合成空流兜底: {joined}"
    );
    assert!(!outcome.terminal_injected, "不得伪造终端");
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "缺 [DONE] 须记 open_ended"
    );
    server.abort();
}

#[tokio::test]
async fn responses_error_event_synthesizes_exactly_one_failed() {
    // B4.1：Responses `error` 事件 → 恰一 response.failed，无 completed，无重复终端。
    let sse = b"data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, _metrics) = tracked_ctx(Protocol::Responses, scope, vault, detector);
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.failed"))
            .count(),
        1,
        "error 须映射为恰一 failed: {joined}"
    );
    assert!(!joined.contains("response.completed"), "不得出现 completed");
    assert!(
        !joined.contains("response.incomplete"),
        "原始 error 不得透出"
    );
    assert!(outcome.terminal_injected, "映射后 terminal 须落位");
    server.abort();
}

#[tokio::test]
async fn anthropic_tool_use_stop_plus_message_delta_audits_once() {
    // B5.2：tool_use 槽在 content_block_stop 完成并审计恰一次；
    // 同流 message_delta 不重复审计/清理（粘滞终止与按槽清理职责正交）。
    let sse = br#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"exec","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"rm -rf /\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":2}}

event: message_stop
data: {"type":"message_stop"}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Anthropic, scope, vault, detector);
    ctx.audit_mode = AuditMode::Block;
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    assert!(outcome.block_injected, "危险 tool 须阻断");
    let joined = frames.join("");
    assert_eq!(
        joined.matches("[blocked:").count(),
        1,
        "审计恰一次（message_delta 不得重复触发）: {joined}"
    );
    assert_eq!(
        frames.iter().filter(|f| f.contains("message_stop")).count(),
        1,
        "恰一终端帧"
    );
    assert!(!joined.contains("rm -rf"), "危险参数不得泄漏: {joined}");
    server.abort();
}

#[tokio::test]
async fn responses_out_of_order_sequence_number_tolerated_passthrough() {
    // B6.1：sequence_number 断序帧原样透传、不 panic、恰一终端、不升级错误。
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":5,\"delta\":\"A\"}\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"B\"}\n\ndata: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"r1\",\"status\":\"completed\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, metrics) = tracked_ctx(Protocol::Responses, scope, vault, detector);
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(
        joined.contains("\"delta\":\"A\"") && joined.contains("\"delta\":\"B\""),
        "断序两帧均须原样透传: {joined}"
    );
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed"))
            .count(),
        1,
        "恰一终端"
    );
    assert!(
        !joined.contains("response.failed"),
        "不得升级为 failed: {joined}"
    );
    assert_eq!(
        metrics.terminal_fallback_count(),
        0,
        "合法 JSON 断序不得走兜底（无错误升级）"
    );
    server.abort();
}

#[tokio::test]
async fn responses_usage_recorded_from_completed_without_injection() {
    // B1.5 本地 mock 对照：Responses 不注入 stream_options，用量仍自
    // `response.completed.response.usage` 记录（真上游对照延后部署，R1 保持待命）。
    let sse = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":12,\"output_tokens\":45,\"total_tokens\":57}}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let admin_metrics = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-b1-5-usage-test.sqlite",
    )));
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.admin_metrics = admin_metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    assert!(
        frames.iter().any(|f| f.contains("response.completed")),
        "完成帧须透传: {frames:?}"
    );
    let snap = admin_metrics.snapshot();
    assert_eq!(
        (
            snap.prompt_tokens,
            snap.completion_tokens,
            snap.total_tokens
        ),
        (12, 45, 57),
        "Responses 用量须自 response.completed 记录，不依赖请求注入"
    );
    assert_eq!(snap.per_protocol.get("v1/responses"), Some(&1));
    server.abort();
}
