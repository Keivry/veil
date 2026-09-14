//! RED-5/RED-8 Chat 审计到期/全局完成分离、终端最终审计与截断审计回归（流泵级）。

use crate::{
    config::AuditMode,
    handler::llm::{
        pump::StreamPumpCtx,
        stream_tests::{collect_pump, fresh_arcs, loopback_server},
    },
    service::{block_inject, llm_gateway::Protocol},
};

fn chat_block_ctx() -> StreamPumpCtx {
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx =
        crate::handler::llm::stream_tests::pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.audit_mode = AuditMode::Block;
    ctx.pii_boundary_chars = 0;
    ctx
}

async fn run_with(
    sse: &'static [u8],
    ctx: StreamPumpCtx,
) -> (crate::handler::llm::pump::PumpOutcome, Vec<String>) {
    let (url, server) = loopback_server(200, "text/event-stream", sse.to_vec()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let out = collect_pump(upstream, ctx).await;
    server.abort();
    out
}

#[tokio::test]
async fn chat_late_tool_fragment_audited() {
    // RED-5：`finish_reason:"tool_calls"` 后晚到的危险 tool 分片不再被短路，
    // 仍累积入槽并在终端审计中被 `block` 阻断、不透传。
    let ctx = chat_block_ctx();
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-late","function":{"name":"run","arguments":"{\"cmd\":\"echo "}}]}}]}

data: {"choices":[{"index":0,"finish_reason":"tool_calls"}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"rm -rf /\"}"}}]}}]}

"#;
    let (outcome, frames) = run_with(sse, ctx).await;
    assert!(outcome.block_injected, "晚到危险分片须阻断: {frames:?}");
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险明文不得到达下游: {joined}");
}

#[tokio::test]
async fn terminal_flush_audits_unfinished_tool() {
    // RED-5：截断/未完成且未判定的 tool 参数在终端被审计，`block` 模式阻断且
    // 不透出参数明文。
    let ctx = chat_block_ctx();
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-u","function":{"name":"run","arguments":"{\"command\":\"rm -rf /\"}"}}]}}]}

"#;
    let (outcome, frames) = run_with(sse, ctx).await;
    assert!(
        outcome.block_injected,
        "未完成危险 tool 须终端审计阻断: {frames:?}"
    );
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险参数明文不得透出: {joined}");
    assert!(!joined.contains("call-u"), "危险 id 不得透出: {joined}");
}

#[tokio::test]
async fn terminal_flush_audit_idempotent() {
    // RED-5：已判定参数经 `release_audited` 移出持仓，终端最终审计不重复评估，
    // 阻断终端恒恰一。
    let ctx = chat_block_ctx();
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"run","arguments":"{\"command\":\"rm -rf /\"}"}}]}}]}

data: {"choices":[{"index":0,"finish_reason":"tool_calls"}]}

data: [DONE]

"#;
    let (outcome, frames) = run_with(sse, ctx).await;
    assert!(outcome.block_injected, "危险参数须阻断");
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "阻断终端恰一（幂等不重复评估）: {frames:?}"
    );
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险明文不得透出: {joined}");
}

#[tokio::test]
async fn truncation_unfinished_tool_audited() {
    // RED-8：截断未完成 tool 分片须产生审计记录/告警（含槽号/分片数、不含参数明文），
    // 并保留 `truncated_tool_dropped` 指标。
    let ctx = chat_block_ctx();
    let metrics = ctx.gateway_metrics.clone();
    let sink = ctx.audit_sink.clone();
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-u","function":{"name":"run","arguments":"{\"command\":\"rm -rf /\"}"}}]}}]}

"#;
    let (outcome, frames) = run_with(sse, ctx).await;
    assert!(outcome.block_injected, "未完成危险 tool 须阻断");
    assert!(
        metrics.truncated_tool_dropped_count() >= 1,
        "须记 truncated_tool_dropped 指标"
    );
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险参数明文不得透出: {joined}");
    let events = sink.admin().query_events(Some("audit"), None, 20);
    assert!(
        events.iter().any(|e| e.summary.contains("truncated")),
        "须有截断审计记录: {events:?}"
    );
    assert!(
        events.iter().all(|e| !e.summary.contains("rm -rf")),
        "审计记录不得含参数明文: {events:?}"
    );
}

#[tokio::test]
async fn normal_complete_no_truncation_audit() {
    // RED-8 回归：正常完成路径不产生截断型审计告警。
    let ctx = chat_block_ctx();
    let metrics = ctx.gateway_metrics.clone();
    let sink = ctx.audit_sink.clone();
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"cok","function":{"name":"run","arguments":"{\"note\":\"hello\"}"}}]}}]}

data: {"choices":[{"index":0,"finish_reason":"tool_calls"}]}

data: [DONE]

"#;
    let (outcome, frames) = run_with(sse, ctx).await;
    assert!(!outcome.block_injected, "良性完成不得阻断");
    assert_eq!(
        metrics.truncated_tool_dropped_count(),
        0,
        "正常完成无截断丢弃"
    );
    let events = sink.admin().query_events(Some("audit"), None, 20);
    assert!(
        events.iter().all(|e| !e.summary.contains("truncated")),
        "正常完成不得产生截断审计: {events:?}"
    );
    let joined = frames.join("");
    assert!(joined.contains("hello"), "良性参数须放行: {joined}");
}
