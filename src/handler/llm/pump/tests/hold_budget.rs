//! 审计 hold 缓冲预算回归（端到端泵路径）：单次大 tool 调用按 token 分片时
//! 不得因帧数或整帧信封字节被误判为洪泛。

use crate::{
    config::AuditMode,
    handler::llm::{
        pump::{PumpOutcome, StreamPumpCtx},
        tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
    },
    service::llm_gateway::Protocol,
};

/// 单槽 `deltas` 个 tool 参数分片（每片载荷 `chunk` 字节）的 Chat SSE 流。
fn chat_tool_stream(deltas: usize, chunk: usize) -> Vec<u8> {
    let mut sse = String::new();
    sse.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\
         \"id\":\"call-big\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\"}}]}}]}\n\n",
    );
    let text = "x".repeat(chunk);
    for _ in 0..deltas {
        sse.push_str(&format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\
             \"function\":{{\"arguments\":\"{text}\"}}}}]}}}}]}}\n\n"
        ));
    }
    sse.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
    );
    sse.push_str("data: [DONE]\n\n");
    sse.into_bytes()
}

async fn run(sse: Vec<u8>, ctx: StreamPumpCtx) -> (PumpOutcome, String) {
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (outcome, frames.join(""))
}

fn chat_block_ctx() -> StreamPumpCtx {
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Block;
    ctx
}

#[tokio::test]
async fn large_streamed_tool_call_not_rejected_by_frame_or_envelope_counting() {
    // 回归：8000 个分片、载荷合计约 20KB、预算 1MiB。旧实现按「整帧信封字节」
    // 计费（每帧数百字节 → 20KB 载荷放大成数 MB）且每帧都撞 4096 硬顶，
    // 于是同一流量被判 `audit-hold-overflow` 并提前结束回合。
    let mut ctx = chat_block_ctx();
    ctx.hold_max = 1_048_576;
    ctx.hold_max_frames = crate::config::AUDIT_HOLD_MAX_FRAMES_DEFAULT as usize;
    let (outcome, joined) = run(chat_tool_stream(8000, 3), ctx).await;
    assert!(
        !joined.contains("[blocked:"),
        "合法大 tool 调用不得注入阻断帧: {}",
        &joined[..joined.len().min(400)]
    );
    assert!(!outcome.block_injected, "不得置阻断位");
    assert!(
        joined.contains("get_weather"),
        "完整调用须放行到下游（hold 在完成事件后重放）"
    );
    assert!(joined.contains("[DONE]"), "流须正常收尾而非提前结束回合");
}

#[tokio::test]
async fn pending_byte_budget_still_rejects_oversized_buffer() {
    // 内存有界性保留：同一路径把预算压到 64 字节，载荷累计超限仍须 fail-closed。
    let mut ctx = chat_block_ctx();
    ctx.hold_max = 64;
    let (outcome, joined) = run(chat_tool_stream(64, 8), ctx).await;
    assert!(outcome.block_injected, "超字节预算须阻断: {joined}");
    assert!(
        joined.contains("[blocked: audit-hold-overflow]"),
        "阻断帧文本须逐字节不变: {joined}"
    );
}

#[tokio::test]
async fn zero_payload_frame_flood_still_rejected() {
    // 原始反洪泛意图保留：载荷为 0 的分片不增字节，仍须在独立维度上收敛——
    // 即便字节预算给到 1MiB、帧数上限放大到 65536。
    let mut ctx = chat_block_ctx();
    ctx.hold_max = 1_048_576;
    ctx.hold_max_frames = crate::config::AUDIT_HOLD_MAX_FRAMES_DEFAULT as usize;
    let mut sse = String::new();
    sse.push_str(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\
         \"id\":\"call-zero\",\"type\":\"function\",\"function\":{\"name\":\"run\",\
         \"arguments\":\"\"}}]}}]}\n\n",
    );
    // 零载荷分片上限为 4096，取 5000 片确定性越界。
    for _ in 0..5000 {
        // 每帧都带 id/name，确保被 `extract_tool_calls_with` 识别为 tool 分片
        // （仅空 arguments 的帧可能被提取层判为非 tool 事件，从而不进缓冲）。
        sse.push_str(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\
             \"id\":\"call-zero\",\"function\":{\"name\":\"run\",\"arguments\":\"\"}}]}}]}\n\n",
        );
    }
    let (outcome, joined) = run(sse.into_bytes(), ctx).await;
    assert!(outcome.block_injected, "零载荷洪泛须阻断: {joined}");
    assert!(
        joined.contains("[blocked: audit-hold-overflow]"),
        "阻断帧文本须逐字节不变: {joined}"
    );
}
