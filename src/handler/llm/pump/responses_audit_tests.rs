//! F3/D3 Responses 工具分片先审后放回归：未完成
//! `response.function_call_arguments.delta` 缓冲至槽 `.done`，审计后再放行/阻断，
//! 危险明文不得先于 done 抵达下游。

use crate::{
    config::AuditMode,
    handler::llm::{
        pump::StreamPumpCtx,
        stream_tests::{collect_pump, fresh_arcs, loopback_server},
    },
    service::{block_inject, llm_gateway::Protocol},
};

/// Block 模式 + 零边界缝窗：隔离审计缓冲行为，帧即时入 `agg`，断言确定。
fn block_ctx() -> StreamPumpCtx {
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx =
        crate::handler::llm::stream_tests::pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Block;
    ctx.pii_boundary_chars = 0;
    ctx
}

async fn run(sse: &'static [u8]) -> (crate::handler::llm::pump::PumpOutcome, Vec<String>) {
    let (url, server) = loopback_server(200, "text/event-stream", sse.to_vec()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let out = collect_pump(upstream, block_ctx()).await;
    server.abort();
    out
}

#[tokio::test]
async fn responses_tool_delta_buffered() {
    // 良性参数拆分两帧：须缓冲至 done，两分片与 done 同批释放（done 前不得下发）。
    let sse = br#"data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":"{\"query\":\"ALPHA"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":" OMEGA\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-0","output_index":0,"arguments":"{\"query\":\"ALPHA OMEGA\"}"}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(!outcome.block_injected, "良性分片不得阻断");
    let joined = frames.join("");
    assert!(
        joined.contains("ALPHA") && joined.contains("OMEGA"),
        "分片须在 done 后放行: {joined}"
    );
    assert!(
        frames.iter().any(|f| f.contains("ALPHA")),
        "分片须放行（不得整段丢弃）: {frames:?}"
    );
    for f in &frames {
        if f.contains("ALPHA") || f.contains("OMEGA") {
            assert!(
                f.contains("function_call_arguments.done"),
                "delta 须与 done 同批释放（done 前不得下发）: {f}"
            );
        }
    }
}

#[tokio::test]
async fn responses_tool_delta_allow_passthrough() {
    // 安全参数拆分两帧：审计 Allow，按原序放行。
    let sse = br#"data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":"{\"query\":\"ALPHA"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":" OMEGA\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-0","output_index":0,"arguments":"{\"query\":\"ALPHA OMEGA\"}"}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(!outcome.block_injected, "安全参数不得阻断");
    let joined = frames.join("");
    let (a, b) = (
        joined.find("ALPHA").expect("ALPHA 须放行"),
        joined.find("OMEGA").expect("OMEGA 须放行"),
    );
    assert!(a < b, "安全参数须按原序放行: {joined}");
    assert!(
        !joined.contains("audit-policy-block"),
        "不得注入阻断: {joined}"
    );
}

#[tokio::test]
async fn responses_tool_delta_no_leak_block() {
    // 危险参数拆分两帧：须先审后放——下游零危险明文、恰一阻断帧。
    let sse = br#"data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"{\"command\":\"rm "}

data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"-rf /\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-1","output_index":0,"arguments":"{\"command\":\"rm -rf /\"}"}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(outcome.block_injected, "危险参数须阻断");
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险明文不得到达下游: {joined}");
    assert!(
        !joined.contains("call-1"),
        "危险 item id 不得透传: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "阻断终端恰一: {joined}"
    );
}

#[tokio::test]
async fn responses_tool_multi_item_delta_e2e() {
    // 多 item + delta 拆分：item0 良性放行、item1 危险阻断，结论互不串扰。
    let sse = br#"data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":"{\"query\":\"SAFE"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-0","output_index":0,"delta":" DATA\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-0","output_index":0,"arguments":"{\"query\":\"SAFE DATA\"}"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":1,"delta":"{\"command\":\"rm "}

data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":1,"delta":"-rf /\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-1","output_index":1,"arguments":"{\"command\":\"rm -rf /\"}"}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(outcome.block_injected, "item1 危险调用须阻断");
    let joined = frames.join("");
    assert!(
        joined.contains("SAFE DATA"),
        "item0 良性参数须放行: {joined}"
    );
    assert!(joined.contains("call-0"), "item0 id 须放行: {joined}");
    assert!(
        !joined.contains("rm -rf"),
        "item1 危险明文不得透传: {joined}"
    );
    assert!(!joined.contains("call-1"), "item1 id 不得透传: {joined}");
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "阻断终端恰一: {joined}"
    );
}

#[tokio::test]
async fn web_search_action_audit_hold_stream() {
    // F11/D11：`web_search_call.action.query` 经完整流式 hold 进入审计（非仅提取单测）。
    let sse = br#"data: {"type":"response.output_item.done","output_index":0,"item":{"type":"web_search_call","id":"ws-bad","action":{"type":"search","query":"rm -rf /"}}}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(outcome.block_injected, "危险检索查询须阻断: {frames:?}");
    let joined = frames.join("");
    assert!(
        !joined.contains("rm -rf"),
        "危险查询明文不得到达下游: {joined}"
    );
    assert!(
        !joined.contains("ws-bad"),
        "危险 item id 不得透传: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "阻断终端恰一: {joined}"
    );
}

/// 与 [`run`] 同语义，接受动态构造的 SSE 体（四类 delta 危险/良性矩阵）。
async fn run_bytes(sse: Vec<u8>) -> (crate::handler::llm::pump::PumpOutcome, Vec<String>) {
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let out = collect_pump(upstream, block_ctx()).await;
    server.abort();
    out
}

#[tokio::test]
async fn responses_four_delta_block_matrix() {
    // RED-4：四类工具 delta 危险参数在 block 模式阻断且不透传，良性放行。
    let cases = [
        (
            "response.code_interpreter_call_code",
            "{\"code\":\"rm -rf /\"}",
        ),
        ("response.shell_call_command", "{\"command\":\"rm -rf /\"}"),
        ("response.mcp_call_arguments", "{\"query\":\"rm -rf /\"}"),
        (
            "response.custom_tool_call_input",
            "{\"input\":\"rm -rf /\"}",
        ),
    ];
    for (base, dangerous) in cases {
        let sse = format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\n",
            serde_json::json!({"type": format!("{base}.delta"), "item_id": "call-x", "output_index": 0, "delta": dangerous}),
            serde_json::json!({"type": format!("{base}.done"), "item_id": "call-x", "output_index": 0}),
            serde_json::json!({"type": "response.completed", "response": {"id": "r1", "status": "completed"}}),
        );
        let (outcome, frames) = run_bytes(sse.into_bytes()).await;
        assert!(outcome.block_injected, "{base} 危险参数须阻断");
        let joined = frames.join("");
        assert!(
            !joined.contains("rm -rf"),
            "{base} 危险明文不得到达下游: {joined}"
        );
        assert!(
            !joined.contains("call-x"),
            "{base} 危险 item id 不得透传: {joined}"
        );
        assert_eq!(
            block_inject::terminal_count(&frames, "responses"),
            1,
            "{base} 阻断终端恰一: {joined}"
        );

        let benign = format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\n",
            serde_json::json!({"type": format!("{base}.delta"), "item_id": "call-y", "output_index": 0, "delta": "{\"note\":\"hello\"}"}),
            serde_json::json!({"type": format!("{base}.done"), "item_id": "call-y", "output_index": 0}),
            serde_json::json!({"type": "response.completed", "response": {"id": "r1", "status": "completed"}}),
        );
        let (ok, ok_frames) = run_bytes(benign.into_bytes()).await;
        assert!(!ok.block_injected, "{base} 良性参数不得阻断");
        let ok_joined = ok_frames.join("");
        assert!(
            ok_joined.contains("hello"),
            "{base} 良性参数须放行: {ok_joined}"
        );
    }
}

#[tokio::test]
async fn responses_missing_item_done_blocked_param() {
    // D5/STP-1/RSP-2：仅在 `response.completed` 前发参数分片、不发 per-item `.done`，
    // 全局完成路径须先审后放——危险参数 Block 并筛除该槽不重放；与逐-item done
    // 路径（`responses_tool_delta_no_leak_block`）同 verdict。
    let sse = br#"data: {"type":"response.function_call_arguments.delta","item_id":"call-9","output_index":0,"delta":"{\"command\":\"rm "}

data: {"type":"response.function_call_arguments.delta","item_id":"call-9","output_index":0,"delta":"-rf /\"}"}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#;
    let (outcome, frames) = run(sse).await;
    assert!(outcome.block_injected, "缺 done + 危险参数须阻断");
    let joined = frames.join("");
    assert!(!joined.contains("rm -rf"), "危险明文不得到达下游: {joined}");
    assert!(
        !joined.contains("call-9"),
        "危险 item id 不得透传: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "阻断终端恰一: {joined}"
    );
}
