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
    ctx.req.gateway_metrics = metrics.clone();
    (ctx, metrics)
}

#[tokio::test]
async fn anthropic_vacuum_emits_minimal_start_and_stop() {
    // P2/D3：Anthropic 真空流补最小 `message_start`+`message_stop`：空 content、
    // null stop_reason、usage 全 0，无 `content_block_*`，不伪造成功。
    let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, metrics) = tracked_ctx(Protocol::Anthropic, scope, vault, detector);
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert_eq!(frames.len(), 2, "最小终止恰两帧: {frames:?}");
    let mut types: Vec<String> = Vec::new();
    for f in &frames {
        for line in f.lines() {
            if let Some(p) = line.strip_prefix("data: ") {
                let v: serde_json::Value = serde_json::from_str(p).expect("下游帧须为合法 JSON");
                types.push(v["type"].as_str().unwrap_or("").to_string());
                if v["type"] == "message_start" {
                    assert_eq!(
                        v["message"]["content"].as_array().map(|a| a.len()),
                        Some(0),
                        "content 须为空数组: {v}"
                    );
                    assert!(
                        v["message"]["stop_reason"].is_null(),
                        "stop_reason 须 null: {v}"
                    );
                    assert_eq!(v["message"]["usage"]["input_tokens"], 0);
                    assert_eq!(v["message"]["usage"]["output_tokens"], 0);
                }
            }
        }
    }
    assert_eq!(types, vec!["message_start", "message_stop"]);
    assert!(
        !joined.contains("content_block"),
        "不得注入 content_block_*: {joined}"
    );
    assert!(outcome.block_injected, "合成终端须置位 block_injected");
    assert!(outcome.terminal_injected, "最小终止须落位终端标记");
    assert_eq!(metrics.truncated_count("open_ended"), 1);
    server.abort();
}

#[tokio::test]
async fn vacuum_stream_three_protocol_e2e_comparison() {
    // P2：三协议真空流均补终止帧——chat 恰一 [DONE]、anthropic 最小终止、
    // responses 恰一 failed；open-ended 仅余 chat/anthropic metrics 观测口径。
    for proto in [Protocol::Chat, Protocol::Anthropic] {
        let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (ctx, metrics) = tracked_ctx(proto, scope, vault, detector);
        let (outcome, frames) = collect_pump(upstream, ctx).await;
        let joined = frames.join("");
        assert!(!frames.is_empty(), "{proto:?} 真空流须补终止帧");
        assert!(outcome.terminal_injected, "{proto:?} 须落位终端标记");
        if proto == Protocol::Chat {
            assert_eq!(
                frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
                1,
                "chat 真空流恰一 [DONE]: {joined}"
            );
        } else {
            assert!(
                joined.contains("message_start") && joined.contains("message_stop"),
                "anthropic 最小终止信封: {joined}"
            );
        }
        assert_eq!(
            metrics.truncated_count("open_ended"),
            1,
            "{proto:?} 须记 open_ended 观测"
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
async fn anthropic_error_terminal() {
    // P2/D3：Anthropic `type:"error"` 即终端——原样透传后不再发任何帧
    //（尤其不得注入 `message_stop` 或后续 message_delta）。
    let sse = b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"overloaded\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, _metrics) = tracked_ctx(Protocol::Anthropic, scope, vault, detector);
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(
        joined.contains("overloaded"),
        "error 帧须原样透传: {joined}"
    );
    assert_eq!(frames.len(), 1, "error 后不得透出任何数据帧: {frames:?}");
    assert!(
        !joined.contains("message_stop") && !joined.contains("message_delta"),
        "error 后不得注入 message_stop/message_delta: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn chat_finish_reason_without_done_synthesizes_single_done() {
    // P1/D2 + CHC-5/2.24：Chat 已见 finish_reason:"stop" 后 EOF 无 [DONE] →
    // 补发恰一 [DONE]，属干净收尾不记 open_ended（内容帧与 finish_reason 不丢）。
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
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "缺 [DONE] 须补发恰一: {joined}"
    );
    assert!(outcome.terminal_injected, "补发后终端须落位");
    assert_eq!(
        metrics.truncated_count("open_ended"),
        0,
        "有 finish_reason 的干净收尾不记 open_ended"
    );
    server.abort();
}

#[tokio::test]
async fn responses_error_single_failed() {
    // P4/D4：Responses `error` → 单帧 `response.failed`（携带上游 error message），
    // 不注入 `output_index` 合成序列、无重复序号、无 completed。
    let sse =
        b"data: {\"type\":\"error\",\"sequence_number\":2,\"error\":{\"message\":\"boom\"}}\n\n"
            .to_vec();
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
    assert!(
        joined.contains("\"message\":\"boom\""),
        "上游 error message 须随帧携带: {joined}"
    );
    assert!(!joined.contains("response.completed"), "不得出现 completed");
    assert!(
        !joined.contains("output_item.added") && !joined.contains("output_index"),
        "不得注入 output_index 合成序列: {joined}"
    );
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
    ctx.req.audit_mode = AuditMode::Block;
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
    ctx.req.admin_metrics = admin_metrics.clone();
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

#[tokio::test]
async fn responses_completed_then_error() {
    // N1：`response.completed` 后跟 `type:"error"`——终端恰一、无合成 failed、终端后无数据帧。
    let sse = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"status\":\"completed\"}}\n\ndata: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (ctx, _metrics) = tracked_ctx(Protocol::Responses, scope, vault, detector);
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert_eq!(
        frames
            .iter()
            .filter(|f| f.contains("response.completed"))
            .count(),
        1,
        "completed 恰一: {joined}"
    );
    assert!(
        !joined.contains("response.failed"),
        "终端后不得合成 failed: {joined}"
    );
    assert_eq!(
        crate::service::block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 终端恰一: {joined}"
    );
    let completed_idx = frames
        .iter()
        .position(|f| f.contains("response.completed"))
        .expect("须有 completed");
    assert!(
        frames[completed_idx + 1..]
            .iter()
            .all(|f| !f.contains("data:")),
        "终端后不得再透出数据帧: {frames:?}"
    );
    server.abort();
}

#[tokio::test]
async fn n1_single_terminal_completed_then_error_or_incomplete() {
    // N1：`completed → error` 与 `completed → incomplete` 两序列均恒恰一终端、无 failed。
    for tail in [
        "data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n",
        "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r1\",\"status\":\"incomplete\"}}\n\n",
    ] {
        let sse = format!(
            "data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"r1\",\"status\":\"completed\"}}}}\n\n{tail}"
        );
        let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (ctx, _metrics) = tracked_ctx(Protocol::Responses, scope, vault, detector);
        let (_outcome, frames) = collect_pump(upstream, ctx).await;
        let joined = frames.join("");
        assert_eq!(
            crate::service::block_inject::terminal_count(&frames, "responses"),
            1,
            "终端恰一（tail={tail:?}）: {joined}"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.failed"))
                .count(),
            0,
            "不得出现 failed（tail={tail:?}）: {joined}"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.completed"))
                .count(),
            1,
            "completed 恰一（tail={tail:?}）: {joined}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn p1_chat_done_three_scenarios() {
    // P1/D2 + CHC-5/2.24 三场景：finish_reason 后断流补发恰一且不记 open_ended；
    // usage 尾帧（choices: []）保留；上游已发 [DONE] 不重复补发。
    for (name, sse, expect_open_ended) in [
        (
            "finish_reason 后断流",
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n".to_vec(),
            0u64,
        ),
        (
            "finish_reason+usage 尾帧后断流",
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n\n".to_vec(),
            0,
        ),
        (
            "正常 [DONE] 不重复",
            b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".to_vec(),
            0,
        ),
    ] {
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (ctx, metrics) = tracked_ctx(Protocol::Chat, scope, vault, detector);
        let (_outcome, frames) = collect_pump(upstream, ctx).await;
        let joined = frames.join("");
        assert_eq!(
            frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
            1,
            "{name}: [DONE] 恰一: {joined}"
        );
        if name.contains("usage") {
            assert!(
                joined.contains("\"prompt_tokens\":1"),
                "{name}: usage 尾帧不得丢: {joined}"
            );
        }
        assert_eq!(
            metrics.truncated_count("open_ended"),
            expect_open_ended,
            "{name}: open_ended 观测须符合补发/不补发语义"
        );
        server.abort();
    }
}
