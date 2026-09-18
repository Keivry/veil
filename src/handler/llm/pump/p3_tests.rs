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
    // MSP-4/2.28 + B3：thinking 明文 opaque 增量接入 TokenCarry，跨帧切开的凭证
    // token 缝合后经还原路径还原为明文；token 须由请求侧脱敏实际产出方可还原
    // （minted-set 授权，返回值经残缺清理剥离、不消费）。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
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
    // A-6/F-08：错误载荷帧即终端——本帧作为终端帧透出，其后数据帧被终端守卫
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
    // A-6/F-08 + 2.5：错误帧终端不进入断流收尾——不补 [DONE]、不记
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
    // 2.6/GAP-2：新态 `upstream_error` 落 metrics 分标签计数，四态白名单口径
    // 与 canonical `llm-gateway` 一致（四态之外不落该指标）。
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
    // F-05/A-4：Anthropic 中途断流（已发内容帧后异常 EOF）仅记 `open_ended`，
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
async fn signature_delta_bytes_identical_while_neighbor_pii_masked() {
    // R8-08/D9：签名/密文载体帧无掩码直通——邻帧新检出 PII 被掩码，signature
    // 载荷（含 PII 形数字串）字节恒等、未被 `mask_span_bytes` 改写。
    let phone = "13812345678";
    let plain = format!(
        r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"call {phone}"}}}}"#
    );
    let signature = format!(
        r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"signature_delta","signature":"sig {phone} \"x"}}}}"#
    );
    let sse = format!(
        "event: content_block_delta\ndata: {plain}\n\nevent: content_block_delta\ndata: {signature}\n\nevent: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
    )
    .into_bytes();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Anthropic, scope, vault, detector),
    )
    .await;
    server.abort();
    let downstream_plain = frames
        .iter()
        .flat_map(|f| f.lines())
        .find_map(|l| {
            l.strip_prefix("data: ")
                .filter(|p| p.contains("text_delta"))
        })
        .expect("普通帧须送达下游");
    assert!(
        !downstream_plain.contains(phone),
        "邻帧新检出 PII 须掩码: {downstream_plain}"
    );
    assert!(
        downstream_plain.contains("__PII_"),
        "须注入响应侧 token: {downstream_plain}"
    );
    let downstream_sig = frames
        .iter()
        .flat_map(|f| f.lines())
        .find_map(|l| {
            l.strip_prefix("data: ")
                .filter(|p| p.contains("signature_delta"))
        })
        .expect("签名帧须送达下游");
    assert_eq!(downstream_sig, signature, "签名帧须字节恒等");
}

#[tokio::test]
async fn thinking_delta_masks_pii_and_stitches_token() {
    // R8-19/D9 对照：纯 `thinking_delta` 走普通帧路径——响应侧新 PII 被掩码，
    // 跨帧切开的凭据 token 仍经 `TokenCarry` 缝合还原（不被 opaque 直通旁路）。
    let (scope, vault, detector) = fresh_arcs();
    let token = vault.register("my-secret-001").expect("注册恒成功");
    let _ = scope
        .redact_request_plain(&vault, &detector, "my-secret-001")
        .await;
    let (head, tail) = token.split_at(8);
    let sse = format!(
        r#"event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{head}"}}}}

event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"thinking_delta","thinking":"{tail} call 13812345678"}}}}

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
    server.abort();
    let joined = frames.join("");
    assert!(
        joined.contains("my-secret-001"),
        "thinking 跨帧 token 须缝合还原: {joined}"
    );
    assert!(!joined.contains(&token), "token 不得残留: {joined}");
    assert!(
        !joined.contains("13812345678"),
        "thinking 明文中的 PII 须掩码: {joined}"
    );
    assert!(joined.contains("__PII_"), "须注入响应侧 token: {joined}");
}
