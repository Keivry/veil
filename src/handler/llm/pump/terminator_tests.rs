//! 4.2：`StreamTerminator` 收敛的行为锁定测试（终止闭合矩阵 + 注入幂等）。
//!
//! 复用 `crate::handler::llm::stream_tests` 的回环 mock（`collect_pump`/`fresh_arcs`/
//! `loopback_server`/`broken_body_server`/`pump_ctx`），不修改 `spawn_tests.rs`。

use {
    super::{
        PumpOutcome,
        spawn::terminator::{StreamTerminator, TerminalKind, TerminalPlan},
    },
    crate::{
        config::AuditMode,
        handler::llm::stream_tests::{
            broken_body_server,
            collect_pump,
            fresh_arcs,
            loopback_server,
            pump_ctx,
        },
        service::{
            block_inject,
            llm_gateway::{GatewayMetrics, Protocol},
            sse::StreamMeta,
        },
    },
    std::sync::Arc,
};

const CT: &str = "text/event-stream";

type PumpRun = (PumpOutcome, Vec<String>, Arc<GatewayMetrics>);

/// 固定回环上游（正常 EOF）泵一次；`audit` 打开审计阻断模式。
async fn pump_ok(proto: Protocol, body: Vec<u8>, audit: bool) -> PumpRun {
    let (url, server) = loopback_server(200, CT, body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(proto, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    if audit {
        ctx.req.audit_mode = AuditMode::Block;
    }
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (outcome, frames, metrics)
}

/// 中途传输错误上游（`chunk()` 返回 `Err`）泵一次。
async fn pump_broken(proto: Protocol, body: Vec<u8>) -> PumpRun {
    let (url, server) = broken_body_server(CT, body.len() + 128, body).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(proto, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    (outcome, frames, metrics)
}

fn proto_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Chat => "chat",
        Protocol::Anthropic => "anthropic",
        Protocol::Responses => "responses",
        Protocol::NonDialog => "non-dialog",
    }
}

/// 协议阻断输入：builtin 危险规则命中（`exec` + `rm -rf /`）。
fn block_body(proto: Protocol) -> Vec<u8> {
    match proto {
        Protocol::Chat => concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
            "\"id\":\"call-bad\",\"type\":\"function\",\"function\":{\"name\":\"exec\",",
            "\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        )
        .as_bytes()
        .to_vec(),
        Protocol::Anthropic => concat!(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,",
            "\"content_block\":{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"exec\",\"input\":{}}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,",
            "\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n",
        )
        .as_bytes()
        .to_vec(),
        Protocol::Responses => concat!(
            "data: {\"type\":\"response.output_item.done\",\"output_index\":0,",
            "\"item\":{\"type\":\"function_call\",\"id\":\"call-0\",\"name\":\"exec\",",
            "\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}\n\n",
        )
        .as_bytes()
        .to_vec(),
        Protocol::NonDialog => Vec::new(),
    }
}

/// 中途断流输入：已发一帧内容后异常 EOF。
fn midstream_body(proto: Protocol) -> Vec<u8> {
    match proto {
        Protocol::Chat => "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"甲\"}}]}\n\n"
            .as_bytes()
            .to_vec(),
        Protocol::Anthropic => concat!(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,",
            "\"delta\":{\"type\":\"text_delta\",\"text\":\"甲\"}}\n\n",
        )
        .as_bytes()
        .to_vec(),
        Protocol::Responses => concat!(
            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",",
            "\"sequence_number\":1,\"delta\":\"甲\"}\n\n",
        )
        .as_bytes()
        .to_vec(),
        Protocol::NonDialog => Vec::new(),
    }
}

#[tokio::test]
async fn stream_terminator_exact_one_terminal_matrix() {
    // 阻断：三协议各恰一终端（Chat [DONE] / Anthropic message_stop /
    // Responses response.completed），由单一 plan_block 入口产出。
    for proto in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
        let name = proto_name(proto);
        let (outcome, frames, _m) = pump_ok(proto, block_body(proto), true).await;
        let joined = frames.join("");
        assert!(
            outcome.block_injected,
            "{name} 阻断须置 block_injected: {joined}"
        );
        assert_eq!(
            block_inject::terminal_count(&frames, name),
            1,
            "{name} 阻断终端恰一: {joined}"
        );
    }

    // 中途断流（chunk Err）：Chat 恰一 [DONE] + open_ended；Responses 恰一
    // response.failed + synthesized_failed；Anthropic 零合成终端帧 + open_ended
    //（零合成帧即合法终止一次，不伪造 message_stop）。
    let (outcome, frames, m) = pump_broken(Protocol::Chat, midstream_body(Protocol::Chat)).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 断流恰一 [DONE]: {}",
        frames.join("")
    );
    assert_eq!(m.truncated_count("open_ended"), 1, "Chat 断流记 open_ended");
    assert!(
        outcome.terminal_injected,
        "Chat 中途断流终端帧实际下行，terminal_injected 须置位"
    );

    let (outcome, frames, m) =
        pump_broken(Protocol::Anthropic, midstream_body(Protocol::Anthropic)).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        0,
        "Anthropic 中途断流零合成终端帧（不得伪造 message_stop）: {}",
        frames.join("")
    );
    assert_eq!(
        m.truncated_count("open_ended"),
        1,
        "Anthropic 断流记 open_ended"
    );
    assert!(
        !outcome.terminal_injected,
        "Anthropic 中途断流零合成帧，terminal_injected 不得置位"
    );

    let (outcome, frames, m) =
        pump_broken(Protocol::Responses, midstream_body(Protocol::Responses)).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 断流恰一 failed: {}",
        frames.join("")
    );
    assert_eq!(
        m.truncated_count("synthesized_failed"),
        1,
        "Responses 断流记 synthesized_failed"
    );
    assert!(
        outcome.terminal_injected,
        "Responses 中途断流终端帧实际下行，terminal_injected 须置位"
    );

    // 真空流：Chat 恰一 [DONE]；Anthropic message_start + message_stop 各恰一；
    // Responses 恰一 response.failed（失败语义，不伪造 completed）。
    let (_, frames, m) = pump_ok(Protocol::Chat, Vec::new(), false).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        1,
        "Chat 真空流恰一 [DONE]: {}",
        frames.join("")
    );
    assert_eq!(m.truncated_count("open_ended"), 1);

    let (_, frames, _m) = pump_ok(Protocol::Anthropic, Vec::new(), false).await;
    let joined = frames.join("");
    assert_eq!(
        joined.matches("\"type\":\"message_start\"").count(),
        1,
        "Anthropic 真空流 message_start 恰一: {joined}"
    );
    assert_eq!(
        joined.matches("\"type\":\"message_stop\"").count(),
        1,
        "Anthropic 真空流 message_stop 恰一: {joined}"
    );

    let (_, frames, m) = pump_ok(Protocol::Responses, Vec::new(), false).await;
    let joined = frames.join("");
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 真空流恰一 failed: {joined}"
    );
    assert!(
        !joined.contains("response.completed"),
        "不得伪造完成: {joined}"
    );
    assert_eq!(m.truncated_count("synthesized_failed"), 1);

    // 上游 error：Chat error 帧自身终端、零合成帧 + upstream_error；Anthropic
    // error 帧自身终端、零合成帧；Responses 恰一合成 response.failed。
    let chat_err = b"data: {\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (outcome, frames, m) = pump_ok(Protocol::Chat, chat_err, false).await;
    assert!(!outcome.block_injected);
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        0,
        "Chat 上游 error 零合成终端帧: {}",
        frames.join("")
    );
    assert_eq!(
        m.truncated_count("upstream_error"),
        1,
        "Chat 上游 error 记 upstream_error"
    );

    let anth_err =
        b"event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (_, frames, m) = pump_ok(Protocol::Anthropic, anth_err, false).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "anthropic"),
        0,
        "Anthropic 上游 error 零合成终端帧: {}",
        frames.join("")
    );
    assert_eq!(
        m.truncated_count("upstream_error"),
        1,
        "R5-04：Anthropic 上游 error 须记 upstream_error（非 None/open_ended）"
    );

    let resp_err = b"data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (_, frames, _m) = pump_ok(Protocol::Responses, resp_err, false).await;
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "Responses 上游 error 恰一 failed: {}",
        frames.join("")
    );
}

#[test]
fn stream_terminator_injection_idempotent() {
    // MAJOR-6 + 单入口：任一 kind 闭合后，全部 plan_* 返回 None（不再产第二终端）。
    for kind in [
        TerminalKind::Block,
        TerminalKind::Midstream,
        TerminalKind::EmptyStream,
        TerminalKind::ResponsesError,
    ] {
        let mut t = StreamTerminator::new();
        let mut meta = StreamMeta::default();
        assert!(t.is_open(), "{kind:?} 初始须 Open");
        t.commit(&mut meta, kind, true, true);
        assert!(!t.is_open(), "{kind:?} commit 后须闭合");
        assert!(
            matches!(
                t.plan_block(
                    Protocol::Chat,
                    "audit-policy-block",
                    None,
                    "",
                    0,
                    None,
                    None
                ),
                TerminalPlan::None
            ),
            "{kind:?} 闭合后 plan_block 须 None"
        );
        assert!(
            matches!(
                t.plan_midstream(Protocol::Chat, None, "", false, None, None),
                TerminalPlan::None
            ),
            "{kind:?} 闭合后 plan_midstream 须 None"
        );
        assert!(
            matches!(t.plan_empty_stream("chat", "c", ""), TerminalPlan::None),
            "{kind:?} 闭合后 plan_empty_stream 须 None"
        );
        assert!(
            matches!(
                t.plan_responses_error("r", None, None, ""),
                TerminalPlan::None
            ),
            "{kind:?} 闭合后 plan_responses_error 须 None"
        );
        // 终态后重复 commit 为 no-op，不产生第二终端。
        t.commit(&mut meta, TerminalKind::Block, true, true);
        assert!(!t.is_open(), "{kind:?} 重复 commit 不得回退");
    }
}

#[tokio::test]
async fn block_frames_echo_stream_model_and_conv() {
    // R5-03/R5-39：泵内阻断帧回显流内 model 与会话 id（不得硬编码 unknown_model/blocked-0）。
    let body = concat!(
        "data: {\"id\":\"chatcmpl-echo\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,",
        "\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call-bad\",\"type\":\"function\",",
        "\"function\":{\"name\":\"exec\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}]}}]}\n\n",
        "data: {\"id\":\"chatcmpl-echo\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,",
        "\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
    )
    .as_bytes()
    .to_vec();
    let (outcome, frames, _m) = pump_ok(Protocol::Chat, body, true).await;
    assert!(outcome.block_injected, "须阻断");
    let joined = frames.join("");
    assert!(
        joined.contains("\"model\":\"gpt-4o\""),
        "阻断帧须回显流内 model: {joined}"
    );
    assert!(
        !joined.contains("\"model\":\"unknown_model\""),
        "不得硬编码 unknown_model: {joined}"
    );
    assert!(
        joined.contains("\"id\":\"chatcmpl-echo\""),
        "阻断帧须回显会话 id: {joined}"
    );
    // R5-26：拒绝即消费——触发阻断的 tool 帧内容不得在阻断终端之后下行。
    assert!(
        !joined.contains("rm -rf /") && !joined.contains("\"name\":\"exec\""),
        "触发帧内容不得透出: {joined}"
    );
}

#[tokio::test]
async fn terminal_then_final_block_no_second_terminal_but_observable() {
    // R5-35/D3：流已终端（Chat 错误帧）后收尾终审命中 Block——不注入第二终端，
    // 但 block_injected 为真、terminal_injected 不变（观测语义保留）。
    let body = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,",
        "\"id\":\"call-late\",\"type\":\"function\",\"function\":{\"name\":\"exec\",",
        "\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}]}}]}\n\n",
        "data: {\"error\":{\"message\":\"boom\"}}\n\n",
    )
    .as_bytes()
    .to_vec();
    let (outcome, frames, _m) = pump_ok(Protocol::Chat, body, true).await;
    let joined = frames.join("");
    assert!(
        outcome.block_injected,
        "收尾命中 Block 须保留 block_injected: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "chat"),
        0,
        "已终端后不得注入第二终端: {joined}"
    );
    assert!(
        !outcome.terminal_injected,
        "不得置 terminal_injected（未下行第二终端）: {joined}"
    );
}
