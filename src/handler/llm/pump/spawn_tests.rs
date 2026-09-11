//! 流泵决策点直测（`veil-test-coverage-fill` T1/D1）：`decide.rs` 纯函数真值表
//! + `spawn_stream_pump` 泵直测；harness 复用 `stream_tests` 的回环 mock
//!   （`pump_ctx`/`loopback_server`/`collect_pump`），无外部网络、无墙钟断言。

use {
    super::{
        decide::{
            ResponsesAction,
            StickyAction,
            responses_control_action,
            should_backfill_chat_done,
            should_buffer_tool_frame,
            should_suppress_held_output,
            sticky_suppress_action,
            tool_replay_slot,
        },
        event::should_synthesize_empty_stream,
        spawn::guard_restored_frame,
    },
    crate::{
        config::AuditMode,
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            block_inject,
            llm_gateway::{GatewayMetrics, Protocol},
        },
    },
    serde_json::Value,
    std::sync::Arc,
};

#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 hygiene-round4 模板）：
    // 超 800 即失败，须按模板拆分，不得只改数字放行。
    const SELF_SRC: &str = include_str!("spawn.rs");
    let lines = SELF_SRC.lines().count();
    assert!(
        lines <= 800,
        "spawn.rs {lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}

#[test]
fn stream_restore_fallback_keeps_token() {
    // H2/D1 病态回退：还原后仍破损时下游收还原前占位符帧——
    // JSON 可解析、token 保留、`restore_fallback` 计数 +1（对齐非流回退）。
    let metrics = GatewayMetrics::default();
    let broken = r#"{"text":"pa"ss"}"#;
    let placeholder = r#"{"text":"__VG_CRED_000001__"}"#;
    let out = guard_restored_frame(broken.to_string(), placeholder, &metrics);
    assert_eq!(out, placeholder, "须回退还原前占位符帧");
    assert!(out.contains("__VG_CRED_"), "占位符须保留: {out}");
    let v: Value = serde_json::from_str(&out).expect("回退帧须为合法 JSON");
    assert_eq!(v["text"], "__VG_CRED_000001__");
    assert_eq!(metrics.restore_fallback_count(), 1, "回退须计数");
    // 合法还原帧不回退、不计数。
    let ok = guard_restored_frame(r#"{"text":"pa\"ss"}"#.to_string(), placeholder, &metrics);
    assert_eq!(ok, r#"{"text":"pa\"ss"}"#);
    assert_eq!(metrics.restore_fallback_count(), 1, "合法帧不得计数");
}

#[test]
fn spawn_decision_responses_control_truth_table() {
    // 决策点 N1 + error/failed 分类（穷举 16 组合对拍公式）：
    // terminal_sent 优先 → Ignore；否则 error → SynthesizeFailed；
    // failed 且已发 → DuplicateFailed；其余 → Passthrough。
    for terminal_sent in [false, true] {
        for failed_sent in [false, true] {
            for is_error in [false, true] {
                for is_failed in [false, true] {
                    let expected = if terminal_sent {
                        ResponsesAction::Ignore
                    } else if is_error {
                        ResponsesAction::SynthesizeFailed
                    } else if is_failed && failed_sent {
                        ResponsesAction::DuplicateFailed
                    } else {
                        ResponsesAction::Passthrough
                    };
                    assert_eq!(
                        responses_control_action(terminal_sent, failed_sent, is_error, is_failed),
                        expected,
                        "组合 terminal={terminal_sent} failed_sent={failed_sent} \
                         error={is_error} failed={is_failed}"
                    );
                }
            }
        }
    }
}

#[test]
fn spawn_decision_backfill_chat_done_truth_table() {
    // 决策点 P1（穷举协议 × 三布尔共 24 组合对拍公式）：仅
    // 「Chat 且未终端且见 finish_reason 且未置截断」为真。
    for protocol in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
        for terminal_sent in [false, true] {
            for saw_finish_reason in [false, true] {
                for truncated_mode_set in [false, true] {
                    let expected = protocol == Protocol::Chat
                        && !terminal_sent
                        && saw_finish_reason
                        && !truncated_mode_set;
                    assert_eq!(
                        should_backfill_chat_done(
                            protocol,
                            terminal_sent,
                            saw_finish_reason,
                            truncated_mode_set
                        ),
                        expected,
                        "组合 proto={protocol:?} terminal={terminal_sent} \
                         saw={saw_finish_reason} truncated={truncated_mode_set}"
                    );
                }
            }
        }
    }
    // 正例锚点：唯一真组合。
    assert!(should_backfill_chat_done(
        Protocol::Chat,
        false,
        true,
        false
    ));
    // 负例锚点：四条件逐一破坏。
    assert!(!should_backfill_chat_done(
        Protocol::Chat,
        true,
        true,
        false
    ));
    assert!(!should_backfill_chat_done(
        Protocol::Chat,
        false,
        false,
        false
    ));
    assert!(!should_backfill_chat_done(
        Protocol::Chat,
        false,
        true,
        true
    ));
}

#[test]
fn spawn_decision_buffer_tool_frame_truth_table() {
    // 决策点 hold-until-complete（穷举 16 组合对拍公式）：审计开 + tool +
    // 未完成 + 非按槽完成 才缓冲。
    for audit_hold_on in [false, true] {
        for is_tool_event in [false, true] {
            for is_complete in [false, true] {
                for is_index_complete in [false, true] {
                    let expected =
                        audit_hold_on && is_tool_event && !is_complete && !is_index_complete;
                    assert_eq!(
                        should_buffer_tool_frame(
                            audit_hold_on,
                            is_tool_event,
                            is_complete,
                            is_index_complete
                        ),
                        expected,
                        "组合 audit={audit_hold_on} tool={is_tool_event} \
                         complete={is_complete} index_complete={is_index_complete}"
                    );
                }
            }
        }
    }
    // 正例锚点：全局未完成缓冲。
    assert!(should_buffer_tool_frame(true, true, false, false));
    // 负例锚点：审计关 / 非 tool / 已完成为各自破坏条件。
    assert!(!should_buffer_tool_frame(false, true, false, false));
    assert!(!should_buffer_tool_frame(true, false, false, false));
    assert!(!should_buffer_tool_frame(true, true, true, false));
    assert!(!should_buffer_tool_frame(true, true, false, true));
}

#[test]
fn spawn_decision_tool_replay_slot_truth_table() {
    // 决策点完成帧重放槽：全局完成 Some(None)；按槽完成取外层序号；
    // 非完成 / 序号缺失 / 协议不产出外层序号 → None（不误清）。
    let anth = serde_json::json!({"type":"content_block_stop","index":3});
    let resp = serde_json::json!({"type":"response.completed","output_index":2});
    // 正例：全局完成（两协议同结果）+ 按槽完成（anthropic index / responses output_index）。
    assert_eq!(
        tool_replay_slot(Protocol::Anthropic, &anth, true, true),
        Some(None)
    );
    assert_eq!(
        tool_replay_slot(Protocol::Responses, &resp, true, false),
        Some(None)
    );
    assert_eq!(
        tool_replay_slot(Protocol::Anthropic, &anth, false, true),
        Some(Some(3))
    );
    assert_eq!(
        tool_replay_slot(Protocol::Responses, &resp, false, true),
        Some(Some(2))
    );
    // 负例：非完成、按槽完成但序号缺失、协议不产出外层序号。
    assert_eq!(
        tool_replay_slot(Protocol::Anthropic, &anth, false, false),
        None
    );
    assert_eq!(
        tool_replay_slot(
            Protocol::Anthropic,
            &serde_json::json!({"type":"x"}),
            false,
            true
        ),
        None
    );
    assert_eq!(tool_replay_slot(Protocol::Chat, &anth, false, true), None);
}

#[test]
fn spawn_decision_suppress_held_output_truth_table() {
    // 决策点边界 hold 抑制（穷举 8 组合对拍公式）：非次要 + hold 有滞留 +
    // 本帧有输出 才继续持有。
    for minor in [false, true] {
        for hold_held in [false, true] {
            for out_data_nonempty in [false, true] {
                let expected = !minor && hold_held && out_data_nonempty;
                assert_eq!(
                    should_suppress_held_output(minor, hold_held, out_data_nonempty),
                    expected,
                    "组合 minor={minor} held={hold_held} nonempty={out_data_nonempty}"
                );
            }
        }
    }
    // 正例锚点：唯一真组合。
    assert!(should_suppress_held_output(false, true, true));
    // 负例锚点：次要 / 无滞留 / 空输出逐一破坏。
    assert!(!should_suppress_held_output(true, true, true));
    assert!(!should_suppress_held_output(false, false, true));
    assert!(!should_suppress_held_output(false, true, false));
}

#[test]
fn spawn_decision_sticky_suppress_truth_table() {
    // 决策点 rejected_sticky 抑制（穷举 32 组合对拍公式）：粘滞后
    // DONE/终端/tool或完成/空数据 Drop，普通文本 Pass；未粘滞恒 Pass。
    for rejected in [false, true] {
        for data_empty in [false, true] {
            for is_done in [false, true] {
                for is_terminal in [false, true] {
                    for is_tool in [false, true] {
                        let expected =
                            if rejected && (data_empty || is_done || is_terminal || is_tool) {
                                StickyAction::Drop
                            } else {
                                StickyAction::Pass
                            };
                        assert_eq!(
                            sticky_suppress_action(
                                rejected,
                                data_empty,
                                is_done,
                                is_terminal,
                                is_tool
                            ),
                            expected,
                            "组合 rejected={rejected} empty={data_empty} done={is_done} \
                             terminal={is_terminal} tool={is_tool}"
                        );
                    }
                }
            }
        }
    }
    // 正例锚点：Drop 四类（DONE/终端/tool 或完成/空数据）。
    assert_eq!(
        sticky_suppress_action(true, false, true, false, false),
        StickyAction::Drop
    );
    assert_eq!(
        sticky_suppress_action(true, false, false, true, false),
        StickyAction::Drop
    );
    assert_eq!(
        sticky_suppress_action(true, false, false, false, true),
        StickyAction::Drop
    );
    assert_eq!(
        sticky_suppress_action(true, true, false, false, false),
        StickyAction::Drop
    );
    // 负例锚点：普通文本 Pass、未粘滞 Pass。
    assert_eq!(
        sticky_suppress_action(true, false, false, false, false),
        StickyAction::Pass
    );
    assert_eq!(
        sticky_suppress_action(false, false, true, true, true),
        StickyAction::Pass
    );
}

#[test]
fn spawn_decision_empty_stream_gate_call_order() {
    // 决策点空流守门（既有 `event::should_synthesize_empty_stream`）：
    // 三位全假才合成，任一置位即跳过。
    assert!(should_synthesize_empty_stream(false, false, false));
    assert!(!should_synthesize_empty_stream(true, false, false));
    assert!(!should_synthesize_empty_stream(false, true, false));
    assert!(!should_synthesize_empty_stream(false, false, true));
    // 调用序不变量（P1 在守门前）：Chat 缺 [DONE] 补发后 terminal_sent 已置，
    // 守门必假——不会在补发后再二次合成终端。
    let backfill = should_backfill_chat_done(Protocol::Chat, false, true, false);
    assert!(backfill, "补发条件须成立");
    let terminal_sent_after_backfill = true;
    assert!(
        !should_synthesize_empty_stream(terminal_sent_after_backfill, true, false),
        "补发置终端后空流守门不得再触发"
    );
}

#[tokio::test]
async fn direct_n1_completed_then_error_single_terminal() {
    // T1/D1 决策点 N1（原仓 `llm_test.py::test_completed_is_other`）：
    // `response.completed` 后跟 `error`/`incomplete` 两真值组合，下游终端恰一
    //（completed），无合成 failed、终端后帧零透传。
    for tail in [
        "data: {\"type\":\"error\",\"error\":{\"message\":\"boom-after-completed\"}}\n\n",
        "data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r1\",\"status\":\"incomplete\"}}\n\n",
    ] {
        let sse = format!(
            "data: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"r1\",\"status\":\"completed\"}}}}\n\n{tail}"
        );
        let (url, server) = loopback_server(200, "text/event-stream", sse.into_bytes()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (_outcome, frames) = collect_pump(
            upstream,
            pump_ctx(Protocol::Responses, scope, vault, detector),
        )
        .await;
        let joined = frames.join("");
        assert_eq!(
            block_inject::terminal_count(&frames, "responses"),
            1,
            "终端恰一（tail={tail:?}）: {joined}"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.completed"))
                .count(),
            1,
            "completed 恰一（tail={tail:?}）: {joined}"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.failed"))
                .count(),
            0,
            "终端后不得合成 failed（tail={tail:?}）: {joined}"
        );
        assert!(
            !joined.contains("boom-after-completed") && !joined.contains("response.incomplete"),
            "终端后控制帧不得透传（tail={tail:?}）: {joined}"
        );
        server.abort();
    }
}

#[tokio::test]
async fn direct_p1_backfill_preserves_usage_tail() {
    // T1/D1 决策点 P1（原仓 `llm_test.py::test_finish_reason_with_pending` 与
    // `test_done_flushes_pending`）：finish_reason 后 usage 尾帧照常透传，
    // EOF 无 `[DONE]` 时补发恰一且置于尾帧之后，`truncated_mode=open_ended` 保留。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":8,"total_tokens":15}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.gateway_metrics = metrics.clone();
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "补发后 [DONE] 恰一: {joined}"
    );
    assert!(
        joined.contains("\"total_tokens\":15"),
        "usage 尾帧不得丢: {joined}"
    );
    let usage_at = joined.find("\"total_tokens\":15").expect("usage 须在帧内");
    let done_at = joined.find("[DONE]").expect("[DONE] 须在帧内");
    assert!(usage_at < done_at, "[DONE] 须在 usage 尾帧之后: {joined}");
    assert!(outcome.terminal_injected, "补发后终端标记须落位");
    assert_eq!(
        metrics.truncated_count("open_ended"),
        1,
        "缺 [DONE] 须保留 open_ended 观测"
    );
    server.abort();
}

#[tokio::test]
async fn direct_boundary_hold_released_at_terminal() {
    // T1/D1 决策点边界 hold 释放（原仓 `llm_test.py::test_flush_incomplete_hold_at_end`）：
    // 两段内容帧首帧被 hold 延迟，`[DONE]` 终端处 flush 放行最后滞留帧——
    // 不吞帧、保到达序、终端恰一。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"segment-A\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"segment-B\"}}]}\n\ndata: [DONE]\n\n"
        .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    let a = joined.find("segment-A").expect("A 段不得被 hold 吞帧");
    let b = joined
        .find("segment-B")
        .expect("B 段须在终端帧处 flush 释放");
    let done = joined.find("[DONE]").expect("[DONE] 须存在");
    assert!(a < b && b < done, "释放序须 A→B→[DONE]: {joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "终端恰一: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn direct_rejected_sticky_suppresses_tool_frames() {
    // T1/D1 决策点 rejected_sticky（原仓 `llm_test.py::test_done_flushes_pending` 的
    // DONE 处置 + `audit_approve_stream_test.py::test_anthropic_hold_overflow_fail_closed`）：
    // 极小 hold 上限触发阻断粘滞，后续 tool/文本/完成/`[DONE]` 帧一律不透传；
    // 下游仅收阻断帧（恰一 [DONE]），危险参数零泄漏。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-bad","type":"function","function":{"name":"exec","arguments":"{\"command\":\"rm -rf / --no-preserve-root\"}"}}]}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":" tail-after-block"}}]}}]}

data: {"choices":[{"index":0,"delta":{"content":"leak-after-block"}}]}

data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}

data: [DONE]

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.audit_mode = AuditMode::Block;
    ctx.hold_max = 16;
    ctx.gateway_metrics = metrics.clone();
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "审计超限须注入阻断帧: {joined}");
    assert_eq!(joined.matches("[blocked:").count(), 1, "{joined}");
    assert_eq!(
        frames.iter().filter(|f| f.contains("data: [DONE]")).count(),
        1,
        "粘滞后终止帧恰一: {joined}"
    );
    for leak in [
        "rm -rf",
        "call-bad",
        "exec",
        "tail-after-block",
        "leak-after-block",
    ] {
        assert!(!joined.contains(leak), "粘滞后不得透传 {leak}: {joined}");
    }
    assert_eq!(
        metrics.truncated_tool_dropped_count(),
        0,
        "阻断清缓冲非截断，不得记截断丢弃"
    );
    server.abort();
}
