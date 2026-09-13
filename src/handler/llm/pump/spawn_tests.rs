//! 流泵决策点直测（`veil-test-coverage-fill` T1/D1）：`decide.rs` 纯函数真值表
//! + `spawn_stream_pump` 泵直测；harness 复用 `stream_tests` 的回环 mock
//!   （`pump_ctx`/`loopback_server`/`collect_pump`），无外部网络、无墙钟断言。

use {
    super::{
        decide::{
            ResponsesAction,
            StickyAction,
            responses_control_action,
            should_apply_midstream_terminal,
            should_buffer_tool_frame,
            should_suppress_held_output,
            sticky_suppress_action,
            tool_replay_slot,
        },
        event::should_synthesize_empty_stream,
        spawn::{guard_restored_frame, spawn_stream_pump},
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
fn spawn_decision_midstream_terminal_gate_truth_table() {
    // D6/S11 决策点：穷举协议 × 四布尔（未终端/未阻断/已发帧/截断信号）对拍公式。
    // 未终端且未阻断，且「已发帧或有截断信号」才注入；Responses 零帧（未发帧）
    // 例外——保持真空流最小终止，不进本策略。
    for protocol in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
        for terminal_sent in [false, true] {
            for block_injected in [false, true] {
                for any_frame_sent in [false, true] {
                    for stream_truncated in [false, true] {
                        let expected = !terminal_sent
                            && !block_injected
                            && (any_frame_sent || stream_truncated)
                            && (protocol != Protocol::Responses || any_frame_sent);
                        assert_eq!(
                            should_apply_midstream_terminal(
                                protocol,
                                terminal_sent,
                                block_injected,
                                any_frame_sent,
                                stream_truncated
                            ),
                            expected,
                            "组合 proto={protocol:?} terminal={terminal_sent} \
                             blocked={block_injected} sent={any_frame_sent} \
                             truncated={stream_truncated}"
                        );
                    }
                }
            }
        }
    }
    // 正例锚点：Chat 已发帧 / Chat 有截断信号（零帧）。
    assert!(should_apply_midstream_terminal(
        Protocol::Chat,
        false,
        false,
        true,
        false
    ));
    assert!(should_apply_midstream_terminal(
        Protocol::Chat,
        false,
        false,
        false,
        true
    ));
    // 负例锚点：已终端 / 已阻断 / 真空无信号 / Responses 零帧例外。
    assert!(!should_apply_midstream_terminal(
        Protocol::Chat,
        true,
        false,
        true,
        true
    ));
    assert!(!should_apply_midstream_terminal(
        Protocol::Chat,
        false,
        true,
        true,
        true
    ));
    assert!(!should_apply_midstream_terminal(
        Protocol::Chat,
        false,
        false,
        false,
        false
    ));
    assert!(!should_apply_midstream_terminal(
        Protocol::Responses,
        false,
        false,
        false,
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
    // 决策点边界 hold 抑制（穷举 16 组合对拍新公式 D1）：审计开启 + 确有未完成
    // 分片 + 本帧有输出 + 非次要 才继续持有；流级 held() 不再参与。
    for audit_hold_on in [false, true] {
        for has_pending in [false, true] {
            for out_data_nonempty in [false, true] {
                for minor in [false, true] {
                    let expected = audit_hold_on && has_pending && out_data_nonempty && !minor;
                    assert_eq!(
                        should_suppress_held_output(
                            audit_hold_on,
                            has_pending,
                            out_data_nonempty,
                            minor
                        ),
                        expected,
                        "组合 on={audit_hold_on} pending={has_pending} \
                         nonempty={out_data_nonempty} minor={minor}"
                    );
                }
            }
        }
    }
    // 正例锚点：唯一真组合。
    assert!(should_suppress_held_output(true, true, true, false));
    // 负例锚点：审计关 / 无 pending / 空输出 / 次要 逐一破坏。
    assert!(!should_suppress_held_output(false, true, true, false));
    assert!(!should_suppress_held_output(true, false, true, false));
    assert!(!should_suppress_held_output(true, true, false, false));
    assert!(!should_suppress_held_output(true, true, true, true));
}

#[test]
fn suppress_gate_pending_only() {
    use crate::service::audit::{AuditHold, HoldVerdict};
    // pending 判据（D1）：流开头无分片不得视为持有。
    let mut hold = AuditHold::new(1024);
    assert!(!hold.has_pending_fragments(), "流开头不得视为持有");
    assert_eq!(
        hold.push_fragment(0, Some("c1"), Some("run"), "{\"x\":"),
        HoldVerdict::Approved
    );
    assert!(hold.has_pending_fragments(), "累积分片后须 pending");
    hold.mark_completed();
    hold.release_audited();
    assert!(!hold.has_pending_fragments(), "完成审计释放后须非 pending");
    // Responses：未 done 槽为 pending，done + 释放后归 false。
    let mut resp = AuditHold::new(1024);
    let key = AuditHold::responses_key(Some("item-1"), 0);
    resp.push_responses_fragment(&key, 0, Some(0), Some("item-1"), Some("run"), "{}");
    assert!(resp.has_pending_fragments());
    resp.mark_responses_done(&key, None);
    resp.release_audited();
    assert!(!resp.has_pending_fragments());
    // 默认 AUDIT_MODE=off（audit_hold_on=false）抑制恒 false。
    assert!(!should_suppress_held_output(false, true, true, false));
    // 有未完成分片且三条件齐备才抑制。
    assert!(should_suppress_held_output(true, true, true, false));
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
    // 调用序不变量（D6 在守门前）：断流收尾置终端后 terminal_sent/any_frame_sent
    // 已置，守门必假——不会在收尾后再二次合成终端。
    let tail_gate = should_apply_midstream_terminal(Protocol::Chat, false, false, true, false);
    assert!(tail_gate, "断流收尾条件须成立");
    assert!(
        !should_synthesize_empty_stream(true, true, false),
        "断流收尾置终端后空流守门不得再触发"
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

#[tokio::test]
async fn sse_incremental_default_off() {
    // 1.2 回归：默认 AUDIT_MODE=off，多帧文本须在终止帧前逐帧到达（非终止时
    // 一次性拼接），且到达序与上游投递序一致。
    let sse = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"segment-A\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"segment-B\"}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"segment-C\"}}]}\n\ndata: [DONE]\n\n"
        .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let done_idx = frames
        .iter()
        .position(|f| f.contains("[DONE]"))
        .expect("须有 [DONE] 终止帧");
    let content_before = frames
        .iter()
        .take(done_idx)
        .filter(|f| f.contains("\"content\""))
        .count();
    assert!(
        content_before >= 2,
        "终止帧前须收到 ≥2 个独立内容帧（非单帧拼接）: {frames:?}"
    );
    let at = |needle: &str| {
        frames
            .iter()
            .position(|f| f.contains(needle))
            .unwrap_or_else(|| panic!("缺 {needle}: {frames:?}"))
    };
    let (a, b, c) = (at("segment-A"), at("segment-B"), at("segment-C"));
    assert!(a < b && b < c, "帧到达序须与上游投递序一致: {frames:?}");
    let joined = frames.join("");
    let (ja, jb, jc) = (
        joined.find("segment-A").expect("A"),
        joined.find("segment-B").expect("B"),
        joined.find("segment-C").expect("C"),
    );
    let jdone = joined.find("[DONE]").expect("[DONE]");
    assert!(
        ja < jb && jb < jc && jc < jdone,
        "内容序须 A→B→C→[DONE]: {joined}"
    );
    assert!(
        !frames[a].contains("segment-B"),
        "内容帧不得被合并为单帧: {frames:?}"
    );
    server.abort();
}

#[tokio::test]
async fn responses_multi_item_block() {
    // 2.2/S2 回归：item0 良性 done 后 item1 危险调用（block 模式）——槽级审计与
    // 全局完成隔离，item1 仍累积并被阻断；危险参数零透传。
    let sse = br#"data: {"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"call-0","name":"run","arguments":"{\"x\":1}"}}

data: {"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","id":"call-1","name":"exec","arguments":"{\"command\":\"rm -rf /\"}"}}

data: {"type":"response.completed","response":{"id":"r1","status":"completed"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.audit_mode = AuditMode::Block;
    let (outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(outcome.block_injected, "item1 危险调用须被阻断: {joined}");
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "阻断终端恰一: {joined}"
    );
    assert!(!joined.contains("rm -rf /"), "危险参数不得透传: {joined}");
    assert!(
        !joined.contains("call-1"),
        "危险 item id 不得透传: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn synth_terminal_flush_order() {
    // 3.1/S3/D3：`type:"error"` 合成 `response.failed` 前须先 flush 边界滞留的
    // delta A，下游先收内容帧、再收恰一失败终端（滞留帧不得拖到终端之后）。
    let sse = br#"data: {"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"A"}

data: {"type":"error","error":{"message":"boom"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let joined = frames.join("");
    let a_at = joined
        .find("\"delta\":\"A\"")
        .unwrap_or_else(|| panic!("delta A 须先落下: {joined}"));
    let failed_at = joined
        .find("response.failed")
        .unwrap_or_else(|| panic!("须合成 response.failed: {joined}"));
    assert!(
        a_at < failed_at,
        "滞留内容须先于合成终端 A→failed: {joined}"
    );
    assert_eq!(
        block_inject::terminal_count(&frames, "responses"),
        1,
        "终端恰一: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn synth_terminal_single() {
    // 3.2/S3 回归：合成终端恰一（`response.failed` 计数为 1），且终端帧之后
    // 不再出现任何数据帧。
    let sse = br#"data: {"type":"response.output_text.delta","item_id":"msg-1","output_index":0,"content_index":0,"delta":"A"}

data: {"type":"error","error":{"message":"boom"}}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (_outcome, frames) = collect_pump(
        upstream,
        pump_ctx(Protocol::Responses, scope, vault, detector),
    )
    .await;
    let failed = frames
        .iter()
        .filter(|f| f.contains("response.failed"))
        .count();
    assert_eq!(failed, 1, "response.failed 须恰一: {frames:?}");
    let term_idx = frames
        .iter()
        .position(|f| f.contains("response.failed"))
        .expect("终端帧须存在");
    for f in frames.iter().skip(term_idx + 1) {
        assert!(
            !f.contains("data:") || f.trim().is_empty(),
            "终端后不得再有数据帧: {f:?}"
        );
    }
    server.abort();
}

#[tokio::test]
async fn truncation_terminal_flush_order() {
    // 3.1/S3/D3：截断合成路径（`pending_tool_frames` 非空）前须先 flush 边界
    // 滞留帧——滞留内容按到达序落下，残缺 tool 分片丢弃且不伪造成功终端。
    let sse = br#"data: {"choices":[{"index":0,"delta":{"content":"held-A"}}]}

data: {"choices":[{"index":0,"delta":{"content":"held-B"}}]}

data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-t","function":{"name":"get_weather","arguments":"{\"city\":\""}}]}}]}

"#
    .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.audit_mode = AuditMode::Block;
    ctx.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    let a = joined.find("held-A").expect("滞留段 A 须落下");
    let b = joined
        .find("held-B")
        .expect("滞留段 B 须在截断收尾前 flush 落下");
    assert!(a < b, "滞留帧须按到达序落下 A→B: {joined}");
    assert_eq!(
        metrics.truncated_tool_dropped_count(),
        1,
        "残缺 tool 分片须丢弃并计数"
    );
    assert_eq!(
        joined.matches("data: [DONE]").count(),
        1,
        "D6：Chat 截断收尾须补恰一 [DONE]: {joined}"
    );
    assert!(!joined.contains("call-t"), "残缺 tool 不得透传: {joined}");
    server.abort();
}

#[tokio::test]
async fn truncation_send_failure_guard() {
    // S9/D9：下游早断（receiver 已 drop）时截断合成 send 全失败——泵不悬挂、
    // 不 panic，terminal_sent 不强制置位，PumpOutcome 如实反映未注入终端。
    let sse =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"held-A\"}}]}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
    drop(rx);
    let ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    let handle = spawn_stream_pump(upstream, tx, ctx);
    let outcome = handle.await.expect("下游早断时泵不得 panic");
    assert!(
        !outcome.terminal_injected,
        "合成终端未实际下行，terminal_injected 不得置位"
    );
    assert!(!outcome.block_injected, "下游早断不得伪造阻断");
    server.abort();
}
