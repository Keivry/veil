//! 阻断帧/体合成门面（H1.2 两切拆分，D1）：子模块重导出，对外 `service::block_inject::*` 路径不变。
//!
//! 子模块划分：`frames` 三协议帧/体合成（流式阻断帧 + 非流阻断体 + 截断/空流合成），
//! `terminal` 去重终结（终端去重 + 计数 + `mark_terminal`）。
//! 单测留门面（`super::*` 经重导出解析），两切单文件均 ≤800。

pub mod frames;
pub mod terminal;

pub use {frames::*, terminal::*};

/// 单测经 `super::*` 取 `PendingApprovals/StreamMeta/GatewayProtocol`，生产构建不引入（防
/// unused 警告）。
#[cfg(test)]
use crate::{
    approval::PendingApprovals,
    service::{llm_gateway::Protocol as GatewayProtocol, sse::StreamMeta},
};

#[cfg(test)]
mod tests {
    use {super::*, crate::service::audit::test_whitelist};

    #[test]
    fn chat_block_ends_with_exactly_one_bare_done() {
        let frames = ensure_event_lines(chat_block_frames("policy"));
        assert_eq!(frames.len(), 3, "delta 首帧 + 终端帧 + 裸 DONE");
        assert_eq!(count_done(&frames), 1);
        let done = frames
            .iter()
            .find(|f| is_done_frame(f))
            .expect("须含 DONE 帧");
        assert_eq!(
            done.as_str(),
            "data: [DONE]\n\n",
            "DONE 恒为裸帧，不得带 event:"
        );
        assert!(
            frames.iter().all(|f| !f.contains("event:")),
            "Chat 全帧恒为纯 data: 形态，不得补 event: 行"
        );
    }

    #[test]
    fn bare_done_frame_exempt_from_event_completion() {
        assert_eq!(chat_done_frame(), "data: [DONE]\n\n");
        let raw = vec![
            "data: [DONE]\n\n".to_string(),
            "data:[DONE]\n\n".to_string(),
        ];
        let fixed = ensure_event_lines(raw);
        assert!(fixed.iter().all(|f| !f.contains("event:")));
        assert_eq!(count_done(&fixed), 2);
    }

    #[test]
    fn anthropic_four_part_termination_order_locked() {
        let frames = ensure_event_lines(anthropic_block_frames("policy"));
        let joined = frames.join("");
        for key in [
            "content_block_start",
            "content_block_stop",
            "message_delta",
            "message_stop",
        ] {
            assert!(joined.contains(key), "缺 {key}");
        }
        let pos = |k: &str| joined.find(k).unwrap();
        assert!(
            pos("content_block_start") < pos("content_block_stop")
                && pos("content_block_stop") < pos("message_delta")
                && pos("message_delta") < pos("message_stop"),
            "顺序恒为 start/stop/delta/message_stop"
        );
        assert!(
            frames
                .iter()
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
        assert!(
            frames[0].contains("\"type\":\"text\""),
            "首块恒为 text 文本块"
        );
        assert!(frames[0].contains("[blocked: policy]"));
        assert!(!joined.contains("tool_use"), "文本阻断不得伪装 tool_use");
        let stop = frames
            .iter()
            .find(|f| f.contains("message_stop"))
            .expect("须含 message_stop");
        assert!(
            stop.contains("{\"type\":\"message_stop\"}"),
            "message_stop 回归空对象"
        );
        assert!(!stop.contains("reason"), "不得自造 reason 字段");
    }

    #[test]
    fn responses_block_vs_truncate_distinguished() {
        let done = ensure_event_lines(responses_block_frames("r1"));
        let failed = ensure_event_lines(responses_truncated_frames("r1"));
        assert!(done.join("").contains("response.completed"));
        assert!(!done.join("").contains("response.failed"));
        assert!(failed.join("").contains("response.failed"));
        assert!(!failed.join("").contains("response.completed"));
        assert!(
            done.iter()
                .chain(failed.iter())
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
    }

    #[test]
    fn missing_event_line_completed_per_protocol() {
        // Chat（`choices` 载荷）：豁免补全，恒为纯 `data:` 形态。
        let chat_raw = vec!["data: {\"choices\":[{\"index\":0}]}\n\n".to_string()];
        let chat_fixed = ensure_event_lines(chat_raw);
        assert!(!chat_fixed[0].contains("event:"), "Chat 帧不得补 event: 行");
        assert!(chat_fixed[0].contains("data:"));
        // Anthropic/Responses 缺 `event:` 行仍被补全。
        for raw in [
            "data: {\"type\":\"message_delta\"}\n\n".to_string(),
            "data: {\"type\":\"response.completed\"}\n\n".to_string(),
        ] {
            let fixed = ensure_event_lines(vec![raw]);
            assert!(fixed[0].lines().any(|l| l.starts_with("event:")));
            assert!(fixed[0].contains("data:"));
        }
    }

    #[test]
    fn terminal_marker_recorded_in_meta() {
        let mut meta = StreamMeta::default();
        mark_terminal(&mut meta);
        assert!(meta.terminal_injected);
    }

    #[test]
    fn chat_empty_stream_and_dup_done_deduped_to_one() {
        let dup = vec![
            "event: message\ndata: {\"a\":1}\n\n".to_string(),
            "data: [DONE]\n\n".to_string(),
            "data:[DONE]\n\n".to_string(),
            chat_done_frame(),
        ];
        let norm = dedupe_terminal_frames(dup, "chat");
        assert_eq!(count_done(&norm), 1);
        assert!(norm.last().is_some_and(|f| is_done_frame(f)));
        assert_eq!(norm.last().map(String::as_str), Some("data: [DONE]\n\n"));
        assert!(
            norm.iter()
                .filter(|f| !is_done_frame(f))
                .all(|f| f.lines().any(|l| l.starts_with("event:")))
        );
        let empty_norm = dedupe_terminal_frames(vec![], "chat");
        assert_eq!(count_done(&empty_norm), 1);
    }

    #[test]
    fn synthesize_truncation_covers_all_protocols_without_fake_success() {
        // P0-3.2：responses 合成 failed；chat/anthropic open-ended 空实现
        // （不伪造成功终止）；与 C8 空流合成形态互斥可联动。
        let failed =
            ensure_event_lines(synthesize_truncation(GatewayProtocol::Responses, "r-drop"));
        assert!(!failed.is_empty());
        assert!(failed.join("").contains("response.failed"));
        assert!(!failed.join("").contains("response.completed"));
        for proto in [GatewayProtocol::Chat, GatewayProtocol::Anthropic] {
            assert!(
                synthesize_truncation(proto, "x").is_empty(),
                "chat/anthropic 截断不合成成功终止"
            );
        }
    }

    #[test]
    fn truncation_tss01_openended_no_fake_success() {
        let chat_frames = ensure_event_lines(chat_block_frames("truncated"));
        let joined = chat_frames.join("");
        assert!(!joined.contains("response.completed"));
        assert!(joined.contains("[blocked: truncated]"));
        let anth_frames = ensure_event_lines(anthropic_block_frames("truncated"));
        let joined_a = anth_frames.join("");
        assert!(!joined_a.contains("message_stop") || joined_a.contains("truncated"));
        assert!(terminal_count(&chat_frames, "chat") == 1);
    }

    #[test]
    fn truncation_tss02_tooldrop_drops_incomplete_no_fake_done() {
        let failed = ensure_event_lines(responses_truncated_frames("r-drop"));
        let joined = failed.join("");
        assert!(joined.contains("response.failed"));
        assert!(!joined.contains("response.completed"));
        assert!(!joined.contains("\"status\":\"completed\""));
        assert!(terminal_count(&failed, "responses") == 1);
    }

    #[test]
    fn truncation_tss03_block_and_truncate_shapes_exclusive() {
        let done = ensure_event_lines(responses_block_frames("r1"));
        let failed = ensure_event_lines(responses_truncated_frames("r1"));
        assert!(done.join("").contains("response.completed"));
        assert!(!failed.join("").contains("response.completed"));
        assert!(failed.join("").contains("response.failed"));
        assert!(!done.join("").contains("response.failed"));
    }

    #[test]
    fn truncation_tss04_empty_stream_single_terminal_all_protocols() {
        // C8 open-ended：真空流 chat/anthropic 为空帧集（不伪造成功终止）；
        // Responses 仍合成 failed 且恰一终端。
        assert!(
            empty_stream_frames("chat", "c1").is_empty(),
            "chat 真空流须 open-ended，不合成终止"
        );
        assert!(
            empty_stream_frames("anthropic", "c1").is_empty(),
            "anthropic 真空流须 open-ended，不合成终止"
        );
        assert_eq!(
            terminal_count(&empty_stream_frames("responses", "c1"), "responses"),
            1
        );
        let chat_empty = dedupe_terminal_frames(vec![], "chat");
        assert_eq!(count_done(&chat_empty), 1);
    }

    #[test]
    fn responses_completed_vs_failed_shapes_deduped() {
        let frames = vec![
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
        ];
        let out = dedupe_terminal_frames(frames, "responses");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("response.completed"));
        assert!(!out[0].contains("response.failed"));
    }

    #[test]
    fn nonstream_dangerous_call_blocked_with_protocol_shape() {
        use {
            super::super::{audit::AuditPolicy, llm_gateway::Protocol},
            crate::config::AuditMode,
        };
        let policy = AuditPolicy::default_policy();
        let pending = PendingApprovals::default();
        let chat = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}]});
        let blocked = evaluate_nonstream(
            Protocol::Chat,
            &chat,
            AuditMode::Block,
            &policy,
            "r1",
            test_whitelist(),
            &pending,
        )
        .expect("危险调用须阻断");
        assert!(blocked.to_string().contains("[blocked:"));
        assert_eq!(blocked["choices"][0]["finish_reason"], "stop");
        let benign = serde_json::json!({"choices":[{"message":{"content":"hi"}}]});
        assert!(
            evaluate_nonstream(
                Protocol::Chat,
                &benign,
                AuditMode::Block,
                &policy,
                "r1",
                test_whitelist(),
                &pending
            )
            .is_none()
        );
        assert!(
            evaluate_nonstream(
                Protocol::Chat,
                &chat,
                AuditMode::Off,
                &policy,
                "r1",
                test_whitelist(),
                &pending
            )
            .is_none()
        );
        let anth = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"exec","input":{"cmd":"rm -rf /"}}]});
        let blocked_a = evaluate_nonstream(
            Protocol::Anthropic,
            &anth,
            AuditMode::Block,
            &policy,
            "r1",
            test_whitelist(),
            &pending,
        )
        .expect("anthropic 危险须阻断");
        assert_eq!(blocked_a["stop_reason"], "end_turn");
        let resp = serde_json::json!({"output":[{"type":"function_call","id":"f1","name":"exec","arguments":"rm -rf /"}]});
        let blocked_r = evaluate_nonstream(
            Protocol::Responses,
            &resp,
            AuditMode::Block,
            &policy,
            "r1",
            test_whitelist(),
            &pending,
        )
        .expect("responses 危险须阻断");
        assert_eq!(blocked_r["id"], "r1");
        assert_eq!(blocked_r["status"], "failed");
        assert!(!blocked_r.to_string().contains("response.completed"));
        // P0-1.4：approve 命中记 pending + 透传（不断链、不合成阻断体）。
        let need = evaluate_nonstream(
            Protocol::Chat,
            &chat,
            AuditMode::Approve,
            &policy,
            "r1",
            test_whitelist(),
            &pending,
        );
        assert!(need.is_none(), "approve 命中须透传上游，不得合成阻断体");
        assert!(
            pending.get("nonstream-r1-exec").is_some(),
            "approve 命中须有 pending 建单"
        );
    }

    #[test]
    fn anthropic_nonstream_block_has_six_fields() {
        use super::super::llm_gateway::Protocol;
        let body = nonstream_block_body(Protocol::Anthropic, "policy", "msg-1", None);
        assert_eq!(body["id"], "msg-1");
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert!(body.get("model").is_some(), "严格 SDK 要求 model 字段");
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 0);
        assert_eq!(body["usage"]["output_tokens"], 1);
        assert_eq!(body["content"][0]["type"], "text");
        let fallback = nonstream_block_body(Protocol::Anthropic, "policy", "", None);
        assert_eq!(fallback["id"], "blocked-0");
        assert_eq!(fallback["model"], "unknown_model", "C13：不用字面 blocked");
        // C13：上游模型回显（归一后），阻断体不伪造模型。
        let upstream = serde_json::json!({"model": "claude-test"});
        let echo = nonstream_block_body(Protocol::Anthropic, "policy", "m9", Some(&upstream));
        assert_eq!(echo["model"], "claude-test");
    }

    #[test]
    fn chat_nonstream_block_echoes_upstream_fields() {
        use super::super::llm_gateway::Protocol;
        let upstream = serde_json::json!({
            "id": "chatcmpl-123", "object": "chat.completion", "created": 1700000000,
            "model": "gpt-4o", "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        });
        let echo = nonstream_block_body(Protocol::Chat, "policy", "c1", Some(&upstream));
        assert_eq!(echo["object"], "chat.completion");
        assert_eq!(echo["id"], "chatcmpl-123", "优先回显上游 id");
        assert_eq!(echo["model"], "gpt-4o");
        assert_eq!(echo["created"], 1700000000);
        assert_eq!(echo["usage"]["total_tokens"], 15);
        assert_eq!(echo["choices"][0]["finish_reason"], "stop");
        assert!(
            echo["choices"][0]["message"]["content"]
                .as_str()
                .unwrap()
                .contains("[blocked: policy]")
        );
        let synth = nonstream_block_body(Protocol::Chat, "policy", "c9", None);
        assert_eq!(synth["object"], "chat.completion");
        assert_eq!(synth["id"], "blocked-c9", "无上游值时合成 id");
        assert!(!synth["id"].as_str().unwrap().is_empty());
        assert_eq!(synth["model"], "unknown_model", "C13：不用字面 blocked");
        assert_eq!(synth["usage"]["prompt_tokens"], 0);
        assert_eq!(synth["usage"]["completion_tokens"], 1);
        assert_eq!(synth["usage"]["total_tokens"], 1);
    }

    #[test]
    fn responses_block_text_then_completed_single_terminal() {
        let frames = ensure_event_lines(responses_block_frames("r9"));
        assert_eq!(
            frames.len(),
            7,
            "added/add/delta/done/done/done + 唯一 completed"
        );
        let joined = frames.join("");
        for key in [
            "response.output_item.added",
            "response.content_part.added",
            "response.output_text.delta",
            "response.output_text.done",
            "response.content_part.done",
            "response.output_item.done",
            "response.completed",
        ] {
            assert!(joined.contains(key), "缺 {key}");
        }
        let pos = |k: &str| joined.find(k).unwrap();
        assert!(
            pos("response.output_item.added") < pos("response.content_part.added")
                && pos("response.content_part.added") < pos("response.output_text.delta")
                && pos("response.output_text.delta") < pos("response.output_text.done")
                && pos("response.output_text.done") < pos("response.content_part.done")
                && pos("response.content_part.done") < pos("response.output_item.done")
                && pos("response.output_item.done") < pos("response.completed"),
            "全序列顺序锁定"
        );
        assert!(frames[2].contains("[blocked:"));
        assert_eq!(terminal_count(&frames, "responses"), 1);
        let trunc = ensure_event_lines(responses_truncated_frames("r9"));
        assert_eq!(trunc.len(), 7);
        assert_eq!(terminal_count(&trunc, "responses"), 1);
        assert!(trunc.join("").contains("response.failed"));
        assert!(!trunc.join("").contains("response.completed"));
    }

    #[test]
    fn count_done_line_precise_ignores_payload_substring() {
        let tricky = vec!["event: message\ndata: {\"arguments\":\"data: [DONE]\"}\n\n".to_string()];
        assert_eq!(count_done(&tricky), 0, "参数内同串不得计入终止");
        assert_eq!(terminal_count(&tricky, "chat"), 0);
        let real = vec!["data: [DONE]\n\n".to_string()];
        assert_eq!(count_done(&real), 1);
    }

    #[test]
    fn blocked_placeholder_does_not_retrigger_audit() {
        use {
            super::super::audit::{AuditPolicy, AuditVerdict, evaluate_with_whitelist},
            crate::config::AuditMode,
        };
        let policy = AuditPolicy::default_policy();
        let verdict =
            evaluate_with_whitelist(AuditMode::Block, "blocked", "{}", &policy, test_whitelist());
        assert!(
            matches!(verdict, AuditVerdict::Allow),
            "占位名 blocked + 空 input 须放行，否则下游二次调用被拦死循环"
        );
    }

    #[test]
    fn approve_empty_whitelist_direct_call_downgrades_to_block() {
        // T4.2/D2：approve + 空白名单直调 → Block 降级（与流式同口径）。
        // 生产不可达：启动门禁拒绝 approve 空白名单（`src/config/env_parse.rs:307-310`），
        // 本用例锁定降级语义本身。
        use {
            super::super::{audit::AuditPolicy, llm_gateway::Protocol},
            crate::config::AuditMode,
        };
        let policy = AuditPolicy::default_policy();
        let pending = PendingApprovals::default();
        let chat = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}]});
        let blocked = evaluate_nonstream(
            Protocol::Chat,
            &chat,
            AuditMode::Approve,
            &policy,
            "wl-empty",
            &[],
            &pending,
        )
        .expect("approve 空白名单须降级 Block 合成阻断体");
        assert!(blocked.to_string().contains("[blocked:"));
        assert!(
            pending.get("nonstream-wl-empty-exec").is_none(),
            "降级 block 不得建 pending"
        );
    }

    #[test]
    fn chat_block_copy_unified_self_closed() {
        let frames = ensure_event_lines(chat_block_frames("policy"));
        let first = &frames[0];
        assert!(
            first.contains("[blocked: policy]"),
            "文案统一为 [blocked: reason]"
        );
        assert!(first.contains("\"delta\""), "流式增量恒用 delta 形态");
        assert!(!first.contains("\"message\""), "不得用非流 message 形态");
        assert_eq!(count_done(&frames), 1);
    }

    #[test]
    fn audit_off_denies_forward_per_policy_without_block_body() {
        use {
            super::super::{audit::AuditPolicy, llm_gateway::Protocol},
            crate::config::AuditMode,
        };
        let policy = AuditPolicy::default_policy();
        let pending = PendingApprovals::default();
        let chat = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","type":"function","function":{"name":"exec","arguments":"{\"x\":1}"}}]}}]});
        assert!(
            evaluate_nonstream(
                Protocol::Chat,
                &chat,
                AuditMode::Off,
                &policy,
                "c1",
                test_whitelist(),
                &pending
            )
            .is_none(),
            "审计关闭时 deny 路径不得合成阻断体，按策略转发原文"
        );
        let anth =
            serde_json::json!({"content":[{"type":"tool_use","id":"t1","name":"exec","input":{}}]});
        assert!(
            evaluate_nonstream(
                Protocol::Anthropic,
                &anth,
                AuditMode::Off,
                &policy,
                "m1",
                test_whitelist(),
                &pending
            )
            .is_none()
        );
    }

    #[test]
    fn done_fallback_audits_single_terminal_all_protocols() {
        // C8：chat/anthropic 真空流 open-ended（空帧集）；responses 合成 failed。
        assert!(empty_stream_frames("chat", "c1").is_empty());
        assert!(empty_stream_frames("anthropic", "m1").is_empty());
        let resp = empty_stream_frames("responses", "r1");
        assert_eq!(terminal_count(&resp, "responses"), 1);
        assert!(resp.join("").contains("response.failed"));
        assert!(!resp.join("").contains("response.completed"));
        assert!(empty_stream_frames("passthrough", "x").is_empty());
    }
}
