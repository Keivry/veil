use {
    super::{
        audit::{AuditPolicy, AuditVerdict, evaluate},
        llm_gateway::{Protocol as GatewayProtocol, extract_tool_calls},
        sse::StreamMeta,
    },
    crate::config::AuditMode,
    serde_json::Value,
};

pub fn chat_block_frames(reason: &str) -> Vec<String> {
    vec![
        format!(
            "event: message\ndata: {{\"choices\":[{{\"finish_reason\":\"stop\",\"message\":{{\"role\":\"assistant\",\"content\":\"[blocked: {reason}]\"}}}}]}}\n\n"
        ),
        "data: [DONE]\n\n".to_string(),
    ]
}

pub fn anthropic_block_frames(reason: &str) -> Vec<String> {
    vec![
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"blocked-0\",\"name\":\"blocked\",\"input\":{}}}\n\n".to_string(),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n".to_string(),
        format!("event: message_stop\ndata: {{\"type\":\"message_stop\",\"reason\":\"{reason}\"}}\n\n"),
    ]
}

pub fn responses_block_frames(response_id: &str) -> Vec<String> {
    // 可读性修复：空 completed 下游见空完成不可用，补 output_text.delta 明文；
    // delta 帧不计入终止计数（dedupe 仅认 completed/failed），恰一约束不受影响。
    let text = "[blocked: audit]";
    vec![
        format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"item_id\":\"{response_id}\",\"delta\":\"{text}\"}}\n\n"
        ),
        format!(
            "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"completed\"}}}}\n\n"
        ),
    ]
}

pub fn responses_truncated_frames(response_id: &str) -> Vec<String> {
    let text = "[truncated]";
    vec![
        format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"item_id\":\"{response_id}\",\"delta\":\"{text}\"}}\n\n"
        ),
        format!(
            "event: response.failed\ndata: {{\"type\":\"response.failed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"failed\"}}}}\n\n"
        ),
    ]
}

pub fn ensure_event_lines(frames: Vec<String>) -> Vec<String> {
    frames
        .into_iter()
        .map(|f| {
            // DONE 裸帧豁免：Chat 终止符恒为裸 `data: [DONE]`，不得补 `event:`。
            if is_done_frame(&f) || f.lines().any(|l| l.starts_with("event:")) {
                f
            } else if let Some(pos) = f.find("data:") {
                format!("event: message\n{}", &f[pos..])
            } else {
                f
            }
        })
        .collect()
}

pub fn mark_terminal(meta: &mut StreamMeta) { meta.terminal_injected = true; }

pub fn chat_done_frame() -> String { "data: [DONE]\n\n".to_string() }

pub fn is_done_frame(frame: &str) -> bool {
    frame.lines().any(|l| {
        // §2.6：BOM 剥离后判 DONE（`﻿data: [DONE]` 同样是终止帧，参与去重）。
        let t = l.trim().trim_start_matches('\u{feff}');
        t == "data: [DONE]" || t == "data:[DONE]"
    })
}

pub fn has_chat_terminal(frames: &[String]) -> bool { frames.iter().any(|f| is_done_frame(f)) }

pub fn normalize_chat_done(frames: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = frames.into_iter().filter(|f| !is_done_frame(f)).collect();
    kept = ensure_event_lines(kept);
    kept.push(chat_done_frame());
    kept
}

pub fn dedupe_terminal_frames(frames: Vec<String>, protocol: &str) -> Vec<String> {
    match protocol {
        "chat" => normalize_chat_done(frames),
        "anthropic" => {
            let mut seen_stop = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_stop = f.contains("message_stop");
                if is_stop {
                    if seen_stop {
                        continue;
                    }
                    seen_stop = true;
                }
                out.push(f);
            }
            out
        }
        _ => {
            let mut seen_term = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_term = f.contains("response.completed") || f.contains("response.failed");
                if is_term {
                    if seen_term {
                        continue;
                    }
                    seen_term = true;
                }
                out.push(f);
            }
            out
        }
    }
}

pub fn should_discard_after_terminal(terminated: bool) -> bool { terminated }

/// 非流阻断体（§2.3）：三协议各自正确的 JSON 形态，与流式阻断帧语义对齐：
/// chat 为 `choices/finish_reason=stop` 消息体；anthropic 为 `stop_reason=end_turn`
/// 文本体；responses 为 `status=failed` 错误体（失败语义，不伪造完成）。
/// `NonDialog` 非对话不审计，返回 `Null`（调用方不应调用）。
pub fn nonstream_block_body(
    protocol: GatewayProtocol,
    reason: &str,
    conv_id: &str,
) -> Value {
    let text = format!("[blocked: {reason}]");
    match protocol {
        GatewayProtocol::Chat => serde_json::json!({
            "choices": [{"finish_reason": "stop",
                "message": {"role": "assistant", "content": text}}]
        }),
        GatewayProtocol::Anthropic => {
            let id = if conv_id.is_empty() { "blocked".to_string() } else { conv_id.to_string() };
            serde_json::json!({
                "id": id,
                "type": "message",
                "role": "assistant",
                "model": "blocked",
                "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 0, "output_tokens": 1}
            })
        }
        GatewayProtocol::Responses => serde_json::json!({
            "id": conv_id, "status": "failed",
            "error": {"message": text}
        }),
        GatewayProtocol::NonDialog => Value::Null,
    }
}

/// 非流 tool 提取 + 审计（§2.3）：提取三协议 tool 调用
/// （chat `tool_calls`、anthropic `tool_use`、responses `function_call`）
/// 并逐条 `audit::evaluate`；任一条 `Block`/`NeedApproval` 即 fail-closed
/// 返回 `Some(阻断体)`，全放行返回 `None`。
/// handler 接线说明：`Some(body)` 直接替代上游响应返回（状态码沿用上游），
/// `None` 走正常还原透传；approve 转人工需上层另行实现
/// （本 helper 按阻断处理，不静默放行危险调用）。
pub fn evaluate_nonstream(
    protocol: GatewayProtocol,
    body: &Value,
    mode: AuditMode,
    policy: &AuditPolicy,
    conv_id: &str,
) -> Option<Value> {
    if matches!(mode, AuditMode::Off) {
        return None;
    }
    let mut first_reason: Option<String> = None;
    for call in extract_tool_calls(protocol, body) {
        let name = call.name.as_deref().unwrap_or("");
        match evaluate(mode, name, &call.args, policy) {
            AuditVerdict::Allow => {}
            AuditVerdict::Block { reason } | AuditVerdict::NeedApproval { reason, .. } => {
                first_reason = Some(reason);
                break;
            }
        }
    }
    first_reason.map(|r| nonstream_block_body(protocol, &r, conv_id))
}

pub fn empty_stream_frames(protocol: &str, conv_id: &str) -> Vec<String> {
    match protocol {
        "chat" => chat_block_frames("empty-stream"),
        "anthropic" => anthropic_block_frames("empty-stream"),
        "responses" => responses_truncated_frames(conv_id),
        _ => vec![],
    }
}

pub fn terminal_count(frames: &[String], protocol: &str) -> usize {
    match protocol {
        "chat" => count_done(frames),
        "anthropic" => frames.iter().filter(|f| f.contains("message_stop")).count(),
        _ => frames
            .iter()
            .filter(|f| f.contains("response.completed") || f.contains("response.failed"))
            .count(),
    }
}

pub fn count_done(frames: &[String]) -> usize {
    frames.iter().filter(|f| is_done_frame(f)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat阻断恒以裸done恰1个收尾() {
        let frames = ensure_event_lines(chat_block_frames("policy"));
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
            frames
                .iter()
                .filter(|f| !is_done_frame(f))
                .all(|f| f.lines().any(|l| l.starts_with("event:"))),
            "非 DONE 帧仍须带 event 行"
        );
    }

    #[test]
    fn done裸帧豁免event补全() {
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
    fn anthropic四件套终止且顺序锁定() {
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
    }

    #[test]
    fn responses阻断与截断区分() {
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
    fn 缺event行阻断载荷补全() {
        let raw = vec!["data: {\"a\":1}\n\n".to_string()];
        let fixed = ensure_event_lines(raw);
        assert!(fixed[0].lines().any(|l| l.starts_with("event:")));
        assert!(fixed[0].contains("data:"));
    }

    #[test]
    fn 终止标记落meta() {
        let mut meta = StreamMeta::default();
        mark_terminal(&mut meta);
        assert!(meta.terminal_injected);
    }

    #[test]
    fn chat空流与重复done恒恰1个且去重不重复计费() {
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
        assert!(has_chat_terminal(&norm));
        let empty_norm = dedupe_terminal_frames(vec![], "chat");
        assert_eq!(count_done(&empty_norm), 1);
    }

    #[test]
    fn truncation_TSS01_openended不造假成功() {
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
    fn truncation_TSS02_tooldrop无参数不伪造完成() {
        let failed = ensure_event_lines(responses_truncated_frames("r-drop"));
        let joined = failed.join("");
        assert!(joined.contains("response.failed"));
        assert!(!joined.contains("response.completed"));
        assert!(!joined.contains("\"status\":\"completed\""));
        assert!(terminal_count(&failed, "responses") == 1);
    }

    #[test]
    fn truncation_TSS03_阻断与截断形态互斥() {
        let done = ensure_event_lines(responses_block_frames("r1"));
        let failed = ensure_event_lines(responses_truncated_frames("r1"));
        assert!(done.join("").contains("response.completed"));
        assert!(!failed.join("").contains("response.completed"));
        assert!(failed.join("").contains("response.failed"));
        assert!(!done.join("").contains("response.failed"));
    }

    #[test]
    fn truncation_TSS04_空流兜底三协议恰一个终止() {
        assert_eq!(
            terminal_count(&empty_stream_frames("chat", "c1"), "chat"),
            1
        );
        assert_eq!(
            terminal_count(&empty_stream_frames("anthropic", "c1"), "anthropic"),
            1
        );
        assert_eq!(
            terminal_count(&empty_stream_frames("responses", "c1"), "responses"),
            1
        );
        let chat_empty = dedupe_terminal_frames(vec![], "chat");
        assert_eq!(count_done(&chat_empty), 1);
    }

    #[test]
    fn responses完成失败形态区分且去重() {
        let frames = vec![
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
            "event: response.completed\ndata: {\"type\":\"response.completed\"}\n\n".to_string(),
        ];
        let out = dedupe_terminal_frames(frames, "responses");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("response.completed"));
        assert!(!out[0].contains("response.failed"));
        assert!(should_discard_after_terminal(true));
        assert!(!should_discard_after_terminal(false));
    }

    #[test]
    fn 非流危险调用被拦且形态协议正确() {
        use crate::config::AuditMode;
        use super::super::{audit::AuditPolicy, llm_gateway::Protocol};
        let policy = AuditPolicy::default_policy();
        let chat = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}]});
        let blocked = evaluate_nonstream(Protocol::Chat, &chat, AuditMode::Block, &policy, "r1")
            .expect("危险调用须阻断");
        assert!(blocked.to_string().contains("[blocked:"));
        assert_eq!(blocked["choices"][0]["finish_reason"], "stop");
        let benign = serde_json::json!({"choices":[{"message":{"content":"hi"}}]});
        assert!(
            evaluate_nonstream(Protocol::Chat, &benign, AuditMode::Block, &policy, "r1").is_none()
        );
        assert!(
            evaluate_nonstream(Protocol::Chat, &chat, AuditMode::Off, &policy, "r1").is_none()
        );
        let anth = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"exec","input":{"cmd":"rm -rf /"}}]});
        let blocked_a =
            evaluate_nonstream(Protocol::Anthropic, &anth, AuditMode::Block, &policy, "r1")
                .expect("anthropic 危险须阻断");
        assert_eq!(blocked_a["stop_reason"], "end_turn");
        let resp = serde_json::json!({"output":[{"type":"function_call","id":"f1","name":"exec","arguments":"rm -rf /"}]});
        let blocked_r =
            evaluate_nonstream(Protocol::Responses, &resp, AuditMode::Block, &policy, "r1")
                .expect("responses 危险须阻断");
        assert_eq!(blocked_r["id"], "r1");
        assert_eq!(blocked_r["status"], "failed");
        assert!(!blocked_r.to_string().contains("response.completed"));
        let need = evaluate_nonstream(Protocol::Chat, &chat, AuditMode::Approve, &policy, "r1");
        assert!(need.is_some(), "approve 命中按阻断处理，不静默放行");
    }

    #[test]
    fn anthropic非流阻断六字段完整() {
        use super::super::llm_gateway::Protocol;
        let body = nonstream_block_body(Protocol::Anthropic, "policy", "msg-1");
        assert_eq!(body["id"], "msg-1");
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert!(body.get("model").is_some(), "严格 SDK 要求 model 字段");
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 0);
        assert_eq!(body["usage"]["output_tokens"], 1);
        assert_eq!(body["content"][0]["type"], "text");
        let fallback = nonstream_block_body(Protocol::Anthropic, "policy", "");
        assert_eq!(fallback["id"], "blocked");
    }

    #[test]
    fn responses阻断先文本后完成且终止恰一() {
        let frames = ensure_event_lines(responses_block_frames("r9"));
        assert_eq!(frames.len(), 2, "delta 明文 + 唯一 completed");
        assert!(frames[0].contains("response.output_text.delta"));
        assert!(frames[0].contains("[blocked:"));
        assert!(frames[1].contains("response.completed"));
        assert_eq!(terminal_count(&frames, "responses"), 1);
        let trunc = ensure_event_lines(responses_truncated_frames("r9"));
        assert_eq!(terminal_count(&trunc, "responses"), 1);
        assert!(trunc.join("").contains("response.failed"));
        assert!(!trunc.join("").contains("response.completed"));
    }

    #[test]
    fn count_done行级精确不误计参数同串() {
        let tricky = vec![
            "event: message\ndata: {\"arguments\":\"data: [DONE]\"}\n\n".to_string(),
        ];
        assert_eq!(count_done(&tricky), 0, "参数内同串不得计入终止");
        assert_eq!(terminal_count(&tricky, "chat"), 0);
        let real = vec!["data: [DONE]\n\n".to_string()];
        assert_eq!(count_done(&real), 1);
    }

    #[test]
    fn blocked占位不触发二次调用() {
        use super::super::audit::{AuditPolicy, AuditVerdict, evaluate};
        use crate::config::AuditMode;
        let policy = AuditPolicy::default_policy();
        let verdict = evaluate(AuditMode::Block, "blocked", "{}", &policy);
        assert!(
            matches!(verdict, AuditVerdict::Allow),
            "占位名 blocked + 空 input 须放行，否则下游二次调用被拦死循环"
        );
    }

    #[test]
    fn chat阻断文案统一自闭合() {
        let frames = ensure_event_lines(chat_block_frames("policy"));
        let first = &frames[0];
        assert!(first.contains("[blocked: policy]"), "文案统一为 [blocked: reason]");
        assert!(first.contains("\"message\""), "自闭合 message 形态");
        assert!(!first.contains("\"delta\""), "不得用 delta 增量形态");
        assert_eq!(count_done(&frames), 1);
    }
}
