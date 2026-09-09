use {
    super::{
        audit::{AuditPolicy, AuditVerdict, evaluate},
        llm_gateway::{Protocol as GatewayProtocol, extract_tool_calls},
        metrics::normalize_model,
        sse::StreamMeta,
    },
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
    },
    serde_json::Value,
};

/// Chat 流阻断帧（D1）：规范流式增量载体恒为 `choices[].delta`
/// （`message` 为非流形态，严格 SDK 按 `delta` 拼接会丢弃 `message` 致空输出）。
/// 三帧：`delta{role,content}` 首帧 + `delta{} finish_reason:stop` 终端
/// + 裸 `data: [DONE]`（`count_done==1`）。全帧恒为纯 `data:` 形态， 不得带 `event:` 行（见
///   `ensure_event_lines` 的 Chat 豁免）。 阻断文案 `[blocked: reason]` 不变。
pub fn chat_block_frames(reason: &str) -> Vec<String> {
    vec![
        format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":\"[blocked: {reason}]\"}}}}]}}\n\n"
        ),
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
            .to_string(),
        "data: [DONE]\n\n".to_string(),
    ]
}

pub fn anthropic_block_frames(reason: &str) -> Vec<String> {
    vec![
        format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"[blocked: {reason}]\"}}}}\n\n"
        ),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ]
}

/// Responses 阻断全序列（D3）：按 `output_index:0` 对齐的严格客户端缺中间帧即乱序，
/// 故发出 `output_item.added → content_part.added → output_text.delta →
/// output_text.done → content_part.done → output_item.done → response.completed`
/// 全链路（`item_id` 统一用 `response_id`）。
/// delta/done 帧不计入终止计数（dedupe 仅认 completed/failed），恰一约束不受影响。
pub fn responses_block_frames(response_id: &str) -> Vec<String> {
    let text = "[blocked: audit]";
    responses_sequence(response_id, text, true)
}

/// Responses 截断全序列（D3）：与阻断同序列，尾帧改 `response.failed`
/// （失败语义，不伪造完成），`terminal_count==1` 且不含 `completed`。
pub fn responses_truncated_frames(response_id: &str) -> Vec<String> {
    let text = "[truncated]";
    responses_sequence(response_id, text, false)
}

fn responses_sequence(response_id: &str, text: &str, completed: bool) -> Vec<String> {
    let tail = if completed {
        format!(
            "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"completed\"}}}}\n\n"
        )
    } else {
        format!(
            "event: response.failed\ndata: {{\"type\":\"response.failed\",\"response\":{{\"id\":\"{response_id}\",\"status\":\"failed\"}}}}\n\n"
        )
    };
    vec![
        format!(
            "event: response.output_item.added\ndata: {{\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{{\"id\":\"{response_id}\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}}}\n\n"
        ),
        format!(
            "event: response.content_part.added\ndata: {{\"type\":\"response.content_part.added\",\"item_id\":\"{response_id}\",\"output_index\":0,\"content_index\":0,\"part\":{{\"type\":\"output_text\",\"text\":\"\",\"annotations\":[]}}}}\n\n"
        ),
        format!(
            "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"item_id\":\"{response_id}\",\"output_index\":0,\"content_index\":0,\"delta\":\"{text}\"}}\n\n"
        ),
        format!(
            "event: response.output_text.done\ndata: {{\"type\":\"response.output_text.done\",\"item_id\":\"{response_id}\",\"output_index\":0,\"content_index\":0,\"text\":\"{text}\"}}\n\n"
        ),
        format!(
            "event: response.content_part.done\ndata: {{\"type\":\"response.content_part.done\",\"item_id\":\"{response_id}\",\"output_index\":0,\"content_index\":0,\"part\":{{\"type\":\"output_text\",\"text\":\"{text}\",\"annotations\":[]}}}}\n\n"
        ),
        format!(
            "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{{\"id\":\"{response_id}\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"{text}\",\"annotations\":[]}}]}}}}\n\n"
        ),
        tail,
    ]
}

/// Chat 帧判定（D1）：Chat Completions 流式分片载荷恒含 `choices`
/// （`data: {"choices":...}`），或为裸 `[DONE]` 终止帧；此类帧按规范恒为
/// 纯 `data:` 形态，`ensure_event_lines` 不得补 `event:` 行。
/// 仅检查 `data:` 行载荷，避免 `event:` 行名干扰。
fn is_chat_frame(frame: &str) -> bool {
    if is_done_frame(frame) {
        return true;
    }
    frame
        .lines()
        .filter(|l| l.trim_start().starts_with("data:"))
        .any(|l| l.contains("\"choices\""))
}

pub fn ensure_event_lines(frames: Vec<String>) -> Vec<String> {
    frames
        .into_iter()
        .map(|f| {
            // DONE 裸帧豁免：Chat 终止符恒为裸 `data: [DONE]`，不得补 `event:`。
            // D1：Chat 分片帧（`choices` 载荷）同样豁免补全；
            // Anthropic/Responses 缺 `event:` 行仍按原语义补全。
            if is_done_frame(&f) || is_chat_frame(&f) || f.lines().any(|l| l.starts_with("event:"))
            {
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

/// DONE 帧判定（D6 帧级）：整帧任一行为裸 `data: [DONE]` 即终止帧。
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

/// 非流阻断体（§2.3/D3）：三协议各自正确的 JSON 形态，与流式阻断帧语义对齐：
/// chat 为 `choices/finish_reason=stop` 消息体，另含 `id/object/created/model/usage`
/// 回显（严格 SDK 要求 `id` 非空；值优先回显上游响应，缺失时合成
/// `id:"blocked-<conv>"`、`model:"unknown_model"`（C13：回显上游值，
/// 不用字面 `blocked`）、`usage:{0,1,1}`）；
/// anthropic 为 `stop_reason=end_turn` 文本体（空 `conv` 回退 `blocked-0`，
/// 与流帧口径统一）；responses 为 `status=failed` 错误体（失败语义，不伪造完成）。
/// `NonDialog` 非对话不审计，返回 `Null`（调用方不应调用）。
pub fn nonstream_block_body(
    protocol: GatewayProtocol,
    reason: &str,
    conv_id: &str,
    upstream: Option<&Value>,
) -> Value {
    let text = format!("[blocked: {reason}]");
    match protocol {
        GatewayProtocol::Chat => {
            let id = upstream
                .and_then(|u| u.get("id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    if conv_id.is_empty() {
                        "blocked-unknown".to_string()
                    } else {
                        format!("blocked-{conv_id}")
                    }
                });
            let created = upstream
                .and_then(|u| u.get("created"))
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                });
            let model = upstream
                .and_then(|u| u.get("model"))
                .and_then(|v| v.as_str())
                .map(normalize_model)
                .unwrap_or_else(|| "unknown_model".to_string());
            let usage = upstream
                .and_then(|u| u.get("usage"))
                .filter(|v| v.is_object())
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({"prompt_tokens": 0, "completion_tokens": 1, "total_tokens": 1})
                });
            serde_json::json!({
                "id": id, "object": "chat.completion", "created": created, "model": model,
                "choices": [{"index": 0, "finish_reason": "stop",
                    "message": {"role": "assistant", "content": text}}],
                "usage": usage
            })
        }
        GatewayProtocol::Anthropic => {
            let id = if conv_id.is_empty() {
                "blocked-0".to_string()
            } else {
                conv_id.to_string()
            };
            // C13：阻断体 model 回显上游值（归一后），缺失归
            // `unknown_model`，不再用字面 `blocked`。
            let model = upstream
                .and_then(|u| u.get("model"))
                .and_then(|v| v.as_str())
                .map(normalize_model)
                .unwrap_or_else(|| "unknown_model".to_string());
            serde_json::json!({
                "id": id,
                "type": "message",
                "role": "assistant",
                "model": model,
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

/// 非流 tool 提取 + 审计（§2.3/P0-1.4）：提取三协议 tool 调用
/// （chat `tool_calls`、anthropic `tool_use`、responses `function_call`）
/// 并逐条 `audit::evaluate`；仅 `Block` 返回 `Some(阻断体)`（fail-closed），
/// `NeedApproval` 记 pending 后返回 `None` 走上游透传（与流式 B 案 `README 6.4`
/// 一致：不断链、不合成阻断帧）；全放行返回 `None`。
/// R5 职责声明：本模块只合成帧/体（阻断体/截断帧/空流帧），不累积字节；
/// 字节累积归 `audit_hold::AuditHold`（只累积、不合成帧），两边不交叉。
/// handler 接线说明：`Some(body)` 直接替代上游响应返回（E4 状态码统一恒 200，
/// 与流式恒 200 闭合对称，不再沿用上游码），`None` 走正常还原透传。
pub fn evaluate_nonstream(
    protocol: GatewayProtocol,
    body: &Value,
    mode: AuditMode,
    policy: &AuditPolicy,
    conv_id: &str,
    pending: &PendingApprovals,
) -> Option<Value> {
    if matches!(mode, AuditMode::Off) {
        return None;
    }
    let mut blocked_reason: Option<String> = None;
    for call in extract_tool_calls(protocol, body) {
        let name = call.name.as_deref().unwrap_or("");
        match evaluate(mode, name, &call.args, policy) {
            AuditVerdict::Allow => {}
            AuditVerdict::Block { reason } => {
                blocked_reason = Some(reason);
                break;
            }
            AuditVerdict::NeedApproval { reason, summary } => {
                pending.insert(PendingRecord::new(
                    &format!("nonstream-{conv_id}-{name}"),
                    &format!("{reason}: {summary}"),
                ));
            }
        }
    }
    blocked_reason.map(|r| nonstream_block_body(protocol, &r, conv_id, Some(body)))
}

/// 截断合成（P0-3.2/TSS-02，对标 Python `_synthesize_truncation`）：
/// responses 合成截断文本 + `response.failed`（失败语义，不伪造完成）；
/// chat/anthropic 不合成成功终止（open-ended，以已透传块收尾；残缺分片
/// 由泵内 TSS-03 缓冲丢弃）。返回帧由调用方经 `ensure_event_lines` 归一化后发送。
pub fn synthesize_truncation(protocol: GatewayProtocol, conv_id: &str) -> Vec<String> {
    match protocol {
        GatewayProtocol::Responses => responses_truncated_frames(conv_id),
        GatewayProtocol::Chat | GatewayProtocol::Anthropic | GatewayProtocol::NonDialog => {
            vec![]
        }
    }
}

/// 空流合成（C8 open-ended 回归，对标 Python `_synthesize_truncation`）：
/// 真空流（零残余）chat/anthropic 保持 open-ended（空帧集，不伪造成功终止，
/// 下游靠缺失 `finish_reason` 走 stub 路径）；Responses 仍合成 failed 终端
/// （TSS04，失败语义不伪造完成）；未知协议空实现。
pub fn empty_stream_frames(protocol: &str, conv_id: &str) -> Vec<String> {
    match protocol {
        "responses" => responses_truncated_frames(conv_id),
        _ => vec![],
    }
}

/// 协议级终端计数（D6 帧级）：chat 数 `[DONE]` 帧、anthropic 数 `message_stop`、
/// responses 数 `completed/failed`；恰一约束的计数口径。
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

/// DONE 行级计数（D6 行级）：逐帧按行精确匹配裸终止行（载荷内同串不误计）。
pub fn count_done(frames: &[String]) -> usize { frames.iter().filter(|f| is_done_frame(f)).count() }

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(has_chat_terminal(&norm));
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
        assert!(should_discard_after_terminal(true));
        assert!(!should_discard_after_terminal(false));
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
            super::super::audit::{AuditPolicy, AuditVerdict, evaluate},
            crate::config::AuditMode,
        };
        let policy = AuditPolicy::default_policy();
        let verdict = evaluate(AuditMode::Block, "blocked", "{}", &policy);
        assert!(
            matches!(verdict, AuditVerdict::Allow),
            "占位名 blocked + 空 input 须放行，否则下游二次调用被拦死循环"
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
