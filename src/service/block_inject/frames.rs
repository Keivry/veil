//! 三协议阻断帧/体合成（H1.2 一切：帧合成）。
//!
//! - 流式帧：`chat/anthropic/responses_block_frames` + 截断/空流合成
//!   （`synthesize_truncation`/`empty_stream_frames`，Responses 合成 failed， chat/anthropic
//!   真空保持 open-ended 不伪造成功终止）。
//! - 非流体：`nonstream_block_body` 三协议 JSON 形态 + `evaluate_nonstream` tool 提取与审计（仅
//!   `Block` 合成阻断体，`NeedApproval` 记 pending 透传）。
//! - `ensure_event_lines` 归一化（Chat/`[DONE]` 豁免补 `event:` 行）。
//! - 对外路径不变：经 `super`（`service::block_inject`）重导出，调用方零改。

use {
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
        service::{
            audit::{AuditPolicy, AuditVerdict, evaluate},
            llm_gateway::{Protocol as GatewayProtocol, extract_tool_calls},
            metrics::normalize_model,
        },
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

pub fn chat_done_frame() -> String { "data: [DONE]\n\n".to_string() }

/// DONE 帧判定（D6 帧级）：整帧任一行为裸 `data: [DONE]` 即终止帧。
pub fn is_done_frame(frame: &str) -> bool {
    frame.lines().any(|l| {
        // §2.6：BOM 剥离后判 DONE（`﻿data: [DONE]` 同样是终止帧，参与去重）。
        let t = l.trim().trim_start_matches('\u{feff}');
        t == "data: [DONE]" || t == "data:[DONE]"
    })
}

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
