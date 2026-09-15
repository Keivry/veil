//! 三协议阻断帧/体合成（H1.2 一切：帧合成）。
//!
//! - 流式帧：`chat/anthropic/responses_block_frames` + 截断/空流合成
//!   （`synthesize_truncation`/`empty_stream_frames`：Responses 合成 failed 单帧/全序列，
//!   Chat/Anthropic 真空补最小线级终止，不伪造内容/usage/成功语义）。
//! - 非流体：`nonstream_block_body` 三协议 JSON 形态 + `evaluate_nonstream` tool 提取与审计（仅
//!   `Block` 合成阻断体，`NeedApproval` 记 pending 透传）。
//! - `ensure_event_lines` 归一化（RSP-7：不注入 `event: message`，保持原 data 帧形态）。
//! - 对外路径不变：经 `super`（`service::block_inject`）重导出，调用方零改。

use {
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
        service::{
            audit::{AuditPolicy, AuditVerdict, evaluate_with_whitelist},
            llm_gateway::{
                GatewayMetrics,
                Protocol as GatewayProtocol,
                extract_tool_calls,
                resolve_conv_id,
            },
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
///
/// CHC-6/2.25 声明覆盖范围：合成阻断帧仅覆盖 `choices[].index == 0` 单 choice 面；
/// 审计阻断为流级动作（替换整条流），多 choice 流的其余 choice 不再逐条重建。
/// 该声明由 `block_frame_choice_coverage` 测试锁定。
pub fn chat_block_frames(reason: &str) -> Vec<String> {
    // CHC-3/D8：补齐 OpenAI 流式对象必需字段 `id`/`object`/`created`/`model`，
    // 使官方 SDK 可解析（`object` 为流式 `chat.completion.chunk`）。
    let created = now_created();
    let head = serde_json::json!({
        "id": "blocked-0",
        "object": "chat.completion.chunk",
        "created": created,
        "model": "unknown_model",
        "choices": [{"index": 0,
            "delta": {"role": "assistant", "content": format!("[blocked: {reason}]")}}]
    });
    let tail = serde_json::json!({
        "id": "blocked-0",
        "object": "chat.completion.chunk",
        "created": created,
        "model": "unknown_model",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    });
    vec![
        format!("data: {head}\n\n"),
        format!("data: {tail}\n\n"),
        "data: [DONE]\n\n".to_string(),
    ]
}

/// Unix 秒时间戳（合成 `created`/`created_at` 的合规默认值）。
fn now_created() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn anthropic_block_frames(reason: &str, index: u32) -> Vec<String> {
    vec![
        format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"text\",\"text\":\"[blocked: {reason}]\"}}}}\n\n"
        ),
        format!(
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
        ),
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

/// 协议阻断帧的单一声明式分派（7.6）：收敛泵内两处重复的
/// `match protocol { .. chat/anthropic/responses_block_frames }`。`blocked_index` 为触发
/// 阻断的真实 content block index（Anthropic 专用，其余协议忽略）；`conv_id` 缺失时
/// Responses 走归档回退（`metrics` 仅参与该回退计数）。
pub fn protocol_block_frames(
    protocol: GatewayProtocol,
    reason: &str,
    conv_id: Option<&str>,
    blocked_index: u32,
    metrics: Option<&GatewayMetrics>,
) -> Vec<String> {
    match protocol {
        GatewayProtocol::Chat => chat_block_frames(reason),
        GatewayProtocol::Anthropic => anthropic_block_frames(reason, blocked_index),
        GatewayProtocol::Responses => {
            let bid = conv_id
                .map(str::to_string)
                .unwrap_or_else(|| resolve_conv_id(None, &Value::Null, metrics, "block").0);
            responses_block_frames(&bid)
        }
        GatewayProtocol::NonDialog => vec![],
    }
}

/// Responses 截断全序列（D3）：与阻断同序列，尾帧改 `response.failed`
/// （失败语义，不伪造完成），`terminal_count==1` 且不含 `completed`。
/// P4/D4：本全序列**仅真空流**（`empty_stream_frames`）使用——含 `output_index`
/// 的注入仅对无已流出 item 的零帧流安全；流中段 `error`/截断改单帧
/// [`responses_failed_frame`]（避免重复 `output_index`）。
pub fn responses_truncated_frames(response_id: &str) -> Vec<String> {
    let text = "[truncated]";
    responses_sequence(response_id, text, false)
}

/// P4/D4 + D5 + TRN-2：`type:"error"` 单帧合成——`response.failed` 单帧携带上游
/// error 诊断对象（`code`/`type`/`param`/`message` 存在即保留；`None` 时保持
/// 既有 `{"id","status"}` 形态，不带 error 字段）；`sequence_number` 可得时写入
/// 载荷顶层（对齐官方 `ResponseErrorEvent`）；不注入
/// `output_index`/`output_item.*` 序列，不与已流出 item 冲突。
pub fn responses_failed_frame(
    response_id: &str,
    error: Option<&Value>,
    sequence_number: Option<u64>,
) -> String {
    // RSP-4/D9：合成 `response` 对象补齐必需字段（`object`/`created_at`/`model`/
    // `output`/`status`），使 SDK 解析不因缺 `output` 抛 `TypeError`。
    let mut response = serde_json::json!({
        "id": response_id, "object": "response", "created_at": now_created(),
        "model": "unknown_model", "status": "failed", "output": []
    });
    if let Some(err) = error {
        response["error"] = err.clone();
    }
    let mut payload = serde_json::json!({"type": "response.failed", "response": response});
    if let Some(seq) = sequence_number {
        payload["sequence_number"] = serde_json::json!(seq);
    }
    format!("event: response.failed\ndata: {payload}\n\n")
}

/// RSP-3/D8：合成 Responses 帧统一写入单调 `sequence_number`（0 起、逐帧 +1、无缺口）。
fn responses_frame(event: &str, mut payload: Value, seq: u64) -> String {
    payload["sequence_number"] = serde_json::json!(seq);
    format!("event: {event}\ndata: {payload}\n\n")
}

fn responses_sequence(response_id: &str, text: &str, completed: bool) -> Vec<String> {
    let created = now_created();
    let output_item = serde_json::json!({
        "id": response_id, "type": "message", "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}]
    });
    // RSP-4/D9：终端 `response` 对象补齐必需字段（含 `output`/`status`），
    // `object` 恒为 `response`，使 SDK `get_final_response().output_text` 可达。
    let terminal = if completed {
        serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": response_id, "object": "response", "created_at": created,
                "model": "unknown_model", "status": "completed",
                "output": [output_item.clone()],
                "parallel_tool_calls": false, "tool_choice": "auto", "tools": [],
                "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            }
        })
    } else {
        serde_json::json!({
            "type": "response.failed",
            "response": {
                "id": response_id, "object": "response", "created_at": created,
                "model": "unknown_model", "status": "failed",
                "output": [output_item.clone()],
                "error": {"message": text},
                "parallel_tool_calls": false, "tool_choice": "auto", "tools": []
            }
        })
    };
    let terminal_event = if completed {
        "response.completed"
    } else {
        "response.failed"
    };
    vec![
        responses_frame(
            "response.output_item.added",
            serde_json::json!({
                "type": "response.output_item.added", "output_index": 0,
                "item": {"id": response_id, "type": "message", "role": "assistant", "content": []}
            }),
            0,
        ),
        responses_frame(
            "response.content_part.added",
            serde_json::json!({
                "type": "response.content_part.added", "item_id": response_id,
                "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []}
            }),
            1,
        ),
        responses_frame(
            "response.output_text.delta",
            serde_json::json!({
                "type": "response.output_text.delta", "item_id": response_id,
                "output_index": 0, "content_index": 0, "delta": text
            }),
            2,
        ),
        responses_frame(
            "response.output_text.done",
            serde_json::json!({
                "type": "response.output_text.done", "item_id": response_id,
                "output_index": 0, "content_index": 0, "text": text
            }),
            3,
        ),
        responses_frame(
            "response.content_part.done",
            serde_json::json!({
                "type": "response.content_part.done", "item_id": response_id,
                "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": text, "annotations": []}
            }),
            4,
        ),
        responses_frame(
            "response.output_item.done",
            serde_json::json!({
                "type": "response.output_item.done", "output_index": 0, "item": output_item
            }),
            5,
        ),
        responses_frame(terminal_event, terminal, 6),
    ]
}

/// RSP-7/2.31：SSE 出口/合成不得为缺 `event:` 行的 data 帧注入 `event: message`——
/// 保持原 data 帧形态（WHATWG 无 `event:` 即默认事件类型，由下游自行处理）。
/// 合成帧（Anthropic/Responses）均自带 `event:`；Chat/`[DONE]` 恒为纯 `data:` 形态。
/// 本入口保留为显式归一化点，语义为原样透传。
pub fn ensure_event_lines(frames: Vec<String>) -> Vec<String> { frames }

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

/// 非流 tool 提取 + 审计（§2.3/P0-1.4，T1/P2-1）：提取三协议 tool 调用
/// （chat `tool_calls`、anthropic `tool_use`、responses `function_call`）
/// 并逐条 `audit::evaluate_with_whitelist`（与流式同口径白名单入口）；
/// 仅 `Block` 返回 `Some(阻断体)`（fail-closed），
/// `NeedApproval` 记 pending 后返回 `None` 走上游透传（与流式 B 案 `README 6.4`
/// 一致：不断链、不合成阻断帧）；全放行返回 `None`。
/// R5 职责声明：本模块只合成帧/体（阻断体/截断帧/空流帧），不累积字节；
/// 字节累积归 `service::audit::AuditHold`（只累积、不合成帧），两边不交叉。
/// handler 接线说明：`Some(body)` 是否替代上游响应由调用方按上游状态码裁决
/// （T3/D3：仅上游 2xx 合成 200 阻断体；错误状态保留上游状态与正文并照记审计，
/// 见 `src/handler/llm/nonstream.rs`），`None` 走正常还原透传。
pub fn evaluate_nonstream(
    protocol: GatewayProtocol,
    body: &Value,
    mode: AuditMode,
    policy: &AuditPolicy,
    conv_id: &str,
    approval_whitelist: &[String],
    pending: &PendingApprovals,
) -> Option<Value> {
    if matches!(mode, AuditMode::Off) {
        return None;
    }
    let mut blocked_reason: Option<String> = None;
    for call in extract_tool_calls(protocol, body) {
        let name = call.name.as_deref().unwrap_or("");
        match evaluate_with_whitelist(mode, name, &call.args, policy, approval_whitelist) {
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
/// responses 合成单帧 `response.failed`（`response.error.message="truncated"`，
/// 失败语义不伪造完成；P4/D4：不再注入 7 帧 `output_index` 序列——流中段可能
/// 已流出 `output_index:0` 的 item，重复注入违反序号单调）；chat/anthropic
/// 不合成成功终止（open-ended，以已透传块收尾；残缺分片由泵内 TSS-03 缓冲丢弃）。
/// 返回帧由调用方经 `ensure_event_lines` 归一化后发送。
pub fn synthesize_truncation(protocol: GatewayProtocol, conv_id: &str) -> Vec<String> {
    if !protocol.is_responses() {
        return vec![];
    }
    vec![responses_failed_frame(
        conv_id,
        Some(&serde_json::json!({"message": "truncated"})),
        None,
    )]
}

/// 空流合成（P2/D2/D3，对标 Python `_synthesize_truncation`）：
/// 真空流（零残余）三协议均补最小可解析终止——chat 恰一 `data: [DONE]`；
/// anthropic 最小 `message_start`+`message_stop`（空 content、null stop_reason、
/// usage 全 0，不含 `content_block_*`，不伪造成功）；responses 保持
/// `response.failed` 全序列（失败语义不伪造完成）；未知协议空实现。
pub fn empty_stream_frames(protocol: &str, conv_id: &str) -> Vec<String> {
    match protocol {
        "chat" => vec![chat_done_frame()],
        "anthropic" => anthropic_vacuum_frames(conv_id),
        "responses" => responses_truncated_frames(conv_id),
        _ => vec![],
    }
}

/// P2/D3：Anthropic 真空流最小终止信封——`message_start` 空 content、
/// null `stop_reason`、usage 全 0，`model` 按既有回退口径置 `unknown_model`；
/// 不注入 `content_block_*`、不声称语义 stop_reason。
fn anthropic_vacuum_frames(conv_id: &str) -> Vec<String> {
    let id = if conv_id.is_empty() {
        "vacuum-0"
    } else {
        conv_id
    };
    let start = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": id,
            "type": "message",
            "role": "assistant",
            "model": "unknown_model",
            "content": [],
            "stop_reason": null,
            "usage": {"input_tokens": 0, "output_tokens": 0}
        }
    });
    vec![
        format!("event: message_start\ndata: {start}\n\n"),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::service::block_inject::{count_done, ensure_event_lines},
    };

    /// 抽取帧内所有 `data:` 行的合法 JSON 载荷（`[DONE]` 跳过）。
    fn data_payloads(frame: &str) -> Vec<Value> {
        frame
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter(|p| p.trim() != "[DONE]")
            .filter_map(|p| serde_json::from_str::<Value>(p).ok())
            .collect()
    }

    #[test]
    fn synth_chat_frame_fields_complete() {
        // CHC-3/D8：合成 chat 流帧补齐 id/object/created/model 四字段且类型正确。
        let frames = chat_block_frames("policy");
        assert_eq!(frames.len(), 3);
        for (i, expected_content) in [(0usize, true), (1, false)] {
            let payload = data_payloads(&frames[i]).remove(0);
            assert!(
                payload["id"].as_str().is_some_and(|s| !s.is_empty()),
                "id 非空: {payload}"
            );
            assert_eq!(payload["object"], "chat.completion.chunk");
            assert!(payload["created"].is_u64(), "created 为整数: {payload}");
            assert!(
                payload["model"].as_str().is_some_and(|s| !s.is_empty()),
                "model 非空: {payload}"
            );
            assert_eq!(payload["choices"][0]["index"], 0);
            if expected_content {
                assert!(payload["choices"][0]["delta"]["content"].is_string());
            } else {
                assert_eq!(payload["choices"][0]["finish_reason"], "stop");
            }
        }
    }

    #[test]
    fn no_synthetic_event_message() {
        // RSP-7/2.31：缺 `event:` 的 data 帧保持原形态，不注入 `event: message`。
        let raw = vec!["data: {\"a\":1}\n\n".to_string()];
        let out = ensure_event_lines(raw.clone());
        assert_eq!(out, raw, "不得注入 event: 行");
        assert!(!out[0].contains("event:"), "{}", out[0]);
        let with_event = vec!["event: x\ndata: {\"a\":1}\n\n".to_string()];
        assert_eq!(ensure_event_lines(with_event.clone()), with_event);
    }

    #[test]
    fn block_frame_choice_coverage() {
        // CHC-6/2.25：合成 Chat 阻断帧的声明覆盖范围为单 choice index 0，锁定之。
        let frames = ensure_event_lines(chat_block_frames("policy"));
        let mut choice_indices = Vec::new();
        for f in &frames {
            for payload in data_payloads(f) {
                let choices = payload["choices"].as_array().expect("choices 须为数组");
                assert_eq!(choices.len(), 1, "声明覆盖单 choice: {payload}");
                choice_indices.push(choices[0]["index"].as_u64().expect("index 须为整数"));
            }
        }
        assert_eq!(choice_indices.len(), 2, "两数据帧各一个 choice");
        assert!(
            choice_indices.iter().all(|i| *i == 0),
            "声明覆盖 choices[].index == 0: {choice_indices:?}"
        );
    }

    #[test]
    fn synth_chat_frame_sdk_parse() {
        // CHC-3/D8（SDK 等价）：规范流式增量为 `choices[].delta`，恰一裸 `[DONE]`。
        let frames = ensure_event_lines(chat_block_frames("policy"));
        assert_eq!(count_done(&frames), 1, "恰一 [DONE]");
        assert!(
            frames.iter().all(|f| !f.contains("event:")),
            "Chat 帧恒为纯 data: 形态"
        );
        let head = data_payloads(&frames[0]).remove(0);
        assert_eq!(head["object"], "chat.completion.chunk");
        assert_eq!(head["choices"][0]["delta"]["role"], "assistant");
        assert!(
            head["choices"][0]["delta"]["content"]
                .as_str()
                .unwrap()
                .contains("[blocked: policy]")
        );
        assert!(head["created"].is_u64() && head["model"].as_str().is_some());
        let tail = data_payloads(&frames[1]).remove(0);
        assert_eq!(tail["choices"][0]["finish_reason"], "stop");
        assert_eq!(tail["object"], "chat.completion.chunk");
    }

    #[test]
    fn synth_frames_sequence_number_monotonic() {
        // RSP-3/D8：阻断与真空流全序列均自 0 单调递增、无缺口。
        for frames in [
            ensure_event_lines(responses_block_frames("r1")),
            ensure_event_lines(responses_truncated_frames("r1")),
        ] {
            let seqs: Vec<u64> = frames
                .iter()
                .flat_map(|f| data_payloads(f))
                .filter_map(|p| p["sequence_number"].as_u64())
                .collect();
            assert_eq!(seqs.len(), 7, "7 帧均须带序号: {seqs:?}");
            assert_eq!(
                seqs,
                (0..7u64).collect::<Vec<u64>>(),
                "须自 0 单调无缺口: {seqs:?}"
            );
        }
    }

    #[test]
    fn synth_frames_sequence_number_required() {
        // RSP-3/D8：每帧结构断言含 `sequence_number`，不得省略。
        let frames = ensure_event_lines(responses_block_frames("r1"));
        assert_eq!(frames.len(), 7);
        for f in &frames {
            let payload = data_payloads(f).remove(0);
            assert!(
                payload.get("sequence_number").is_some(),
                "缺 sequence_number: {f}"
            );
        }
    }

    #[test]
    fn synth_response_required_fields() {
        // RSP-4/D9：合成 `response` 对象含 `output`/`status`，
        // `output_text` 语义可达（`output` 为数组且含 output_text part）。
        let frames = ensure_event_lines(responses_block_frames("r1"));
        let completed = frames
            .iter()
            .find(|f| f.contains("response.completed"))
            .expect("须含 response.completed");
        let payload = data_payloads(completed).remove(0);
        let response = &payload["response"];
        assert_eq!(response["object"], "response");
        assert_eq!(response["status"], "completed");
        assert!(response["created_at"].is_number());
        assert!(response["model"].as_str().is_some_and(|s| !s.is_empty()));
        let output = response["output"].as_array().expect("output 须为数组");
        assert_eq!(output[0]["type"], "message");
        assert_eq!(output[0]["content"][0]["type"], "output_text");
        assert!(
            output[0]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("[blocked:")
        );
        let failed = ensure_event_lines(responses_truncated_frames("r1"));
        let payload = data_payloads(failed.last().unwrap()).remove(0);
        assert_eq!(payload["response"]["status"], "failed");
        assert!(payload["response"]["output"].is_array());
    }
}
