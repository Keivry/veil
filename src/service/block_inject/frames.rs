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
///
/// 旧 1 参入口：委托 [`chat_block_frames_full`]（`conv_id = None` / `model = ""`），
/// 保持既有调用点与测试零改。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn chat_block_frames(reason: &str) -> Vec<String> { chat_block_frames_full(reason, None, "") }

/// R5-03/R5-39：Chat 流阻断帧回显会话标识与归一模型名——`id` 取 `conv_id`
/// （非空）否则 `blocked-0`，`model` 取 `normalize_model(model)`（空归
/// `unknown_model`），与非流 [`nonstream_block_body`] 回显口径对齐。
pub fn chat_block_frames_full(reason: &str, conv_id: Option<&str>, model: &str) -> Vec<String> {
    // CHC-3/D8：补齐 OpenAI 流式对象必需字段 `id`/`object`/`created`/`model`，
    // 使官方 SDK 可解析（`object` 为流式 `chat.completion.chunk`）。
    let id = conv_id.filter(|s| !s.is_empty()).unwrap_or("blocked-0");
    let model = normalize_model(model);
    let created = now_created();
    let head = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0,
            "delta": {"role": "assistant", "content": format!("[blocked: {reason}]")}}]
    });
    let tail = serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
    });
    vec![
        format!("data: {head}\n\n"),
        format!("data: {tail}\n\n"),
        chat_done_frame(),
    ]
}

/// Unix 秒时间戳（合成 `created`/`created_at` 的合规默认值）。
fn now_created() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A-3/F-04：Anthropic `message_start` 首帧唯一构造（阻断五件套与真空流最小终止
/// 共用）——空 `content`、null `stop_reason`、usage 全 0；`id`/`model` 由调用方
/// 决定（阻断：`conv_id` 非空回退 `blocked-0` + `unknown_model`；真空流：非空
/// 回退 `vacuum-0`）。
fn anthropic_message_start(id: &str, model: &str) -> String {
    let start = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [],
            "stop_reason": null,
            "usage": {"input_tokens": 0, "output_tokens": 0}
        }
    });
    format!("event: message_start\ndata: {start}\n\n")
}

/// 旧 2 参入口：委托五件套（`conv_id = None` → `id` 回退 `blocked-0`），
/// 保持既有测试/调用点零改。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn anthropic_block_frames(reason: &str, index: u32) -> Vec<String> {
    anthropic_block_frames_full(reason, index, None)
}

/// A-3/F-04：Anthropic 阻断五件套——既有四帧前补恰一 `message_start`
/// （官方 Messages SSE 首事件，缺首帧时严格 SDK 流式累加器无初始 message 快照）；
/// `id = conv_id 非空 ? conv_id : "blocked-0"`；`model` 旧入口恒 `unknown_model`
/// （R5-39 回显入口见 [`anthropic_block_frames_modeled`]）。
/// 原四帧内容与顺序不动，`message_stop` 保持空对象。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn anthropic_block_frames_full(reason: &str, index: u32, conv_id: Option<&str>) -> Vec<String> {
    anthropic_block_frames_modeled(reason, index, conv_id, "")
}

/// R5-39：Anthropic 阻断五件套模型回显入口——`model` 经 `normalize_model` 回显
/// （缺失归 `unknown_model`），与非流 [`nonstream_block_body`] 同口径。
pub fn anthropic_block_frames_modeled(
    reason: &str,
    index: u32,
    conv_id: Option<&str>,
    model: &str,
) -> Vec<String> {
    let id = conv_id.filter(|s| !s.is_empty()).unwrap_or("blocked-0");
    let mut frames = vec![anthropic_message_start(id, &normalize_model(model))];
    frames.extend([
        format!(
            "event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":{index},\"content_block\":{{\"type\":\"text\",\"text\":\"[blocked: {reason}]\"}}}}\n\n"
        ),
        format!(
            "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
        ),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\n".to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ]);
    frames
}

/// Responses 阻断全序列（D3）：按 `output_index:0` 对齐的严格客户端缺中间帧即乱序，
/// 故发出 `output_item.added → content_part.added → output_text.delta →
/// output_text.done → content_part.done → output_item.done → response.completed`
/// 全链路（`item_id` 统一用 `response_id`）。
/// delta/done 帧不计入终止计数（dedupe 仅认 completed/failed），恰一约束不受影响。
/// A-2/F-02：真空流口径 0 起（既有 0..6 全序列不变）。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn responses_block_frames(response_id: &str) -> Vec<String> {
    responses_block_frames_at(response_id, 0)
}

/// A-2/F-02：以 `base` 为起始序号的阻断全序列——流内阻断接续上游已见最大
/// `sequence_number`（`base = cursor.map_or(0, |c| c.saturating_add(1))`，R8-04），
/// 全程单调不倒退（`u64::MAX` 饱和不溢出）。
/// 旧入口模型恒 `unknown_model`（R5-39 回显入口见 [`responses_block_frames_at_modeled`]）。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn responses_block_frames_at(response_id: &str, base: u64) -> Vec<String> {
    responses_block_frames_at_modeled(response_id, base, "")
}

/// R5-39：Responses 阻断全序列模型回显入口（`model` 缺失归 `unknown_model`）。
pub fn responses_block_frames_at_modeled(response_id: &str, base: u64, model: &str) -> Vec<String> {
    responses_sequence(response_id, "[blocked: audit]", true, base, model)
}

/// 协议阻断帧的单一声明式分派（7.6）：收敛泵内两处重复的
/// `match protocol { .. chat/anthropic/responses_block_frames }`。`blocked_index` 为触发
/// 阻断的真实 content block index（Anthropic 专用，其余协议忽略）；`conv_id` 缺失时
/// Responses 走归档回退（`metrics` 仅参与该回退计数）。
/// A-2/F-02：`seq_cursor` 为泵内「已见上游序号上界」游标，Responses 合成序列
/// 据此取 `base = cursor.map_or(0, |c| c + 1)` 接续，不再从 0 重编号。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn protocol_block_frames(
    protocol: GatewayProtocol,
    reason: &str,
    conv_id: Option<&str>,
    blocked_index: u32,
    metrics: Option<&GatewayMetrics>,
    seq_cursor: Option<u64>,
) -> Vec<String> {
    protocol_block_frames_modeled(
        protocol,
        reason,
        conv_id,
        "",
        blocked_index,
        metrics,
        seq_cursor,
    )
}

/// R5-39：阻断帧分派模型回显入口——`model` 透传到三协议各自的回显构造
/// （缺失归 `unknown_model`），旧 [`protocol_block_frames`] 委托本函数（`model = ""`）。
pub fn protocol_block_frames_modeled(
    protocol: GatewayProtocol,
    reason: &str,
    conv_id: Option<&str>,
    model: &str,
    blocked_index: u32,
    metrics: Option<&GatewayMetrics>,
    seq_cursor: Option<u64>,
) -> Vec<String> {
    match protocol {
        GatewayProtocol::Chat => chat_block_frames_full(reason, conv_id, model),
        GatewayProtocol::Anthropic => {
            anthropic_block_frames_modeled(reason, blocked_index, conv_id, model)
        }
        GatewayProtocol::Responses => {
            let bid = conv_id
                .map(str::to_string)
                .unwrap_or_else(|| resolve_conv_id(None, &Value::Null, metrics, "block").0);
            responses_block_frames_at_modeled(&bid, synth_seq_base(seq_cursor), model)
        }
        GatewayProtocol::NonDialog => vec![],
    }
}

/// A-2/F-02：合成序列起始基准——真空流/无上游序号时取 0，否则接续 `max + 1`。
/// R8-04：`max == u64::MAX` 时按饱和加法保持 `u64::MAX`（不回绕、不 panic）。
fn synth_seq_base(cursor: Option<u64>) -> u64 { cursor.map_or(0, |c| c.saturating_add(1)) }

/// Responses 截断全序列（D3）：与阻断同序列，尾帧改 `response.failed`
/// （失败语义，不伪造完成），`terminal_count==1` 且不含 `completed`。
/// P4/D4：本全序列**仅真空流**（`empty_stream_frames`）使用——含 `output_index`
/// 的注入仅对无已流出 item 的零帧流安全；流中段 `error`/截断改单帧
/// [`responses_failed_frame`]（避免重复 `output_index`）。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn responses_truncated_frames(response_id: &str) -> Vec<String> {
    responses_truncated_frames_modeled(response_id, "")
}

/// R5-39：Responses 真空/截断全序列模型回显入口（`model` 缺失归 `unknown_model`）。
pub fn responses_truncated_frames_modeled(response_id: &str, model: &str) -> Vec<String> {
    responses_sequence(response_id, "[truncated]", false, 0, model)
}

/// P4/D4 + D5 + TRN-2：`type:"error"` 单帧合成——`response.failed` 单帧携带上游
/// error 诊断对象（`code`/`type`/`param`/`message` 存在即保留；`None` 时保持
/// 既有 `{"id","status"}` 形态，不带 error 字段）；`sequence_number` 可得时写入
/// 载荷顶层（对齐官方 `ResponseErrorEvent`）；不注入
/// `output_index`/`output_item.*` 序列，不与已流出 item 冲突。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn responses_failed_frame(
    response_id: &str,
    error: Option<&Value>,
    sequence_number: Option<u64>,
) -> String {
    responses_failed_frame_modeled(response_id, error, sequence_number, "")
}

/// R5-39：`response.failed` 单帧模型回显入口——`model` 经 `normalize_model`
/// （缺失归 `unknown_model`），与非流 [`nonstream_block_body`] 同口径。
pub fn responses_failed_frame_modeled(
    response_id: &str,
    error: Option<&Value>,
    sequence_number: Option<u64>,
    model: &str,
) -> String {
    // RSP-4/D9：合成 `response` 对象补齐必需字段（`object`/`created_at`/`model`/
    // `output`/`status`），使 SDK 解析不因缺 `output` 抛 `TypeError`。
    let mut response = serde_json::json!({
        "id": response_id, "object": "response", "created_at": now_created(),
        "model": normalize_model(model), "status": "failed", "output": []
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

fn responses_sequence(
    response_id: &str,
    text: &str,
    completed: bool,
    base: u64,
    model: &str,
) -> Vec<String> {
    let created = now_created();
    let model = normalize_model(model);
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
                "model": model, "status": "completed",
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
                "model": model, "status": "failed",
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
            base,
        ),
        responses_frame(
            "response.content_part.added",
            serde_json::json!({
                "type": "response.content_part.added", "item_id": response_id,
                "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []}
            }),
            base.saturating_add(1),
        ),
        responses_frame(
            "response.output_text.delta",
            serde_json::json!({
                "type": "response.output_text.delta", "item_id": response_id,
                "output_index": 0, "content_index": 0, "delta": text
            }),
            base.saturating_add(2),
        ),
        responses_frame(
            "response.output_text.done",
            serde_json::json!({
                "type": "response.output_text.done", "item_id": response_id,
                "output_index": 0, "content_index": 0, "text": text
            }),
            base.saturating_add(3),
        ),
        responses_frame(
            "response.content_part.done",
            serde_json::json!({
                "type": "response.content_part.done", "item_id": response_id,
                "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": text, "annotations": []}
            }),
            base.saturating_add(4),
        ),
        responses_frame(
            "response.output_item.done",
            serde_json::json!({
                "type": "response.output_item.done", "output_index": 0, "item": output_item
            }),
            base.saturating_add(5),
        ),
        responses_frame(terminal_event, terminal, base.saturating_add(6)),
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
/// 与流帧口径统一）；responses 为 `status=failed` 失败体且必需字段与流式
/// `responses_failed_frame` 同形（`object/created_at/model/output` 齐全，
/// `output` 恒空、`error` 仅 `message`；A-1/F-01）。
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
        GatewayProtocol::Responses => {
            // A-1/F-01：与流式 `responses_failed_frame` 同形——`object`/`created_at`/
            // `model`/`output`/`status` 必需字段齐全（严格 SDK 解析不抛错），
            // `output` 恒空数组、`status` 恒 `failed`；`id` 三级回退（上游 `id` →
            // `conv_id` → `blocked-0`），`model`/`created_at` 优先回显上游归一值
            // （与 chat/anthropic 分支同口径），`error` 仅保留 `message`
            // （不合成 `code`/`param`，与流式逐字段对齐）。
            let id = upstream
                .and_then(|u| u.get("id"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if conv_id.is_empty() {
                        "blocked-0".to_string()
                    } else {
                        conv_id.to_string()
                    }
                });
            let model = upstream
                .and_then(|u| u.get("model"))
                .and_then(|v| v.as_str())
                .map(normalize_model)
                .unwrap_or_else(|| "unknown_model".to_string());
            let created_at = upstream
                .and_then(|u| u.get("created_at"))
                .and_then(|v| v.as_u64())
                .unwrap_or_else(now_created);
            serde_json::json!({
                "id": id, "object": "response", "created_at": created_at,
                "model": model, "status": "failed", "output": [],
                "error": {"message": text}
            })
        }
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
/// A-2/F-02：`seq_cursor` 为泵内上游序号上界游标——单帧 `sequence_number` 取
/// `base = cursor.map_or(0, |c| c.saturating_add(1))`（R8-04 饱和），接续已发序号
/// （修正原误传 `None` 致缺字段）。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn synthesize_truncation(
    protocol: GatewayProtocol,
    conv_id: &str,
    seq_cursor: Option<u64>,
) -> Vec<String> {
    synthesize_truncation_modeled(protocol, conv_id, seq_cursor, "")
}

/// R5-39：截断合成模型回显入口（`response.failed` 单帧携带 `model`，缺失归
/// `unknown_model`）；旧 [`synthesize_truncation`] 委托本函数（`model = ""`）。
pub fn synthesize_truncation_modeled(
    protocol: GatewayProtocol,
    conv_id: &str,
    seq_cursor: Option<u64>,
    model: &str,
) -> Vec<String> {
    if !protocol.is_responses() {
        return vec![];
    }
    vec![responses_failed_frame_modeled(
        conv_id,
        Some(&serde_json::json!({"message": "truncated"})),
        Some(synth_seq_base(seq_cursor)),
        model,
    )]
}

/// 空流合成（P2/D2/D3，对标 Python `_synthesize_truncation`）：
/// 真空流（零残余）三协议均补最小可解析终止——chat 恰一 `data: [DONE]`；
/// anthropic 最小 `message_start`+`message_stop`（空 content、null stop_reason、
/// usage 全 0，不含 `content_block_*`，不伪造成功）；responses 保持
/// `response.failed` 全序列（失败语义不伪造完成）；未知协议空实现。
/// R5-39：生产合成一律经 `_modeled` 入口；本入口 `#[cfg(test)]` 收编防生产误用。
#[cfg(test)]
pub fn empty_stream_frames(protocol: &str, conv_id: &str) -> Vec<String> {
    empty_stream_frames_modeled(protocol, conv_id, "")
}

/// R5-39：空流/真空流合成模型回显入口（Anthropic/Responses 回显 `model`，
/// 缺失归 `unknown_model`）；旧 [`empty_stream_frames`] 委托本函数（`model = ""`）。
pub fn empty_stream_frames_modeled(protocol: &str, conv_id: &str, model: &str) -> Vec<String> {
    match protocol {
        "chat" => vec![chat_done_frame()],
        "anthropic" => anthropic_vacuum_frames(conv_id, model),
        "responses" => responses_truncated_frames_modeled(conv_id, model),
        _ => vec![],
    }
}

/// P2/D3：Anthropic 真空流最小终止信封——首帧复用 [`anthropic_message_start`]
/// 构造（空 content、null `stop_reason`、usage 全 0），`model` 经 `normalize_model`
/// 回显；不注入 `content_block_*`、不声称语义 stop_reason。
fn anthropic_vacuum_frames(conv_id: &str, model: &str) -> Vec<String> {
    let id = if conv_id.is_empty() {
        "vacuum-0"
    } else {
        conv_id
    };
    vec![
        anthropic_message_start(id, &normalize_model(model)),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ]
}

#[cfg(test)]
mod tests;
