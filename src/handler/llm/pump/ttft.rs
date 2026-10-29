//! 首 token 时延（TTFT）采样：请求起始 → 首个**生成 token** 真正下行。
//!
//! 定格判据由 [`carries_output_token`] 单一承载：只有真正产出 token 文本的帧
//! 才让计时器起跑，协议簿记帧（`message_start`/`response.created` 等）不参与，
//! 否则 TTFT 会退化成「首字节时延」。

use {
    crate::service::llm_gateway::Protocol,
    serde_json::Value,
    std::{
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        time::Instant,
    },
};

/// 首 token 时延追踪器（毫秒）：请求起始 → **首个生成 token 真正下行**。
///
/// `note_content` 在承载生成 token 文本的帧（内容或推理，判据见
/// [`carries_output_token`]）并入聚合缓冲时置位，`note_sent` 在该批帧
/// `pump_tx.send` 成功后采样一次，只记首个时刻。
/// 用原子而非 `Cell`：`PumpEnv` 以 `&` 跨 `.await` 传递，须满足 `Sync`。
pub(super) struct TtftTracker {
    req_start: Instant,
    pending: AtomicBool,
    first_ms: AtomicU64,
}

/// `first_ms` 的「尚未采样」哨兵值。
const TTFT_UNSET: u64 = u64::MAX;

impl TtftTracker {
    pub(super) fn new(req_start: Instant) -> Self {
        Self {
            req_start,
            pending: AtomicBool::new(false),
            first_ms: AtomicU64::new(TTFT_UNSET),
        }
    }

    /// 标记「聚合缓冲中已有待下发内容」。
    pub(super) fn note_content(&self) { self.pending.store(true, Ordering::Relaxed); }

    /// 帧批次已成功下发：若含待发内容且尚未采样，落首个时延。
    pub(super) fn note_sent(&self) {
        if !self.pending.swap(false, Ordering::Relaxed)
            || self.first_ms.load(Ordering::Relaxed) != TTFT_UNSET
        {
            return;
        }
        let ms = u64::try_from(self.req_start.elapsed().as_millis()).unwrap_or(TTFT_UNSET);
        // 竞态下可能被别的调用点先写；`store` 以先到为准不改写已采样值。
        let _ =
            self.first_ms
                .compare_exchange(TTFT_UNSET, ms, Ordering::Relaxed, Ordering::Relaxed);
    }

    pub(super) fn first_ms(&self) -> Option<u32> {
        let ms = self.first_ms.load(Ordering::Relaxed);
        (ms != TTFT_UNSET).then(|| u32::try_from(ms).unwrap_or(u32::MAX))
    }
}

/// 本帧是否携带**生成 token 文本**（TTFT 定格的唯一判据）。
///
/// 只认真正产出 token 文本的帧，三类协议各自显式列举；协议簿记帧
/// （Anthropic `message_start`/`content_block_start`、Responses
/// `response.created`/`response.in_progress`/`response.output_item.added`、
/// Chat 仅带 `role` 的增量）与 signature/citation/redacted 等 opaque 帧一律不计，
/// 否则 50ms 的流头会把真实 2s 的首 token 时延抹掉。
///
/// 推理 token 同样是**生成 token**（`completion_tokens` 含推理），故 Chat 的
/// `delta.reasoning_content`/`delta.reasoning` 与 Anthropic 的 `thinking_delta`
/// 均计入，与 TPS 窗口口径一致（见 `service::request_log::store::tokens_per_sec`）。
/// 工具调用参数增量不是可见输出 token，不计（纯工具调用流 TTFT 为 `None`）。
pub(super) fn carries_output_token(protocol: Protocol, v: &Value) -> bool {
    match protocol {
        Protocol::Chat => chat_carries_token(v),
        Protocol::Anthropic => anthropic_carries_token(v),
        Protocol::Responses => responses_carries_token(v),
        // 非对话臂按字节透传，不产生 SSE token 帧，无 TTFT 口径。
        Protocol::NonDialog => false,
    }
}

/// 非空字符串取值（空串增量不构成 token）。
fn non_empty_str(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

/// Chat：`choices[].delta.content` 或 `delta.reasoning_content`/`reasoning` 非空。
fn chat_carries_token(v: &Value) -> bool {
    v.get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|ch| {
                let delta = ch.get("delta");
                ["content", "reasoning_content", "reasoning"]
                    .iter()
                    .any(|k| non_empty_str(delta.and_then(|d| d.get(*k))))
            })
        })
}

/// Anthropic：仅 `content_block_delta` 且 delta 类型为 `text_delta`/`thinking_delta`。
///
/// `signature_delta`（签名）与 `content_block_start`/`message_start` 等簿记帧不计。
fn anthropic_carries_token(v: &Value) -> bool {
    if v.get("type").and_then(Value::as_str) != Some("content_block_delta") {
        return false;
    }
    let Some(delta) = v.get("delta") else {
        return false;
    };
    match delta.get("type").and_then(Value::as_str) {
        // `text_delta.text` 与 `thinking_delta.thinking` 各承其文本键。
        Some("text_delta") => non_empty_str(delta.get("text")),
        Some("thinking_delta") => non_empty_str(delta.get("thinking")),
        _ => false,
    }
}

/// Responses：`response.output_text.delta` / `response.reasoning_text.delta` /
/// `response.refusal.delta` 且 `delta` 为非空字符串。
///
/// `response.created`/`response.in_progress`/`response.output_item.added` 等
/// 生命周期帧与 `response.function_call_arguments.delta`（工具参数）不计。
fn responses_carries_token(v: &Value) -> bool {
    match v.get("type").and_then(Value::as_str) {
        Some(
            "response.output_text.delta"
            | "response.reasoning_text.delta"
            | "response.refusal.delta",
        ) => non_empty_str(v.get("delta")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use {super::*, serde_json::json};

    // Chat：仅带 `role` 的增量是簿记帧，不得定格；content/推理增量才定格。
    #[test]
    fn chat_bookkeeping_delta_is_not_a_token() {
        assert!(!carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{"role":"assistant"}}]})
        ));
        assert!(!carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{"content":""}}]})
        ));
        assert!(!carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})
        ));
    }

    #[test]
    fn chat_content_and_reasoning_deltas_are_tokens() {
        assert!(carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{"content":"hi"}}]})
        ));
        assert!(carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{"reasoning_content":"想"}}]})
        ));
        assert!(carries_output_token(
            Protocol::Chat,
            &json!({"choices":[{"index":0,"delta":{"reasoning":"think"}}]})
        ));
    }

    // Anthropic：`message_start`/`content_block_start` 与非文本 delta 定格即缺陷。
    #[test]
    fn anthropic_bookkeeping_and_signature_are_not_tokens() {
        for frame in [
            json!({"type":"message_start","message":{"id":"msg_1","content":[]}}),
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}),
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":""}}),
            json!({"type":"ping"}),
        ] {
            assert!(
                !carries_output_token(Protocol::Anthropic, &frame),
                "不得定格: {frame}"
            );
        }
    }

    #[test]
    fn anthropic_text_and_thinking_deltas_are_tokens() {
        assert!(carries_output_token(
            Protocol::Anthropic,
            &json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}})
        ));
        assert!(carries_output_token(
            Protocol::Anthropic,
            &json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"想"}})
        ));
    }

    // Responses：生命周期帧不得定格，文本/推理/拒答 delta 才定格。
    #[test]
    fn responses_lifecycle_frames_are_not_tokens() {
        for frame in [
            json!({"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}),
            json!({"type":"response.in_progress","response":{"id":"resp_1"}}),
            json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message"}}),
            json!({"type":"response.output_text.delta","sequence_number":1,"delta":""}),
            json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"a\""}),
        ] {
            assert!(
                !carries_output_token(Protocol::Responses, &frame),
                "不得定格: {frame}"
            );
        }
    }

    #[test]
    fn responses_text_reasoning_and_refusal_deltas_are_tokens() {
        for frame in [
            json!({"type":"response.output_text.delta","sequence_number":1,"delta":"hi"}),
            json!({"type":"response.reasoning_text.delta","sequence_number":1,"delta":"想"}),
            json!({"type":"response.refusal.delta","sequence_number":1,"delta":"不能"}),
        ] {
            assert!(
                carries_output_token(Protocol::Responses, &frame),
                "须定格: {frame}"
            );
        }
    }

    #[test]
    fn nondialog_never_carries_token() {
        assert!(!carries_output_token(
            Protocol::NonDialog,
            &json!({"choices":[{"delta":{"content":"hi"}}]})
        ));
    }
}
