//! 响应侧上游标识捕获：仅 Responses 2xx 的响应形态取 id，供别名绑定使用。
//!
//! 响应形态由调用方显式传入，不靠字段猜测：非流响应体（含 `stream:true` 但上游
//! 返回 2xx JSON 的透传整包）取顶层 `id` 与 `conversation`；流式事件只认
//! `response.id` 与 `response.conversation`，缺少 `response` 对象即视为未捕获，
//! MUST NOT 回退事件顶层 `id`。两种形态均 MUST NOT 回退
//! `error.id`/`message.id`/`data.id`；错误状态一律返回空（即使体内含 `id`）。
//! 纯函数、幂等。

use {crate::service::llm_gateway::Protocol, serde_json::Value};

/// 响应形态：整包响应体 vs 单条流式事件。
///
/// 由调用点显式区分，避免用“是否存在 `response` 对象”反推——流式事件缺失
/// `response` 时不得把事件自身的顶层 `id` 误当 `response.id`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseShape {
    /// 非流响应体，或 `stream:true` 但上游返回 2xx JSON 的透传整包。
    Complete,
    /// SSE 流中的单条事件：只认 `response` 对象。
    StreamEvent,
}

/// 一次响应（或单帧）捕获到的上游标识；缺省分量为 `None`。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CapturedIds {
    pub response_id: Option<String>,
    pub conversation_id: Option<String>,
}

/// 手工 `Debug`：上游标识原值不得经 `{:?}` 落入日志，仅暴露是否存在。
impl std::fmt::Debug for CapturedIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedIds")
            .field(
                "response_id",
                &self.response_id.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "conversation_id",
                &self.conversation_id.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl CapturedIds {
    /// 是否未捕获到任何可用标识。
    pub fn is_empty(&self) -> bool { self.response_id.is_none() && self.conversation_id.is_none() }
}

/// 捕获响应标识：非 Responses 或非 2xx 一律空；否则按显式响应形态取 id。
pub fn capture_response_ids(
    value: &Value,
    status: u16,
    protocol: Protocol,
    shape: ResponseShape,
) -> CapturedIds {
    if !protocol.is_responses() || !(200..=299).contains(&status) {
        return CapturedIds::default();
    }
    let source = match shape {
        ResponseShape::Complete => value,
        ResponseShape::StreamEvent => match value.get("response") {
            Some(inner @ Value::Object(_)) => inner,
            _ => return CapturedIds::default(),
        },
    };
    if !source.is_object() {
        return CapturedIds::default();
    }
    CapturedIds {
        response_id: non_empty_str(source.get("id")),
        conversation_id: conversation_id(source),
    }
}

/// 取非空字符串字段（空串视为缺失）。
fn non_empty_str(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|raw| !raw.is_empty())
        .map(str::to_string)
}

/// `conversation` 取 id：字符串形态取自身，对象形态取 `id`；空串视为缺失。
fn conversation_id(source: &Value) -> Option<String> {
    match source.get("conversation")? {
        Value::String(_) => non_empty_str(source.get("conversation")),
        Value::Object(map) => non_empty_str(map.get("id")),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
