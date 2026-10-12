//! 协议识别与流判定：尾缀匹配（严格/宽容）+ `stream` 意图判定 + `stream_options` 注入。

use {super::GatewayMetrics, serde_json::Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Chat,
    Anthropic,
    Responses,
    NonDialog,
}

/// 协议差异的**最小只读声明**：只承载 `done_terminator` 与
/// `terminal_event_types`，消费者为 `[DONE]` 短路门控
/// （`crate::handler::llm::pump::spawn::event_loop.rs::handle_event`）与
/// `crate::handler::llm::pump::event::is_terminal_event`。其余协议差异字段
/// （`line_terminator`/`accepts_stream_options`/`empty_stream_frames`/`block_frames` 等）
/// 不在本声明内。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSpec {
    /// Chat 的传输层终止标记（`data: [DONE]`）；非 Chat 恒 `None`（视为非事件）。
    pub done_terminator: Option<&'static str>,
    /// 流式真终端事件 `type` 集合——`is_terminal_event` 唯一来源。
    pub terminal_event_types: &'static [&'static str],
}

impl Protocol {
    pub fn as_tail(&self) -> &'static str {
        match self {
            Self::Chat => "chat/completions",
            Self::Anthropic => "v1/messages",
            Self::Responses => "v1/responses",
            Self::NonDialog => "non-dialog",
        }
    }

    /// 协议线级标签的单一来源：下游 `x-veil-protocol` 头值（`NonDialog` 对外为
    /// `passthrough`）。收敛 `handler/llm/mod.rs::protocol_header_value` 的重复 match。
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Anthropic => "anthropic",
            Self::Responses => "responses",
            Self::NonDialog => "passthrough",
        }
    }

    /// 类型化分派谓词：全仓 `protocol == Protocol::X` 比较统一经此收敛，
    /// 新增变体只改本组方法（穷举 `match` 臂仍由编译器强制）。
    pub fn is_chat(self) -> bool { matches!(self, Self::Chat) }

    pub fn is_anthropic(self) -> bool { matches!(self, Self::Anthropic) }

    pub fn is_responses(self) -> bool { matches!(self, Self::Responses) }

    pub fn is_nondialog(self) -> bool { matches!(self, Self::NonDialog) }

    /// 对话协议（`Chat`/`Anthropic`/`Responses`）——`NonDialog` 为唯一字节透传协议。
    pub fn is_dialog(self) -> bool { !self.is_nondialog() }

    /// 协议差异的最小只读声明（唯一来源，见 [`ProtocolSpec`]）。仅 Chat 有终止标记。
    pub fn spec(self) -> ProtocolSpec {
        match self {
            // Chat 以传输层 `data: [DONE]` 收尾，真终端事件集合为空（错误帧由
            // `is_chat_error_terminal` 独立承载，不并入本声明）。
            Self::Chat => ProtocolSpec {
                done_terminator: Some("[DONE]"),
                terminal_event_types: &[],
            },
            Self::Anthropic => ProtocolSpec {
                done_terminator: None,
                terminal_event_types: &["message_stop", "error"],
            },
            Self::Responses => ProtocolSpec {
                done_terminator: None,
                terminal_event_types: &[
                    "response.completed",
                    "response.failed",
                    "response.incomplete",
                ],
            },
            Self::NonDialog => ProtocolSpec {
                done_terminator: None,
                terminal_event_types: &[],
            },
        }
    }
}

// 新增协议检查清单：新增第 4 协议时，除本表外还须同步：
// `usage.rs`（用量提取/缓存列）、`tool.rs`（工具调用判定）、`sse/meta.rs`（截断模式）、
// `block_inject/frames.rs`（终止帧合成）、`placeholder.rs`（说明注入/schema 判定）、
// `handler/llm/mod.rs::protocol_header_value`（下游协议头）、`rewrite.rs`（请求改写）、
// `block_inject.rs`（阻断体）。本清单为最低覆盖，新增协议仍须全量
// grep `Protocol::` 复查。
//
// `ProtocolSpec` 承载字段与消费者：
// - 落字段：`done_terminator: Option<&str>` + `terminal_event_types`（见 `spec()`）。
// - 消费者：① `[DONE]` 短路协议门控 `handler/llm/pump/spawn/event_loop.rs::handle_event` 的
//   `[DONE]` 分支（经 `done_terminator`）；② `handler/llm/pump/event.rs::is_terminal_event`（经
//   `terminal_event_types`）。
// - 本声明之外的语义不同事件集合（保持独立判定，SHALL NOT 被单一字段强制替换）：① 粘滞抑制集合
//   `event.rs::sticky_terminal_precise`（含 `content_block_stop`/`message_delta`）；② Responses
//   失败/未完成分类 `event.rs::responses_failed_incomplete`；③ Chat 错误终端集合
//   `event.rs::is_chat_error_terminal`。
// - `is_done_payload` 其余调用点清单（低层字符串判定，协议门控在消费点）： ①
//   `service/sse/parser.rs:402`（`residual_json_aware`）——残余层； ②
//   `service/sse/parser.rs:432`（`classify_residue`）——残余层； ③
//   `handler/llm/pump/event.rs::parse_event_data`——帧解析对 DONE 返回 None； ④
//   `handler/llm/pump/spawn/event_loop.rs` 粘滞抑制分支的
//   `is_done`（粘滞态丢弃判定，与协议终态无关）； ⑤ `event_loop.rs::handle_event` 的 `[DONE]`
//   分支（经 `spec().done_terminator` 门控）。
const STRICT_TAILS: [(&str, Protocol); 3] = [
    ("chat/completions", Protocol::Chat),
    ("v1/messages", Protocol::Anthropic),
    ("v1/responses", Protocol::Responses),
];

fn strip_query(path: &str) -> &str { path.split(['?', '#']).next().unwrap_or(path) }

fn strict_match(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    for (suffix, proto) in STRICT_TAILS {
        // 宽容匹配大小写不敏感为**有意声明**——
        // 仅大小写不同的同一对话尾 SHALL 归类一致，不得回落 `NonDialog`。
        if p.eq_ignore_ascii_case(&format!("/{suffix}")) || p.eq_ignore_ascii_case(suffix) {
            return Some(proto);
        }
        if p.len() > suffix.len() + 1
            && p.as_bytes()[p.len() - suffix.len() - 1] == b'/'
            && p[p.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return Some(proto);
        }
    }
    None
}

/// 官方子资源排除。尾后缀的一层额外路径段若命中官方子资源，MUST NOT
/// 判为对话协议（`lenient_match` 返回 `None` ⇒ `NonDialog` 字节透传），避免请求被
/// 改写、响应被注入占位符或触发审计后处理：
/// - Anthropic `v1/messages/{batches}`：异步批处理元数据端点，body 与响应形态均不同；
/// - Responses `v1/responses/{任意单段}`：均为响应对象检索（`.cancel`/`.input_items`
///   为两段后缀，`strict_match` 已不命中，天然 `NonDialog`，无需另列）。
///
/// `count_tokens` 已由 [`redact_only_protocol`] 收窄为 redact-only 对话变体，不再经
/// 此排除：它在 `is_chat_tail` 中先于宽容匹配被
/// **精确识别**为 `Protocol::Anthropic`，故不计 `chat_tail_lenient_total`。
///
/// Chat 无同类官方子资源，保留一层宽容（`/v1/chat/completions/extra` 仍命中）。
fn is_official_subresource(proto: Protocol, seg: &str) -> bool {
    if proto.is_anthropic() {
        return seg.eq_ignore_ascii_case("batches");
    }
    proto.is_responses()
}

/// Anthropic `count_tokens` 官方子资源判定——**redact-only 对话变体**。
///
/// 仅 `/v1/messages/{count_tokens}`（大小写不敏感、剥离 query 与尾斜杠）命中，返回
/// `Protocol::Anthropic`。**SHALL NOT 新增 `Protocol` 变体**——redact-only 切分由
/// `RequestCtx::redact_only` 布尔标记承载（见 `handler/llm/dispatch.rs` 装配点）；
/// `is_passthrough`（[`is_passthrough`]）/`is_dialog`（[`Protocol::is_dialog`]）语义不变。
///
/// 与 `is_official_subresource` 同源的一层子资源识别：本函数在 `is_chat_tail` 中先于
/// `lenient_match` 拦截，故 `count_tokens` 归类为 `Anthropic` 而非 `NonDialog`，且不计
/// 宽容计数；`batches` 仍由 `is_official_subresource` 排除为 `NonDialog` 字节透传。
pub fn redact_only_protocol(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    let p = p.strip_suffix('/').unwrap_or(p);
    let (parent, seg) = p.rsplit_once('/')?;
    if seg.eq_ignore_ascii_case("count_tokens") && strict_match(parent) == Some(Protocol::Anthropic)
    {
        return Some(Protocol::Anthropic);
    }
    None
}

fn lenient_match(path: &str) -> Option<(Protocol, String)> {
    let p = strip_query(path);
    let trimmed = p.strip_suffix('/').unwrap_or(p);
    if trimmed != p
        && let Some(proto) = strict_match(trimmed)
    {
        return Some((proto, proto.as_tail().to_string()));
    }
    if let Some(slash) = p.rfind('/')
        && slash > 0
    {
        let parent = &p[..slash];
        if parent.contains('/') || parent.is_empty() {
            if let Some(proto) = strict_match(parent) {
                let rest = &p[slash + 1..];
                if !rest.is_empty() && !rest.contains('/') {
                    if is_official_subresource(proto, rest) {
                        return None;
                    }
                    return Some((proto, proto.as_tail().to_string()));
                }
            }
        } else {
            return None;
        }
    }
    None
}

pub fn is_chat_tail(path: &str, metrics: Option<&GatewayMetrics>) -> (bool, Protocol) {
    if let Some(proto) = strict_match(path) {
        return (true, proto);
    }
    // `count_tokens` 为**精确识别**的 redact-only 对话变体（官方子资源，非宽容
    // 命中），先于宽容匹配拦截，故不计 `chat_tail_lenient_total`。
    if let Some(proto) = redact_only_protocol(path) {
        return (true, proto);
    }
    if let Some((proto, tail)) = lenient_match(path) {
        if let Some(m) = metrics {
            m.record_lenient(&tail);
        }
        tracing::debug!(path = %path, tail = %tail, "chat tail 宽容命中");
        return (true, proto);
    }
    (false, Protocol::NonDialog)
}

pub fn resolve_protocol(
    tail: &str,
    content_type: Option<&str>,
    metrics: Option<&GatewayMetrics>,
) -> Protocol {
    let (hit, proto) = is_chat_tail(tail, metrics);
    if let Some(ct) = content_type {
        tracing::debug!(tail = %tail, content_type = %ct, is_chat = %hit, "tail 优先分发，Content-Type 仅日志参考");
    }
    if hit { proto } else { Protocol::NonDialog }
}

/// 透传谓词：`NonDialog` 为唯一字节透传协议（无用量/审计/还原）。
/// 全仓布尔判定统一经此函数，新增协议变体只改一处；穷举 `match` 臂保留模式。
pub fn is_passthrough(protocol: Protocol) -> bool { protocol.is_nondialog() }

pub fn is_stream_body(body: &Value) -> bool {
    body.as_object().is_some_and(|m| {
        m.get("stream")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    })
}

pub fn should_inject_stream_options(protocol: Protocol, body: &Value) -> bool {
    // 官方 Responses `stream_options` 仅接受 `include_obfuscation`，
    // 无 `include_usage`，故注入收窄为仅 `Protocol::Chat`。Responses 流式用量经
    // `response.completed.response.usage` 携带，由 `extract_usage_stream` 三级回退
    // 闭环（见 `usage.rs`），不依赖请求注入；用户自带 `stream_options` 原样保留。
    if !protocol.is_chat() {
        return false;
    }
    if !is_stream_body(body) {
        return false;
    }
    match body.as_object().and_then(|m| m.get("stream_options")) {
        // 键内合并语义：整键缺失或
        // `include_usage` 缺失即需注入，保留用户自带其他键。
        None => true,
        // `null` 是用户显式第三态，原样保留、不注入不替换。
        Some(Value::Null) => false,
        Some(Value::Object(opts)) => opts.get("include_usage").is_none(),
        // 非对象非 null（畸形）视为缺失，由 inject 整体替换 + warn。
        Some(_) => true,
    }
}

pub fn inject_stream_options(body: &mut Value) {
    if let Some(map) = body.as_object_mut() {
        match map.get_mut("stream_options") {
            Some(Value::Object(opts)) => {
                opts.entry("include_usage".to_string())
                    .or_insert(serde_json::json!(true));
            }
            // 显式 `null` 不动（不注入、不替换、不告警）。
            Some(Value::Null) => {}
            Some(slot) => {
                tracing::warn!("stream_options 非对象形态，已整体替换为 include_usage");
                *slot = serde_json::json!({"include_usage": true});
            }
            None => {
                map.insert(
                    "stream_options".to_string(),
                    serde_json::json!({"include_usage": true}),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
