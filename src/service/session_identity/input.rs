//! 候选来源提取与 ①–④ 会话级解析（头部可见 ASCII 校验、协议白名单、别名优先）。
//!
//! 本模块只做「从请求头/请求体取到合法候选并派生 canonical」，不构造日志口径；
//! 用户级仅日志来源在父模块处理。

use {
    super::{AnchorSource, LogUserAnchor, SessionAnchor, SessionSource},
    crate::service::{
        llm_gateway::Protocol,
        redaction::{
            ConversationKey,
            SessionAliasMap,
            conversation_key::EXPLICIT_HEADER_MAX_BYTES,
            scoped_key,
        },
    },
    axum::http::HeaderMap,
    serde_json::Value,
};

/// 解析一次请求所需的只读输入（把 7 个参数收拢为单一值对象，避免参数膨胀）。
pub(super) struct ResolveInput<'a> {
    pub headers: &'a HeaderMap,
    pub body: Option<&'a Value>,
    pub protocol: Protocol,
    pub headers_chain: &'a [String],
    pub alias: &'a SessionAliasMap,
    pub secret: &'a [u8],
    pub tenant_fingerprint: &'a str,
}

/// ①–④ 会话级解析（首个命中者胜；返回锚点、canonical 与来源）。
pub(super) fn session_level(
    input: &ResolveInput<'_>,
) -> Option<(SessionAnchor, ConversationKey, SessionSource)> {
    let ResolveInput {
        headers,
        body,
        protocol,
        headers_chain,
        alias,
        secret,
        tenant_fingerprint,
    } = *input;
    if let Some(value) = header_candidate(headers, headers_chain) {
        return Some((
            SessionAnchor {
                value: value.to_string(),
                source: AnchorSource::Header,
            },
            scoped_key(secret, tenant_fingerprint, value),
            SessionSource::Header,
        ));
    }
    let body = body?;

    // ② Responses `conversation`：先查别名，未命中才原生派生。
    if protocol.is_responses()
        && let Some(conv_id) = conversation_id(body)
    {
        let canonical = alias
            .resolve(secret, tenant_fingerprint, conv_id)
            .unwrap_or_else(|| scoped_key(secret, tenant_fingerprint, conv_id));
        return Some((
            SessionAnchor {
                value: conv_id.to_string(),
                source: AnchorSource::Conversation,
            },
            canonical,
            SessionSource::Conversation,
        ));
    }

    // ③ Responses `previous_response_id`：别名未命中即视为该来源未命中（不设锚点）。
    if protocol.is_responses()
        && let Some(prev) = body
            .get("previous_response_id")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        && let Some(canonical) = alias.resolve(secret, tenant_fingerprint, prev)
    {
        return Some((
            SessionAnchor {
                value: prev.to_string(),
                source: AnchorSource::PreviousResponse,
            },
            canonical,
            SessionSource::PrevResponse,
        ));
    }

    // ④ Chat/Responses `prompt_cache_key`（Anthropic MUST NOT 接受）。
    if (protocol.is_chat() || protocol.is_responses())
        && let Some(value) = body
            .get("prompt_cache_key")
            .and_then(Value::as_str)
            .and_then(visible_ascii_candidate)
    {
        return Some((
            SessionAnchor {
                value: value.to_string(),
                source: AnchorSource::CacheKey,
            },
            scoped_key(secret, tenant_fingerprint, value),
            SessionSource::CacheKey,
        ));
    }
    None
}

/// 头链中首个**存在但取值非法**（空串/超长/控制字符/非 ASCII/非 UTF-8）的
/// 候选头名——仅返回**头名**，绝不返回头值。
///
/// 供运行期告警定位（observability category c）：出现本结果且身份未由头链命中时，
/// 说明该头「本可命中第 ① 级」却被丢弃。头链靠前者合法命中时本函数不应被使用。
pub fn first_rejected_header<'a>(headers: &HeaderMap, chain: &'a [String]) -> Option<&'a str> {
    chain.iter().find_map(|name| {
        let value = headers.get(name.as_str())?;
        let rejected = value
            .to_str()
            .map_or(true, |raw| visible_ascii_candidate(raw).is_none());
        rejected.then_some(name.as_str())
    })
}

/// 头链候选：按配置顺序取首个非空、≤256 字节且全可见 ASCII（0x20–0x7E）的值。
fn header_candidate<'a>(headers: &'a HeaderMap, chain: &'a [String]) -> Option<&'a str> {
    chain.iter().find_map(|name| {
        headers
            .get(name.as_str())
            .and_then(|value| value.to_str().ok())
            .and_then(visible_ascii_candidate)
    })
}

/// 可见 ASCII 候选校验：空串、超长、含非可见字节（控制/非 ASCII）一律不命中。
fn visible_ascii_candidate(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() > EXPLICIT_HEADER_MAX_BYTES {
        return None;
    }
    value
        .bytes()
        .all(|b| (0x20..=0x7e).contains(&b))
        .then_some(value)
}

/// Responses `conversation` 取 id：字符串形态取自身，对象形态取 `id`；空串视为未命中。
fn conversation_id(body: &Value) -> Option<&str> {
    let raw = match body.get("conversation")? {
        Value::String(value) => value.as_str(),
        Value::Object(map) => map.get("id").and_then(Value::as_str)?,
        _ => return None,
    };
    (!raw.is_empty()).then_some(raw)
}

/// `request_carried_conversation`：body 顶层**存在** `conversation` 键即 true
/// （空串/空对象/对象缺 `id` 都算存在；仅键缺失为 false），与协议无关。
pub(super) fn carried_conversation(body: Option<&Value>) -> bool {
    body.and_then(Value::as_object)
        .is_some_and(|map| map.contains_key("conversation"))
}

/// 用户级仅日志锚点（按协议白名单）：Anthropic 仅 `metadata.user_id`；
/// Chat/Responses 取 `safety_identifier` → `user`（首个非空）；其余协议不产生。
pub(super) fn log_user_anchor(body: Option<&Value>, protocol: Protocol) -> Option<LogUserAnchor> {
    let body = body?;
    let (value, source) = if protocol.is_anthropic() {
        (
            body.get("metadata")
                .and_then(|m| m.get("user_id"))
                .and_then(Value::as_str),
            SessionSource::UserId,
        )
    } else if protocol.is_chat() || protocol.is_responses() {
        let safety = body
            .get("safety_identifier")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        if safety.is_some() {
            (safety, SessionSource::SafetyIdentifier)
        } else {
            (
                body.get("user").and_then(Value::as_str),
                SessionSource::User,
            )
        }
    } else {
        return None;
    };
    let value = value.filter(|v| !v.is_empty())?;
    Some(LogUserAnchor {
        value: value.to_string(),
        source,
    })
}
