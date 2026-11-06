//! 统一会话身份解析器：一次解析产出 PII/锚点口径与请求记录口径。
//!
//! 优先级（首个命中者胜，design D2）：
//! ① `[session].headers` 有序头链首个合法非空值 → ② Responses `conversation`
//! （先查别名）→ ③ Responses `previous_response_id`（仅别名命中）→ ④ Chat/Responses
//! `prompt_cache_key` → ⑤ 稳定前缀 HMAC（仅产生 PII 派生键）→ ⑥ 逐请求。
//! 用户级 `metadata.user_id`/`safety_identifier`/`user` 只进日志口径
//! （`log_user`/`log_source`/`log_scope`），MUST NOT 参与 PII 键或出站。
//!
//! 不发起网络 I/O；别名表**内容**参与派生（命中返回绑定 canonical），其 LRU 顺序与
//! 计数不改变派生结果。`ConversationKey` 一律经租户命名空间 HMAC 派生，客户端原值
//! 绝不直接作键。出站标识见 [`outbound`]，响应捕获见 [`capture`]。

use {
    crate::service::{
        llm_gateway::Protocol,
        redaction::{SessionAliasMap, stable_prefix_key},
    },
    axum::http::HeaderMap,
    serde_json::Value,
};

mod input;
mod types;

pub mod capture;
pub mod outbound;

pub use {
    capture::{CapturedIds, ResponseShape, capture_response_ids},
    input::first_rejected_header,
    outbound::{OutboundId, outbound_id},
    types::{
        AnchorSource,
        LogUserAnchor,
        SessionAnchor,
        SessionIdentity,
        SessionScope,
        SessionSource,
    },
};

/// 解析单次请求的会话身份（无网络 I/O，同上文档的优先级与口径）。
///
/// `headers_chain` 为已校验的 `[session].headers` 有序头链（取 `&[String]` 以与本层
/// 解耦）；`body` 在 NonDialog/无正文时为 `None`，此时仅头链可命中。
pub fn resolve(
    headers: &HeaderMap,
    body: Option<&Value>,
    protocol: Protocol,
    headers_chain: &[String],
    alias: &SessionAliasMap,
    secret: &[u8],
    tenant_fingerprint: &str,
) -> SessionIdentity {
    let mut identity = SessionIdentity {
        anchor: None,
        canonical: None,
        tenant_fingerprint: tenant_fingerprint.to_string(),
        scope: SessionScope::None,
        source: SessionSource::None,
        log_source: SessionSource::None,
        log_scope: SessionScope::None,
        log_user: None,
        request_carried_conversation: input::carried_conversation(body),
    };

    if let Some((anchor, canonical, source)) = input::session_level(&input::ResolveInput {
        headers,
        body,
        protocol,
        headers_chain,
        alias,
        secret,
        tenant_fingerprint,
    }) {
        identity.anchor = Some(anchor);
        identity.canonical = Some(canonical);
        identity.scope = SessionScope::Session;
        identity.source = source;
        identity.log_source = source;
        identity.log_scope = SessionScope::Session;
        return identity;
    }

    // ⑤ 稳定前缀：只产生 PII 派生键，不产生锚点与日志会话来源。
    if let Some(canonical) =
        body.and_then(|b| stable_prefix_key(secret, tenant_fingerprint, protocol, b))
    {
        identity.canonical = Some(canonical);
        identity.scope = SessionScope::Session;
    }

    // 用户级仅日志；稳定前缀级与逐请求级均适用（PII 口径不变）。
    if let Some(user) = input::log_user_anchor(body, protocol) {
        identity.log_source = user.source;
        identity.log_scope = SessionScope::User;
        identity.log_user = Some(user);
    }
    identity
}

#[cfg(test)]
mod tests;
