//! `$conversation` 出站标识：客户端锚点原值，或服务端锚点的域分离不可逆 HMAC。
//!
//! 服务端锚点（Responses `conversation` / 经别名解析的 `previous_response_id`）
//! 必须不可逆化——输出 MUST NOT 等于 PII `ConversationKey`（不同域），MUST NOT 等于
//! 上游 id 原值。无锚点（含空头、仅稳定前缀）返回 `None`，由调用方跳过注入。

use {
    super::{AnchorSource, SessionIdentity},
    crate::service::redaction::conversation_key::hmac_hex,
};

/// 出站标识承载：客户端声明的原值 vs 服务端锚点的域分离 HMAC。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundId {
    /// 客户端声明的锚点原值（已发往上游，保留原值维持缓存亲和语义）。
    Client(String),
    /// `veil-outbound-v1` 域分离 HMAC（不可逆，不同域于 PII 会话键）。
    ServerHmac(String),
}

impl OutboundId {
    /// 出站字符串视图（注入头值时使用）。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Client(value) | Self::ServerHmac(value) => value,
        }
    }

    /// 是否为服务端锚点 HMAC（`session_outbound_hmac` 计数判据）。
    pub fn is_server_hmac(&self) -> bool { matches!(self, Self::ServerHmac(_)) }
}

/// 域串：与 `ConversationKey` 的租户命名空间域分离。
const OUTBOUND_DOMAIN: &[u8] = b"veil-outbound-v1";
/// 分量分隔符（同一字面量 `0x1f`）。
const SEPARATOR: &[u8] = b"\x1f";

/// 计算本次请求的 `$conversation` 出站标识。
pub fn outbound_id(identity: &SessionIdentity, secret: &[u8]) -> Option<OutboundId> {
    let anchor = identity.anchor.as_ref()?;
    match anchor.source {
        AnchorSource::Header | AnchorSource::CacheKey => {
            Some(OutboundId::Client(anchor.value.clone()))
        }
        AnchorSource::Conversation | AnchorSource::PreviousResponse => {
            let canonical = identity.canonical.as_ref()?;
            Some(OutboundId::ServerHmac(hmac_hex(
                secret,
                &[
                    OUTBOUND_DOMAIN,
                    SEPARATOR,
                    identity.tenant_fingerprint.as_bytes(),
                    SEPARATOR,
                    canonical.as_str().as_bytes(),
                ],
            )))
        }
    }
}

#[cfg(test)]
mod tests;
