//! 会话身份的数据模型：锚点、来源/作用域枚举与解析结果（含手写脱敏 `Debug`）。
//!
//! 与解析逻辑（父模块 `resolve` 与 `input` 的候选提取）分离，便于单独审阅
//! 「哪些字段敏感、哪些字段仅供日志」这一契约。

use crate::service::redaction::ConversationKey;

/// 锚点来源：仅客户端/上游可见的原始 id 来源，不含用户级（见 [`SessionSource`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorSource {
    /// 显式会话头链命中。
    Header,
    /// Responses `conversation`（字符串或 `{id}`）。
    Conversation,
    /// Responses `previous_response_id`（仅别名表命中）。
    PreviousResponse,
    /// Chat/Responses `prompt_cache_key`。
    CacheKey,
}

/// PII/锚点与日志共用的来源标记：[`AnchorSource`] 的超集 + 用户级 + `None`。
///
/// 会话级（①–④）取值 `Header`/`Conversation`/`PrevResponse`/`CacheKey`；用户级
/// （日志 ⑤–⑦）取值 `UserId`/`SafetyIdentifier`/`User`；末档 `None`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionSource {
    Header,
    Conversation,
    PrevResponse,
    CacheKey,
    UserId,
    SafetyIdentifier,
    User,
    None,
}

impl SessionSource {
    /// 落库/响应体中的稳定文本（与 `request_log::SessionSource` 文本一致）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Conversation => "conversation",
            Self::PrevResponse => "prev_response",
            Self::CacheKey => "cache_key",
            Self::UserId => "user_id",
            Self::SafetyIdentifier => "safety_identifier",
            Self::User => "user",
            Self::None => "none",
        }
    }
}

/// 会话作用域：会话级 / 用户级（仅日志）/ 无。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionScope {
    Session,
    User,
    None,
}

impl SessionScope {
    /// 落库/响应体中的稳定文本。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::User => "user",
            Self::None => "none",
        }
    }
}

/// 锚点：客户端或上游可见的原始 id + 来源。`value` 为敏感值。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionAnchor {
    pub value: String,
    pub source: AnchorSource,
}

/// 手工 `Debug`：锚点原值（头值/上游 id）不得经 `{:?}` 泄漏。
impl std::fmt::Debug for SessionAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAnchor")
            .field("value", &"[redacted]")
            .field("source", &self.source)
            .finish()
    }
}

/// 仅日志的用户级锚点：`metadata.user_id`/`safety_identifier`/`user` 原值 + 来源。
#[derive(Clone, PartialEq, Eq)]
pub struct LogUserAnchor {
    pub value: String,
    pub source: SessionSource,
}

/// 手工 `Debug`：用户标识原值不得经 `{:?}` 泄漏。
impl std::fmt::Debug for LogUserAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogUserAnchor")
            .field("value", &"[redacted]")
            .field("source", &self.source)
            .finish()
    }
}

/// 一次请求的解析结果：PII/锚点口径（`anchor`/`canonical`/`scope`/`source`）与
/// 请求记录口径（`log_source`/`log_scope`/`log_user`）分离，二者可预期分歧。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub anchor: Option<SessionAnchor>,
    pub canonical: Option<ConversationKey>,
    pub tenant_fingerprint: String,
    pub scope: SessionScope,
    pub source: SessionSource,
    pub log_source: SessionSource,
    pub log_scope: SessionScope,
    pub log_user: Option<LogUserAnchor>,
    pub request_carried_conversation: bool,
}

/// 手工 `Debug`：锚点原值、canonical、租户指纹、用户标识原值一律 `[redacted]`。
impl std::fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionIdentity")
            .field("anchor", &self.anchor)
            .field("canonical", &self.canonical.as_ref().map(|_| "[redacted]"))
            .field("tenant_fingerprint", &"[redacted]")
            .field("scope", &self.scope)
            .field("source", &self.source)
            .field("log_source", &self.log_source)
            .field("log_scope", &self.log_scope)
            .field("log_user", &self.log_user)
            .field(
                "request_carried_conversation",
                &self.request_carried_conversation,
            )
            .finish()
    }
}
