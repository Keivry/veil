//! 会话标识推导：九档优先级 + HMAC 摘要（与 `conversation_key` 域分离）。
//!
//! 三协议均无原生 `session_id` 字段，故按 design §4 的九档「尽量填充」：前五档为
//! 会话级锚点（显式头 / `conversation` / 链式 `previous_response_id` /
//! `diagnostics.previous_message_id` / `prompt_cache_key`），第六至八档为用户级标识
//! （`metadata.user_id` / `safety_identifier` / `user`），第九档为「无」。
//!
//! 摘要口径（design §4）：`hex(hmac_sha256(key, "veil-session-v1" || 0x1f ||
//! protocol || 0x1f || raw))[..16]`。原始值绝不落库/进日志，只留 16 hex。
//!
//! 域分离：`conversation_key::scoped_key` 用 `tenant || 0x1f || conversation` 域，
//! 本模块用固定的 `veil-session-v1` 前缀，故同一 raw 两条路径的摘要必然不等
//! （tasks 2.2）。`hmac_hex` 在 `conversation_key` 内为私有且不带域串，故此处用同一
//! `hmac`/`sha2` crate 本地实现，不跨模块改可见性。
//!
//! 密钥：只取既有可选 env `PII_VALUE_SAMPLE_HMAC_KEY`（空串已由配置层过滤为 `None`）。
//! 密钥缺失 → `None`（`session_id=NULL` / `session_scope="none"`），**不得**退化为
//! 无密钥哈希或进程随机盐（空密钥 HMAC 可字典反查）。

use axum::http::HeaderMap;

/// 摘要域串（与 `conversation_key` 的 `tenant || 0x1f || conversation` 域不同）。
const SESSION_DOMAIN: &[u8] = b"veil-session-v1";
/// 分量分隔符（与 `conversation_key::SEPARATOR` 同一字面量 `0x1f`）。
const SEPARATOR: u8 = 0x1f;
/// `session_id` 保留的 hex 字符数（16 hex = 64 bit，碰撞概率对 7 天窗口可接受）。
pub const SESSION_ID_HEX_LEN: usize = 16;

/// 内置会话头回退链（**遥测口径**，配置头之后依次尝试；HTTP 头名查找大小写不敏感）。
///
/// 起因：opencode 仅在 `providerID.startsWith("opencode")` 时发送
/// `x-opencode-session`；其余 provider（如 `commandcode-veil/deepseek/...`）改发
/// `x-opencode-session-id` / `x-opencode-parent-session-id` / `x-session-affinity` /
/// `X-Session-Id`，且不设 `prompt_cache_key`。只读单一配置头会让这些调用在全部九档上
/// 落空（`session_id=NULL` / `session_source="none"`），故固定一条回退链兜底。
///
/// 本链**只**服务 `llm_requests` 的会话摘要（[`resolve_session_header`]）。PII 会话
/// 作用域用更窄的 [`PII_SCOPE_HEADER_FALLBACKS`]，两者不得合并，理由见该常量。
pub const SESSION_HEADER_FALLBACKS: [&str; 5] = [
    "x-opencode-session",
    "x-opencode-session-id",
    "x-opencode-parent-session-id",
    "x-session-affinity",
    "x-session-id",
];

/// PII 会话作用域专用回退链——**刻意比 [`SESSION_HEADER_FALLBACKS`] 窄**。
///
/// 只接受 opencode 明确表达「本会话」的两个头。被排除的三者都不是可信的客户端
/// 隔离标识：`x-opencode-parent-session-id` 指向**父**会话（不是本会话身份，同父的
/// 多个子会话会被合并）；`x-session-affinity` 是路由/亲和性提示（常见为固定常量或
/// 跨客户端共享）；`x-session-id` 过于通用（代理、sidecar、网关常自行注入同一值）。
///
/// 为何必须窄（**不得**为了「日志与脱敏共用一条链」而重新合并两条链）：PII 会话
/// 作用域的隔离边界只剩会话键值本身——上游 API key 由 `[llm.targets].headers` 注入
/// 时客户端不带任何凭据头，`conversation_key::tenant_fingerprint` 对所有客户端取值
/// 相同。若把上述基础设施头纳入键，两个逻辑客户端会落到同一会话键、共享同一
/// `PiiScope` 占位符注册表，一方的明文可被还原进另一方的响应。
pub const PII_SCOPE_HEADER_FALLBACKS: [&str; 2] = ["x-opencode-session", "x-opencode-session-id"];

/// 单头取值：缺失、非 UTF-8 或空串一律视为未命中（空串不参与摘要）。
fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
}

/// 会话头解析（**遥测口径**）：配置头 `[pii_scope].key_header` 最高优先，其后按
/// [`SESSION_HEADER_FALLBACKS`] 顺序逐项尝试，首个非空值胜出。
///
/// 仅供 `llm_requests.session_id` 的会话摘要推导（`RequestTrace::attach_identity`）。
/// PII 会话作用域 MUST NOT 复用本函数——宽链含不可信的路由/通用头，见
/// [`resolve_pii_scope_header`]。返回值的来源语义恒为 [`SessionSource::Header`]，
/// 不新增来源变体。
pub fn resolve_session_header<'a>(headers: &'a HeaderMap, configured: &str) -> Option<&'a str> {
    header_value(headers, configured).or_else(|| {
        SESSION_HEADER_FALLBACKS
            .iter()
            .find_map(|name| header_value(headers, name))
    })
}

/// PII 会话作用域键解析（**隔离口径**）：配置头最高优先，其后仅按
/// [`PII_SCOPE_HEADER_FALLBACKS`] 尝试，首个非空值胜出。
///
/// 与 [`resolve_session_header`] 的差异即隔离边界：客户端若只发
/// `x-opencode-parent-session-id` / `x-session-affinity` / `x-session-id`，日志仍有
/// `session_id`，但 PII 作用域退化为**逐请求**（键推导落第 4 级）——这是有意的取舍，
/// 宁可损失跨轮 token 稳定，也不让共享的路由头把两个客户端并进同一 `PiiScope`。
/// 空串与非 UTF-8 值同样跳过，配置头仍在最高优先级。
pub fn resolve_pii_scope_header<'a>(headers: &'a HeaderMap, configured: &str) -> Option<&'a str> {
    header_value(headers, configured).or_else(|| {
        PII_SCOPE_HEADER_FALLBACKS
            .iter()
            .find_map(|name| header_value(headers, name))
    })
}

/// 会话头链路中是否有任一头存在（配置头或回退头）。
///
/// 仅供「头存在但取值非法被丢弃」的告警/计数判定；头名列表仍只由
/// [`SESSION_HEADER_FALLBACKS`] 单点维护。
pub fn session_header_present(headers: &HeaderMap, configured: &str) -> bool {
    std::iter::once(configured)
        .chain(SESSION_HEADER_FALLBACKS)
        .any(|name| headers.contains_key(name))
}

/// PII 链路中是否有任一头存在（配置头或 [`PII_SCOPE_HEADER_FALLBACKS`]）。
///
/// 仅供「PII 键头存在但取值非法被丢弃」的计数/告警；与宽链
/// [`session_header_present`] 分开，避免把只在遥测链命中的头误报为 PII 键头非法。
pub fn pii_scope_header_present(headers: &HeaderMap, configured: &str) -> bool {
    pii_scope_header_name(headers, configured).is_some()
}

/// 解析出 PII 链路中实际存在的头名（配置头优先，其后按
/// [`PII_SCOPE_HEADER_FALLBACKS`]），不校验取值合法性。
///
/// 取值非法被丢弃时告警须指名真正出问题的头：配置头缺席时值来自回退头，
/// 只打印配置头名会误导排查。
pub fn pii_scope_header_name<'a>(headers: &'a HeaderMap, configured: &'a str) -> Option<&'a str> {
    std::iter::once(configured)
        .chain(PII_SCOPE_HEADER_FALLBACKS)
        .find(|name| headers.contains_key(*name))
}

/// 会话标识来源（design §4 九档；`None` 为末档「无标识」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionSource {
    /// 显式头（`[pii_scope].key_header`，默认 `x-veil-conversation-id`）。
    Header,
    /// Responses `conversation`（`string` 或 `{id}`）。
    Conversation,
    /// Responses `previous_response_id`（链式锚点）。
    PrevResponse,
    /// Anthropic `diagnostics.previous_message_id`（链式锚点）。
    PrevMessage,
    /// Chat/Responses `prompt_cache_key`（缓存桶）。
    CacheKey,
    /// Anthropic `metadata.user_id`（用户级）。
    UserId,
    /// Chat/Responses `safety_identifier`（用户级）。
    SafetyIdentifier,
    /// Chat/Responses `user`（用户级）。
    User,
    /// 无任何可关联标识。
    None,
}

impl SessionSource {
    /// 落库/响应体中的稳定文本（`llm_requests.session_source`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Conversation => "conversation",
            Self::PrevResponse => "prev_response",
            Self::PrevMessage => "prev_message",
            Self::CacheKey => "cache_key",
            Self::UserId => "user_id",
            Self::SafetyIdentifier => "safety_identifier",
            Self::User => "user",
            Self::None => "none",
        }
    }

    /// 是否链式锚点（UI「链」徽标依据）。
    pub fn is_chain(self) -> bool { matches!(self, Self::PrevResponse | Self::PrevMessage) }
}

/// 会话标识作用域（避免把用户级标识当会话聚合）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionScope {
    /// 会话级锚点（可跨轮关联）。
    Session,
    /// 用户级标识（同一用户跨会话）。
    User,
    /// 无标识。
    None,
}

impl SessionScope {
    /// 落库/响应体中的稳定文本（`llm_requests.session_scope`）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::User => "user",
            Self::None => "none",
        }
    }
}

/// 已解析的会话候选原始值（借用调用方请求体，零拷贝）。
///
/// 字段名与协议 JSON 键一一对应，便于 `gateway_serve` 解析后直接填充；
/// 任一字段为空串视为缺失（不产生空串摘要），由 [`derive_session`] 统一过滤。
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionInputs<'a> {
    /// 显式头值（经 [`resolve_session_header`] 解析：配置头 + 内置回退链）。
    pub header: Option<&'a str>,
    /// Responses `conversation`（`string` 形态或 `{id}` 已折算为字符串）。
    pub conversation: Option<&'a str>,
    /// Responses `previous_response_id`。
    pub previous_response_id: Option<&'a str>,
    /// Anthropic `diagnostics.previous_message_id`。
    pub previous_message_id: Option<&'a str>,
    /// Chat/Responses `prompt_cache_key`。
    pub prompt_cache_key: Option<&'a str>,
    /// Anthropic `metadata.user_id`。
    pub metadata_user_id: Option<&'a str>,
    /// Chat/Responses `safety_identifier`。
    pub safety_identifier: Option<&'a str>,
    /// Chat/Responses `user`。
    pub user: Option<&'a str>,
}

impl<'a> SessionInputs<'a> {
    /// 按九档优先级取首个非空候选（第九档「无」返回 `None`）。
    pub fn priority(&self) -> Option<(&'a str, SessionSource, SessionScope)> {
        pick(self.header, SessionSource::Header, SessionScope::Session)
            .or_else(|| {
                pick(
                    self.conversation,
                    SessionSource::Conversation,
                    SessionScope::Session,
                )
            })
            .or_else(|| {
                pick(
                    self.previous_response_id,
                    SessionSource::PrevResponse,
                    SessionScope::Session,
                )
            })
            .or_else(|| {
                pick(
                    self.previous_message_id,
                    SessionSource::PrevMessage,
                    SessionScope::Session,
                )
            })
            .or_else(|| {
                pick(
                    self.prompt_cache_key,
                    SessionSource::CacheKey,
                    SessionScope::Session,
                )
            })
            .or_else(|| {
                pick(
                    self.metadata_user_id,
                    SessionSource::UserId,
                    SessionScope::User,
                )
            })
            .or_else(|| {
                pick(
                    self.safety_identifier,
                    SessionSource::SafetyIdentifier,
                    SessionScope::User,
                )
            })
            .or_else(|| pick(self.user, SessionSource::User, SessionScope::User))
    }
}

/// 空串视为缺失（不做 trim：显式头/标识值原样参与摘要）。
fn pick(
    raw: Option<&str>,
    source: SessionSource,
    scope: SessionScope,
) -> Option<(&str, SessionSource, SessionScope)> {
    raw.filter(|v| !v.is_empty()).map(|v| (v, source, scope))
}

/// 九档优先级推导会话标识。
///
/// 返回 `(session_id, source, scope)`；`hmac_key` 为 `None` 或空切片时返回 `None`
/// （design §4：密钥缺失不产生会话列，且**不得**用无密钥哈希或随机盐兜底）。
pub fn derive_session(
    inputs: &SessionInputs<'_>,
    hmac_key: Option<&[u8]>,
    protocol: &str,
) -> Option<(String, SessionSource, SessionScope)> {
    let key = hmac_key.filter(|k| !k.is_empty())?;
    let (raw, source, scope) = inputs.priority()?;
    let digest = session_digest(key, protocol, raw)?;
    Some((digest, source, scope))
}

/// `hex(hmac_sha256(key, domain || 0x1f || protocol || 0x1f || raw))[..16]`。
///
/// HMAC 接受任意长度密钥，`new_from_slice` 实际不会失败；按「生产路径不 `expect`」
/// 约束改为返回 `Option`，失败即降级为「无会话」。
fn session_digest(key: &[u8], protocol: &str, raw: &str) -> Option<String> {
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).ok()?;
    mac.update(SESSION_DOMAIN);
    mac.update(&[SEPARATOR]);
    mac.update(protocol.as_bytes());
    mac.update(&[SEPARATOR]);
    mac.update(raw.as_bytes());
    let hex = hex::encode(mac.finalize().into_bytes());
    Some(hex[..SESSION_ID_HEX_LEN].to_string())
}

#[cfg(test)]
mod tests;
