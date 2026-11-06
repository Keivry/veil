//! 会话键派生原语与租户命名空间。
//!
//! 本模块只保留**纯函数**成分：租户指纹、会话键 HMAC 派生、稳定前缀规范化与
//! 别名表共用的 LRU 顺序辅助。分层身份推导已迁至 `service::session_identity`
//! （单一解析器），响应侧别名绑定见 `service::redaction::writeback` 与
//! `session_alias`。
//!
//! 原始客户端值绝不直接作键，一律经
//! `HMAC(secret, tenant_fingerprint || conversation_id)` 命名空间化。

use {crate::service::llm_gateway::Protocol, serde_json::Value, std::collections::VecDeque};

/// 会话头候选上限（字节）：超长/非法不命中，`MUST NOT` 截断或哈希原始超长值。
pub const EXPLICIT_HEADER_MAX_BYTES: usize = 256;
/// 分量分隔符（固定单一字面量，界定 HMAC 输入各拼接边界）。
const SEPARATOR: &[u8] = b"\x1f";
/// 多凭据归一化的固定子分隔符（去重排序后 join 用）。
const CREDENTIAL_SUB_SEPARATOR: &str = "\x1e";

/// 会话键：`HMAC-SHA256` hex（64 字符），不可由客户端预测/枚举。
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConversationKey(String);

/// 手工 `Debug`：会话键为 HMAC hex，派生 `Debug` 会打印可用键值；一律 `[redacted]`。
impl std::fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ConversationKey")
            .field(&"[redacted]")
            .finish()
    }
}

impl ConversationKey {
    /// 线内代表（用于存储映射键；不含任何客户端原文）。
    pub fn as_str(&self) -> &str { &self.0 }

    /// 仅测试：直接构造已知键（生产键一律经 [`scoped_key`]）。
    #[cfg(test)]
    pub(crate) fn for_test(s: &str) -> Self { Self(s.to_string()) }
}

/// 通用 HMAC-SHA256（hex），复用 `service::metrics::sample` 既有模式。
///
/// `pub(crate)`：会话别名表（[`super::session_alias`]）与出站标识
/// （`service::session_identity::outbound`）复用本实现，不另复制 HMAC 代码。
pub(crate) fn hmac_hex(secret: &[u8], parts: &[&[u8]]) -> String {
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC key 恒可载入");
    for part in parts {
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}

/// 会话键派生：`HMAC(secret, tenant_fingerprint || SEP || conversation_id)`。
/// 所有级别（含头链/协议原生键）均经本函数命名空间化。
pub fn scoped_key(
    secret: &[u8],
    tenant_fingerprint: &str,
    conversation_id: &str,
) -> ConversationKey {
    ConversationKey(hmac_hex(
        secret,
        &[
            tenant_fingerprint.as_bytes(),
            SEPARATOR,
            conversation_id.as_bytes(),
        ],
    ))
}

/// 客户端凭据头归一化：零个 → 固定空串分量；多个去重后按字节序排序、以固定
/// 子分隔符 join；全程不含凭据原文。
fn normalize_credentials(credentials: &[&str]) -> String {
    let mut values: Vec<&str> = credentials
        .iter()
        .copied()
        .filter(|v| !v.is_empty())
        .collect();
    values.sort_unstable();
    values.dedup();
    values.join(CREDENTIAL_SUB_SEPARATOR)
}

/// 租户指纹：`HMAC(secret, 完整上游基址 || SEP || 凭据头归一化)`。
/// 主判别项为**完整 `upstream_base`（含 path/query）**——仅用上游主机会把不同
/// 租户（同主机不同上游路径/端口）折叠进同一命名空间。
pub fn tenant_fingerprint(secret: &[u8], upstream_base: &str, credentials: &[&str]) -> String {
    let normalized = normalize_credentials(credentials);
    hmac_hex(
        secret,
        &[upstream_base.as_bytes(), SEPARATOR, normalized.as_bytes()],
    )
}

/// 对象键递归升序、`tools` 按工具名稳定排序、其余数组保序的确定性规范化。
fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(v) = map.get(&k) {
                    out.insert(k.clone(), canonicalize(v.clone()));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

/// 工具名提取（Chat/Anthropic `name`；Chat 兼容 `function.name`），供稳定排序。
fn tool_name(tool: &Value) -> String {
    tool.get("name")
        .and_then(Value::as_str)
        .or_else(|| {
            tool.get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string()
}

/// `tools` 数组按工具名稳定排序（同名保序），逐元素规范化。
fn normalize_tools(tools: &[Value]) -> Vec<Value> {
    let mut named: Vec<(String, Value)> = tools
        .iter()
        .map(|t| (tool_name(t), canonicalize(t.clone())))
        .collect();
    named.sort_by(|a, b| a.0.cmp(&b.0));
    named.into_iter().map(|(_, v)| v).collect()
}

/// 系统前缀提取（按协议白名单）：Responses 取 `instructions`；
/// Anthropic 取原生顶层 `system`（存在且非 null 时优先）或 `messages` 首条
/// `system`|`developer`；Chat 仅 `messages` 首条 `system`|`developer`（顶层 `system`
/// MUST NOT 参与）。协议外字段 MUST NOT 越界参与——Chat 的 `instructions`
/// MUST NOT 被当作 `system`，Responses 的 `messages` MUST NOT 被当作 system 来源。
fn extract_system(body: &Value, protocol: Protocol) -> Option<Value> {
    if protocol.is_responses() {
        return body
            .get("instructions")
            .filter(|v| !v.is_null())
            .map(|v| canonicalize(v.clone()));
    }
    if protocol.is_anthropic()
        && let Some(s) = body.get("system").filter(|v| !v.is_null())
    {
        return Some(canonicalize(s.clone()));
    }
    let first = body.get("messages")?.as_array()?.first()?;
    matches!(
        first.get("role").and_then(Value::as_str),
        Some("system") | Some("developer")
    )
    .then(|| canonicalize(first.clone()))
}

/// 首个 user turn 提取（按协议白名单）：Chat/Anthropic 取
/// `messages` 数组首条 `role=user`；Responses 取**数组形** `input` 首条
/// `role=user`。Responses **标量（字符串）`input`** 不参与稳定前缀级，返回 `None`
/// （其内容随轮次增长、无法作稳定 turn 锚点），使推导落逐请求并由
/// 既有 `record_request_fallback()` 计入观测。协议外字段 MUST NOT 越界参与——
/// Responses 的 `messages` MUST NOT 被当作首个 user turn。
fn extract_first_user(body: &Value, protocol: Protocol) -> Option<Value> {
    if protocol.is_responses() {
        return match body.get("input") {
            Some(Value::Array(items)) => items
                .iter()
                .find(|item| item.get("role").and_then(Value::as_str) == Some("user"))
                .map(|m| canonicalize(m.clone())),
            _ => None,
        };
    }
    let messages = body.get("messages")?.as_array()?;
    messages
        .iter()
        .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
        .map(|m| canonicalize(m.clone()))
}

/// 稳定前缀规范化串：`tools`+`system`+首个 user turn **三者齐备**才产出；
/// 任一缺失返回 `None`（不伪造键）。字段提取按协议白名单，
/// 标量 Responses `input` 在此不命中。
fn canonical_stable_prefix(body: &Value, protocol: Protocol) -> Option<String> {
    let tools = body.get("tools")?.as_array().filter(|a| !a.is_empty())?;
    let system = extract_system(body, protocol)?;
    let first_user = extract_first_user(body, protocol)?;
    let mut obj = serde_json::Map::new();
    obj.insert("tools".to_string(), Value::Array(normalize_tools(tools)));
    obj.insert("system".to_string(), system);
    obj.insert("first_user".to_string(), first_user);
    serde_json::to_string(&canonicalize(Value::Object(obj))).ok()
}

/// 稳定前缀 HMAC 键：对**脱敏前**规范化前缀做 HMAC。
/// 字段提取按协议白名单。
pub fn stable_prefix_key(
    secret: &[u8],
    tenant_fingerprint: &str,
    protocol: Protocol,
    body: &Value,
) -> Option<ConversationKey> {
    let canonical = canonical_stable_prefix(body, protocol)?;
    Some(ConversationKey(hmac_hex(
        secret,
        &[
            tenant_fingerprint.as_bytes(),
            SEPARATOR,
            canonical.as_bytes(),
        ],
    )))
}

/// LRU 顺序提升：命中即移到队尾，队首为最久未用。
pub(crate) fn touch_order(order: &mut VecDeque<String>, key: &str) {
    if let Some(pos) = order.iter().position(|v| v == key) {
        order.remove(pos);
    }
    order.push_back(key.to_string());
}

#[cfg(test)]
mod tests;
