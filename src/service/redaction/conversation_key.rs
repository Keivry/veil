//! 会话键分层推导与租户命名空间（veil-pii-conversation-cache D1/D2）。
//!
//! 纯函数单元（不触网络）：按四级优先级返回 `Option<ConversationKey>`——
//! 显式头优先于协议原生（`prompt_cache_key` / Responses `previous_response_id`
//! 映射），其后为稳定前缀 HMAC，末级 `None`（回退逐请求）。原始客户端值绝不
//! 直接作键，一律经 `HMAC(secret, tenant_fingerprint || conversation_id)` 命名空间化。

use {
    crate::service::{llm_gateway::Protocol, lock_recover::lock_or_recover},
    serde_json::Value,
    std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
    },
};

/// 显式会话键头上限（字节）：超长/非法不命中，`MUST NOT` 截断或哈希原始超长值。
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
fn hmac_hex(secret: &[u8], parts: &[&[u8]]) -> String {
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC key 恒可载入");
    for part in parts {
        mac.update(part);
    }
    hex::encode(mac.finalize().into_bytes())
}

/// 会话键派生：`HMAC(secret, tenant_fingerprint || SEP || conversation_id)`。
/// 所有级别（含显式头/协议原生键）均经本函数命名空间化。
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

/// 显式会话键头值校验：≤256 字节且无控制字符；否则不命中（不截断、不哈希原文）。
pub fn valid_explicit_header(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() > EXPLICIT_HEADER_MAX_BYTES {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value)
}

/// 采用显式会话键头值：`enabled=false`（`request` 模式）时一律不读头。
pub fn explicit_header(enabled: bool, raw: Option<&str>) -> Option<String> {
    if !enabled {
        return None;
    }
    raw.and_then(valid_explicit_header).map(str::to_string)
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

/// 系统前缀提取：Anthropic `system` / Responses `instructions` / messages 首条
/// `system`|`developer`。
fn extract_system(body: &Value) -> Option<Value> {
    if let Some(s) = body.get("system").filter(|v| !v.is_null()) {
        return Some(canonicalize(s.clone()));
    }
    if let Some(s) = body.get("instructions").filter(|v| !v.is_null()) {
        return Some(canonicalize(s.clone()));
    }
    let messages = body.get("messages")?.as_array()?;
    messages.iter().find_map(|m| {
        matches!(
            m.get("role").and_then(Value::as_str),
            Some("system") | Some("developer")
        )
        .then(|| canonicalize(m.clone()))
    })
}

/// 首个 user turn 提取：messages 首条 `role=user`；Responses `input` 字符串或数组
/// 中首条 `role=user`。
fn extract_first_user(body: &Value) -> Option<Value> {
    if let Some(messages) = body.get("messages").and_then(Value::as_array)
        && let Some(m) = messages
            .iter()
            .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
    {
        return Some(canonicalize(m.clone()));
    }
    match body.get("input") {
        Some(Value::String(s)) => Some(Value::String(s.clone())),
        Some(Value::Array(items)) => items
            .iter()
            .find(|item| item.get("role").and_then(Value::as_str) == Some("user"))
            .map(|m| canonicalize(m.clone())),
        _ => None,
    }
}

/// 稳定前缀规范化串：`tools`+`system`+首个 user turn **三者齐备**才产出；
/// 任一缺失返回 `None`（落第 4 级，不伪造键）。
fn canonical_stable_prefix(body: &Value) -> Option<String> {
    let tools = body.get("tools")?.as_array().filter(|a| !a.is_empty())?;
    let system = extract_system(body)?;
    let first_user = extract_first_user(body)?;
    let mut obj = serde_json::Map::new();
    obj.insert("tools".to_string(), Value::Array(normalize_tools(tools)));
    obj.insert("system".to_string(), system);
    obj.insert("first_user".to_string(), first_user);
    serde_json::to_string(&canonicalize(Value::Object(obj))).ok()
}

/// 稳定前缀 HMAC 键（第 3 级）：对**脱敏前**规范化前缀做 HMAC。
pub fn stable_prefix_key(
    secret: &[u8],
    tenant_fingerprint: &str,
    body: &Value,
) -> Option<ConversationKey> {
    let canonical = canonical_stable_prefix(body)?;
    Some(ConversationKey(hmac_hex(
        secret,
        &[
            tenant_fingerprint.as_bytes(),
            SEPARATOR,
            canonical.as_bytes(),
        ],
    )))
}

/// 四级分层推导（首个可命中者胜）：
/// ① 显式头 → ② `prompt_cache_key` → ③ `previous_response_id` 映射 →
/// ④ 稳定前缀 → ⑤ `None`。**MUST NOT** 使用 `user` 字段。
pub fn derive_conversation_key(
    secret: &[u8],
    tenant_fingerprint: &str,
    explicit: Option<&str>,
    prompt_cache_key: Option<&str>,
    previous_response_id: Option<&str>,
    body: Option<&Value>,
    previous_map: Option<&PreviousResponseMap>,
) -> Option<ConversationKey> {
    if let Some(v) = explicit.and_then(valid_explicit_header) {
        return Some(scoped_key(secret, tenant_fingerprint, v));
    }
    if let Some(k) = prompt_cache_key.filter(|s| !s.is_empty()) {
        return Some(scoped_key(secret, tenant_fingerprint, k));
    }
    if let Some(id) = previous_response_id.filter(|s| !s.is_empty())
        && let Some(m) = previous_map
        && let Some(key) = m.resolve(secret, tenant_fingerprint, id)
    {
        return Some(key);
    }
    body.and_then(|b| stable_prefix_key(secret, tenant_fingerprint, b))
}

/// LRU 顺序提升：命中即移到队尾，队首为最久未用。
pub(crate) fn touch_order(order: &mut VecDeque<String>, key: &str) {
    if let Some(pos) = order.iter().position(|v| v == key) {
        order.remove(pos);
    }
    order.push_back(key.to_string());
}

#[derive(Default)]
struct PrevInner {
    map: HashMap<String, ConversationKey>,
    order: VecDeque<String>,
}

/// `previous_response_id` → 会话键进程内映射（租户分域）：映射键 =
/// `HMAC(secret, tenant_fingerprint || previous_response_id)`，跨租户 MUST NOT 解析。
pub struct PreviousResponseMap {
    inner: Mutex<PrevInner>,
    max_entries: usize,
}

/// 手工 `Debug`：映射键（HMAC hex）与会话键不得经 `{:?}` 泄漏，仅暴露条目数。
impl std::fmt::Debug for PreviousResponseMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreviousResponseMap")
            .field("entries", &self.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

impl PreviousResponseMap {
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(PrevInner::default()),
            max_entries: max_entries.max(1),
        }
    }

    /// 记录响应 id → 会话键（已存在则覆盖并提升 LRU）。
    pub fn record(
        &self,
        secret: &[u8],
        tenant_fingerprint: &str,
        response_id: &str,
        key: &ConversationKey,
    ) {
        if response_id.is_empty() {
            return;
        }
        let map_key = scoped_key(secret, tenant_fingerprint, response_id);
        let mut inner = lock_or_recover(self.inner.lock());
        if !inner.map.contains_key(map_key.as_str())
            && inner.map.len() >= self.max_entries
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.map.remove(&oldest);
        }
        touch_order(&mut inner.order, map_key.as_str());
        inner.map.insert(map_key.0, key.clone());
    }

    /// 解析响应 id → 会话键（未命中返回 `None`，调用方继续下一级）。
    pub fn resolve(
        &self,
        secret: &[u8],
        tenant_fingerprint: &str,
        response_id: &str,
    ) -> Option<ConversationKey> {
        if response_id.is_empty() {
            return None;
        }
        let map_key = scoped_key(secret, tenant_fingerprint, response_id);
        let mut inner = lock_or_recover(self.inner.lock());
        let found = inner.map.get(map_key.as_str()).cloned();
        if found.is_some() {
            touch_order(&mut inner.order, map_key.as_str());
        }
        found
    }

    /// 当前条目数（有界断言用）。
    pub fn len(&self) -> usize { lock_or_recover(self.inner.lock()).map.len() }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

/// 响应完成写入点：仅 `Protocol::Responses` 且 id 非空时写入；Chat（`chatcmpl-*`）
/// / Anthropic（`msg_*`）的响应 id **MUST NOT** 进入映射。返回是否写入。
pub fn record_response_id(
    map: &PreviousResponseMap,
    secret: &[u8],
    tenant_fingerprint: &str,
    protocol: Protocol,
    response_id: Option<&str>,
    key: &ConversationKey,
) -> bool {
    if !protocol.is_responses() {
        return false;
    }
    let Some(id) = response_id.filter(|s| !s.is_empty()) else {
        return false;
    };
    map.record(secret, tenant_fingerprint, id, key);
    true
}

/// 请求级会话写回上下文（挂在 [`super::Scope`] 上，供响应完成处写映射）。
/// 仅 `conversation` 模式且键推导成功时存在。
#[derive(Clone)]
pub(crate) struct ConversationWriteback {
    key: ConversationKey,
    tenant_fingerprint: String,
    secret: Arc<[u8]>,
    previous_map: Arc<PreviousResponseMap>,
}

/// 手工 `Debug`：会话键/租户指纹/HMAC 密钥均为敏感值，派生 `Debug` 会泄漏；一律脱敏。
impl std::fmt::Debug for ConversationWriteback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWriteback")
            .field("key", &"[redacted]")
            .field("tenant_fingerprint", &"[redacted]")
            .field("secret", &"[redacted]")
            .field("previous_map", &"[redacted]")
            .finish()
    }
}

impl ConversationWriteback {
    pub(crate) fn new(
        key: ConversationKey,
        tenant_fingerprint: String,
        secret: Arc<[u8]>,
        previous_map: Arc<PreviousResponseMap>,
    ) -> Self {
        Self {
            key,
            tenant_fingerprint,
            secret,
            previous_map,
        }
    }

    /// 响应完成写回（协议门控在 [`record_response_id`] 内）。
    pub(crate) fn record(&self, protocol: Protocol, response_id: &str) -> bool {
        record_response_id(
            &self.previous_map,
            &self.secret,
            &self.tenant_fingerprint,
            protocol,
            Some(response_id),
            &self.key,
        )
    }
}

#[cfg(test)]
#[path = "conversation_key_tests.rs"]
mod conversation_key_tests;
