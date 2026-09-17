//! PII 会话作用域开关域（`PII_SCOPE_*`，veil-pii-conversation-cache D7）。
//!
//! 默认 `request` 即现行为（逐请求作用域，零行为变化）；`conversation` 启用
//! 会话级 PII 共享。合法值以外的取值 fail-closed 拒启动，不静默回退。

use {
    super::super::validate::{parse_positive, parse_positive_usize},
    crate::error::{Result, VeilError},
};

/// `PII_SCOPE_TTL_SECS` 默认值（秒，30 分钟空闲 TTL）。
pub const PII_SCOPE_TTL_SECS_DEFAULT: i64 = 1800;
/// `PII_SCOPE_MAX_CONVERSATIONS` 默认值（会话条目上限）。
pub const PII_SCOPE_MAX_CONVERSATIONS_DEFAULT: usize = 1024;
/// `PII_SCOPE_KEY_HEADER` 默认头名（属 `x-veil-*` 内部命名空间，转发前剔除）。
pub const PII_SCOPE_KEY_HEADER_DEFAULT: &str = "x-veil-conversation-id";

/// PII 作用域模式：`request`（默认，逐请求）/ `conversation`（会话级共享）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PiiScopeMode {
    #[default]
    Request,
    Conversation,
}

impl PiiScopeMode {
    /// 是否启用会话级作用域（唯一判定入口，避免各处重复 `matches!`）。
    pub fn is_conversation(self) -> bool { matches!(self, Self::Conversation) }
}

impl std::str::FromStr for PiiScopeMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "request" => Ok(Self::Request),
            "conversation" => Ok(Self::Conversation),
            other => Err(format!(
                "PII_SCOPE_MODE 非法: {other:?}（取值 request/conversation）"
            )),
        }
    }
}

/// PII 作用域域解析产物（`Config` 字段的装配输入）。
pub struct PiiScopeParts {
    pub mode: PiiScopeMode,
    pub ttl_secs: i64,
    pub max_conversations: usize,
    pub key_header: String,
    pub prev_id_max_entries: usize,
}

/// 保留会话键头名（R5-40/D7，大小写不敏感对比）：与真实鉴权头冲突者。
/// HOP 集经 `service::llm_gateway::HOP_HEADERS` 单一来源并入，避免两处漂移。
const RESERVED_KEY_HEADERS: [&str; 7] = [
    "authorization",
    "x-api-key",
    "api-key",
    "host",
    "content-length",
    "content-encoding",
    "accept-encoding",
];

/// 会话键头保留名判定（R5-40/D7）：命中即拒启动——无条件剔除会令 `request`
/// 模式亦删除真实鉴权/传输头转发上游而静默断链。
fn is_reserved_key_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    RESERVED_KEY_HEADERS.contains(&lower.as_str())
        || crate::service::llm_gateway::HOP_HEADERS.contains(&lower.as_str())
}

/// 解析 `PII_SCOPE_*`：模式非法与 TTL/上限非正整数一律拒启动并指明变量；
/// 保留会话键头名拒启动（R5-40/D7）。`PII_PREV_ID_MAX_ENTRIES` 未设置时取
/// `PII_SCOPE_MAX_CONVERSATIONS` 的**生效值**（配置相关默认，非钉死 1024）。
pub fn load(get: &dyn Fn(&str) -> Option<String>) -> Result<PiiScopeParts> {
    let mode = match get("PII_SCOPE_MODE").filter(|v| !v.is_empty()) {
        Some(v) => v.parse().map_err(|message| VeilError::Config {
            var: "PII_SCOPE_MODE".to_string(),
            message,
        })?,
        None => PiiScopeMode::Request,
    };
    let ttl_secs = parse_positive(get, "PII_SCOPE_TTL_SECS", PII_SCOPE_TTL_SECS_DEFAULT)?;
    let max_conversations = parse_positive_usize(
        get,
        "PII_SCOPE_MAX_CONVERSATIONS",
        PII_SCOPE_MAX_CONVERSATIONS_DEFAULT,
    )?;
    let key_header = get("PII_SCOPE_KEY_HEADER")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| PII_SCOPE_KEY_HEADER_DEFAULT.to_string());
    if is_reserved_key_header(&key_header) {
        return Err(VeilError::Config {
            var: "PII_SCOPE_KEY_HEADER".to_string(),
            message: format!(
                "PII_SCOPE_KEY_HEADER 取值 {key_header:?} 与保留鉴权/传输头名冲突，拒绝启动\
                （会话键头无条件剔除，保留名会在转发上游前删除真实头）"
            ),
        });
    }
    let prev_id_max_entries =
        parse_positive_usize(get, "PII_PREV_ID_MAX_ENTRIES", max_conversations)?;
    Ok(PiiScopeParts {
        mode,
        ttl_secs,
        max_conversations,
        key_header,
        prev_id_max_entries,
    })
}

#[cfg(test)]
#[path = "pii_scope_tests.rs"]
mod tests;
