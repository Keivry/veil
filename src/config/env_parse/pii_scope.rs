//! PII 会话作用域开关域（`PII_SCOPE_*`）。
//!
//! 默认 `request` 即现行为（逐请求作用域，零行为变化）；`conversation` 启用
//! 会话级 PII 共享。合法值以外的取值 fail-closed 拒启动，不静默回退。
//!
//! 会话头链与别名容量已迁至 `[session]`（见 `env_parse::session`）：本模块不再读取
//! `PII_SCOPE_KEY_HEADER` / `PII_SCOPE_PREV_ID_MAX_ENTRIES`；这两个旧规范名在进程 env
//! 非空置位时由 `Config::from_env_map` 的 fail-closed 预扫描拒绝启动。

use {
    super::super::validate::{parse_positive_u64, parse_positive_usize},
    crate::error::{Result, VeilError},
};

/// `PII_SCOPE_TTL_SECS` 默认值（秒，30 分钟空闲 TTL）。
pub const PII_SCOPE_TTL_SECS_DEFAULT: u64 = 1800;
/// `PII_SCOPE_MAX_CONVERSATIONS` 默认值（会话条目上限）。
pub const PII_SCOPE_MAX_CONVERSATIONS_DEFAULT: usize = 1024;

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
    pub ttl_secs: u64,
    pub max_conversations: usize,
}

/// 解析 `PII_SCOPE_*`：模式非法与 TTL/上限非正整数一律拒启动并指明变量。
pub fn load(get: &dyn Fn(&str) -> Option<String>) -> Result<PiiScopeParts> {
    let mode = match get("PII_SCOPE_MODE").filter(|v| !v.is_empty()) {
        Some(v) => v.parse().map_err(|message| VeilError::Config {
            var: "PII_SCOPE_MODE".to_string(),
            message,
        })?,
        None => PiiScopeMode::Request,
    };
    let ttl_secs = parse_positive_u64(get, "PII_SCOPE_TTL_SECS", PII_SCOPE_TTL_SECS_DEFAULT)?;
    let max_conversations = parse_positive_usize(
        get,
        "PII_SCOPE_MAX_CONVERSATIONS",
        PII_SCOPE_MAX_CONVERSATIONS_DEFAULT,
    )?;
    Ok(PiiScopeParts {
        mode,
        ttl_secs,
        max_conversations,
    })
}

#[cfg(test)]
mod tests;
