//! 会话身份解析器测试入口（sibling 目录，父模块 `#[cfg(test)] mod tests;`）。
//!
//! 三个子模块分别覆盖：头链（①②优先级与候选校验）、协议原生键与稳定前缀、
//! 日志口径与脱敏。共享的密钥/租户/辅助函数在本文件。

use {
    super::*,
    crate::service::redaction::{SessionAliasMap, conversation_key::scoped_key},
    axum::http::{HeaderMap, HeaderValue},
    serde_json::json,
};

const SECRET: &[u8] = b"session-identity-secret";
const TENANT: &str = "tenant-fp";
const CHAIN: [&str; 3] = [
    "x-veil-conversation-id",
    "x-opencode-session",
    "x-opencode-session-id",
];

fn chain() -> Vec<String> { CHAIN.iter().map(|name| (*name).to_string()).collect() }

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            name.parse::<axum::http::HeaderName>()
                .expect("测试头名合法"),
            HeaderValue::from_str(value).expect("测试头值合法"),
        );
    }
    map
}

/// 解析辅助：默认空头链输入为配置链，与别名表。
fn resolve_with(
    headers: &HeaderMap,
    body: Option<&serde_json::Value>,
    protocol: Protocol,
    alias: &SessionAliasMap,
) -> SessionIdentity {
    resolve(headers, body, protocol, &chain(), alias, SECRET, TENANT)
}

/// 稳定前缀体：`tools` + `system` + 首个 user turn 三者齐备（第 ⑤ 级可命中）。
fn prefix_body() -> serde_json::Value {
    json!({
        "tools": [{"type": "function", "function": {"name": "alpha"}}],
        "messages": [
            {"role": "system", "content": "you are helpful"},
            {"role": "user", "content": "hello"}
        ],
    })
}

mod headers;
mod logging;
mod native;
mod rounds;
