//! 会话摘要：与 `conversation_key` 域分离的 16-hex HMAC（仅日志列）。
//!
//! 身份解析已统一到 `service::session_identity`（一次解析同时产出 PII 口径与日志口径，
//! 见 design D1/D2）；本模块只剩摘要计算：
//! `hex(hmac_sha256(key, "veil-session-v1" || 0x1f || protocol || 0x1f || raw))[..16]`。
//! 原始值（头值/`conversation.id`/`prompt_cache_key`/用户标识）绝不落库、绝不进日志，
//! 只留 16 hex。
//!
//! 域分离：`conversation_key::scoped_key` 用 `tenant || 0x1f || conversation` 域，
//! 本模块用固定的 `veil-session-v1` 前缀，故同一 raw 两条路径的摘要必然不等
//! （tasks 2.2）。`hmac_hex` 在 `conversation_key` 内为私有且不带域串，故此处用同一
//! `hmac`/`sha2` crate 本地实现，不跨模块改可见性。
//!
//! 密钥：只取既有可选 env `PII_VALUE_SAMPLE_HMAC_KEY`（空串已由配置层过滤为 `None`）。
//! 密钥缺失时调用方（`RequestTrace::attach_identity`）不写会话列且来源标 `none`，
//! **不得**退化为无密钥哈希或进程随机盐（空密钥 HMAC 可字典反查）。

/// 摘要域串（与 `conversation_key` 的 `tenant || 0x1f || conversation` 域不同）。
const SESSION_DOMAIN: &[u8] = b"veil-session-v1";
/// 分量分隔符（与 `conversation_key::SEPARATOR` 同一字面量 `0x1f`）。
const SEPARATOR: u8 = 0x1f;
/// `session_id` 保留的 hex 字符数（16 hex = 64 bit，碰撞概率对 7 天窗口可接受）。
pub const SESSION_ID_HEX_LEN: usize = 16;

/// `hex(hmac_sha256(key, domain || 0x1f || protocol || 0x1f || raw))[..16]`。
///
/// `raw` 为会话作用域的 `identity.canonical` 文本，或用户作用域的 `log_user.value`
/// （spec「会话标识派生与作用域」）。HMAC 接受任意长度密钥，`new_from_slice` 实际不会
/// 失败；按「生产路径不 `expect`」约束返回 `Option`，失败即降级为「无会话」。
pub fn session_digest(key: &[u8], protocol: &str, raw: &str) -> Option<String> {
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
