//! 摘要稳定性、协议域分离与无密钥降级断言。
//!
//! 身份优先级已迁至 `service::session_identity`（其自带阶梯测试）；本模块只保留
//! 摘要函数本身的契约。

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("session.rs", include_str!("../session.rs"));
    crate::test_support::file_len_under_800_or_split("session/tests.rs", include_str!("tests.rs"));
}

use super::*;

const KEY: &[u8] = b"test-hmac-key";

#[test]
fn digest_is_stable_and_protocol_scoped() {
    let a = session_digest(KEY, "chat", "raw-anchor").expect("摘要");
    let b = session_digest(KEY, "chat", "raw-anchor").expect("摘要");
    assert_eq!(a, b, "同输入须稳定");
    assert_eq!(a.len(), SESSION_ID_HEX_LEN);
    assert!(
        a.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "摘要须为小写 hex"
    );
    let other_proto = session_digest(KEY, "anthropic", "raw-anchor").expect("摘要");
    assert_ne!(a, other_proto, "跨协议摘要须不同");
    let other_key = session_digest(b"other-key", "chat", "raw-anchor").expect("摘要");
    assert_ne!(a, other_key, "跨密钥摘要须不同");
    let other_raw = session_digest(KEY, "chat", "another-anchor").expect("摘要");
    assert_ne!(a, other_raw, "不同原文摘要须不同");
}

#[test]
fn digest_differs_from_conversation_scoped_key() {
    use crate::service::redaction::conversation_key::scoped_key;
    let session_id = session_digest(KEY, "chat", "conv-raw").expect("摘要");
    let conversation = scoped_key(KEY, "", "conv-raw");
    assert_ne!(
        session_id,
        conversation.as_str()[..SESSION_ID_HEX_LEN],
        "会话摘要须与 PII 会话键域分离"
    );
}
