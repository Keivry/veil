//! 会话头链：顺序、空值/非法候选跳过与 ① > ② 优先级。

use super::*;

#[test]
fn header_chain_first_valid_candidate_wins() {
    let alias = SessionAliasMap::new(8);
    // 首个候选为空串 → 跳过；第二个命中。
    let id = resolve_with(
        &headers(&[
            ("x-veil-conversation-id", ""),
            ("x-opencode-session", "sess-2"),
            ("x-opencode-session-id", "sess-3"),
        ]),
        Some(&json!({})),
        Protocol::Chat,
        &alias,
    );
    assert_eq!(id.source, SessionSource::Header);
    assert_eq!(id.scope, SessionScope::Session);
    assert_eq!(id.log_source, SessionSource::Header);
    assert_eq!(id.log_scope, SessionScope::Session);
    assert_eq!(id.anchor.as_ref().map(|a| a.value.as_str()), Some("sess-2"));
    assert_eq!(
        id.anchor.as_ref().map(|a| a.source),
        Some(AnchorSource::Header)
    );
    assert_eq!(id.canonical, Some(scoped_key(SECRET, TENANT, "sess-2")));

    // 头链靠前者胜过靠后者（不因后者存在而变化）。
    let first = resolve_with(
        &headers(&[
            ("x-veil-conversation-id", "sess-1"),
            ("x-opencode-session", "sess-2"),
        ]),
        None,
        Protocol::Chat,
        &alias,
    );
    assert_eq!(first.canonical, Some(scoped_key(SECRET, TENANT, "sess-1")));
}

#[test]
fn header_candidates_reject_invisible_or_oversized() {
    let alias = SessionAliasMap::new(8);
    // 含控制字符（TAB）→ 跳过。
    let id = resolve_with(
        &headers(&[
            ("x-veil-conversation-id", "bad\tvalue"),
            ("x-opencode-session", "good"),
        ]),
        None,
        Protocol::Chat,
        &alias,
    );
    assert_eq!(id.canonical, Some(scoped_key(SECRET, TENANT, "good")));

    // 非 ASCII（中文）→ 跳过，落第 ⑥ 级（无 canonical）。
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", "会话一")]),
        None,
        Protocol::Chat,
        &alias,
    );
    assert_eq!(id.source, SessionSource::None);
    assert_eq!(id.scope, SessionScope::None);
    assert!(id.canonical.is_none());
    assert!(id.anchor.is_none());

    // 超 256 字节 → 跳过。
    let long = "a".repeat(257);
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", &long)]),
        None,
        Protocol::Chat,
        &alias,
    );
    assert!(id.canonical.is_none(), "超长候选 MUST NOT 截断/哈希");

    // 恰好 256 字节 → 命中。
    let exact = "a".repeat(256);
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", &exact)]),
        None,
        Protocol::Chat,
        &alias,
    );
    assert!(id.canonical.is_some(), "256 字节须命中");
}

#[test]
fn header_beats_conversation() {
    let alias = SessionAliasMap::new(8);
    let body = json!({"conversation": "conv_1"});
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", "sess-1")]),
        Some(&body),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(id.source, SessionSource::Header, "① 须优先于 ②");
    assert_eq!(id.canonical, Some(scoped_key(SECRET, TENANT, "sess-1")));
}
