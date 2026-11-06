//! 日志口径（用户级仅日志、`request_carried_conversation`）与 `Debug` 脱敏。

use super::*;

#[test]
fn user_level_sources_follow_protocol_whitelist() {
    let alias = SessionAliasMap::new(8);
    for (body, protocol, expected) in [
        (
            json!({"metadata": {"user_id": "u-1"}}),
            Protocol::Anthropic,
            Some(SessionSource::UserId),
        ),
        (
            json!({"safety_identifier": "s-1"}),
            Protocol::Anthropic,
            None,
        ),
        (json!({"user": "uu-1"}), Protocol::Anthropic, None),
        (
            json!({"safety_identifier": "s-1"}),
            Protocol::Chat,
            Some(SessionSource::SafetyIdentifier),
        ),
        (
            json!({"user": "uu-1"}),
            Protocol::Chat,
            Some(SessionSource::User),
        ),
        (
            json!({"metadata": {"user_id": "u-1"}}),
            Protocol::Chat,
            None,
        ),
        (
            json!({"safety_identifier": "s-1"}),
            Protocol::Responses,
            Some(SessionSource::SafetyIdentifier),
        ),
        (
            json!({"user": "uu-1"}),
            Protocol::Responses,
            Some(SessionSource::User),
        ),
        (
            json!({"metadata": {"user_id": "u-1"}}),
            Protocol::Responses,
            None,
        ),
        (json!({"user": "uu-1"}), Protocol::NonDialog, None),
    ] {
        let id = resolve_with(&HeaderMap::new(), Some(&body), protocol, &alias);
        let expected_source = expected.unwrap_or(SessionSource::None);
        assert_eq!(id.log_source, expected_source, "{protocol:?} {body}");
        if expected.is_some() {
            assert_eq!(id.log_scope, SessionScope::User);
            assert_eq!(id.log_user.as_ref().map(|u| u.source), expected);
            assert!(id.log_user.as_ref().is_some_and(|u| !u.value.is_empty()));
            // 用户级 MUST NOT 参与 PII/出站。
            assert!(id.canonical.is_none());
            assert!(id.anchor.is_none());
            assert_eq!(id.scope, SessionScope::None);
            assert_eq!(id.source, SessionSource::None);
        } else {
            assert!(id.log_user.is_none(), "{protocol:?} {body}");
            assert_eq!(id.log_scope, SessionScope::None);
        }
    }
}

#[test]
fn chat_and_responses_user_sources_prefer_safety_identifier() {
    let alias = SessionAliasMap::new(8);
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"safety_identifier": "s-1", "user": "uu-1"})),
        Protocol::Chat,
        &alias,
    );
    assert_eq!(id.log_source, SessionSource::SafetyIdentifier);
    assert_eq!(id.log_user.as_ref().map(|u| u.value.as_str()), Some("s-1"));

    // 空串视为缺失，落到 `user`。
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"safety_identifier": "", "user": "uu-1"})),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(id.log_source, SessionSource::User);

    // Anthropic 的 `metadata.user_id` 为空时不得落到 `safety_identifier`/`user`。
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&json!({
            "metadata": {"user_id": ""},
            "safety_identifier": "s-1",
            "user": "uu-1",
        })),
        Protocol::Anthropic,
        &alias,
    );
    assert_eq!(id.log_source, SessionSource::None);
    assert!(id.log_user.is_none());
}

#[test]
fn session_level_log_fields_match_pii_and_user_does_not_override() {
    let alias = SessionAliasMap::new(8);
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", "sess-1")]),
        Some(&json!({"user": "u-1"})),
        Protocol::Chat,
        &alias,
    );
    assert_eq!(id.source, SessionSource::Header);
    assert_eq!(id.log_source, SessionSource::Header, "①–④ 与 PII 同源");
    assert_eq!(id.log_scope, SessionScope::Session);
    assert!(id.log_user.is_none(), "①–④ 命中时用户级 MUST NOT 覆盖");

    // 稳定前缀 + 用户级：PII 用稳定前缀 canonical，日志用用户级。
    let body = prefix_body();
    let mut merged = body.clone();
    merged["user"] = json!("uu-1");
    let id = resolve_with(&HeaderMap::new(), Some(&merged), Protocol::Chat, &alias);
    assert_eq!(id.source, SessionSource::None);
    assert!(id.canonical.is_some(), "PII 仍用稳定前缀");
    assert_eq!(id.log_source, SessionSource::User);
    assert_eq!(id.log_scope, SessionScope::User);
}

#[test]
fn request_carried_conversation_tracks_key_presence() {
    let alias = SessionAliasMap::new(8);
    for (body, expected) in [
        (json!({}), false),
        (json!({"model": "m"}), false),
        (json!({"conversation": "conv_1"}), true),
        (json!({"conversation": ""}), true),
        (json!({"conversation": {}}), true),
        (json!({"conversation": {"id": ""}}), true),
        (json!({"conversation": {"id": "conv_1"}}), true),
    ] {
        // 与协议无关：Chat 体同样按键存在性判定。
        let id = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Chat, &alias);
        assert_eq!(id.request_carried_conversation, expected, "{body}");
    }
    // 无正文恒 false。
    let id = resolve_with(&HeaderMap::new(), None, Protocol::Responses, &alias);
    assert!(!id.request_carried_conversation);
}

#[test]
fn alias_counters_do_not_change_derivation() {
    let alias = SessionAliasMap::new(8);
    let body = json!({"conversation": "conv_1"});
    let first = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Responses, &alias);
    // 重复解析（LRU 提升 + hit 计数路径）不改变派生结果。
    let second = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Responses, &alias);
    let third = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Responses, &alias);
    assert_eq!(first.canonical, second.canonical);
    assert_eq!(second.canonical, third.canonical);
    assert_eq!(first.source, third.source);
}

#[test]
fn debug_redacts_sensitive_values() {
    let alias = SessionAliasMap::new(8);
    assert_eq!(
        alias.bind(
            SECRET,
            TENANT,
            "resp_secret_id",
            &scoped_key(SECRET, TENANT, "canonical-secret")
        ),
        crate::service::redaction::session_alias::BindOutcome::Bound
    );
    let id = resolve_with(
        &headers(&[("x-veil-conversation-id", "header-secret-value")]),
        Some(&json!({"user": "user-secret-value"})),
        Protocol::Chat,
        &alias,
    );
    let debug = format!("{id:?}");
    for secret in [
        "header-secret-value",
        TENANT,
        "canonical-secret",
        "user-secret-value",
        id.canonical
            .as_ref()
            .expect("头命中须有 canonical")
            .as_str(),
    ] {
        assert!(!debug.contains(secret), "Debug 不得含 {secret:?}: {debug}");
    }
    assert!(debug.contains("[redacted]"));

    // 子结构同样脱敏。
    let anchor = format!("{:?}", id.anchor.as_ref().expect("anchor"));
    assert!(!anchor.contains("header-secret-value"));
    let user = format!("{:?}", id.log_user);
    assert!(!user.contains("user-secret-value"));
}

#[test]
fn mode_is_not_a_resolver_input_so_log_and_pii_are_mode_orthogonal() {
    // 解析器无 `[pii_scope].mode` 入参：同一输入的日志字段与 PII 字段恒定。
    // `request` 模式由消费者跳过 `ConversationScopeStore`，解析结果不变——
    // 因此日志仍可显示 `session_source=header`/`session_scope=session`，
    // 而 PII canonical 也照常计算（是否共享由消费方决定）。
    let alias = SessionAliasMap::new(8);
    let input_headers = headers(&[("x-veil-conversation-id", "sess-1")]);
    let first = resolve_with(&input_headers, None, Protocol::Chat, &alias);
    let second = resolve_with(&input_headers, None, Protocol::Chat, &alias);
    assert_eq!(first, second, "解析结果与调用次数/模式无关");
    assert_eq!(first.log_source, SessionSource::Header);
    assert_eq!(first.log_scope, SessionScope::Session);
    assert_eq!(first.source, SessionSource::Header);
    assert_eq!(first.scope, SessionScope::Session);
    assert_eq!(first.canonical, Some(scoped_key(SECRET, TENANT, "sess-1")));
}
