//! 协议原生键（`conversation`/`previous_response_id`/`prompt_cache_key`）与稳定前缀。

use {
    super::*,
    crate::service::redaction::{session_alias::BindOutcome, stable_prefix_key},
};

#[test]
fn conversation_forms_share_key_and_prefer_alias() {
    let alias = SessionAliasMap::new(8);
    // 字符串形态与对象形态派生同键。
    let string_form = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"conversation": "conv_1"})),
        Protocol::Responses,
        &alias,
    );
    let object_form = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"conversation": {"id": "conv_1"}})),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(string_form.canonical, object_form.canonical);
    assert_eq!(
        string_form.canonical,
        Some(scoped_key(SECRET, TENANT, "conv_1")),
        "未命中别名时才原生派生"
    );
    assert_eq!(string_form.source, SessionSource::Conversation);
    assert_eq!(string_form.scope, SessionScope::Session);

    // 别名命中 → 使用绑定 canonical（不另建键）。
    let bound = scoped_key(SECRET, TENANT, "K1");
    assert_eq!(
        alias.bind(SECRET, TENANT, "conv_1", &bound),
        BindOutcome::Bound
    );
    let hit = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"conversation": "conv_1"})),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(hit.canonical, Some(bound), "conversation 须先查别名");
    assert_eq!(
        hit.anchor.as_ref().map(|a| a.value.as_str()),
        Some("conv_1")
    );

    // 空串/空对象/对象缺 id → 该来源未命中，继续下一级。
    for empty in [
        json!({"conversation": ""}),
        json!({"conversation": {}}),
        json!({"conversation": {"id": ""}}),
    ] {
        let id = resolve_with(&HeaderMap::new(), Some(&empty), Protocol::Responses, &alias);
        assert_eq!(id.source, SessionSource::None, "{empty} 须未命中");
        assert!(id.canonical.is_none());
    }
}

#[test]
fn conversation_beats_previous_response_id_and_prompt_cache_key() {
    let alias = SessionAliasMap::new(8);
    let prev_key = scoped_key(SECRET, TENANT, "K_prev");
    alias.bind(SECRET, TENANT, "resp_1", &prev_key);
    let body = json!({
        "conversation": "conv_1",
        "previous_response_id": "resp_1",
        "prompt_cache_key": "pck",
    });
    let id = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Responses, &alias);
    assert_eq!(id.source, SessionSource::Conversation);
    assert_eq!(id.canonical, Some(scoped_key(SECRET, TENANT, "conv_1")));
}

#[test]
fn previous_response_id_alias_hit_and_miss_never_sets_anchor() {
    let alias = SessionAliasMap::new(8);
    let bound = scoped_key(SECRET, TENANT, "K1");
    alias.bind(SECRET, TENANT, "resp_1", &bound);

    let hit = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1"})),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(hit.source, SessionSource::PrevResponse);
    assert_eq!(hit.canonical, Some(bound));
    assert_eq!(
        hit.anchor.as_ref().map(|a| a.source),
        Some(AnchorSource::PreviousResponse)
    );
    assert_eq!(hit.log_source, SessionSource::PrevResponse);

    // 未命中：不设 PreviousResponse 锚点、不自行建键，继续下一级。
    let miss = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_unknown"})),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(miss.source, SessionSource::None);
    assert!(miss.anchor.is_none(), "未命中 MUST NOT 设锚点");
    assert!(miss.canonical.is_none());
    assert_eq!(miss.log_source, SessionSource::None);

    // 未命中后继续第 ④ 级。
    let fallthrough = resolve_with(
        &HeaderMap::new(),
        Some(&json!({
            "previous_response_id": "resp_unknown",
            "prompt_cache_key": "pck",
        })),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(fallthrough.source, SessionSource::CacheKey);
    assert_eq!(
        fallthrough.anchor.as_ref().map(|a| a.value.as_str()),
        Some("pck")
    );
}

#[test]
fn previous_response_id_beats_prompt_cache_key_when_hit() {
    let alias = SessionAliasMap::new(8);
    let bound = scoped_key(SECRET, TENANT, "K1");
    alias.bind(SECRET, TENANT, "resp_1", &bound);
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&json!({
            "previous_response_id": "resp_1",
            "prompt_cache_key": "pck",
        })),
        Protocol::Responses,
        &alias,
    );
    assert_eq!(id.source, SessionSource::PrevResponse);
    assert_eq!(id.canonical, Some(bound), "③ 须优先于 ④");
}

#[test]
fn prompt_cache_key_valid_invalid_and_anthropic_excluded() {
    let alias = SessionAliasMap::new(8);
    for protocol in [Protocol::Chat, Protocol::Responses] {
        let id = resolve_with(
            &HeaderMap::new(),
            Some(&json!({"prompt_cache_key": "pck"})),
            protocol,
            &alias,
        );
        assert_eq!(id.source, SessionSource::CacheKey, "{protocol:?}");
        assert_eq!(id.canonical, Some(scoped_key(SECRET, TENANT, "pck")));
        assert_eq!(
            id.anchor.as_ref().map(|a| a.source),
            Some(AnchorSource::CacheKey)
        );
    }

    // 非法候选（超长/非可见 ASCII）→ 跳过。
    let long = "a".repeat(257);
    for bad in [long.as_str(), "pck\t", "会话"] {
        let id = resolve_with(
            &HeaderMap::new(),
            Some(&json!({"prompt_cache_key": bad})),
            Protocol::Chat,
            &alias,
        );
        assert_eq!(id.source, SessionSource::None, "{bad:?} 须跳过");
        assert!(id.canonical.is_none());
    }

    // Anthropic 不接受 prompt_cache_key / previous_response_id / conversation。
    let anthropic = json!({
        "prompt_cache_key": "pck",
        "previous_response_id": "resp_1",
        "conversation": "conv_1",
    });
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&anthropic),
        Protocol::Anthropic,
        &alias,
    );
    assert_eq!(
        id.source,
        SessionSource::None,
        "Anthropic MUST NOT 命中协议原生键"
    );
    assert!(id.anchor.is_none());
    assert!(id.canonical.is_none());
}

#[test]
fn stable_prefix_yields_canonical_without_source_or_log() {
    let alias = SessionAliasMap::new(8);
    let body = prefix_body();
    let id = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Chat, &alias);
    assert!(id.canonical.is_some(), "第 ⑤ 级须产出 PII 派生键");
    assert_eq!(
        id.canonical,
        stable_prefix_key(SECRET, TENANT, Protocol::Chat, &body)
    );
    assert!(id.anchor.is_none(), "稳定前缀 MUST NOT 产生锚点");
    assert_eq!(id.scope, SessionScope::Session);
    assert_eq!(id.source, SessionSource::None);
    assert_eq!(
        id.log_source,
        SessionSource::None,
        "稳定前缀级日志无会话来源"
    );
    assert_eq!(id.log_scope, SessionScope::None);
    assert!(id.log_user.is_none());
}

#[test]
fn previous_response_id_cross_tenant_does_not_resolve() {
    // 租户 A 的响应铸造 `response.id` 并写入其别名表；同一 `previous_response_id`
    // 出现在租户 B 的请求时因租户分域而未命中，继续下一优先级。
    let alias = SessionAliasMap::new(8);
    let tenant_a_key = scoped_key(SECRET, "tenant-a", "K1");
    alias.bind(SECRET, "tenant-a", "resp_1", &tenant_a_key);

    let foreign = resolve(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1"})),
        Protocol::Responses,
        &chain(),
        &alias,
        SECRET,
        "tenant-b",
    );
    assert_eq!(foreign.source, SessionSource::None, "跨租户 MUST NOT 命中");
    assert!(foreign.anchor.is_none());
    assert!(foreign.canonical.is_none());

    // 回落链路照常：同请求带 prompt_cache_key 时取 ④。
    let fallthrough = resolve(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1", "prompt_cache_key": "pck-b"})),
        Protocol::Responses,
        &chain(),
        &alias,
        SECRET,
        "tenant-b",
    );
    assert_eq!(fallthrough.source, SessionSource::CacheKey);
    assert_eq!(
        fallthrough.canonical,
        Some(scoped_key(SECRET, "tenant-b", "pck-b"))
    );
    // 另一把密钥同样分域。
    let other_secret = resolve(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1"})),
        Protocol::Responses,
        &chain(),
        &alias,
        b"another-secret",
        "tenant-a",
    );
    assert!(other_secret.canonical.is_none(), "跨密钥亦须分域");
}

#[test]
fn anthropic_diagnostics_previous_message_id_is_not_a_session_key() {
    // GA Messages 无会话锚点；该字段语义为缓存诊断、跨轮取值变化，MUST NOT 参与身份。
    let alias = SessionAliasMap::new(8);
    for body in [
        json!({"diagnostics": {"previous_message_id": "msg_prev_1"}, "messages": []}),
        json!({"diagnostics": {"previous_message_id": "msg_prev_1"}}),
    ] {
        let id = resolve_with(&HeaderMap::new(), Some(&body), Protocol::Anthropic, &alias);
        assert!(id.canonical.is_none(), "{body} MUST NOT 产生会话键");
        assert!(id.anchor.is_none());
        assert_eq!(id.source, SessionSource::None);
        assert_eq!(id.log_source, SessionSource::None, "不得记 prev_message");
        assert_eq!(id.log_scope, SessionScope::None);
    }
}

#[test]
fn no_source_yields_empty_identity() {
    let alias = SessionAliasMap::new(8);
    let id = resolve_with(
        &HeaderMap::new(),
        Some(&json!({"model": "m"})),
        Protocol::Chat,
        &alias,
    );
    assert!(id.anchor.is_none());
    assert!(id.canonical.is_none());
    assert_eq!(id.scope, SessionScope::None);
    assert_eq!(id.source, SessionSource::None);
    assert_eq!(id.log_source, SessionSource::None);
    assert_eq!(id.log_scope, SessionScope::None);
    assert!(id.log_user.is_none());
    assert!(!id.request_carried_conversation);

    // NonDialog/无正文：解析不得 panic，结果为空。
    let id = resolve_with(&HeaderMap::new(), None, Protocol::NonDialog, &alias);
    assert!(id.canonical.is_none());
    assert!(id.log_user.is_none());
}
