//! 九档优先级、摘要稳定性与跨域分离断言。

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("session.rs", include_str!("../session.rs"));
    crate::test_support::file_len_under_800_or_split("session/tests.rs", include_str!("tests.rs"));
}

use super::*;

const KEY: &[u8] = b"test-hmac-key";

fn all_inputs() -> SessionInputs<'static> {
    SessionInputs {
        header: Some("hdr"),
        conversation: Some("conv"),
        previous_response_id: Some("resp_1"),
        previous_message_id: Some("msg_1"),
        prompt_cache_key: Some("cache-1"),
        metadata_user_id: Some("user-1"),
        safety_identifier: Some("safe-1"),
        user: Some("end-user"),
    }
}

#[test]
fn ladder_picks_first_present_in_order() {
    let cases = [
        (
            SessionInputs {
                header: Some("hdr"),
                ..all_inputs()
            },
            SessionSource::Header,
            SessionScope::Session,
        ),
        (
            SessionInputs {
                header: None,
                ..all_inputs()
            },
            SessionSource::Conversation,
            SessionScope::Session,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                ..all_inputs()
            },
            SessionSource::PrevResponse,
            SessionScope::Session,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                previous_response_id: None,
                ..all_inputs()
            },
            SessionSource::PrevMessage,
            SessionScope::Session,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                previous_response_id: None,
                previous_message_id: None,
                ..all_inputs()
            },
            SessionSource::CacheKey,
            SessionScope::Session,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                previous_response_id: None,
                previous_message_id: None,
                prompt_cache_key: None,
                ..all_inputs()
            },
            SessionSource::UserId,
            SessionScope::User,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                previous_response_id: None,
                previous_message_id: None,
                prompt_cache_key: None,
                metadata_user_id: None,
                ..all_inputs()
            },
            SessionSource::SafetyIdentifier,
            SessionScope::User,
        ),
        (
            SessionInputs {
                header: None,
                conversation: None,
                previous_response_id: None,
                previous_message_id: None,
                prompt_cache_key: None,
                metadata_user_id: None,
                safety_identifier: None,
                ..all_inputs()
            },
            SessionSource::User,
            SessionScope::User,
        ),
    ];
    for (inputs, source, scope) in cases {
        let (id, got_source, got_scope) = derive_session(&inputs, Some(KEY), "chat")
            .unwrap_or_else(|| panic!("{source:?} 应产出示会话摘要"));
        assert_eq!((got_source, got_scope), (source, scope), "{source:?}");
        assert_eq!(id.len(), SESSION_ID_HEX_LEN);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}

#[test]
fn ninth_rung_is_none_without_any_identifier() {
    let inputs = SessionInputs::default();
    assert!(inputs.priority().is_none());
    assert!(derive_session(&inputs, Some(KEY), "chat").is_none());
}

#[test]
fn empty_values_are_treated_as_absent() {
    let inputs = SessionInputs {
        header: Some(""),
        user: Some("end-user"),
        ..SessionInputs::default()
    };
    let (_, source, scope) = derive_session(&inputs, Some(KEY), "chat").expect("回落到 user 档");
    assert_eq!((source, scope), (SessionSource::User, SessionScope::User));
}

#[test]
fn missing_key_yields_none_even_with_identifiers() {
    assert!(derive_session(&all_inputs(), None, "chat").is_none());
    assert!(derive_session(&all_inputs(), Some(&[]), "chat").is_none());
}

#[test]
fn digest_is_stable_and_protocol_scoped() {
    let a = derive_session(&all_inputs(), Some(KEY), "chat").expect("摘要");
    let b = derive_session(&all_inputs(), Some(KEY), "chat").expect("摘要");
    assert_eq!(a, b, "同输入须稳定");
    let other_proto = derive_session(&all_inputs(), Some(KEY), "anthropic").expect("摘要");
    assert_ne!(a.0, other_proto.0, "跨协议摘要须不同");
    let other_key = derive_session(&all_inputs(), Some(b"other-key"), "chat").expect("摘要");
    assert_ne!(a.0, other_key.0, "跨密钥摘要须不同");
}

#[test]
fn digest_differs_from_conversation_scoped_key() {
    use crate::service::redaction::conversation_key::scoped_key;
    let inputs = SessionInputs {
        header: Some("conv-raw"),
        ..SessionInputs::default()
    };
    let (session_id, ..) = derive_session(&inputs, Some(KEY), "chat").expect("摘要");
    let conversation = scoped_key(KEY, "", "conv-raw");
    assert_ne!(session_id, conversation.as_str()[..SESSION_ID_HEX_LEN]);
}

/// tasks 2.3：`conversation` 的字符串与 `{id}` 对象两种形态经生产折算路径
/// （`RequestTrace::attach_identity`）派生出同一会话标识，来源均为 `Conversation`。
#[test]
fn conversation_string_and_object_forms_derive_same_session() {
    use crate::{
        handler::llm::{test_support::test_config, trace::RequestTrace},
        service::llm_gateway::Protocol,
    };
    let config = test_config(&[("PII_VALUE_SAMPLE_HMAC_KEY", "session-test-key")]);
    let headers = axum::http::HeaderMap::new();
    let derive_from = |body: &serde_json::Value| {
        let mut trace = RequestTrace::new(
            "req-conv-shape".to_string(),
            Protocol::Responses,
            Some(8877),
            true,
            std::time::Instant::now(),
        );
        trace.attach_identity(Some(body), &headers, &config);
        let row = trace.into_row();
        (row.session_id, row.session_source, row.session_scope)
    };
    let from_string = derive_from(&serde_json::json!({
        "model": "m",
        "conversation": "conv_x",
        "input": "hi",
    }));
    let from_object = derive_from(&serde_json::json!({
        "model": "m",
        "conversation": {"id": "conv_x"},
        "input": "hi",
    }));
    assert!(
        from_string.0.is_some(),
        "字符串形态须派生会话: {from_string:?}"
    );
    assert_eq!(
        from_string.0, from_object.0,
        "字符串与对象形态须派生同一会话标识"
    );
    for (id, source, scope) in [&from_string, &from_object] {
        assert_eq!(source, &SessionSource::Conversation.as_str().to_string());
        assert_eq!(scope, &SessionScope::Session.as_str().to_string());
        assert_eq!(id.as_deref().map(str::len), Some(SESSION_ID_HEX_LEN));
    }
}

#[test]
fn source_and_scope_labels_are_stable() {
    assert_eq!(SessionSource::None.as_str(), "none");
    assert_eq!(SessionSource::PrevMessage.as_str(), "prev_message");
    assert_eq!(SessionScope::None.as_str(), "none");
    assert_eq!(SessionScope::User.as_str(), "user");
    assert!(SessionSource::PrevResponse.is_chain());
    assert!(!SessionSource::CacheKey.is_chain());
}

/// D1：非 `opencode*` provider 只发 `x-opencode-session-id`，配置头缺席时
/// 须经回退链命中，来源仍为 `Header`。
#[test]
fn fallback_header_derives_session_when_configured_header_absent() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-opencode-session-id",
        axum::http::HeaderValue::from_static("ses_fallback_1"),
    );
    let resolved = resolve_session_header(&headers, "x-veil-conversation-id");
    assert_eq!(resolved, Some("ses_fallback_1"));

    let inputs = SessionInputs {
        header: resolved,
        ..SessionInputs::default()
    };
    let (id, source, scope) = derive_session(&inputs, Some(KEY), "chat").expect("须派生会话摘要");
    assert_eq!(
        (source, scope),
        (SessionSource::Header, SessionScope::Session)
    );
    assert_eq!(id.len(), SESSION_ID_HEX_LEN);
}

/// 配置头仍最高优先：两者同时存在时取配置头。
#[test]
fn configured_header_wins_over_fallback_headers() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        axum::http::HeaderValue::from_static("from-configured"),
    );
    headers.insert(
        "x-opencode-session-id",
        axum::http::HeaderValue::from_static("from-fallback"),
    );
    assert_eq!(
        resolve_session_header(&headers, "x-veil-conversation-id"),
        Some("from-configured")
    );
}

/// 空串不算命中：配置头为空时继续向下取回退头。
#[test]
fn empty_header_value_is_skipped_in_favour_of_next_candidate() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        axum::http::HeaderValue::from_static(""),
    );
    headers.insert(
        "x-opencode-session",
        axum::http::HeaderValue::from_static(""),
    );
    headers.insert(
        "x-session-affinity",
        axum::http::HeaderValue::from_static("affinity-1"),
    );
    assert_eq!(
        resolve_session_header(&headers, "x-veil-conversation-id"),
        Some("affinity-1")
    );
}

/// 回退链顺序固定：`x-opencode-session` 先于 `x-opencode-session-id`，
/// 再先于 `x-opencode-parent-session-id`、`x-session-affinity`、`x-session-id`。
#[test]
fn fallback_chain_order_is_fixed() {
    let names: Vec<&str> = [
        "x-opencode-session",
        "x-opencode-session-id",
        "x-opencode-parent-session-id",
        "x-session-affinity",
        "x-session-id",
    ]
    .to_vec();
    assert_eq!(SESSION_HEADER_FALLBACKS, names.as_slice());
    for (idx, name) in names.iter().enumerate() {
        let mut headers = axum::http::HeaderMap::new();
        for later in &names[idx..] {
            headers.insert(*later, axum::http::HeaderValue::from_static("v"));
        }
        assert_eq!(
            resolve_session_header(&headers, "x-veil-conversation-id"),
            Some("v"),
            "第 {idx} 项 {name} 须先命中"
        );
    }
}

/// 遥测链仍认基础设施头：`x-opencode-parent-session-id` 与 `x-session-affinity`
/// 在日志口径下仍是合法会话来源。
#[test]
fn telemetry_chain_still_accepts_parent_and_affinity_headers() {
    for name in ["x-opencode-parent-session-id", "x-session-affinity"] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(name, axum::http::HeaderValue::from_static("infra-1"));
        assert_eq!(
            resolve_session_header(&headers, "x-veil-conversation-id"),
            Some("infra-1"),
            "遥测链须命中 {name}"
        );
        assert_eq!(
            resolve_pii_scope_header(&headers, "x-veil-conversation-id"),
            None,
            "PII 链 MUST NOT 接受 {name}（隔离边界）"
        );
    }
}

/// PII 链刻意窄：仅 `x-opencode-session` / `x-opencode-session-id` 两个回退头。
#[test]
fn pii_scope_chain_excludes_infra_and_generic_headers() {
    assert_eq!(
        PII_SCOPE_HEADER_FALLBACKS,
        ["x-opencode-session", "x-opencode-session-id"]
    );
    for name in [
        "x-opencode-parent-session-id",
        "x-session-affinity",
        "x-session-id",
        "X-Session-Id",
    ] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(name, axum::http::HeaderValue::from_static("v"));
        assert_eq!(
            resolve_pii_scope_header(&headers, "x-veil-conversation-id"),
            None,
            "PII 链 MUST NOT 接受 {name}"
        );
    }
    for name in ["x-opencode-session", "x-opencode-session-id"] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(name, axum::http::HeaderValue::from_static("v"));
        assert_eq!(
            resolve_pii_scope_header(&headers, "x-veil-conversation-id"),
            Some("v"),
            "PII 链须接受 {name}"
        );
    }
}

/// PII 链的配置头仍最高优先，且空串/非 UTF-8 值照旧跳过。
#[test]
fn pii_scope_chain_configured_header_wins_and_skips_invalid() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        axum::http::HeaderValue::from_static("from-configured"),
    );
    headers.insert(
        "x-opencode-session",
        axum::http::HeaderValue::from_static("from-opencode"),
    );
    assert_eq!(
        resolve_pii_scope_header(&headers, "x-veil-conversation-id"),
        Some("from-configured"),
        "配置头须胜出"
    );

    let mut empty = axum::http::HeaderMap::new();
    empty.insert(
        "x-veil-conversation-id",
        axum::http::HeaderValue::from_static(""),
    );
    empty.insert(
        "x-opencode-session",
        axum::http::HeaderValue::from_static(""),
    );
    assert_eq!(
        resolve_pii_scope_header(&empty, "x-veil-conversation-id"),
        None,
        "空串须全部跳过"
    );

    let mut bad = axum::http::HeaderMap::new();
    bad.insert(
        "x-opencode-session-id",
        axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).expect("原始字节头值"),
    );
    assert_eq!(
        resolve_pii_scope_header(&bad, "x-veil-conversation-id"),
        None,
        "非 UTF-8 值须跳过"
    );
}

/// 告警定位：配置头缺席时须指名真正被拒的回退头。
#[test]
fn pii_scope_header_name_points_at_rejected_header() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-opencode-session-id",
        axum::http::HeaderValue::from_static("v"),
    );
    assert_eq!(
        pii_scope_header_name(&headers, "x-veil-conversation-id"),
        Some("x-opencode-session-id"),
        "须指回退头而非配置头名"
    );
    assert!(pii_scope_header_present(&headers, "x-veil-conversation-id"));
    let mut only_infra = axum::http::HeaderMap::new();
    only_infra.insert(
        "x-session-affinity",
        axum::http::HeaderValue::from_static("v"),
    );
    assert!(
        !pii_scope_header_present(&only_infra, "x-veil-conversation-id"),
        "仅遥测链头存在时不算 PII 键头存在"
    );
}
