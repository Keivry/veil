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
