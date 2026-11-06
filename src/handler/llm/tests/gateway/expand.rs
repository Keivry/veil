//! `$conversation` 出站标识展开与 `session_outbound_hmac` 计数的直接用例
//! （tasks 4.4；HTTP 级三路径用例见 `dispatch/tests/expand.rs`）。

use {
    super::super::super::{
        HeaderValueSegment,
        HeaderValueSpec,
        UpstreamOverrides,
        forward_headers,
    },
    crate::{
        handler::llm::test_support::{expand_ctx, expand_ctx_with},
        service::{llm_gateway::GatewayMetrics, session_identity::OutboundId},
    },
    axum::http::{HeaderMap, HeaderValue},
};

#[test]
fn forward_headers_template_empty_source_skips_conversation_entry() {
    // spec「来源头存在但值为空照常注入」已按本 change 反转：空会话头不产生锚点，
    // `$conversation` 视为来源缺失并跳过该条目（不注入空值、不生成随机标识）。
    let metrics = GatewayMetrics::default();
    let mut inbound = HeaderMap::new();
    inbound.insert("x-veil-conversation-id", HeaderValue::from_static(""));
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-opencode-session"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
    );
    overrides.headers.insert(
        "x-prefixed"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![
            HeaderValueSegment::Literal("pre-".to_string()),
            HeaderValueSegment::Conversation,
        ]),
    );
    let fwd = forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx(&inbound),
    );
    assert!(
        fwd.get("x-opencode-session").is_none(),
        "无锚点须跳过，不得注入空值"
    );
    assert!(
        fwd.get("x-prefixed").is_none(),
        "含字面段亦整条跳过（不产生半截值）"
    );
    assert_eq!(metrics.session_outbound_hmac_count(), 0, "跳过不计数");
}

#[test]
fn forward_headers_template_empty_mirror_source_still_injects_empty_value() {
    // `$header` 镜像语义零变化：入站头存在但值为空时照常注入空值。
    let metrics = GatewayMetrics::default();
    let mut inbound = HeaderMap::new();
    inbound.insert("x-empty-src", HeaderValue::from_static(""));
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-mirror-empty"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(
            axum::http::HeaderName::from_static("x-empty-src"),
        )]),
    );
    let fwd = forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx(&inbound),
    );
    assert_eq!(
        fwd.get("x-mirror-empty").and_then(|v| v.to_str().ok()),
        Some(""),
        "$header 空值仍照常注入"
    );
}

#[test]
fn forward_headers_conversation_server_hmac_expands_and_counts_once_per_segment() {
    // design D5：服务端锚点展开为域分离 HMAC；一个值内多个 `$conversation` 段逐段计数。
    let metrics = GatewayMetrics::default();
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-conv-single"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
    );
    overrides.headers.insert(
        "x-conv-double"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![
            HeaderValueSegment::Conversation,
            HeaderValueSegment::Literal("-".to_string()),
            HeaderValueSegment::Conversation,
        ]),
    );
    let fwd = forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx_with(
            &HeaderMap::new(),
            Some(OutboundId::ServerHmac("hmac-value".to_string())),
        ),
    );
    assert_eq!(
        fwd.get("x-conv-single").and_then(|v| v.to_str().ok()),
        Some("hmac-value")
    );
    assert_eq!(
        fwd.get("x-conv-double").and_then(|v| v.to_str().ok()),
        Some("hmac-value-hmac-value")
    );
    assert_eq!(
        metrics.session_outbound_hmac_count(),
        3,
        "单段 1 次 + 双段 2 次，逐段计数"
    );
}

#[test]
fn forward_headers_conversation_client_value_does_not_count() {
    // 客户端原值展开不计数；`$header` 镜像也不计数。
    let metrics = GatewayMetrics::default();
    let mut inbound = HeaderMap::new();
    inbound.insert("x-src", HeaderValue::from_static("mirrored"));
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-conv"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
    );
    overrides.headers.insert(
        "x-mirror"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(
            axum::http::HeaderName::from_static("x-src"),
        )]),
    );
    let fwd = forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx_with(
            &inbound,
            Some(OutboundId::Client("client-anchor".to_string())),
        ),
    );
    assert_eq!(
        fwd.get("x-conv").and_then(|v| v.to_str().ok()),
        Some("client-anchor")
    );
    assert_eq!(
        metrics.session_outbound_hmac_count(),
        0,
        "客户端原值与镜像均不计数"
    );
}

#[test]
fn outbound_id_is_source_driven_and_differs_from_conversation_key() {
    // 头锚点 → 原值；conversation 锚点 → 域分离 HMAC，且 ≠ 原 id、≠ ConversationKey。
    use crate::service::{
        redaction::conversation_key::scoped_key,
        session_identity::{
            AnchorSource,
            SessionAnchor,
            SessionIdentity,
            SessionScope,
            SessionSource,
            outbound_id,
        },
    };
    const SECRET: &[u8] = b"outbound-secret";
    const TENANT: &str = "tenant-fp";
    let identity = |source: AnchorSource, value: &str, log_source: SessionSource| SessionIdentity {
        anchor: Some(SessionAnchor {
            value: value.to_string(),
            source,
        }),
        canonical: Some(scoped_key(SECRET, TENANT, value)),
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::Session,
        source: log_source,
        log_source,
        log_scope: SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let from_header = outbound_id(
        &identity(AnchorSource::Header, "sess-1", SessionSource::Header),
        SECRET,
    );
    assert_eq!(from_header, Some(OutboundId::Client("sess-1".to_string())));

    let from_conversation = outbound_id(
        &identity(
            AnchorSource::Conversation,
            "conv_1",
            SessionSource::Conversation,
        ),
        SECRET,
    );
    let emitted = match &from_conversation {
        Some(OutboundId::ServerHmac(value)) => value.clone(),
        other => panic!("conversation 锚点须为服务端 HMAC: {other:?}"),
    };
    assert_ne!(emitted, "conv_1", "不得输出上游 id 原值");
    let conversation_key = scoped_key(SECRET, TENANT, "conv_1");
    assert_ne!(
        emitted,
        conversation_key.as_str(),
        "出站标识不得等于 PII 会话键"
    );
    assert_ne!(
        from_header, from_conversation,
        "来源切换（header→conversation）须改变出站值"
    );
}

#[test]
fn outbound_id_none_without_anchor_or_secret_derives_nothing() {
    // 无锚点（含空头、仅稳定前缀）→ 跳过注入。
    use crate::service::{
        redaction::ConversationKey,
        session_identity::{SessionIdentity, SessionScope, SessionSource, outbound_id},
    };
    let identity = SessionIdentity {
        anchor: None,
        canonical: Some(ConversationKey::for_test(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: SessionScope::Session,
        source: SessionSource::None,
        log_source: SessionSource::None,
        log_scope: SessionScope::None,
        log_user: None,
        request_carried_conversation: false,
    };
    assert!(
        outbound_id(&identity, b"outbound-secret").is_none(),
        "无锚点须返回 None（不生成随机值）"
    );
}
