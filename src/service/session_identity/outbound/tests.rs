//! 出站标识测试（sibling，`session_identity/outbound.rs`）。

use {
    super::*,
    crate::service::{
        llm_gateway::Protocol,
        redaction::{SessionAliasMap, conversation_key::scoped_key},
    },
    axum::http::{HeaderMap, HeaderValue},
    serde_json::json,
};

const SECRET: &[u8] = b"outbound-secret";
const TENANT: &str = "tenant-fp";

fn resolve_header(value: &str) -> SessionIdentity {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id"
            .parse::<axum::http::HeaderName>()
            .expect("头名合法"),
        HeaderValue::from_str(value).expect("头值合法"),
    );
    super::super::resolve(
        &headers,
        Some(&json!({})),
        Protocol::Chat,
        &["x-veil-conversation-id".to_string()],
        &SessionAliasMap::new(8),
        SECRET,
        TENANT,
    )
}

fn resolve_conversation(conv_id: &str, alias: &SessionAliasMap) -> SessionIdentity {
    super::super::resolve(
        &HeaderMap::new(),
        Some(&json!({"conversation": conv_id})),
        Protocol::Responses,
        &["x-veil-conversation-id".to_string()],
        alias,
        SECRET,
        TENANT,
    )
}

#[test]
fn header_anchor_yields_client_value() {
    let identity = resolve_header("sess-1");
    assert_eq!(
        outbound_id(&identity, SECRET),
        Some(OutboundId::Client("sess-1".to_string()))
    );
}

#[test]
fn cache_key_anchor_yields_client_value() {
    let identity = super::super::resolve(
        &HeaderMap::new(),
        Some(&json!({"prompt_cache_key": "pck"})),
        Protocol::Chat,
        &["x-veil-conversation-id".to_string()],
        &SessionAliasMap::new(8),
        SECRET,
        TENANT,
    );
    assert_eq!(
        outbound_id(&identity, SECRET),
        Some(OutboundId::Client("pck".to_string()))
    );
}

#[test]
fn conversation_anchor_yields_server_hmac_not_canonical_nor_raw() {
    let identity = resolve_conversation("conv_1", &SessionAliasMap::new(8));
    let outbound = outbound_id(&identity, SECRET).expect("须有出站标识");
    let value = outbound.as_str();
    assert!(outbound.is_server_hmac());
    assert_ne!(value, "conv_1", "MUST NOT 等于上游 id 原值");
    let canonical = identity.canonical.as_ref().expect("canonical");
    assert_ne!(value, canonical.as_str(), "MUST NOT 等于 ConversationKey");
    assert_eq!(value.len(), 64, "HMAC-SHA256 hex");
}

#[test]
fn previous_response_anchor_yields_server_hmac() {
    let alias = SessionAliasMap::new(8);
    let bound = scoped_key(SECRET, TENANT, "K1");
    alias.bind(SECRET, TENANT, "resp_1", &bound);
    let identity = super::super::resolve(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1"})),
        Protocol::Responses,
        &["x-veil-conversation-id".to_string()],
        &alias,
        SECRET,
        TENANT,
    );
    let outbound = outbound_id(&identity, SECRET).expect("须有出站标识");
    assert!(outbound.is_server_hmac());
    assert_ne!(outbound.as_str(), "resp_1");
    assert_ne!(outbound.as_str(), bound.as_str());
}

#[test]
fn no_anchor_returns_none() {
    // 空头 + 无其它锚点 → None。
    let identity = resolve_header("");
    assert!(identity.anchor.is_none());
    assert_eq!(outbound_id(&identity, SECRET), None);

    // 仅稳定前缀 → 无锚点 → None。
    let identity = super::super::resolve(
        &HeaderMap::new(),
        Some(&json!({
            "tools": [{"name": "t"}],
            "messages": [
                {"role": "system", "content": "s"},
                {"role": "user", "content": "u"}
            ],
        })),
        Protocol::Chat,
        &["x-veil-conversation-id".to_string()],
        &SessionAliasMap::new(8),
        SECRET,
        TENANT,
    );
    assert!(identity.canonical.is_some());
    assert_eq!(outbound_id(&identity, SECRET), None);
}

#[test]
fn source_switch_changes_outbound_value() {
    let alias = SessionAliasMap::new(8);
    let bound = scoped_key(SECRET, TENANT, "K1");
    alias.bind(SECRET, TENANT, "conv_1", &bound);
    let header_identity = resolve_header("H");
    let conv_identity = resolve_conversation("conv_1", &alias);
    let header_out = outbound_id(&header_identity, SECRET);
    let conv_out = outbound_id(&conv_identity, SECRET);
    assert_eq!(
        header_out,
        Some(OutboundId::Client("H".to_string())),
        "头来源为客户端原值"
    );
    assert!(
        conv_out
            .as_ref()
            .is_some_and(|value| value.is_server_hmac()),
        "源切换后按新来源变化"
    );
    assert_ne!(
        header_out.as_ref().map(|v| v.as_str()),
        conv_out.as_ref().map(|v| v.as_str())
    );
}

#[test]
fn outbound_is_tenant_scoped() {
    let make = |tenant: &str| {
        super::super::resolve(
            &HeaderMap::new(),
            Some(&json!({"conversation": "conv_1"})),
            Protocol::Responses,
            &["x-veil-conversation-id".to_string()],
            &SessionAliasMap::new(8),
            SECRET,
            tenant,
        )
    };
    let a = outbound_id(&make("tenant-a"), SECRET).expect("A");
    let b = outbound_id(&make("tenant-b"), SECRET).expect("B");
    assert_ne!(a.as_str(), b.as_str(), "租户指纹参与出站 HMAC");
}
