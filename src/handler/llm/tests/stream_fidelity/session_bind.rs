//! 流式透传路径的会话捕获与别名绑定用例（tasks 3.2/4.1 Verify）。
//!
//! 自 `stream_fidelity.rs` 拆出（测试文件行数红线），语义与断言不变。

use {
    super::loopback_server_with_headers,
    crate::service::{
        llm_gateway::{GatewayMetrics, Protocol},
        redaction::Scope,
    },
    axum::http::StatusCode,
    std::sync::Arc,
};

/// 会话级作用域（canonical 存在 → 挂写回且 `conversation_scope = true`）。
fn conversation_scope_with_alias(
    secret: &'static [u8],
    alias: Arc<crate::service::redaction::session_alias::SessionAliasMap>,
) -> (Arc<Scope>, crate::service::redaction::ConversationKey) {
    use crate::service::session_identity::{
        AnchorSource,
        SessionAnchor,
        SessionIdentity,
        SessionScope,
        SessionSource,
    };
    let canonical = crate::service::redaction::scoped_key(secret, "tenant-fp", "anchor-1");
    let identity = SessionIdentity {
        anchor: Some(SessionAnchor {
            value: "anchor-1".to_string(),
            source: AnchorSource::Header,
        }),
        canonical: Some(canonical.clone()),
        tenant_fingerprint: "tenant-fp".to_string(),
        scope: SessionScope::Session,
        source: SessionSource::Header,
        log_source: SessionSource::Header,
        log_scope: SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    };
    let writeback = crate::service::redaction::writeback::ConversationWriteback::new(
        identity,
        Arc::<[u8]>::from(secret),
        alias,
    );
    (
        Arc::new(Scope::with_opts(false).with_conversation(writeback, true)),
        canonical,
    )
}

#[tokio::test]
async fn stream_passthrough_responses_json_binds_and_keeps_bytes() {
    // tasks 3.2/4.1 Verify：`stream:true` 但上游回 2xx JSON 时，
    // `stream_upstream_passthrough` 须实际捕获并绑定 `response.id`/`conversation.id`，
    // 同时下游收到的字节须逐字节一致（字节保真）。
    const SECRET: &[u8] = b"passthrough-bind-secret";
    let body =
        br#"{"id":"resp_pt_1","conversation":{"id":"conv_pt_1"},"status":"completed","output":[]}"#
            .to_vec();
    let (url, server) =
        loopback_server_with_headers(200, "application/json", vec![], body.clone()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let metrics = GatewayMetrics::default();
    let alias = Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8));
    let (scope, canonical) = conversation_scope_with_alias(SECRET, alias.clone());

    let resp = crate::handler::llm::dispatch::stream_upstream_passthrough(
        upstream,
        false,
        Protocol::Responses,
        4096,
        &metrics,
        scope.as_ref(),
    )
    .await;
    let status = resp.status();
    let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("下游体须可读")
        .to_vec();
    server.abort();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(got, body, "透传路径 MUST 保字节");
    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "resp_pt_1"),
        Some(canonical.clone()),
        "2xx JSON 的 response.id 须实际绑定（不得解析后丢弃）"
    );
    assert_eq!(
        alias.resolve(SECRET, "tenant-fp", "conv_pt_1"),
        Some(canonical),
        "请求未携带 conversation 时响应 conversation.id 亦须绑定"
    );
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(metrics.session_bind_miss_count(), 0);
}

#[tokio::test]
async fn stream_passthrough_error_body_never_binds() {
    // 4xx/5xx 错误体即使含顶层 `id`/`error.id` 也 MUST NOT 绑定或计数。
    const SECRET: &[u8] = b"passthrough-bind-secret";
    let body = br#"{"id":"resp_err","error":{"id":"err_1","message":"boom"}}"#.to_vec();
    let (url, server) =
        loopback_server_with_headers(500, "application/json", vec![], body.clone()).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let metrics = GatewayMetrics::default();
    let alias = Arc::new(crate::service::redaction::session_alias::SessionAliasMap::new(8));
    let (scope, _canonical) = conversation_scope_with_alias(SECRET, alias.clone());

    let resp = crate::handler::llm::dispatch::stream_upstream_passthrough(
        upstream,
        false,
        Protocol::Responses,
        4096,
        &metrics,
        scope.as_ref(),
    )
    .await;
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("下游体须可读");
    server.abort();

    assert!(alias.is_empty(), "错误响应 MUST NOT 写入别名");
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(metrics.session_bind_miss_count(), 0);
}
