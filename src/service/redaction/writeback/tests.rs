//! 响应写回与捕获计数测试（sibling，`redaction/writeback.rs`）。
//!
//! 覆盖 tasks 3.3 Verify：`response.id` 恒绑定、`conversation.id` 仅在未携带
//! `conversation` 时绑定、无 canonical 不绑定、每响应至多一次且互斥的 miss 计数、
//! Chat/Anthropic/4xx/5xx 不计数。

use {
    super::*,
    crate::service::{
        llm_gateway::GatewayMetrics,
        redaction::{
            Scope,
            SessionAliasMap,
            conversation_key::scoped_key,
            session_alias::BindOutcome,
        },
        session_identity::{AnchorSource, SessionAnchor, SessionScope, SessionSource},
    },
    serde_json::json,
    std::sync::Arc,
};

const SECRET: &[u8] = b"writeback-test-secret";
const TENANT: &str = "tenant-fp";

/// 构造仅含必要字段的解析结果（其余字段取无来源默认值）。
fn identity_with_canonical(carried: bool) -> SessionIdentity {
    SessionIdentity {
        anchor: Some(SessionAnchor {
            value: "anchor-1".to_string(),
            source: AnchorSource::Header,
        }),
        canonical: Some(scoped_key(SECRET, TENANT, "anchor-1")),
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::Session,
        source: SessionSource::Header,
        log_source: SessionSource::Header,
        log_scope: SessionScope::Session,
        log_user: None,
        request_carried_conversation: carried,
    }
}

fn identity_without_canonical() -> SessionIdentity {
    SessionIdentity {
        anchor: None,
        canonical: None,
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::None,
        source: SessionSource::None,
        log_source: SessionSource::None,
        log_scope: SessionScope::None,
        log_user: None,
        request_carried_conversation: false,
    }
}

fn writeback(carried: bool, alias: &Arc<SessionAliasMap>) -> ConversationWriteback {
    ConversationWriteback::new(
        identity_with_canonical(carried),
        Arc::<[u8]>::from(SECRET),
        Arc::clone(alias),
    )
}

#[test]
fn writeback_binds_response_and_new_conversation_ids() {
    // 请求未携带 `conversation`：响应新出现的 `conversation.id` 也写入别名。
    let alias = Arc::new(SessionAliasMap::new(8));
    let wb = writeback(false, &alias);
    let canonical = scoped_key(SECRET, TENANT, "anchor-1");
    wb.record(&CapturedIds {
        response_id: Some("resp_1".to_string()),
        conversation_id: Some("conv_1".to_string()),
    });
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_1"),
        Some(canonical.clone())
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_1"),
        Some(canonical),
        "请求未携带 conversation 时响应 conversation.id 须绑定"
    );
}

#[test]
fn writeback_skips_client_supplied_conversation_id() {
    // 请求自带 `conversation`：只绑定 `response.id`，客户端提供的 id 不被抢先绑定。
    let alias = Arc::new(SessionAliasMap::new(8));
    let wb = writeback(true, &alias);
    let canonical = scoped_key(SECRET, TENANT, "anchor-1");
    wb.record(&CapturedIds {
        response_id: Some("resp_x".to_string()),
        conversation_id: Some("conv_client".to_string()),
    });
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_x"),
        Some(canonical),
        "response.id 恒可绑定"
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_client"),
        None,
        "客户端提供的 conversation.id MUST NOT 写入别名"
    );
}

#[test]
fn writeback_without_canonical_is_noop() {
    let alias = Arc::new(SessionAliasMap::new(8));
    let wb = ConversationWriteback::new(
        identity_without_canonical(),
        Arc::<[u8]>::from(SECRET),
        Arc::clone(&alias),
    );
    wb.record(&CapturedIds {
        response_id: Some("resp_1".to_string()),
        conversation_id: Some("conv_1".to_string()),
    });
    assert!(alias.is_empty(), "无 canonical 时 MUST NOT 绑定");
}

#[test]
fn writeback_debug_redacts_all_sensitive_fields() {
    let alias = Arc::new(SessionAliasMap::new(8));
    let wb = writeback(false, &alias);
    let debug = format!("{wb:?}");
    assert!(!debug.contains("anchor-1"), "不得泄漏锚点原值: {debug}");
    assert!(!debug.contains(TENANT), "不得泄漏租户指纹: {debug}");
    assert!(!debug.contains("resp_1"), "不得泄漏上游 id: {debug}");
    assert!(
        !debug.contains(scoped_key(SECRET, TENANT, "anchor-1").as_str()),
        "不得泄漏会话键: {debug}"
    );
    assert!(debug.contains("[redacted]"), "须显式标注已脱敏: {debug}");
}

/// 会话级作用域 Scope（`conversation` 模式）：挂写回且 `conversation_scope = true`。
fn conversation_scope_scope(alias: &Arc<SessionAliasMap>, carried: bool) -> Scope {
    Scope::with_opts(false).with_conversation(writeback(carried, alias), true)
}

/// `request` 模式 Scope：挂写回但 `conversation_scope = false`。
fn request_mode_scope(alias: &Arc<SessionAliasMap>) -> Scope {
    Scope::with_opts(false).with_conversation(writeback(false, alias), false)
}

#[test]
fn tracker_counts_writeback_miss_once_for_conversation_scope() {
    let alias = Arc::new(SessionAliasMap::new(8));
    let scope = conversation_scope_scope(&alias, false);
    let metrics = GatewayMetrics::default();
    let mut tracker = CaptureTracker::default();

    // Responses 2xx 但响应体无 id → 计一次写回失败。
    let body = json!({"status": "completed", "output": []});
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    assert_eq!(metrics.conversation_writeback_miss_count(), 1);
    // 重复帧/重复调用不得多计。
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    tracker.finish(&scope, Protocol::Responses, 200, &metrics);
    assert_eq!(metrics.conversation_writeback_miss_count(), 1);
    assert_eq!(metrics.session_bind_miss_count(), 0, "二者 MUST NOT 双计");
}

#[test]
fn tracker_request_mode_never_counts_writeback_miss() {
    // `request` 模式挂载写回后，`conversation_writeback_miss` 仍须以
    // `has_conversation_scope` 门控（不许因 writeback 存在而开始计数）。
    let alias = Arc::new(SessionAliasMap::new(8));
    let scope = request_mode_scope(&alias);
    assert!(scope.has_writeback(), "request 模式 canonical 存在须挂写回");
    assert!(!scope.has_conversation_scope());
    let metrics = GatewayMetrics::default();
    let mut tracker = CaptureTracker::default();
    let body = json!({"status": "completed"});
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(metrics.session_bind_miss_count(), 0);
}

#[test]
fn tracker_counts_bind_miss_once_without_writeback() {
    // 无 canonical（无写回上下文）但响应可捕获 id → 每响应至多一次 bind miss。
    let scope = Scope::with_opts(false);
    let metrics = GatewayMetrics::default();
    let mut tracker = CaptureTracker::default();
    let body = json!({"id": "resp_1", "conversation": {"id": "conv_1"}});
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    tracker.finish(&scope, Protocol::Responses, 200, &metrics);
    assert_eq!(metrics.session_bind_miss_count(), 1);
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
}

#[test]
fn tracker_writeback_miss_takes_priority_over_bind_miss() {
    // 会话级作用域（已有 canonical/写回）但响应缺 `response.id`：写回失败先占，
    // 即便捕获到 `conversation.id`（`captured_any == true`）也不得再计 bind miss。
    let alias = Arc::new(SessionAliasMap::new(8));
    let scope = conversation_scope_scope(&alias, false);
    let metrics = GatewayMetrics::default();
    let mut tracker = CaptureTracker::default();
    // `conversation.id` 可捕获，`response.id` 缺失。
    let body = json!({"conversation": {"id": "conv_1"}});
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);
    assert_eq!(metrics.conversation_writeback_miss_count(), 1);
    assert_eq!(metrics.session_bind_miss_count(), 0, "二者 MUST NOT 双计");
    // 可捕获的 `conversation.id` 仍按请求未携带 conversation 绑定。
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_1"),
        Some(scoped_key(SECRET, TENANT, "anchor-1"))
    );
}

#[test]
fn tracker_never_counts_for_non_responses_or_error_status() {
    let alias = Arc::new(SessionAliasMap::new(8));
    // ① Chat/Anthropic：即便 2xx 缺 id 也不计数。
    for protocol in [Protocol::Chat, Protocol::Anthropic] {
        let scope = conversation_scope_scope(&alias, false);
        let metrics = GatewayMetrics::default();
        let mut tracker = CaptureTracker::default();
        tracker.observe(&scope, protocol, 200, &json!({"x": 1}), &metrics);
        tracker.finish(&scope, protocol, 200, &metrics);
        assert_eq!(
            metrics.conversation_writeback_miss_count(),
            0,
            "{protocol:?} MUST NOT 计入"
        );
        assert_eq!(metrics.session_bind_miss_count(), 0, "{protocol:?}");
    }
    // ② Responses 4xx/5xx：错误体含 id 也不绑定、不计数。
    for status in [400u16, 500] {
        let scope_empty = Scope::with_opts(false);
        let metrics = GatewayMetrics::default();
        let mut tracker = CaptureTracker::default();
        let captured = tracker.observe(
            &scope_empty,
            Protocol::Responses,
            status,
            &json!({"id": "resp_err", "error": {"id": "err_1"}}),
            &metrics,
        );
        assert!(captured.is_empty(), "错误状态 MUST NOT 捕获 id");
        assert_eq!(metrics.session_bind_miss_count(), 0);
        assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    }
}

#[test]
fn tracker_binds_captured_ids_into_alias() {
    // 正常会话级作用域：响应完成后 `resolve(response.id) == 请求时 canonical`。
    let alias = Arc::new(SessionAliasMap::new(8));
    let scope = conversation_scope_scope(&alias, false);
    let metrics = GatewayMetrics::default();
    let mut tracker = CaptureTracker::default();
    let body = json!({"id": "resp_1", "conversation": {"id": "conv_1"}});
    tracker.observe(&scope, Protocol::Responses, 200, &body, &metrics);

    let canonical = scoped_key(SECRET, TENANT, "anchor-1");
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_1"),
        Some(canonical.clone())
    );
    assert_eq!(alias.resolve(SECRET, TENANT, "conv_1"), Some(canonical));
    assert_eq!(
        alias.bind(
            SECRET,
            TENANT,
            "resp_1",
            &scoped_key(SECRET, TENANT, "other")
        ),
        BindOutcome::Conflict,
        "既有绑定不得被覆盖"
    );
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
}

#[test]
fn request_carried_conversation_binds_only_response_id_from_real_identity() {
    // 经真实解析器产出 `request_carried_conversation` 语义：请求自带
    // `conversation` 时只绑 `response.id`，该客户端提供的 `conversation.id` 不写别名。
    let alias = Arc::new(SessionAliasMap::new(8));
    let chains = ["x-veil-conversation-id".to_string()];
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-veil-conversation-id", "H1".parse().expect("头值须合法"));
    let body = json!({"conversation": "conv_client", "messages": []});
    let identity = crate::service::session_identity::resolve(
        &headers,
        Some(&body),
        Protocol::Responses,
        &chains,
        &alias,
        SECRET,
        TENANT,
    );
    assert!(
        identity.request_carried_conversation,
        "前置：请求体存在 conversation 键"
    );
    let wb = ConversationWriteback::new(identity, Arc::<[u8]>::from(SECRET), Arc::clone(&alias));
    let canonical = scoped_key(SECRET, TENANT, "H1");
    wb.record(&CapturedIds {
        response_id: Some("resp_1".to_string()),
        conversation_id: Some("conv_client".to_string()),
    });
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_1"),
        Some(canonical),
        "response.id 须绑定到请求时 canonical"
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_client"),
        None,
        "客户端提供的 conversation.id MUST NOT 被抢先绑定"
    );
}

#[test]
fn response_stage_binds_without_switching_scope() {
    // spec「响应阶段不换键」：写回只新增别名映射，本次响应的还原仍用请求时
    // 共享的 `PiiScope`（指针不变），新注册值不进入另一作用域。
    const PLAINTEXT: &str = "13800138000";
    let alias = Arc::new(SessionAliasMap::new(8));
    let chains = ["x-veil-conversation-id".to_string()];
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        "H-wb".parse().expect("头值须合法"),
    );
    let identity = crate::service::session_identity::resolve(
        &headers,
        Some(&json!({"messages": []})),
        Protocol::Responses,
        &chains,
        &alias,
        SECRET,
        TENANT,
    );
    let canonical = identity.canonical.clone().expect("头命中须有 canonical");
    let pii = Arc::new(crate::service::pii::PiiScope::new());
    let token = pii.register(PLAINTEXT).expect("注册须成功");

    let scope = Scope::with_shared_pii(Arc::clone(&pii), false).with_conversation(
        ConversationWriteback::new(identity, Arc::<[u8]>::from(SECRET), Arc::clone(&alias)),
        true,
    );
    let canonical_before = canonical.clone();
    let mut tracker = CaptureTracker::default();
    let metrics = GatewayMetrics::default();
    let captured = tracker.observe(
        &scope,
        Protocol::Responses,
        200,
        &json!({"id": "resp_wb", "conversation": {"id": "conv_wb"}}),
        &metrics,
    );
    assert_eq!(captured.response_id.as_deref(), Some("resp_wb"));

    assert_eq!(
        scope.pii_scope().restore(&token),
        PLAINTEXT,
        "还原仍用请求时作用域"
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_wb"),
        Some(canonical_before.clone()),
        "别名绑定只新增映射，canonical 不变"
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_wb"),
        Some(canonical_before)
    );
}

#[test]
fn repeated_stream_frames_bind_idempotently_without_conflict() {
    let metrics = Arc::new(GatewayMetrics::default());
    let alias = Arc::new(SessionAliasMap::new(8).with_metrics(Arc::clone(&metrics)));
    let scope = conversation_scope_scope(&alias, false);
    let mut tracker = CaptureTracker::default();
    let event = json!({
        "type": "response.created",
        "response": {"id": "resp_stream", "conversation": {"id": "conv_stream"}},
    });

    tracker.observe_frame(&scope, Protocol::Responses, 200, &event);
    tracker.observe_frame(&scope, Protocol::Responses, 200, &event);
    tracker.finish(&scope, Protocol::Responses, 200, &metrics);

    assert_eq!(metrics.session_alias_conflict_count(), 0);
    assert_eq!(metrics.conversation_writeback_miss_count(), 0);
    assert_eq!(metrics.session_bind_miss_count(), 0);
    let canonical = scoped_key(SECRET, TENANT, "anchor-1");
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_stream"),
        Some(canonical.clone())
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "conv_stream"),
        Some(canonical)
    );
}

#[test]
fn alias_conflict_reported_once_per_upstream_id_per_response() {
    let metrics = Arc::new(GatewayMetrics::default());
    let alias = Arc::new(SessionAliasMap::new(8).with_metrics(Arc::clone(&metrics)));
    let other = scoped_key(SECRET, TENANT, "other");
    alias.bind(SECRET, TENANT, "resp_dup", &other);
    alias.bind(SECRET, TENANT, "conv_dup", &other);
    let scope = conversation_scope_scope(&alias, false);

    let captured = CapturedIds {
        response_id: Some("resp_dup".to_string()),
        conversation_id: Some("conv_dup".to_string()),
    };
    scope.record_capture(&captured);
    scope.record_capture(&captured);

    assert_eq!(
        metrics.session_alias_conflict_count(),
        2,
        "response 与 conversation 两个 upstream id 各计一次，重复上报须去重"
    );
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_dup"),
        Some(other.clone()),
        "既有绑定不得被覆盖"
    );
    assert_eq!(alias.resolve(SECRET, TENANT, "conv_dup"), Some(other));
}

#[test]
fn response_and_conversation_ids_resolve_to_same_canonical() {
    // tasks 3.3 Verify：请求未携带 `conversation` 时，响应返回后
    // `resolve(response.id) == resolve(conversation.id) == 请求时 canonical`。
    let alias = Arc::new(SessionAliasMap::new(8));
    let chains = ["x-veil-conversation-id".to_string()];
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("x-veil-conversation-id", "H2".parse().expect("头值须合法"));
    let body = json!({"messages": []});
    let identity = crate::service::session_identity::resolve(
        &headers,
        Some(&body),
        Protocol::Responses,
        &chains,
        &alias,
        SECRET,
        TENANT,
    );
    let canonical = identity.canonical.clone().expect("头命中须有 canonical");
    assert_eq!(canonical, scoped_key(SECRET, TENANT, "H2"));

    let wb = ConversationWriteback::new(identity, Arc::<[u8]>::from(SECRET), Arc::clone(&alias));
    wb.record(&CapturedIds {
        response_id: Some("resp_2".to_string()),
        conversation_id: Some("conv_2".to_string()),
    });
    assert_eq!(
        alias.resolve(SECRET, TENANT, "resp_2"),
        Some(canonical.clone())
    );
    assert_eq!(alias.resolve(SECRET, TENANT, "conv_2"), Some(canonical));
}
