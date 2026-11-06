//! `trace` 纯函数单测（由 `trace.rs` 以 `#[cfg(test)] mod tests;` 门控声明）：
//! Responses 嵌套结束原因、超长文本叶子预算截断与摘要长度上界。

use {
    super::{
        RequestTrace,
        SUMMARY_MAX_CHARS,
        SUMMARY_TEXT_CAP,
        finish_reason_of,
        project_summary,
        push_text_leaves,
    },
    crate::service::{
        llm_gateway::Protocol,
        redaction::conversation_key::scoped_key,
        request_log::SESSION_ID_HEX_LEN,
        session_identity::{
            AnchorSource,
            LogUserAnchor,
            SessionAnchor,
            SessionIdentity,
            SessionScope,
            SessionSource,
        },
    },
    serde_json::{Value, json},
    std::time::Instant,
};

const KEY: &str = "session-digest-key";
const SECRET: &[u8] = b"trace-test-secret";
const TENANT: &str = "tenant-fp";

fn trace() -> RequestTrace {
    RequestTrace::new(
        "req-trace".to_string(),
        Protocol::Chat,
        Some(8877),
        true,
        Instant::now(),
    )
}

/// 构造「会话级锚点」身份：`source` 决定日志来源，canonical 固定由 `raw` 派生。
fn session_identity(raw: &str, anchor_source: AnchorSource, log: SessionSource) -> SessionIdentity {
    SessionIdentity {
        anchor: Some(SessionAnchor {
            value: raw.to_string(),
            source: anchor_source,
        }),
        canonical: Some(scoped_key(SECRET, TENANT, raw)),
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::Session,
        source: log,
        log_source: log,
        log_scope: SessionScope::Session,
        log_user: None,
        request_carried_conversation: false,
    }
}

/// 用户级身份：无 canonical，只有 `log_user`。
fn user_identity(value: &str, source: SessionSource) -> SessionIdentity {
    SessionIdentity {
        anchor: None,
        canonical: None,
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::None,
        source: SessionSource::None,
        log_source: source,
        log_scope: SessionScope::User,
        log_user: Some(LogUserAnchor {
            value: value.to_string(),
            source,
        }),
        request_carried_conversation: false,
    }
}

#[test]
fn set_req_model_writes_row_model() {
    let mut trace = trace();
    trace.set_req_model("m-1");
    assert_eq!(trace.into_row().model, "m-1");
}

#[test]
fn attach_identity_digest_is_source_stable_but_source_field_varies() {
    // tasks 4.3 Verify：头 `H`、`conversation` 与 `previous_response_id` 命中同一
    // canonical `K1` 时三轮 `session_id` 相同，`session_source` 随实际来源变化。
    let canonical = scoped_key(SECRET, TENANT, "H");
    let round = |raw: &str, anchor: AnchorSource, log: SessionSource| {
        let mut trace = trace();
        let mut identity = session_identity(raw, anchor, log);
        identity.canonical = Some(canonical.clone());
        trace.attach_identity(&identity, Some(KEY));
        trace.into_row()
    };
    let header_row = round("H", AnchorSource::Header, SessionSource::Header);
    let conversation_row = round(
        "conv-c",
        AnchorSource::Conversation,
        SessionSource::Conversation,
    );
    let prev_row = round(
        "resp_1",
        AnchorSource::PreviousResponse,
        SessionSource::PrevResponse,
    );

    assert_eq!(
        header_row.session_id, conversation_row.session_id,
        "同一 canonical 摘要须相同（头 → conversation）"
    );
    assert_eq!(
        header_row.session_id, prev_row.session_id,
        "同一 canonical 摘要须相同（头 → previous_response_id）"
    );
    assert_eq!(
        header_row.session_id.as_deref().map(str::len),
        Some(SESSION_ID_HEX_LEN)
    );
    assert_eq!(header_row.session_source, "header");
    assert_eq!(conversation_row.session_source, "conversation");
    assert_eq!(prev_row.session_source, "prev_response");
    for row in [&header_row, &conversation_row, &prev_row] {
        assert_eq!(row.session_scope, "session");
    }
}

#[test]
fn attach_identity_user_scope_is_labelled_user() {
    // 仅 `metadata.user_id`：作用域为「用户」，摘要仍为 16 hex。
    let mut trace = trace();
    trace.attach_identity(&user_identity("u-1", SessionSource::UserId), Some(KEY));
    let row = trace.into_row();
    assert_eq!(row.session_source, "user_id");
    assert_eq!(row.session_scope, "user");
    assert_eq!(
        row.session_id.as_deref().map(str::len),
        Some(SESSION_ID_HEX_LEN)
    );
}

#[test]
fn attach_identity_without_key_records_nothing() {
    for key in [None, Some("")] {
        let mut trace = trace();
        trace.attach_identity(
            &session_identity("H", AnchorSource::Header, SessionSource::Header),
            key,
        );
        let row = trace.into_row();
        assert!(row.session_id.is_none(), "无密钥须无会话列");
        assert_eq!(row.session_source, "none");
        assert_eq!(row.session_scope, "none");
    }
}

#[test]
fn attach_identity_without_source_records_nothing() {
    let identity = SessionIdentity {
        anchor: None,
        canonical: None,
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::None,
        source: SessionSource::None,
        log_source: SessionSource::None,
        log_scope: SessionScope::None,
        log_user: None,
        request_carried_conversation: false,
    };
    let mut trace = trace();
    trace.attach_identity(&identity, Some(KEY));
    let row = trace.into_row();
    assert!(row.session_id.is_none());
    assert_eq!(row.session_source, "none");
    assert_eq!(row.session_scope, "none");
}

#[test]
fn attach_identity_stable_prefix_has_no_log_session() {
    // 稳定前缀级：canonical 存在但 log_source/log_scope 均为 none → 日志无会话。
    let identity = SessionIdentity {
        anchor: None,
        canonical: Some(scoped_key(SECRET, TENANT, "prefix")),
        tenant_fingerprint: TENANT.to_string(),
        scope: SessionScope::Session,
        source: SessionSource::None,
        log_source: SessionSource::None,
        log_scope: SessionScope::None,
        log_user: None,
        request_carried_conversation: false,
    };
    let mut trace = trace();
    trace.attach_identity(&identity, Some(KEY));
    let row = trace.into_row();
    assert!(row.session_id.is_none(), "日志不得记录稳定前缀级会话");
    assert_eq!(row.session_source, "none");
    assert_eq!(row.session_scope, "none");
}

#[test]
fn attach_identity_is_protocol_scoped() {
    let identity = session_identity("H", AnchorSource::Header, SessionSource::Header);
    let mut chat = trace();
    chat.attach_identity(&identity, Some(KEY));
    let mut anthropic = RequestTrace::new(
        "req-trace".to_string(),
        Protocol::Anthropic,
        Some(8877),
        true,
        Instant::now(),
    );
    anthropic.attach_identity(&identity, Some(KEY));
    assert_ne!(
        chat.into_row().session_id,
        anthropic.into_row().session_id,
        "摘要须随协议域变化"
    );
}

#[test]
fn finish_reason_reads_responses_stream_envelope() {
    // 流式 `response.completed`：`status` 位于 `response` 信封内，顶层无该键。
    let completed = json!({
        "type": "response.completed",
        "response": {"status": "completed", "incomplete_details": null},
    });
    assert_eq!(
        finish_reason_of(Protocol::Responses, &completed).as_deref(),
        Some("completed")
    );
    // `response.incomplete`：`incomplete_details.reason` 优先于 `status`。
    let incomplete = json!({
        "type": "response.incomplete",
        "response": {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
        },
    });
    assert_eq!(
        finish_reason_of(Protocol::Responses, &incomplete).as_deref(),
        Some("max_output_tokens")
    );
    // 非流响应体：字段仍在顶层，既有口径不变。
    assert_eq!(
        finish_reason_of(
            Protocol::Responses,
            &json!({"status": "completed", "incomplete_details": null})
        )
        .as_deref(),
        Some("completed")
    );
}

#[test]
fn oversized_text_leaf_is_truncated_to_budget() {
    // 单个 10MB 叶子不得整段进入中间串：入 `out` 的长度恒 ≤ 预算。
    let mut out = String::new();
    push_text_leaves(&Value::String("x".repeat(10 * 1024 * 1024)), &mut out);
    assert_eq!(out.len(), SUMMARY_TEXT_CAP, "单叶子须截断到预算上限");
}

#[test]
fn multibyte_leaf_truncates_on_char_boundary() {
    // 3 字节码点使预算尾端落在码点中间：回退到边界即可，不得 panic。
    let mut out = String::new();
    push_text_leaves(&Value::String("汉".repeat(SUMMARY_TEXT_CAP)), &mut out);
    assert!(out.len() <= SUMMARY_TEXT_CAP, "累计长度须 ≤ 预算");
    assert!(out.chars().all(|c| c == '汉'), "不得切出半个码点");
}

#[test]
fn summary_with_huge_leaf_stays_within_limit() {
    let body = json!({
        "model": "m",
        "messages": [{"role": "user", "content": "y".repeat(10 * 1024 * 1024)}],
    });
    let summary = project_summary(Some(&body)).expect("须产出摘要");
    assert!(
        summary.chars().count() <= SUMMARY_MAX_CHARS,
        "摘要长度须 ≤{SUMMARY_MAX_CHARS}: {}",
        summary.chars().count()
    );
}

/// 三轮真实解析（头 → `conversation` 别名命中 → `previous_response_id` 别名命中）：
/// 日志摘要须相同，`session_source` 随实际来源变化（tasks 6.2）。
#[test]
fn real_resolver_three_rounds_share_digest_across_sources() {
    use {
        crate::service::{redaction::SessionAliasMap, session_identity::resolve},
        axum::http::{HeaderMap, HeaderValue},
    };
    const SECRET: &[u8] = b"three-round-secret";
    const TENANT: &str = "tenant-three";
    let chains = ["x-veil-conversation-id".to_string()];
    let alias = SessionAliasMap::new(8);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        HeaderValue::from_static("H-three"),
    );

    let round = |headers: &HeaderMap, body: Option<&Value>| {
        let identity = resolve(
            headers,
            body,
            Protocol::Responses,
            &chains,
            &alias,
            SECRET,
            TENANT,
        );
        let mut trace = RequestTrace::new(
            "req-3".to_string(),
            Protocol::Responses,
            Some(8877),
            true,
            Instant::now(),
        );
        trace.attach_identity(&identity, Some(KEY));
        (identity, trace.into_row())
    };

    let (id1, row1) = round(&headers, Some(&json!({"messages": []})));
    let canonical = id1.canonical.clone().expect("头命中须有 canonical");
    alias.bind(SECRET, TENANT, "resp_1", &canonical);
    alias.bind(SECRET, TENANT, "conv_1", &canonical);

    let (_id2, row2) = round(&HeaderMap::new(), Some(&json!({"conversation": "conv_1"})));
    let (_id3, row3) = round(
        &HeaderMap::new(),
        Some(&json!({"previous_response_id": "resp_1"})),
    );

    assert_eq!(row1.session_source, "header");
    assert_eq!(row2.session_source, "conversation");
    assert_eq!(row3.session_source, "prev_response");
    assert_eq!(
        row1.session_id, row2.session_id,
        "同一 canonical 摘要须相同"
    );
    assert_eq!(
        row1.session_id, row3.session_id,
        "同一 canonical 摘要须相同"
    );
    assert!(row1.session_id.is_some());
}

/// 跨进程重启边界：`conversation_secret` 随机 → 同一客户端头派生的 canonical 变化
/// → 落库 `session_id` 随之变化（tasks 6.6，spec 已登记边界）。
#[test]
fn restart_with_new_secret_changes_stored_session_id() {
    use {
        crate::service::{redaction::SessionAliasMap, session_identity::resolve},
        axum::http::{HeaderMap, HeaderValue},
    };
    const TENANT: &str = "tenant-restart";
    let chains = ["x-veil-conversation-id".to_string()];
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        HeaderValue::from_static("same-client-header"),
    );

    let digest_with = |process_secret: &[u8], alias: &SessionAliasMap| {
        let identity = resolve(
            &headers,
            None,
            Protocol::Chat,
            &chains,
            alias,
            process_secret,
            TENANT,
        );
        let mut trace = trace();
        trace.attach_identity(&identity, Some(KEY));
        let row = trace.into_row();
        assert_eq!(row.session_source, "header", "来源不随密钥变化");
        row.session_id.expect("有密钥须派生会话")
    };

    let first_process = digest_with(b"process-secret-A", &SessionAliasMap::new(8));
    let second_process = digest_with(b"process-secret-B", &SessionAliasMap::new(8));
    assert_ne!(
        first_process, second_process,
        "重启后同一客户端头的 session_id 须变化（密钥随机，缓存失配属预期）"
    );
    assert_eq!(first_process.len(), SESSION_ID_HEX_LEN);
    assert_eq!(second_process.len(), SESSION_ID_HEX_LEN);
}
