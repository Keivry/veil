//! 会话身份的 HTTP 级行为（tasks 6.1/6.5/6.6）：`request` 模式日志口径、稳定前缀
//! 日志无会话、默认头链出站剥离与非 `x-veil-*` 多值头原样转发、错误响应不绑定、
//! `llm_requests.upstream_id` 展示锚点。
//!
//! 夹具复用父模块 `dispatch::tests` 的 `test_app_state*` 与回环上游。

use {
    super::{capture_loopback_complete, captured_body, test_app_state, test_app_state_with_file},
    crate::{
        handler::llm::{dispatch::gateway_serve, tests::loopback_server},
        service::{llm_gateway::Protocol, redaction::session_alias::BindOutcome},
    },
    axum::http::StatusCode,
};

/// 读取唯一落库行（刷盘后）。
fn only_row(state: &crate::state::AppState) -> crate::service::request_log::RequestRow {
    state.request_log.flush_blocking().expect("刷盘须成功");
    let mut rows = state
        .request_log
        .query(&crate::service::request_log::RequestFilter {
            limit: Some(200),
            ..Default::default()
        })
        .expect("查询须成功")
        .rows;
    assert_eq!(rows.len(), 1, "须恰好一行: {rows:?}");
    rows.remove(0)
}

const CHAT_BODY: &[u8] =
    br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
const RESPONSES_BODY: &[u8] =
    br#"{"id":"resp_anchor","object":"response","model":"resp-model","status":"completed","conversation":{"id":"conv_anchor"},"output":[],"usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}"#;

/// tasks 6.1：`request` 模式日志仍记录 `session_source`/`session_scope`，而 PII
/// 逐请求（不构造 `ConversationScopeStore`、每轮新 `PiiScope`、别名照常绑定）。
#[tokio::test]
async fn request_mode_logs_session_source_while_pii_is_per_request() {
    let (url, _captured, server) =
        capture_loopback_complete("application/json", CHAT_BODY.to_vec()).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "request-mode-key"),
    ]);
    assert!(
        state.conversation_scope_store.is_none(),
        "前置：默认 `request` 模式不得装配会话作用域存储"
    );

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "H-req-mode")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/responses",
        br#"{"model":"m","input":"hi"}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = only_row(&state);
    assert_eq!(row.session_source, "header", "日志须显示会话来源");
    assert_eq!(row.session_scope, "session");
    assert_eq!(
        row.session_id.as_deref().map(str::len),
        Some(16),
        "会话摘要仍为 16 hex"
    );
    assert!(
        state.conversation_scope_store.is_none(),
        "`request` 模式 MUST NOT 因日志口径而创建会话存储"
    );

    // 两轮同头请求各自独立 `PiiScope`（逐请求）。
    let upstream = crate::service::llm_gateway::resolve_upstream(&state.config, None)
        .expect("测试配置须有上游");
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        "H-req-mode".parse().expect("头值合法"),
    );
    let body = serde_json::json!({"messages": []});
    let first = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        Protocol::Responses,
        &upstream,
        Some(&body),
    );
    let second = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &headers,
        Protocol::Responses,
        &upstream,
        Some(&body),
    );
    assert!(
        first.has_writeback() && second.has_writeback(),
        "`request` 模式下 canonical 存在时两条路径都须挂写回"
    );
    assert!(
        !first.has_conversation_scope() && !second.has_conversation_scope(),
        "`request` 模式 MUST NOT 落会话级作用域"
    );
    assert!(
        !std::ptr::eq(first.pii_scope(), second.pii_scope()),
        "PII 须逐请求（两轮不得共享同一注册表）"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.1：稳定前缀级只产生 PII canonical，日志 `session_source=none`/
/// `session_scope=none`。
#[tokio::test]
async fn stable_prefix_level_logs_no_session_source() {
    let (url, _captured, server) =
        capture_loopback_complete("application/json", CHAT_BODY.to_vec()).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "prefix-key"),
        ("PII_SCOPE_MODE", "conversation"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let body = br#"{"model":"m","tools":[{"type":"function","function":{"name":"alpha"}}],"messages":[{"role":"system","content":"s"},{"role":"user","content":"u"}]}"#;
    let resp = gateway_serve(&state, &mut parts, "/v1/chat/completions", body.to_vec()).await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = only_row(&state);
    assert_eq!(row.session_source, "none", "稳定前缀级无日志会话来源");
    assert_eq!(row.session_scope, "none");
    assert!(row.session_id.is_none(), "不得记录稳定前缀级会话摘要");
    assert_eq!(
        state.gateway_metrics.request_fallback_count(),
        0,
        "稳定前缀命中不算逐请求回退"
    );

    // PII canonical 确实存在（作用域存储插入了一条），仅日志口径为空。
    let upstream = crate::service::llm_gateway::resolve_upstream(&state.config, None)
        .expect("测试配置须有上游");
    let scope = crate::handler::llm::dispatch::build_request_scope_for_tests(
        &state,
        &axum::http::HeaderMap::new(),
        Protocol::Chat,
        &upstream,
        Some(&serde_json::from_slice(body).expect("测试体须为 JSON")),
    );
    assert!(
        scope.has_conversation_scope(),
        "稳定前缀级须产出 PII 会话 canonical"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.1：默认链中的 `x-veil-conversation-id` 不出站；非 `x-veil-*` 的
/// `[session].headers` 按客户端原值转发（多值全保留）。
#[tokio::test]
async fn default_chain_header_not_forwarded_but_configured_header_is_verbatim() {
    let (url, captured, server) =
        capture_loopback_complete("application/json", CHAT_BODY.to_vec()).await;
    let (state, dir) = test_app_state_with_file(
        &[("LLM_UPSTREAM", url.as_str())],
        "[session]\nheaders = [\"x-veil-conversation-id\", \"x-client-session\"]\n",
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "internal-value")
        .header("x-client-session", "client-a")
        .header("x-client-session", "client-b")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);

    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let head =
        String::from_utf8_lossy(&raw[..raw.len() - captured_body(&raw).len()]).to_lowercase();
    assert!(
        !head.contains("x-veil-conversation-id"),
        "默认链中的 `x-veil-*` 内部头 MUST NOT 出站: {head}"
    );
    assert!(
        !head.contains("internal-value"),
        "内部头值 MUST NOT 出站: {head}"
    );
    let forwarded: Vec<&str> = head
        .lines()
        .filter(|line| line.starts_with("x-client-session:"))
        .collect();
    assert_eq!(forwarded.len(), 2, "多值须全保留: {head}");
    assert_eq!(forwarded[0].trim(), "x-client-session: client-a");
    assert_eq!(forwarded[1].trim(), "x-client-session: client-b");
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.5：4xx/5xx 含 `error.id`/顶层 `id` 时不写别名，且不递增
/// `conversation_writeback_miss` / `session_bind_miss`。
#[tokio::test]
async fn error_response_with_ids_binds_nothing_and_counts_no_miss() {
    for status in [400u16, 500] {
        let up_body = br#"{"id":"resp_err","conversation":{"id":"conv_err"},"error":{"id":"err_1","message":"boom"}}"#.to_vec();
        let (url, server) = loopback_server(status, "application/json", up_body).await;
        let (state, dir) = test_app_state(&[
            ("LLM_UPSTREAM", url.as_str()),
            ("PII_SCOPE_MODE", "conversation"),
        ]);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("content-type", "application/json")
            .header("x-veil-conversation-id", "H-err")
            .body(())
            .expect("请求构造须成功");
        let (mut parts, ()) = request.into_parts();
        let resp = gateway_serve(
            &state,
            &mut parts,
            "/v1/responses",
            br#"{"model":"m","input":"hi"}"#.to_vec(),
        )
        .await;
        server.abort();
        assert_eq!(resp.status().as_u16(), status);

        assert!(
            state.session_alias_map.is_empty(),
            "{status} 错误响应 MUST NOT 写入任何别名"
        );
        assert_eq!(
            state.gateway_metrics.conversation_writeback_miss_count(),
            0,
            "{status} 不得误计写回失败"
        );
        assert_eq!(
            state.gateway_metrics.session_bind_miss_count(),
            0,
            "{status} 不得误计绑定缺失"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// tasks 6.6：`llm_requests.upstream_id` 保留响应 id 作为展示锚点，且绝不写入
/// `conversation.id`；会话列只留摘要，别名表只含哈希键。
#[tokio::test]
async fn upstream_id_keeps_response_id_and_never_stores_conversation_id() {
    let (url, _captured, server) =
        capture_loopback_complete("application/json", RESPONSES_BODY.to_vec()).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "anchor-key"),
        ("PII_SCOPE_MODE", "conversation"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "H-anchor")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/responses",
        br#"{"model":"m","input":"hi"}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = only_row(&state);
    assert_eq!(
        row.upstream_id.as_deref(),
        Some("resp_anchor"),
        "展示锚点须仍是响应 id"
    );
    assert_ne!(
        row.upstream_id.as_deref(),
        Some("conv_anchor"),
        "MUST NOT 以 conversation.id 充当展示锚点"
    );

    // 请求未携带 `conversation` 字段，响应的 conversation.id 须绑定到请求时 canonical。
    let fp = super::super::request_tenant_fingerprint(
        &state,
        &axum::http::HeaderMap::new(),
        url.as_str(),
    );
    let canonical =
        crate::service::redaction::scoped_key(state.conversation_secret.as_ref(), &fp, "H-anchor");
    assert_eq!(
        state
            .session_alias_map
            .resolve(state.conversation_secret.as_ref(), &fp, "conv_anchor"),
        Some(canonical.clone())
    );
    assert_eq!(
        state.session_alias_map.bind(
            state.conversation_secret.as_ref(),
            &fp,
            "resp_anchor",
            &canonical
        ),
        BindOutcome::AlreadyBound,
        "response.id 须已绑定到同一 canonical"
    );
    std::fs::remove_dir_all(&dir).ok();
}
