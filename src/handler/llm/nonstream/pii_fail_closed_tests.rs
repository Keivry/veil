//! R5-14/D5 响应侧 fail-closed 与 R5-09/D10 写回失败计数（sibling，守 `tests.rs` 800 行红线）。

use {
    super::{
        NonstreamOutcome,
        serve_nonstream,
        tests::{loopback_server, test_ctx},
    },
    crate::service::{
        llm_gateway::{GatewayMetrics, Protocol},
        redaction::{ConversationKey, PreviousResponseMap, Scope},
    },
    axum::http::{HeaderMap, StatusCode},
    std::sync::Arc,
};

fn conversation_scope() -> Arc<Scope> {
    Arc::new(Scope::new().with_conversation(
        ConversationKey::for_test("test-conversation-key"),
        "tenant-fp".to_string(),
        Arc::<[u8]>::from(&b"secret"[..]),
        Arc::new(PreviousResponseMap::new(8)),
    ))
}

async fn run_nonstream(
    protocol: Protocol,
    scope: Arc<Scope>,
    up_body: Vec<u8>,
    metrics: Arc<GatewayMetrics>,
) -> axum::response::Response {
    run_nonstream_with_status(200, protocol, scope, up_body, metrics).await
}

async fn run_nonstream_with_status(
    status: u16,
    protocol: Protocol,
    scope: Arc<Scope>,
    up_body: Vec<u8>,
    metrics: Arc<GatewayMetrics>,
) -> axum::response::Response {
    let (url, server) = loopback_server(status, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let mut ctx = test_ctx(protocol);
    ctx.req.scope = scope;
    ctx.req.gateway_metrics = metrics;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("JSON 上游不得转流泵"),
    }
}

#[tokio::test]
async fn nonstream_response_pii_unavailable_fails_closed_502() {
    // R5-14/D5：响应侧新检出注册遇熵源故障——502 + E_PII_UNAVAILABLE，且不外泄未脱敏明文。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"call 13812345678"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let scope = Arc::new(Scope::new());
    scope.pii_scope().force_entropy_failure(true);
    let resp = run_nonstream(
        Protocol::Chat,
        scope.clone(),
        up_body,
        Arc::new(GatewayMetrics::default()),
    )
    .await;
    assert!(scope.pii_unavailable(), "熵源故障须置失败信号");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误体须可读");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("E_PII_UNAVAILABLE"), "错误码须具名: {text}");
    assert!(
        !text.contains("13812345678"),
        "不得外泄未 token 化的明文: {text}"
    );
}

#[tokio::test]
async fn writeback_miss_only_counts_missing_response_id_in_conversation() {
    // R5-09/D10：仅 (c) 响应 id 缺失计数；(a) 无写回上下文与 (b) 有 id 均不计。
    let no_id =
        br#"{"output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#.to_vec();
    let with_id = br#"{"id":"resp_123","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#
        .to_vec();

    // (a) `request` 模式（无写回上下文）→ 不计（否则默认模式每个 Responses 响应误计）。
    let metrics = Arc::new(GatewayMetrics::default());
    let _ = run_nonstream(
        Protocol::Responses,
        Arc::new(Scope::new()),
        no_id.clone(),
        metrics.clone(),
    )
    .await;
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "无写回上下文 MUST NOT 计入"
    );

    // (b) `conversation` 模式 + Responses + 响应 id 存在 → 写入成功，不计。
    let metrics = Arc::new(GatewayMetrics::default());
    let _ = run_nonstream(
        Protocol::Responses,
        conversation_scope(),
        with_id,
        metrics.clone(),
    )
    .await;
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "写入成功 MUST NOT 计入"
    );

    // (c) `conversation` 模式 + Responses + 响应 id 缺失 → 恰计一次。
    let metrics = Arc::new(GatewayMetrics::default());
    let _ = run_nonstream(
        Protocol::Responses,
        conversation_scope(),
        no_id.clone(),
        metrics.clone(),
    )
    .await;
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        1,
        "响应 id 缺失须计一次"
    );

    // (d) `conversation` 模式 + 非 Responses（Chat）无 id → 协议门控不计。
    let metrics = Arc::new(GatewayMetrics::default());
    let _ = run_nonstream(Protocol::Chat, conversation_scope(), no_id, metrics.clone()).await;
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "非 Responses 协议门控 MUST NOT 计入"
    );

    // (e) `conversation` 模式 + Responses + 响应 id 缺失但 `status>=400` 错误体
    // → 错误响应不承载可写回 id，非真实写回失败，D7 门控 MUST NOT 虚计。
    let metrics = Arc::new(GatewayMetrics::default());
    let _ = run_nonstream_with_status(
        400,
        Protocol::Responses,
        conversation_scope(),
        br#"{"error":{"message":"bad request"}}"#.to_vec(),
        metrics.clone(),
    )
    .await;
    assert_eq!(
        metrics.conversation_writeback_miss_count(),
        0,
        "status>=400 错误体 MUST NOT 计入写回失败"
    );
}
