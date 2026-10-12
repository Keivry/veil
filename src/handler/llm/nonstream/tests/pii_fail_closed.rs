//! 非流写回失败计数（`nonstream/tests/` 子模块，守 `tests.rs` 800 行红线）。

use {
    super::{
        super::{NonstreamOutcome, serve_nonstream},
        loopback_server,
        test_ctx,
    },
    crate::service::{
        llm_gateway::{GatewayMetrics, Protocol},
        redaction::{ConversationKey, PreviousResponseMap, Scope},
    },
    axum::http::HeaderMap,
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
async fn writeback_miss_only_counts_missing_response_id_in_conversation() {
    // 仅(c) 响应 id 缺失计数；(a) 无写回上下文与(b) 有 id 均不计。
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
    // → 错误响应不承载可写回 id，非真实写回失败，门控 MUST NOT 虚计。
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
