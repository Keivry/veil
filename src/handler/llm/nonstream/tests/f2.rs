//! F2 非流对话响应体上限（`NONSTREAM_MAX_BYTES`）测试：
//! 超限 502、`len == cap` 放行、`Protocol::NonDialog` 旁路、上限内错误体不变。
//! 归属拆分：`nonstream/tests.rs` 触 800 红线后按测试外迁模板独立成子模块。

use {
    super::{loopback_server, test_ctx},
    crate::{
        handler::llm::nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        service::llm_gateway::{self, Protocol},
    },
    std::sync::Arc,
};

/// F2：带上限覆盖的非流 ctx（其余字段复用默认测试装配）。
fn test_ctx_with_cap(protocol: Protocol, cap: usize) -> NonstreamCtx {
    NonstreamCtx {
        nonstream_max_bytes: cap,
        ..test_ctx(protocol)
    }
}

#[tokio::test]
async fn f2_oversize_dialog_response_returns_502_response_too_large() {
    // F2：对话非流响应体 `len > cap` → 502，体与 Content-Type 对齐 Python `_llm.py:2951-2961`。
    let client = reqwest::Client::new();
    let upstream =
        br#"{"id":"cmpl-big","model":"m","choices":[{"message":{"content":"big"}}]}"#.to_vec();
    let cap = upstream.len() - 1;
    let (url, server) = loopback_server(200, "application/json", upstream).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx_with_cap(Protocol::Chat, cap),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("超限须直接响应而非转流");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("超限体须可读");
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        v,
        serde_json::json!({
            "error": {"message": "response too large", "type": "response_too_large"}
        }),
        "体形态须与 Python `_llm.py:2951-2961` 同字"
    );
}

#[tokio::test]
async fn f2_boundary_len_equal_cap_passes_strict_greater_semantics() {
    // F2 边界：`len == cap` 放行（严格大于语义），与 Python `len > NONSTREAM_MAX_BYTES` 同口径。
    let client = reqwest::Client::new();
    let upstream =
        br#"{"id":"cmpl-eq","model":"m","choices":[{"message":{"content":"eq"}}]}"#.to_vec();
    let cap = upstream.len();
    let (url, server) = loopback_server(200, "application/json", upstream.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx_with_cap(Protocol::Chat, cap),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("等于上限须按正常响应处理");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("放行体须可读");
    // 对话 JSON 出口经还原/脱敏链会重排键序，语义等价即放行（未触发超限体）。
    let got: serde_json::Value = serde_json::from_slice(&bytes).expect("放行体须为 JSON");
    let want: serde_json::Value = serde_json::from_slice(&upstream).expect("上游体须为 JSON");
    assert_eq!(got, want, "等于上限不得触发超限体");
}

#[tokio::test]
async fn f2_nondialog_passthrough_not_limited_by_cap() {
    // F2 旁路：`Protocol::NonDialog` 字节透传不受上限约束（如模型列表大响应）。
    let client = reqwest::Client::new();
    let upstream = format!(
        r#"{{"object":"list","data":[{{"id":"m","note":"{}"}}]}}"#,
        "x".repeat(256)
    )
    .into_bytes();
    let metrics = Arc::new(llm_gateway::GatewayMetrics::default());
    let mut ctx = test_ctx(Protocol::NonDialog);
    ctx.nonstream_max_bytes = 1;
    ctx.gateway_metrics = metrics.clone();
    let (url, server) = loopback_server(200, "application/json", upstream.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::GET,
        &url,
        axum::http::HeaderMap::new(),
        Vec::new(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("非对话须直接响应（字节透传）");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "非对话超限不得改写为 502"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("透传体须可读");
    assert_eq!(bytes.as_ref(), upstream.as_slice(), "非对话须字节透传");
    assert_eq!(metrics.nondialog_passthrough_count(), 1);
}

#[tokio::test]
async fn f2_error_body_under_cap_behavior_unchanged() {
    // F2 旁路：上限内错误体行为不变——`status>=400` 非 JSON 原样透传状态与字节（N2/D6）。
    let client = reqwest::Client::new();
    let upstream = b"too many requests".to_vec();
    let (url, server) = loopback_server(429, "text/plain", upstream.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx(Protocol::Chat),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误体须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误体须可读");
    assert_eq!(
        bytes.as_ref(),
        upstream.as_slice(),
        "上限内错误体字节须不变"
    );
}

#[tokio::test]
async fn f2_oversize_error_body_passes_through_not_rewritten_to_502() {
    // F2 精化：`status>=400` 的错误体不受上限约束——超限非 JSON 错误体
    // 按 N2/D6 原样透传状态与字节，不改写为 502 `response_too_large`。
    let client = reqwest::Client::new();
    let upstream = format!("busy: {}", "x".repeat(256)).into_bytes();
    let (url, server) = loopback_server(503, "text/plain", upstream.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx_with_cap(Protocol::Chat, 1),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误体须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误体须可读");
    assert_eq!(
        bytes.as_ref(),
        upstream.as_slice(),
        "超限错误体须字节透传，不得改写为 502 response_too_large"
    );
}
