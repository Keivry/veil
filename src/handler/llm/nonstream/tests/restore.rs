//! T6 非流 JSON 转义还原测试：明文含 `"`/`\`/控制字符时下游 JSON 仍可解析、
//! 明文完整、无占位符残留、`restore_fallback == 0`；嵌套 stringified JSON 同理。

use {
    super::{loopback_server, test_ctx},
    crate::{
        handler::llm::nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    std::sync::Arc,
};

async fn drive(url: &str, ctx: NonstreamCtx) -> axum::http::Response<axum::body::Body> {
    let client = reqwest::Client::new();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("JSON 上游不得转流泵");
    };
    resp
}

async fn body_of(resp: axum::http::Response<axum::body::Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读")
        .to_vec()
}

async fn run_restore(
    up_body: String,
    plain: &str,
) -> (serde_json::Value, String, Arc<GatewayMetrics>) {
    let metrics = Arc::new(GatewayMetrics::default());
    let vault = Arc::new(CredentialVault::new());
    let token = vault.register(plain).expect("测试凭据须注册成功");
    let up_body = up_body.replace("<TOKEN>", &token);
    let (url, server) = loopback_server(200, "application/json", up_body.into_bytes()).await;
    let detector = Arc::new(PiiDetector::new());
    let scope = Arc::new(Scope::new());
    // B3：请求侧脱敏铸造 token（响应还原仅授权本请求实际产出）。
    let _ = scope.redact_request(&vault, &detector, plain).await;
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.scope = scope;
    ctx.req.vault = vault;
    ctx.req.detector = detector;
    ctx.req.gateway_metrics = metrics.clone();
    let resp = drive(&url, ctx).await;
    server.abort();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = body_of(resp).await;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let got: serde_json::Value = serde_json::from_slice(&bytes).expect("还原后须为可解析 JSON");
    (got, text, metrics)
}

#[tokio::test]
async fn nonstream_restore_escaped_json_variant() {
    // T6/D6：明文含 `"` 与 `\` 时下游 JSON 可解析、字段为完整明文、无占位符、
    // 不触发 `restore_fallback`。
    let (got, text, metrics) = run_restore(
        r#"{"id":"x","choices":[{"message":{"content":"<TOKEN>"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        "a\"b\\c-明文",
    )
    .await;
    assert_eq!(got["choices"][0]["message"]["content"], "a\"b\\c-明文");
    assert!(!text.contains("__VG_CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
}

#[tokio::test]
async fn nonstream_restore_control_chars() {
    // T6.2：明文含换行/制表符时还原后 JSON 可解析且明文完整。
    let (got, text, metrics) = run_restore(
        r#"{"id":"x","choices":[{"message":{"content":"<TOKEN>"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        "line1\nline2\ttab",
    )
    .await;
    assert_eq!(got["choices"][0]["message"]["content"], "line1\nline2\ttab");
    assert!(!text.contains("__VG_CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");

    // T6.2：明文嵌在嵌套 stringified JSON 内时，外层与内层 JSON 均可解析、
    // 内层字段为完整明文。
    let (got, text, metrics) = run_restore(
        r#"{"id":"y","choices":[{"message":{"content":"{\"inner\":\"<TOKEN>\"}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        "nested-secret-123",
    )
    .await;
    let content = got["choices"][0]["message"]["content"]
        .as_str()
        .expect("content 须为字符串");
    let nested: serde_json::Value =
        serde_json::from_str(content).expect("嵌套 stringified JSON 须可解析");
    assert_eq!(nested["inner"], "nested-secret-123");
    assert!(!text.contains("__VG_CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
}
