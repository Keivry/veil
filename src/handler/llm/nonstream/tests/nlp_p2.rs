//! NLP-2/NLP-3/NLP-5 回归：model 分桶回退、错误体有界读、非流内层
//! stringified-JSON 还原守卫（拆分见测试外迁模板）。

use {
    super::{loopback_server, test_ctx},
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        handler::llm::{
            nonstream::{ErrorBody, NonstreamOutcome, read_error_body_bounded, serve_nonstream},
            pump::{RequestCtx, StreamPumpCtx},
            stream_tests::{collect_pump, fresh_arcs, loopback_server as stream_loopback},
        },
        service::{
            audit::AuditSink,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            redaction::restore_guard::restore_guard_ok,
        },
    },
    std::{path::PathBuf, sync::Arc, time::Instant},
};

#[tokio::test]
async fn model_bucket_fallback_request() {
    // NLP-2（3.3）：响应体缺失 model 时回退请求 model，不以 `unknown_model` 分桶。
    let client = reqwest::Client::new();
    let admin = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-nlp2-req-model.sqlite",
    )));
    let up_body = br#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.admin_metrics = admin.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"req-only-model","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("非流响应不得转流泵");
    };
    let _ = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let snap = admin.snapshot();
    assert_eq!(
        snap.per_model.get("req-only-model"),
        Some(&1),
        "响应缺 model 须以请求 model 分桶: {:?}",
        snap.per_model
    );
    assert!(
        !snap.per_model.contains_key("unknown_model"),
        "有请求 model 时不得落 unknown_model: {:?}",
        snap.per_model
    );
}

#[tokio::test]
async fn model_bucket_fallback_stream_and_nonstream() {
    // NLP-2：响应体缺失有效 model 时回退请求 model，流/非流同一分桶口径。
    let client = reqwest::Client::new();
    let admin = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-nlp2-model-nonstream.sqlite",
    )));
    let up_body = br#"{"choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.admin_metrics = admin.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"req-model-x","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("非流响应不得转流泵");
    };
    let _ = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let snap = admin.snapshot();
    assert_eq!(
        snap.per_model.get("req-model-x"),
        Some(&1),
        "响应缺 model 须回退请求 model: {:?}",
        snap.per_model
    );
    assert!(
        !snap.per_model.contains_key("unknown_model"),
        "有请求 model 时不得落 unknown_model: {:?}",
        snap.per_model
    );

    // 响应含 model：优先响应 model（两条路径同桶且不落 unknown_model）。
    let up_body2 = br#"{"model":"resp-model-y","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url2, server2) = loopback_server(200, "application/json", up_body2).await;
    let mut ctx2 = test_ctx(Protocol::Chat);
    ctx2.req.admin_metrics = admin.clone();
    let outcome2 = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url2,
        axum::http::HeaderMap::new(),
        br#"{"model":"req-model-x","messages":[]}"#.to_vec(),
        ctx2,
    )
    .await;
    server2.abort();
    let NonstreamOutcome::Responded(resp2) = outcome2 else {
        panic!("非流响应不得转流泵");
    };
    let _ = axum::body::to_bytes(resp2.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert_eq!(
        admin.snapshot().per_model.get("resp-model-y"),
        Some(&1),
        "响应 model 存在时须优先响应 model"
    );

    // 流式路径：帧内缺 model 时回退请求 model，与上条非流路径同桶（不落 unknown_model）。
    let sse =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
            .to_vec();
    let (url3, server3) = stream_loopback(200, "text/event-stream", sse).await;
    let upstream = client.get(&url3).send().await.expect("回环上游须可达");
    let admin_stream = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-nlp2-model-stream.sqlite",
    )));
    let (scope, vault, detector) = fresh_arcs();
    let ctx_stream = StreamPumpCtx {
        req: RequestCtx {
            protocol: Protocol::Chat,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: AuditSink::test_arc(),
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: admin_stream.clone(),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            normalized_out: false,
        },
        hold_max: 1_048_576,
        pii_boundary_chars: 64,
        init_conv: None,
        req_model: "req-model-x".to_string(),
    };
    let _ = collect_pump(upstream, ctx_stream).await;
    server3.abort();
    let snap_stream = admin_stream.snapshot();
    assert_eq!(
        snap_stream.per_model.get("req-model-x"),
        Some(&1),
        "流式路径须与请求 model 同桶: {:?}",
        snap_stream.per_model
    );
    assert!(
        !snap_stream.per_model.contains_key("unknown_model"),
        "流式路径不得落 unknown_model: {:?}",
        snap_stream.per_model
    );
}

#[tokio::test]
async fn nonstream_error_body_bounded() {
    // NLP-5/D11：错误体有界读——超限走流式转发（不全量缓冲），字节与状态保真。
    let client = reqwest::Client::new();
    let big = format!("busy: {}", "x".repeat(4096)).into_bytes();
    let (url, server) = loopback_server(500, "text/plain", big.clone()).await;
    let up = client.get(&url).send().await.expect("回环上游须可达");
    let metrics = GatewayMetrics::default();
    match read_error_body_bounded(up, 128, &metrics).await {
        ErrorBody::Oversize { prefix, .. } => {
            assert!(prefix.len() <= 128, "缓冲前缀须有界: {}", prefix.len())
        }
        ErrorBody::Complete(_) => panic!("超限错误体须走流式转发而非全量缓冲"),
    }
    server.abort();

    // e2e：大错误体状态码保留、正文字节保真（流式转发）。
    let (url2, server2) = loopback_server(500, "text/plain", big.clone()).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url2,
        axum::http::HeaderMap::new(),
        br#"{"model":"m"}"#.to_vec(),
        test_ctx(Protocol::Chat),
    )
    .await;
    server2.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误体不得转流泵");
    };
    assert_eq!(resp.status().as_u16(), 500, "错误状态须保留");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误正文须可读");
    assert_eq!(
        bytes.as_ref(),
        big.as_slice(),
        "错误体字节须保真（流式转发）"
    );
}

#[tokio::test]
async fn nonstream_error_large_body_status_unchanged() {
    // NLP-5/D11：大错误体不改写状态码（不合成 502），正文语义不变。
    let client = reqwest::Client::new();
    let big = format!("{{\"error\":\"{}\"}}", "x".repeat(4096)).into_bytes();
    let (url, server) = loopback_server(500, "application/json", big.clone()).await;
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.nonstream_max_bytes = 64;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m"}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("错误体不得转流泵");
    };
    assert_eq!(resp.status().as_u16(), 500, "状态码须保持上游原值");
    assert_ne!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误正文须可读");
    assert_eq!(bytes.as_ref(), big.as_slice(), "正文语义不变");
}

#[test]
fn nonstream_inner_json_guard() {
    // NLP-3/D12：非流守卫须递归校验内层 stringified JSON，外层合法不得掩盖内层破损。
    let placeholder = r#"{"arguments":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
    let intact = r#"{"arguments":"{\"k\":\"p@ss\"}"}"#;
    let broken = r#"{"arguments":"{\"k\":\"p@ss\"q\"}"}"#;
    assert!(
        serde_json::from_str::<serde_json::Value>(broken).is_ok(),
        "破损帧外层须仍可解析（构造前提）"
    );
    assert!(
        restore_guard_ok(intact, placeholder, None),
        "内层完好须通过"
    );
    assert!(
        !restore_guard_ok(broken, placeholder, None),
        "内层破损须拒绝"
    );
    assert!(
        restore_guard_ok(placeholder, placeholder, None),
        "占位符帧自身须通过"
    );
}

#[test]
fn nonstream_broken_inner_json() {
    // NLP-3/D12：内层破损不误还原；外层破损同样拒绝。
    let placeholder = r#"{"a":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
    let broken = r#"{"a":"{\"k\":\"x\"y\"}"}"#;
    assert!(
        serde_json::from_str::<serde_json::Value>(broken).is_ok(),
        "外层合法"
    );
    assert!(
        !restore_guard_ok(broken, placeholder, None),
        "内层破损不得误还原"
    );
    assert!(
        !restore_guard_ok("{not json", placeholder, None),
        "外层破损须拒绝"
    );
    assert!(
        restore_guard_ok(r#"{"a":"{\"k\":\"plain\"}"}"#, placeholder, None),
        "内层同构合法须通过"
    );
}
