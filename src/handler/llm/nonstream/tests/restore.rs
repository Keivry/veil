//! 非流 JSON 转义还原测试：明文含 `"`/`\`/控制字符时下游 JSON 仍可解析、
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

async fn drive(url: &str, ctx: NonstreamCtx<'_>) -> axum::http::Response<axum::body::Body> {
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
    // 请求侧脱敏铸造 token（响应还原仅授权本请求实际产出）。
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
    // 明文含 `"` 与 `\` 时下游 JSON 可解析、字段为完整明文、无占位符、
    // 不触发 `restore_fallback`。
    let (got, text, metrics) = run_restore(
        r#"{"id":"x","choices":[{"message":{"content":"<TOKEN>"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        "a\"b\\c-明文",
    )
    .await;
    assert_eq!(got["choices"][0]["message"]["content"], "a\"b\\c-明文");
    assert!(!text.contains("__CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
}

#[tokio::test]
async fn nonstream_restore_control_chars() {
    // 明文含换行/制表符时还原后 JSON 可解析且明文完整。
    let (got, text, metrics) = run_restore(
        r#"{"id":"x","choices":[{"message":{"content":"<TOKEN>"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string(),
        "line1\nline2\ttab",
    )
    .await;
    assert_eq!(got["choices"][0]["message"]["content"], "line1\nline2\ttab");
    assert!(!text.contains("__CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");

    // 明文嵌在嵌套 stringified JSON 内时，外层与内层 JSON 均可解析、
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
    assert!(!text.contains("__CRED_"), "不得残留占位符: {text}");
    assert_eq!(metrics.restore_fallback_count(), 0, "可转义不得回退");
}

/// 文本捕获订阅者：记录每条事件的「级别 + 字段渲染文本」（含 `message`）。
/// `record_u64`/`record_str` 须显式实现——否则只有经 `record_debug` 的 `message`
/// 可见，结构化字段恒不出现，断言会变空洞。
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<String>>>);

struct FieldVisitor<'a>(&'a mut String);

impl tracing::field::Visit for FieldVisitor<'_> {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value}", field.name());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={value}", field.name());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool { true }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut line = event.metadata().level().to_string();
        event.record(&mut FieldVisitor(&mut line));
        self.0.lock().unwrap().push(line);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

#[test]
fn nonstream_restore_fallback_warn_omits_restored_plaintext() {
    // PII 安全：上游把占位符回显为 stringified JSON 的**键位**时，还原后内层键
    // 由 token 变为明文，`restore_guard_ok` 的结构同构比对必然失败且 `retry_stripped`
    // 无从挽回 → 走回退分支。旧实现把 `restored` 前 4000 字符写进默认级别的 warn
    // 日志；本测试锁定「回退 warn 不泄漏还原明文、结构化字段保留、回退语义不变」。
    const CANARY: &str = "leak-canary-9f3a";
    let metrics = Arc::new(GatewayMetrics::default());
    let vault = Arc::new(CredentialVault::new());
    let token = vault.register(CANARY).expect("测试凭据须注册成功");
    let up_body = serde_json::json!({
        "id": "x",
        "choices": [{"message": {"content": format!(r#"{{"{token}":"v"}}"#)}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    })
    .to_string();
    let capture = LogCapture::default();
    let sink = capture.0.clone();
    let metrics_in_thread = metrics.clone();
    let up_body_in_thread = up_body.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("测试运行时须可构造");
        let (url, server) = rt.block_on(loopback_server(
            200,
            "application/json",
            up_body_in_thread.clone().into_bytes(),
        ));
        let bytes = crate::test_support::with_capture_subscriber(capture, || {
            rt.block_on(async {
                let detector = Arc::new(PiiDetector::new());
                let scope = Arc::new(Scope::new());
                // 请求侧脱敏铸造 token（响应还原仅授权本请求实际产出）。
                let _ = scope.redact_request(&vault, &detector, CANARY).await;
                // 前置条件（防空洞）：回退前的还原中间体确实含明文且令守卫失败。
                let (restored, spans) =
                    scope.restore_response_with_spans_json(&vault, &up_body_in_thread);
                assert!(!spans.is_empty(), "token 须被定位还原");
                assert!(
                    restored.contains(CANARY),
                    "前置条件：旧实现所记来源须含明文: {restored}"
                );
                assert!(
                    !crate::service::redaction::restore_guard::restore_guard_ok(
                        &restored,
                        &up_body_in_thread,
                        None
                    ),
                    "前置条件：该场景须令还原守卫失败"
                );
                let mut ctx = test_ctx(Protocol::Chat);
                ctx.req.scope = scope;
                ctx.req.vault = vault.clone();
                ctx.req.detector = detector;
                ctx.req.gateway_metrics = metrics_in_thread.clone();
                let client = reqwest::Client::new();
                let outcome = serve_nonstream(
                    &client,
                    reqwest::Method::POST,
                    &url,
                    axum::http::HeaderMap::new(),
                    br#"{"model":"m","messages":[]}"#.to_vec(),
                    ctx,
                )
                .await;
                let NonstreamOutcome::Responded(resp) = outcome else {
                    panic!("JSON 上游不得转流泵");
                };
                assert_eq!(resp.status(), axum::http::StatusCode::OK);
                axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .expect("响应体须可读")
                    .to_vec()
            })
        });
        server.abort();
        let logs = sink.lock().unwrap().clone();
        (bytes, logs)
    });
    let (bytes, logs) = handle.join().expect("捕获线程须正常结束");
    assert_eq!(
        metrics.restore_fallback_count(),
        1,
        "须走回退分支: {logs:?}"
    );
    let body = String::from_utf8_lossy(&bytes);
    assert_eq!(
        body.as_ref(),
        crate::service::redaction::strip_partials(&up_body),
        "回退须保留 `restored = text` 语义（出口残缺剥离后）"
    );
    assert!(!body.contains(CANARY), "下游不得泄漏明文: {body}");
    let fallback: Vec<&String> = logs
        .iter()
        .filter(|l| l.contains("已回退上游原文"))
        .collect();
    assert_eq!(fallback.len(), 1, "回退 warn 行须恰一条: {logs:?}");
    let line = fallback[0];
    assert!(!line.contains(CANARY), "warn 行不得含还原明文: {line}");
    assert!(
        line.contains("restored_len=") && line.contains("upstream_len="),
        "须保留非敏感结构化诊断字段: {line}"
    );
}
