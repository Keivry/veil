//! 网关改写/非流集成单测（自 `mod.rs` 拆出；`#[cfg(test)]` 门控，见 `mod.rs` 声明）。

use {
    super::super::{
        RequestCtx,
        nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        rewrite::request_rewrite,
        test_support::{expand_ctx, no_expand, test_config},
    },
    crate::{
        approval::PendingApprovals,
        config::{AuditMode, HeaderValueSegment, HeaderValueSpec, UpstreamOverrides},
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{self, GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
        },
    },
    axum::http::{HeaderMap, StatusCode},
    serde_json::Value,
    std::sync::Arc,
};

fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
    (
        Arc::new(Scope::new()),
        Arc::new(CredentialVault::new()),
        Arc::new(PiiDetector::new()),
    )
}

fn nonstream_ctx(
    protocol: Protocol,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> NonstreamCtx<'static> {
    NonstreamCtx {
        req: RequestCtx {
            protocol,
            normalized_out: false,
            redact_only: false,
            redaction_tally: Default::default(),
            scope,
            vault,
            detector,
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: std::time::Instant::now(),
            audit_mode: AuditMode::Off,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            pending: Arc::new(PendingApprovals::default()),
        },
        stream_flag: false,
        nonstream_max_bytes: crate::config::NONSTREAM_MAX_BYTES_DEFAULT,
        overrides: None,
        expand: no_expand(),
    }
}

/// 回环上游：固定状态码/内容类型/体，供非流与流泵回放单测（无外网依赖）。
async fn loopback_server(
    status: u16,
    content_type: &str,
    body: Vec<u8>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        502 => "Bad Gateway",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&body).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, handle)
}

/// 预留端口后立即释放，后续连接恒被拒绝（超时/不可达映射单测用）。
async fn refused_url() -> String {
    let port = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功")
        .local_addr()
        .expect("回环地址须可读")
        .port();
    format!("http://127.0.0.1:{port}/v1/chat/completions")
}

#[tokio::test]
async fn rewrite_default_byte_equivalent_without_network() {
    let config = test_config(&[]);
    assert!(!config.normalize_json_whitespace);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"hello"}]}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert_eq!(out.body, raw, "默认关闭空白压缩时除 token 替换外须字节等价");
    assert!(!out.normalized_out);
    assert!(!out.stream_flag);
    assert!(out.init_conv.is_none());
}

#[tokio::test]
async fn redaction_disabled_passthrough_original_request() {
    let config = test_config(&[("REDACTION_ENABLED", "0")]);
    assert!(!config.redaction_enabled);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert_eq!(
        out.body, raw,
        "显式关闭脱敏时含 PII 请求须原文透传，防旧 compose 静默变严"
    );
}

#[tokio::test]
async fn rewrite_injects_stream_options_and_declares_normalization() {
    let config = test_config(&[("NORMALIZE_JSON_WHITESPACE", "1")]);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","stream":true,"messages":[]}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert!(out.stream_flag);
    assert!(out.normalized_out);
    let v: Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
    assert_eq!(
        v.get("stream_options")
            .and_then(|o| o.get("include_usage"))
            .and_then(|b| b.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn rewrite_injection_declares_normalization_without_config_flag() {
    // 注入分支恒重序列化，声明不跟随配置开关。
    let config = test_config(&[]);
    assert!(!config.normalize_json_whitespace);
    let (scope, vault, detector) = fresh_arcs();
    let raw = br#"{"model":"m","stream":true,"messages":[]}"#;
    let out = request_rewrite(
        raw.to_vec(),
        Protocol::Chat,
        &config,
        scope,
        vault,
        detector,
    )
    .await;
    assert!(out.stream_flag);
    assert!(
        out.normalized_out,
        "stream 注入已重序列化，须声明 normalized"
    );
    let v: Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
    assert_eq!(
        v.get("stream_options")
            .and_then(|o| o.get("include_usage"))
            .and_then(|b| b.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn nonstream_forward_success_returns_verbatim() {
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let admin = Arc::new(MetricsStore::new(std::path::PathBuf::from(
        "/tmp/veil-gateway-units-test.sqlite",
    )));
    let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.admin_metrics = admin.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("JSON 上游不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-veil-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("chat")
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert!(
        body.windows(2).any(|w| w == b"hi"),
        "响应体须原样返回上游内容"
    );
    assert_eq!(admin.ring_len(), 1, "非流成功须记一条 record_chat 快照");
    server.abort();
}

#[tokio::test]
async fn nonstream_error_status_traverses_post_processing() {
    // 回归：502/401 JSON 体走完整后处理（用量记录 + 状态保留），
    // 不再早返原始字节跳过用量/审计/还原。
    for status in [502u16, 401u16] {
        let up_body = br#"{"id":"e1","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}"#.to_vec();
        let (url, server) = loopback_server(status, "application/json", up_body).await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let admin = Arc::new(MetricsStore::new(std::path::PathBuf::from(
            "/tmp/veil-gateway-units-test.sqlite",
        )));
        let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
        ctx.req.admin_metrics = admin.clone();
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(..) => panic!("{status} JSON 体不得转流泵"),
        };
        assert_eq!(resp.status().as_u16(), status, "错误状态码须保留");
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("hi"), "{status} 响应正文须透出: {text}");
        assert_eq!(
            admin.ring_len(),
            1,
            "{status} JSON 体须记一条 record_chat 用量快照"
        );
        server.abort();
    }
}

#[tokio::test]
async fn nonstream_error_non_json_passthrough_without_swallowing() {
    // 显式豁免：非 JSON 的 502 体无用量可提，原样透传不转空体。
    let up_body = b"upstream exploded".to_vec();
    let (url, server) = loopback_server(502, "text/plain", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("非 JSON 错误体不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert_eq!(
        body.as_ref(),
        b"upstream exploded",
        "非 JSON 错误体须原文透传"
    );
    server.abort();
}

#[tokio::test]
async fn nonstream_quote_plain_restored_escaped() {
    // 新语义：明文含引号经 JSON 转义变体还原，不再破裂回退上游原文；
    // 下游 JSON 可解析且字段为完整明文、无占位符。
    let (scope, vault, detector) = fresh_arcs();
    let plain = "ab\"cd-ef";
    let token = vault.register(plain).expect("测试凭据须注册成功");
    // 请求侧脱敏铸造 token（响应还原仅授权本请求实际产出）。
    let _ = scope.redact_request(&vault, &detector, plain).await;
    let up_body = format!(
        "{{\"id\":\"x\",\"choices\":[{{\"message\":{{\"content\":\"{token}\"}}}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}}}"
    );
    assert!(
        serde_json::from_str::<Value>(&up_body).is_ok(),
        "上游原文须为合法 JSON"
    );
    let (url, server) =
        loopback_server(200, "application/json", up_body.clone().into_bytes()).await;
    let client = reqwest::Client::new();
    let ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("JSON 上游不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let got: Value = serde_json::from_slice(&body).expect("还原后下游须收到合法 JSON");
    assert_eq!(
        got["choices"][0]["message"]["content"], plain,
        "字段须为完整明文"
    );
    assert!(
        !String::from_utf8_lossy(&body).contains("__CRED_"),
        "不得残留占位符"
    );
    assert_ne!(
        body.as_ref(),
        up_body.as_bytes(),
        "须完成还原（含转义），不得原样回退上游 token 原文"
    );
    server.abort();
}

#[tokio::test]
async fn nonstream_partial_tokens_stripped_at_exit() {
    // 回归：凭据/PII 残缺前缀不得透出下游。
    let scope = Arc::new(Scope::with_opts(false));
    let vault = Arc::new(CredentialVault::new());
    let detector = Arc::new(PiiDetector::new());
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"a __CRED_00 b __PII_3_ab c"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("JSON 上游不得转流泵"),
    };
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("__CRED_00"), "凭据残缺须剥离: {text}");
    assert!(!text.contains("__PII_3_ab"), "PII 残缺须剥离: {text}");
    assert!(
        text.contains("a ") && text.contains(" c"),
        "正常文本须保留: {text}"
    );
    server.abort();
}

#[tokio::test]
async fn nonstream_approve_records_pending_and_passes_through() {
    // approve 非空白名单 → NeedApproval 记 pending
    // 且透传上游（仅 block 降级/deny 才合成阻断体）。
    let up_body = br#"{"id":"a1","choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req.audit_mode = AuditMode::Approve;
    ctx.req.approval_whitelist = vec!["@admin:example.com".to_string()];
    let pending = ctx.req.pending.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("JSON 上游不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("rm -rf /"), "approve 须透传上游响应: {text}");
    assert!(
        !text.contains("[blocked:"),
        "approve 不得合成阻断体: {text}"
    );
    assert_eq!(pending.len(), 1, "approve 命中须有 pending 建单");
    server.abort();
}

#[tokio::test]
async fn nondialog_arm_passes_through_with_count() {
    // NonDialog 臂字节透传 + 计数，不做还原。
    let up_body = b"plain-nondialog-bytes".to_vec();
    let (url, server) = loopback_server(200, "text/plain", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = nonstream_ctx(Protocol::NonDialog, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::GET,
        &url,
        HeaderMap::new(),
        Vec::new(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("纯文本上游不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert_eq!(
        body.as_ref(),
        b"plain-nondialog-bytes",
        "非对话体须字节透传"
    );
    assert_eq!(metrics.nondialog_passthrough_count(), 1, "透传须计数");
    server.abort();
}

#[tokio::test]
async fn nonstream_upstream_unreachable_maps_to_502_without_hanging() {
    let url = refused_url().await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let ctx = nonstream_ctx(Protocol::NonDialog, scope, vault, detector);
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::GET,
        &url,
        HeaderMap::new(),
        Vec::new(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("不可达上游不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert!(
        body.windows(12).any(|w| w == b"E_EMPTY_BODY"),
        "网关级错误码须为 E_EMPTY_BODY"
    );
}

#[test]
fn nondialog_stream_missing_conv_archived_with_count_e12() {
    // 无会话回退合成且记 `conv_missing`（nondialog 转泵臂同款调用）。
    let m = GatewayMetrics::default();
    let (id, _) = llm_gateway::resolve_conv_id(None, &Value::Null, Some(&m), "nondialog-stream");
    assert!(id.starts_with("unknown_"), "缺失须回退归档: {id}");
    assert_eq!(m.conv_missing_count("nondialog-stream"), 1);
}

#[tokio::test]
async fn nonstream_upstream_400_passthrough_without_swallowing_error() {
    // 回归：`truncation:disabled` 类上游 400 错误体须原样透出（状态码与正文），
    // 不得吞错转 502/空体。
    let up_body = br#"{"error":{"message":"truncation with disabled is not supported","type":"invalid_request_error"}}"#.to_vec();
    let (url, server) = loopback_server(400, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let ctx = nonstream_ctx(Protocol::Responses, scope, vault, detector);
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        br#"{"model":"m","truncation":"disabled"}"#.to_vec(),
        ctx,
    )
    .await;
    let resp = match outcome {
        NonstreamOutcome::Responded(r) => r,
        NonstreamOutcome::Stream(..) => panic!("400 错误体不得转流泵"),
    };
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("truncation"), "错误正文须透出: {text}");
    assert!(
        text.contains("invalid_request_error"),
        "错误类型须透出: {text}"
    );
    server.abort();
}

#[test]
fn forward_headers_strips_accept_encoding() {
    // 下游 `accept-encoding`（含网关不支持编码与多值形态）须剥离，
    // 由 reqwest 在上游请求头缺席时注入支持集（gzip/br/deflate）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut h = HeaderMap::new();
    h.insert("accept-encoding", HeaderValue::from_static("zstd"));
    h.insert("x-real", HeaderValue::from_static("keep"));
    let fwd = super::super::forward_headers(&h, &metrics, None, &no_expand());
    assert!(
        fwd.get("accept-encoding").is_none(),
        "下游 accept-encoding 须剥离"
    );
    assert!(fwd.get("x-real").is_some(), "业务头须保留");
    let mut h2 = HeaderMap::new();
    h2.insert("accept-encoding", HeaderValue::from_static("gzip, br"));
    let fwd2 = super::super::forward_headers(&h2, &metrics, None, &no_expand());
    assert!(
        fwd2.get("accept-encoding").is_none(),
        "支持集多值同样剥离（交由 reqwest 注入）"
    );
}

#[test]
fn forward_headers_injects_config_headers_and_overrides_client_same_name() {
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-provider-version", HeaderValue::from_static("client-old"));
    client.insert("x-unrelated", HeaderValue::from_static("keep"));
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "X-Provider-Version"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config-new").into(),
    );
    overrides.headers.insert(
        "anthropic-version"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("2023-06-01").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("x-provider-version").and_then(|v| v.to_str().ok()),
        Some("config-new"),
        "配置头须覆盖客户端同名头（大小写不敏感）"
    );
    assert_eq!(
        fwd.get("anthropic-version").and_then(|v| v.to_str().ok()),
        Some("2023-06-01"),
        "配置头须注入转发头集"
    );
    assert_eq!(
        fwd.get("x-unrelated").and_then(|v| v.to_str().ok()),
        Some("keep"),
        "未冲突客户端头须原样保留"
    );
}

#[test]
fn forward_headers_config_headers_applied_after_filters() {
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("host", HeaderValue::from_static("downstream.example"));
    client.insert("connection", HeaderValue::from_static("keep-alive"));
    client.insert("accept-encoding", HeaderValue::from_static("zstd"));
    client.insert("x-veil-protocol", HeaderValue::from_static("chat"));
    // 直接构造覆盖：生产硬拒清单禁止声明 `connection`/`x-veil-*`，此处为
    // 「应用顺序在过滤之后」的机械探针——若前移到过滤前，下列断言即失败。
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "connection"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("close").into(),
    );
    overrides.headers.insert(
        "x-provider-version"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("v1").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert!(fwd.get("host").is_none(), "客户端 host 须剔除");
    assert!(
        fwd.get("accept-encoding").is_none(),
        "客户端 accept-encoding 须剥离"
    );
    assert!(
        fwd.keys().all(|k| !k.as_str().starts_with("x-veil-")),
        "客户端 x-veil-* 仍须剥离: {:?}",
        fwd.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        fwd.get("connection").and_then(|v| v.to_str().ok()),
        Some("close"),
        "配置头须在逐跳过滤之后写入（顺序探针）"
    );
    assert_eq!(
        fwd.get("x-provider-version").and_then(|v| v.to_str().ok()),
        Some("v1"),
        "配置头须存活于过滤之后"
    );
}

#[test]
fn downstream_xveil_headers_stripped() {
    // 请求向同样剔除下游 `x-veil-*`（大小写不敏感），防内部头外传上游。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut h = HeaderMap::new();
    h.insert("x-veil-protocol", HeaderValue::from_static("chat"));
    h.insert(
        "X-Veil-Normalized",
        HeaderValue::from_static("json-whitespace"),
    );
    h.insert("x-veil-internal-trace", HeaderValue::from_static("abc"));
    h.insert("authorization", HeaderValue::from_static("Bearer t"));
    let fwd = super::super::forward_headers(&h, &metrics, None, &no_expand());
    assert!(
        fwd.keys().all(|k| !k.as_str().starts_with("x-veil-")),
        "x-veil-* 不得外传: {:?}",
        fwd.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        fwd.get("authorization").map(|v| v.to_str().unwrap()),
        Some("Bearer t"),
        "业务头须保留"
    );
}

#[test]
fn forward_headers_merge_mode_preserves_client_same_name_header() {
    // task 2.1：合并模式（override_existing = false）客户端同名头（任意大小写）
    // 原样保留；缺失配置头新增；其余客户端头不动。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("Anthropic-Version", HeaderValue::from_static("client-2024"));
    client.insert("x-unrelated", HeaderValue::from_static("keep"));
    let mut overrides = UpstreamOverrides {
        override_existing: false,
        ..UpstreamOverrides::default()
    };
    overrides.headers.insert(
        "anthropic-version"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config-2023").into(),
    );
    overrides.headers.insert(
        "x-upstream-feature"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("added").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("anthropic-version").and_then(|v| v.to_str().ok()),
        Some("client-2024"),
        "合并模式客户端同名头须原样保留（大小写不敏感）"
    );
    assert_eq!(
        fwd.get("x-upstream-feature").and_then(|v| v.to_str().ok()),
        Some("added"),
        "客户端缺失的配置头须新增"
    );
    assert_eq!(
        fwd.get("x-unrelated").and_then(|v| v.to_str().ok()),
        Some("keep"),
        "其余客户端头须原样保留"
    );
}

#[test]
fn forward_headers_merge_mode_keeps_all_client_values() {
    // task 2.1：客户端多值条目（同名多值）在合并模式下须整体保留，不被配置折叠。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.append("x-multi", HeaderValue::from_static("a"));
    client.append("x-multi", HeaderValue::from_static("b"));
    let mut overrides = UpstreamOverrides {
        override_existing: false,
        ..UpstreamOverrides::default()
    };
    overrides.headers.insert(
        "x-multi"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    let values: Vec<&str> = fwd
        .get_all("x-multi")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert_eq!(values, vec!["a", "b"], "客户端多值条目须整体保留");
}

#[test]
fn forward_headers_override_mode_still_inserts_over_client_value() {
    // task 2.1 对照：恒胜模式（override_existing = true）仍须覆盖客户端同名头。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert("x-provider-version", HeaderValue::from_static("client-old"));
    // 恒胜模式为 `UpstreamOverrides` 缺省（override_existing = true）。
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-provider-version"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("config-new").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("x-provider-version").and_then(|v| v.to_str().ok()),
        Some("config-new"),
        "恒胜模式须覆盖客户端同名头"
    );
}

#[test]
fn forward_headers_user_agent_force_overrides_in_all_mode_combinations() {
    // task 2.1：UA 恒胜覆盖——override = true/false × 客户端带 UA/不带 UA 四组合，
    // 出站均为配置值且仅单值（客户端多值同样被替换为单一值）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    for config_wins in [true, false] {
        for client_ua in [Some("client-ua/1.0"), None] {
            let mut client = HeaderMap::new();
            if let Some(ua) = client_ua {
                client.append("User-Agent", HeaderValue::from_static(ua));
                client.append("User-Agent", HeaderValue::from_static("second-ua/0.1"));
            }
            let mut overrides = UpstreamOverrides {
                override_existing: config_wins,
                ..UpstreamOverrides::default()
            };
            overrides.user_agent = Some(HeaderValue::from_static("opencode/1.18.33"));
            let fwd =
                super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
            let values: Vec<&str> = fwd
                .get_all("user-agent")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            assert_eq!(
                values,
                vec!["opencode/1.18.33"],
                "override = {config_wins}、客户端 UA = {client_ua:?} 时出站 UA 须为配置单值"
            );
        }
    }
}

#[test]
fn forward_headers_user_agent_none_keeps_client_semantics() {
    // task 2.1：未声明 user_agent（None）时 UA 装配零变化——客户端值原样保留；
    // 客户端未发送时结果不含 UA（对照：其它配置头仍按既有语义注入）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-upstream-feature"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("added").into(),
    );
    let mut client = HeaderMap::new();
    client.insert("user-agent", HeaderValue::from_static("client-ua/1.0"));
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("user-agent").and_then(|value| value.to_str().ok()),
        Some("client-ua/1.0"),
        "None 时客户端 UA 须原样保留（即便同时注入其它配置头）"
    );
    let bare = HeaderMap::new();
    let fwd_bare = super::super::forward_headers(&bare, &metrics, Some(&overrides), &no_expand());
    assert!(
        fwd_bare.get("user-agent").is_none(),
        "None 且客户端未发送时结果不得含 UA（零变化断言）"
    );
    assert_eq!(
        fwd_bare
            .get("x-upstream-feature")
            .and_then(|value| value.to_str().ok()),
        Some("added"),
        "对照：配置头仍按既有语义注入"
    );
}

#[test]
fn forward_headers_user_agent_does_not_affect_other_headers() {
    // task 2.1：UA 覆盖不影响客户端其它头——x-opencode-* 按既有两态语义处理
    // （合并模式下客户端动态身份头保留、缺失项补齐）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut client = HeaderMap::new();
    client.insert(
        "x-opencode-session",
        HeaderValue::from_static("ses_dynamic"),
    );
    let mut overrides = UpstreamOverrides {
        override_existing: false,
        ..UpstreamOverrides::default()
    };
    overrides.user_agent = Some(HeaderValue::from_static("opencode/1.18.33"));
    overrides.headers.insert(
        "x-opencode-client"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("cli").into(),
    );
    let fwd = super::super::forward_headers(&client, &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("x-opencode-session")
            .and_then(|value| value.to_str().ok()),
        Some("ses_dynamic"),
        "合并模式下客户端动态身份头须原样保留"
    );
    assert_eq!(
        fwd.get("x-opencode-client")
            .and_then(|value| value.to_str().ok()),
        Some("cli"),
        "客户端缺失的身份头须补齐"
    );
    assert_eq!(
        fwd.get("user-agent").and_then(|value| value.to_str().ok()),
        Some("opencode/1.18.33"),
        "同一配置中 UA 仍恒胜"
    );
}

#[test]
fn forward_headers_user_agent_applied_after_headers_injection() {
    // task 2.1 序位探针：机械构造「headers."user-agent" 与 user_agent 字段并存」
    // （生产加载期校验会拒启动，此处仅探针），结果须为字段值——证明字段写入
    // 在表注入之后（与既有 connection 序位探针同口径）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "user-agent"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("from-table").into(),
    );
    overrides.user_agent = Some(HeaderValue::from_static("from-field"));
    let fwd =
        super::super::forward_headers(&HeaderMap::new(), &metrics, Some(&overrides), &no_expand());
    assert_eq!(
        fwd.get("user-agent").and_then(|value| value.to_str().ok()),
        Some("from-field"),
        "字段须在 headers 注入之后写入（顺序探针）"
    );
}

#[test]
fn forward_headers_template_expands_from_inbound_sources() {
    // task 2.1：三种来源存在时展开注入并单值；`$$` 转义为字面 `$`；
    // 镜像大小写不敏感且多值取首。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut inbound = HeaderMap::new();
    inbound.insert("x-veil-conversation-id", HeaderValue::from_static("conv-1"));
    inbound.append("x-session-id", HeaderValue::from_static("sess-first"));
    inbound.append("x-session-id", HeaderValue::from_static("sess-second"));
    inbound.insert("x-request-id", HeaderValue::from_static("req-7"));
    inbound.insert(
        "X-Case-Id"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValue::from_static("case-hit"),
    );
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-opencode-session"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
    );
    overrides.headers.insert(
        "x-opencode-request"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::RequestId]),
    );
    overrides.headers.insert(
        "x-mirror"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(
            axum::http::HeaderName::from_static("x-session-id"),
        )]),
    );
    overrides.headers.insert(
        "x-mixed"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![
            HeaderValueSegment::Literal("sid-".to_string()),
            HeaderValueSegment::Conversation,
            HeaderValueSegment::Literal("-$v1".to_string()),
        ]),
    );
    overrides.headers.insert(
        "x-case"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Mirror(
            axum::http::HeaderName::from_static("x-case-id"),
        )]),
    );
    let fwd = super::super::forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx(&inbound),
    );
    assert_eq!(
        fwd.get("x-opencode-session").and_then(|v| v.to_str().ok()),
        Some("conv-1")
    );
    assert_eq!(
        fwd.get("x-opencode-request").and_then(|v| v.to_str().ok()),
        Some("req-7")
    );
    assert_eq!(
        fwd.get("x-mirror").and_then(|v| v.to_str().ok()),
        Some("sess-first"),
        "镜像须大小写不敏感取入站首值"
    );
    assert_eq!(
        fwd.get("x-mixed").and_then(|v| v.to_str().ok()),
        Some("sid-conv-1-$v1"),
        "混排与 `$$` 转义须逐段展开"
    );
    assert_eq!(
        fwd.get("x-case").and_then(|v| v.to_str().ok()),
        Some("case-hit"),
        "入站头大写书写与模板小写镜像须大小写不敏感匹配"
    );
}

#[test]
fn forward_headers_template_missing_source_skips_entry_in_both_modes() {
    // task 2.1：来源缺失 → 该条目跳过（不写/不改/删）——两态下客户端同名头
    // 按「未声明该键」处理；部分来源缺失同样整条跳过；同表其余条目照常注入。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    for config_wins in [true, false] {
        let mut overrides = UpstreamOverrides {
            override_existing: config_wins,
            ..UpstreamOverrides::default()
        };
        overrides.headers.insert(
            "x-opencode-session"
                .parse::<axum::http::HeaderName>()
                .expect("合法头名"),
            HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
        );
        overrides.headers.insert(
            "x-partial"
                .parse::<axum::http::HeaderName>()
                .expect("合法头名"),
            HeaderValueSpec::Template(vec![
                HeaderValueSegment::Literal("pre-".to_string()),
                HeaderValueSegment::Conversation,
                HeaderValueSegment::Mirror(axum::http::HeaderName::from_static("x-absent")),
            ]),
        );
        overrides.headers.insert(
            "x-static"
                .parse::<axum::http::HeaderName>()
                .expect("合法头名"),
            HeaderValueSpec::Static(HeaderValue::from_static("kept")),
        );
        let mut client = HeaderMap::new();
        client.insert("x-opencode-session", HeaderValue::from_static("client-ses"));
        let fwd = super::super::forward_headers(
            &client,
            &metrics,
            Some(&overrides),
            &expand_ctx(&HeaderMap::new()),
        );
        assert_eq!(
            fwd.get("x-opencode-session").and_then(|v| v.to_str().ok()),
            Some("client-ses"),
            "override = {config_wins}：来源缺失须等同未声明，客户端既有头不动"
        );
        assert!(
            fwd.get("x-partial").is_none(),
            "部分来源缺失须整条跳过（不产生空值）"
        );
        assert_eq!(
            fwd.get("x-static").and_then(|v| v.to_str().ok()),
            Some("kept"),
            "同表其余条目须照常注入"
        );
        let fwd_bare = super::super::forward_headers(
            &HeaderMap::new(),
            &metrics,
            Some(&overrides),
            &expand_ctx(&HeaderMap::new()),
        );
        assert!(
            fwd_bare.get("x-opencode-session").is_none(),
            "客户端未携带时同样不得注入"
        );
    }
}

#[test]
fn forward_headers_template_present_empty_source_injects_empty_value() {
    // Oracle 复审 NIT：来源头存在但值为空 →
    // 按「存在」处理，展开为空值并照常注入（与缺失跳过区分）。
    use axum::http::HeaderValue;
    let metrics = GatewayMetrics::default();
    let mut inbound = HeaderMap::new();
    inbound.insert("x-veil-conversation-id", HeaderValue::from_static(""));
    let mut overrides = UpstreamOverrides::default();
    overrides.headers.insert(
        "x-opencode-session"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![HeaderValueSegment::Conversation]),
    );
    overrides.headers.insert(
        "x-prefixed"
            .parse::<axum::http::HeaderName>()
            .expect("合法头名"),
        HeaderValueSpec::Template(vec![
            HeaderValueSegment::Literal("pre-".to_string()),
            HeaderValueSegment::Conversation,
        ]),
    );
    let fwd = super::super::forward_headers(
        &HeaderMap::new(),
        &metrics,
        Some(&overrides),
        &expand_ctx(&inbound),
    );
    assert!(
        fwd.contains_key("x-opencode-session"),
        "空来源按存在处理：须照常注入（不跳过）"
    );
    assert_eq!(
        fwd.get("x-opencode-session").and_then(|v| v.to_str().ok()),
        Some(""),
        "空来源展开为空值"
    );
    assert_eq!(
        fwd.get("x-prefixed").and_then(|v| v.to_str().ok()),
        Some("pre-"),
        "混排模板中字面段照常呈现"
    );
}
