//! 网关改写/非流集成单测（D2 自 `mod.rs` 拆出；`#[cfg(test)]` 门控，见 `mod.rs` 声明）。

use {
    super::{
        nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        rewrite::request_rewrite,
    },
    crate::{
        approval::PendingApprovals,
        config::{AuditMode, Config},
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
    std::{collections::HashMap, sync::Arc},
};

fn base_env() -> HashMap<String, String> {
    HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ])
}

fn test_config(extra: &[(&str, &str)]) -> Config {
    let mut env = base_env();
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    Config::load_from(&env).expect("测试配置须合法")
}

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
) -> NonstreamCtx {
    NonstreamCtx {
        protocol,
        normalized_out: false,
        stream_flag: false,
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
        audit_policy_file: None,
        approval_whitelist: Vec::new(),
        pending: Arc::new(PendingApprovals::default()),
        nonstream_max_bytes: crate::config::NONSTREAM_MAX_BYTES_DEFAULT,
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
    // L15：注入分支恒重序列化，声明不跟随配置开关。
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
    ctx.admin_metrics = admin.clone();
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
    // P0-1.1 回归：502/401 JSON 体走完整后处理（用量记录 + 状态保留），
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
        ctx.admin_metrics = admin.clone();
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
    // P0-1.1 显式豁免：非 JSON 的 502 体无用量可提，原样透传不转空体。
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
async fn nonstream_broken_restore_falls_back_to_upstream() {
    // P0-1.2 回归：还原把含引号明文写回 JSON 串内致破裂时，回退上游原文并 warn。
    let (scope, vault, detector) = fresh_arcs();
    let plain = "ab\"cd-ef";
    let token = vault.register(plain).expect("测试凭据须注册成功");
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
    assert_eq!(body.as_ref(), up_body.as_bytes(), "破裂还原须回退上游原文");
    assert!(
        serde_json::from_slice::<Value>(&body).is_ok(),
        "回退后下游须收到合法 JSON"
    );
    server.abort();
}

#[tokio::test]
async fn nonstream_partial_tokens_stripped_at_exit() {
    // P0-1.3 回归：凭据/PII 残缺前缀不得透出下游（含响应侧关闭旁路）。
    let scope = Arc::new(Scope::with_opts(false, false));
    let vault = Arc::new(CredentialVault::new());
    let detector = Arc::new(PiiDetector::new());
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"a __VG_CRED_00 b __PII_3_ab c"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
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
    assert!(!text.contains("__VG_CRED_00"), "凭据残缺须剥离: {text}");
    assert!(!text.contains("__PII_3_ab"), "PII 残缺须剥离: {text}");
    assert!(
        text.contains("a ") && text.contains(" c"),
        "正常文本须保留: {text}"
    );
    server.abort();
}

#[tokio::test]
async fn nonstream_approve_records_pending_and_passes_through() {
    // P0-1.4 spec 场景 + T1/T4.1：approve 非空白名单 → NeedApproval 记 pending
    // 且透传上游（仅 block 降级/deny 才合成阻断体）。
    let up_body = br#"{"id":"a1","choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
    ctx.audit_mode = AuditMode::Approve;
    ctx.approval_whitelist = vec!["@admin:example.com".to_string()];
    let pending = ctx.pending.clone();
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
    // P0-4.2：NonDialog 臂字节透传 + 计数，不做还原。
    let up_body = b"plain-nondialog-bytes".to_vec();
    let (url, server) = loopback_server(200, "text/plain", up_body).await;
    let client = reqwest::Client::new();
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = nonstream_ctx(Protocol::NonDialog, scope, vault, detector);
    ctx.gateway_metrics = metrics.clone();
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
    // E12/D7 + 7.2：无会话回退合成且记 `conv_missing`（nondialog 转泵臂同款调用）。
    let m = GatewayMetrics::default();
    let (id, _) = llm_gateway::resolve_conv_id(None, &Value::Null, Some(&m), "nondialog-stream");
    assert!(id.starts_with("unknown_"), "缺失须回退归档: {id}");
    assert_eq!(m.conv_missing_count("nondialog-stream"), 1);
}

#[tokio::test]
async fn nonstream_upstream_400_passthrough_without_swallowing_error() {
    // D5 回归：`truncation:disabled` 类上游 400 错误体须原样透出（状态码与正文），
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
