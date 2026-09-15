#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "nonstream.rs",
        include_str!("../nonstream.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "nonstream/tests.rs",
        include_str!("tests.rs"),
    );
}

use {
    super::{NonstreamCtx, NonstreamOutcome, serve_nondialog_passthrough, serve_nonstream},
    crate::{
        approval::PendingApprovals,
        config::{AuditMode, Config},
        handler::llm::pump::RequestCtx,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{self, EmptyAction, Protocol, classify_empty},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::{self, Scope},
        },
    },
    std::{collections::HashMap, sync::Arc, time::Instant},
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

fn test_config() -> Config { Config::load_from(&base_env()).expect("测试配置须合法") }

fn test_ctx(protocol: Protocol) -> NonstreamCtx {
    let _ = test_config();
    NonstreamCtx {
        req: RequestCtx {
            protocol,
            normalized_out: false,
            scope: Arc::new(Scope::new()),
            vault: Arc::new(CredentialVault::new()),
            detector: Arc::new(PiiDetector::new()),
            gateway_metrics: Arc::new(llm_gateway::GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-nonstream-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            audit_mode: AuditMode::Off,
            audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
            approval_whitelist: Vec::new(),
            audit_sink: crate::service::audit::AuditSink::test_arc(),
            pending: Arc::new(PendingApprovals::default()),
        },
        stream_flag: false,
        nonstream_max_bytes: crate::config::NONSTREAM_MAX_BYTES_DEFAULT,
    }
}

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
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
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

#[tokio::test]
async fn nondialog_passthrough_single_entry_returns_response() {
    // H11/D11：专用透传入口返回 `Response`（类型无 `Stream` 臂）；上游意外回
    // SSE 亦按字节透传、不解析，计数照常。
    let up_body = b"data: {\"x\":1}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", up_body.clone()).await;
    let client = reqwest::Client::new();
    let metrics = Arc::new(llm_gateway::GatewayMetrics::default());
    let resp = serve_nondialog_passthrough(
        &client,
        reqwest::Method::GET,
        &url,
        axum::http::HeaderMap::new(),
        Vec::new(),
        Protocol::NonDialog,
        &metrics,
    )
    .await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    assert_eq!(
        body.as_ref(),
        up_body.as_slice(),
        "NonDialog 透传须字节一致"
    );
    assert_eq!(metrics.nondialog_passthrough_count(), 1, "透传须计数");
    server.abort();
}

#[test]
fn llm_empty_1_empty_body_maps_to_502() {
    // T2-1：空体（len 0）非流转 502；空体响应体为 E_EMPTY_BODY/502。
    assert_eq!(
        classify_empty(true, 0, false, 200),
        EmptyAction::NonStreamTo502
    );
    assert_eq!(
        classify_empty(true, 0, true, 200),
        EmptyAction::NonStreamTo502,
        "JSON 与否不影响空体转 502"
    );
}

#[test]
fn llm_empty_2_hallucinated_cred_stripped_to_blank_is_502() {
    // T2-2：仅幻觉凭据 token 经 strip 后空白 → 502（PII 完整形态保留不计入）。
    let vault = CredentialVault::new();
    let cleaned = redaction::strip_token_forms(&vault, "__VG_CRED_000007__");
    assert!(
        cleaned.trim().is_empty(),
        "幻觉凭据剥离后须空白，实际 {cleaned:?}"
    );
    assert_eq!(
        classify_empty(true, cleaned.len(), false, 200),
        EmptyAction::NonStreamTo502
    );
}

#[test]
fn llm_empty_3_complete_pii_token_kept_after_strip() {
    // T2-3：完整 PII token（响应期新 token）在出口保留，不触发 502。
    let vault = CredentialVault::new();
    let kept = redaction::strip_token_forms(&vault, "__PII_7_ab12cd34__");
    assert!(
        kept.contains("__PII_7_ab12cd34__"),
        "完整 PII token 须保留，实际 {kept:?}"
    );
}

#[test]
fn llm_empty_4_normal_text_not_502() {
    // T2-4：正常 JSON 文本 strip 后非空 → PassthroughOk，不转 502。
    let vault = CredentialVault::new();
    let body = r#"{"content":"hello world 正常响应"}"#;
    let out = redaction::strip_token_forms(&vault, body);
    assert!(out.contains("hello world"));
    assert_eq!(
        classify_empty(true, out.len(), true, 200),
        EmptyAction::PassthroughOk
    );
    // 非 JSON 载荷非流恒转 502（无 JSON 可提取用量/工具调用）。
    assert_eq!(
        classify_empty(true, out.len(), false, 200),
        EmptyAction::NonStreamTo502
    );
}

#[test]
fn llm_empty_5_error_status_never_maps_to_502() {
    // N2/D6：4xx/5xx 恒豁免 502 映射——JSON 走完整后处理链，非 JSON（含空体）
    // 原样透传状态码与正文字节。
    for status in [502u16, 401, 429, 500, 404] {
        assert_eq!(
            classify_empty(true, 0, false, status),
            EmptyAction::PassthroughErrorStatus,
            "status={status} 不应转 NonStreamTo502"
        );
    }
    // 2xx 非 JSON/空体维持现值（合成 502 空体）。
    assert_eq!(
        classify_empty(true, 0, false, 200),
        EmptyAction::NonStreamTo502
    );
}

#[test]
fn llm_empty_6_stream_zero_frames_still_synthesizes() {
    // T2-6：流式零帧发出（含 hold 缓冲吞帧）仍合成空流兜底。
    assert!(super::super::pump::should_synthesize_empty_stream(
        false, false, false
    ));
    assert!(!super::super::pump::should_synthesize_empty_stream(
        false, true, false
    ));
    assert!(!super::super::pump::should_synthesize_empty_stream(
        true, false, false
    ));
    assert!(!super::super::pump::should_synthesize_empty_stream(
        false, false, true
    ));
}

#[test]
fn llm_empty_7_nondialog_exempt_from_empty_mapping() {
    // T2-7：非对话路径豁免空体映射（字节透传）。
    assert_eq!(
        classify_empty(false, 0, false, 200),
        EmptyAction::NonDialogExempt
    );
}

mod f2;
mod gate_boundary;
mod headers;
mod nlp_error_sse;
mod nlp_p2;
mod restore;
mod t4_bounded;
#[tokio::test]
async fn llm_empty_e2e_upstream_empty_body_returns_502() {
    // T2-E2E：上游空体经 serve_nonstream 返回 502（回环，无外网）。
    let client = reqwest::Client::new();
    let (url, server) = loopback_server(200, "application/json", vec![]).await;
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
        panic!("空体上游须直接响应而非转流");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn b3_upstream_empty_and_blank_bodies_return_502() {
    // B3.1：上游空体与 strip 后空体（仅空格/仅换行/空格换行混合）e2e 均 502，
    // 错误码 E_EMPTY_BODY，不透传空 200。
    let client = reqwest::Client::new();
    for raw in [
        vec![],
        b"   ".to_vec(),
        b"\n".to_vec(),
        b"  \n \r\n ".to_vec(),
    ] {
        let (url, server) = loopback_server(200, "application/json", raw.clone()).await;
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
            panic!("空体上游须直接响应而非转流，输入 {raw:?}");
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::BAD_GATEWAY,
            "输入 {raw:?}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("502 体须可读");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("E_EMPTY_BODY"), "输入 {raw:?} 实际 {text}");
    }
}

#[tokio::test]
async fn b3_nonempty_body_unaffected_passthrough() {
    // B3.1：非空体不受影响，仍按原语义透传（200 + 原文）。
    let client = reqwest::Client::new();
    let upstream =
        br#"{"id":"cmpl-1","model":"m","choices":[{"message":{"content":"hi"}}]}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", upstream).await;
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
        panic!("非空 JSON 上游须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
}

#[test]
fn b3_zero_bytes_gate_goes_502() {
    // B3.2：bytes.len()==0 守门走 502 分支（JSON 与否无关）。
    assert_eq!(
        classify_empty(true, 0, false, 200),
        EmptyAction::NonStreamTo502
    );
    assert_eq!(
        classify_empty(true, 0, true, 200),
        EmptyAction::NonStreamTo502
    );
}

#[test]
fn b3_single_byte_valid_json_not_misjudged() {
    // B3.2：非零字节不误判——单字节合法 JSON（`1`）通过守门。
    assert_eq!(
        classify_empty(true, 1, true, 200),
        EmptyAction::PassthroughOk
    );
}

#[test]
fn p2_quoted_whitespace_string_is_valid_json_passthrough() {
    // P2：合法 JSON 空白串（带引号的 `"   "`，值为三空格字符串）不得误判为空体。
    // 与 B3 裸空白（`   ` 无引号，非 JSON → 502）对称：引号在则 `is_json=true`
    // 且 `len>0`，当前语义为 `PassthroughOk`；锁定防未来 strip 误改。
    let raw = br#""   ""#.to_vec();
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_ok());
    assert_eq!(
        classify_empty(true, raw.len(), true, 200),
        EmptyAction::PassthroughOk
    );
}

#[tokio::test]
async fn block_verdict_2xx_synthesizes_200_block_body() {
    // T4.3/T3：上游 2xx + 危险调用命中 Block，下游回 200 + 阻断体（既有声明行为）。
    let client = reqwest::Client::new();
    let body = br#"{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}]}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", body).await;
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.audit_mode = AuditMode::Block;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("阻断须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("阻断体须可读");
    assert!(
        String::from_utf8_lossy(&bytes).contains("[blocked:"),
        "须为阻断体而非上游原文"
    );
}

#[tokio::test]
async fn block_verdict_error_status_preserves_upstream_body_and_records_audit() {
    // T4.4/T3：上游 400/500 JSON 体含危险调用 + Block 判定：状态与正文保留
    //（不合成 200 阻断体），审计照记（`audit_blocks` 指标 + warn 日志）。
    let client = reqwest::Client::new();
    for status in [400u16, 500] {
        let upstream = serde_json::json!({
            "error": {"message": format!("upstream failed {status}"), "type": "invalid_request_error"},
            "choices": [{"message": {"tool_calls": [{"id": "c1", "function": {"name": "exec", "arguments": "rm -rf /"}}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        });
        let up_body = serde_json::to_vec(&upstream).unwrap();
        let db = std::path::PathBuf::from(format!("/tmp/veil-t4-4-{status}.sqlite"));
        let _ = std::fs::remove_file(&db);
        let admin = Arc::new(MetricsStore::new(db));
        let (url, server) = loopback_server(status, "application/json", up_body).await;
        let mut ctx = test_ctx(Protocol::Chat);
        ctx.req.audit_mode = AuditMode::Block;
        ctx.req.admin_metrics = admin.clone();
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            axum::http::HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            ctx,
        )
        .await;
        server.abort();
        let NonstreamOutcome::Responded(resp) = outcome else {
            panic!("错误状态 JSON 上游不得转流泵，status={status}");
        };
        assert_eq!(
            resp.status().as_u16(),
            status,
            "错误状态须保留，不得合成 200 阻断体"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("错误正文须可读");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("[blocked:"),
            "status={status} 错误正文不得被阻断体替换: {text}"
        );
        assert!(
            text.contains(&format!("upstream failed {status}")),
            "status={status} 上游正文须保留: {text}"
        );
        admin.flush_to_sqlite_blocking().expect("指标刷盘须成功");
        let pts = admin
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .expect("时序查询须成功");
        assert_eq!(
            pts[0].audit_blocks, 1,
            "status={status} 错误响应内危险调用须记 audit_blocks",
        );
    }
}

#[tokio::test]
async fn block_inject_status_symmetric_all_protocols() {
    // E4/T4.3 三协议对称：Chat/Anthropic/Responses 2xx 非流阻断恒为 200 + 阻断体。
    let client = reqwest::Client::new();
    let cases = [
            (
                Protocol::Chat,
                br#"{"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"exec","arguments":"rm -rf /"}}]}}]}"#.to_vec(),
            ),
            (
                Protocol::Anthropic,
                br#"{"content":[{"type":"tool_use","id":"a1","name":"exec","input":{"cmd":"rm -rf /"}}]}"#.to_vec(),
            ),
            (
                Protocol::Responses,
                br#"{"output":[{"type":"function_call","id":"f1","name":"exec","arguments":"rm -rf /"}]}"#.to_vec(),
            ),
        ];
    for (protocol, upstream_body) in cases {
        let (url, server) = loopback_server(200, "application/json", upstream_body).await;
        let mut ctx = test_ctx(protocol);
        ctx.req.audit_mode = AuditMode::Block;
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
            panic!("{protocol:?} 阻断须直接响应");
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "{protocol:?} 须恒 200"
        );
    }
}

#[test]
fn nonstream_restore_retry_stripped_rescues_partial_tail() {
    // E5/D3 挽回：破裂体剥离残缺后可解析 → 返回剥离体而非原文。
    let rescued = super::retry_stripped(r#"{"id":"x"} __VG_CRED_00"#).expect("剥离后合法须挽回");
    assert!(!rescued.contains("__VG_CRED_00"), "残缺须剥离: {rescued}");
    assert!(serde_json::from_str::<serde_json::Value>(&rescued).is_ok());
}

#[test]
fn nonstream_restore_retry_stripped_gives_up_on_quote_break() {
    // E5/D3 回退：引号破裂剥离无法修复 → None（调用方回退原文并记 metrics）。
    assert!(super::retry_stripped(r#"{"content":"ab"cd"}"#).is_none());
}

#[tokio::test]
async fn nonstream_400_json_traverses_post_processing_e6() {
    // E6/D4：400 系 JSON 走完整后处理（用量记录 + 状态保留），非字节等价有意为之。
    let admin = Arc::new(MetricsStore::new(std::path::PathBuf::from(
        "/tmp/veil-e6-400-test.sqlite",
    )));
    let up_body = br#"{"error":{"message":"truncation with disabled is not supported","type":"invalid_request_error"}}"#.to_vec();
    let (url, server) = loopback_server(400, "application/json", up_body).await;
    let client = reqwest::Client::new();
    let mut ctx = test_ctx(Protocol::Chat);
    ctx.req.admin_metrics = admin.clone();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("400 错误体不得转流泵");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("响应体须可读");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("truncation"), "错误正文须透出: {text}");
    assert_eq!(
        admin.ring_len(),
        1,
        "400 JSON 体须记一条 record_chat 用量快照（后处理证据）"
    );
}

#[tokio::test]
async fn nonstream_to_stream_carries_request_conv_e12() {
    // E12/D7：转泵分支透传请求会话标识，不再空值合成；缺失为 None。
    let client = reqwest::Client::new();
    let sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"id":"chatcmpl-req-9","model":"m","messages":[]}"#.to_vec(),
        test_ctx(Protocol::Chat),
    )
    .await;
    server.abort();
    let NonstreamOutcome::Stream(_, req_conv) = outcome else {
        panic!("SSE 上游须转流泵");
    };
    assert_eq!(req_conv.as_deref(), Some("chatcmpl-req-9"));
    let (url2, server2) =
        loopback_server(200, "text/event-stream", b"data: [DONE]\n\n".to_vec()).await;
    let outcome2 = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url2,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","messages":[]}"#.to_vec(),
        test_ctx(Protocol::Chat),
    )
    .await;
    server2.abort();
    let NonstreamOutcome::Stream(_, req_conv2) = outcome2 else {
        panic!("SSE 上游须转流泵");
    };
    assert!(req_conv2.is_none(), "无会话请求透传 None，由调用方回退合成");
}

#[tokio::test]
async fn llm_empty_e2e_error_status_passthrough_not_502_shape() {
    // T2-E2E：上游 401 非 JSON 体原样透传 401（不吞错转 502 空体）。
    let client = reqwest::Client::new();
    let (url, server) = loopback_server(401, "text/plain", b"unauthorized".to_vec()).await;
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
        panic!("401 上游须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn non_json_error_passthrough() {
    // N2/D6 2.1：429 `text/plain` 非 JSON 体原样透传，状态码与正文字节逐字节一致。
    let client = reqwest::Client::new();
    let body = b"slow down, rate limited".to_vec();
    let (url, server) = loopback_server(429, "text/plain", body.clone()).await;
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
        panic!("非 JSON 错误体须直接响应而非转流泵");
    };
    assert_eq!(
        resp.status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "429 状态码须保留，不得被替换为 502"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("错误正文须可读");
    assert_eq!(bytes.as_ref(), body.as_slice(), "正文字节须逐字节一致");
}

#[tokio::test]
async fn error_status_non_json() {
    // N2/D6 2.2：500 HTML 与 404 非 JSON 体（含空体错误）均保留状态与正文，不被替换为 502。
    let client = reqwest::Client::new();
    for (status, ctype, body) in [
        (
            500u16,
            "text/html",
            b"<html><body>internal error</body></html>".to_vec(),
        ),
        (404, "text/plain", b"no such model".to_vec()),
        (500, "text/plain", Vec::new()),
    ] {
        let (url, server) = loopback_server(status, ctype, body.clone()).await;
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
            panic!("非 JSON 错误体须直接响应而非转流泵，status={status}");
        };
        assert_eq!(
            resp.status().as_u16(),
            status,
            "status={status} 须保留，不得替换为 502"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("错误正文须可读");
        assert_eq!(
            bytes.as_ref(),
            body.as_slice(),
            "status={status} 正文字节须一致"
        );
    }
}

#[tokio::test]
async fn web_search_action_audit_hold_nonstream() {
    // F11/D11：`web_search_call.action.query` 经非流完整审计 hold 进入判定，与流式同结论。
    let client = reqwest::Client::new();
    let body = br#"{"output":[{"type":"web_search_call","id":"ws-bad","action":{"type":"search","query":"rm -rf /"}}]}"#.to_vec();
    let (url, server) = loopback_server(200, "application/json", body).await;
    let mut ctx = test_ctx(Protocol::Responses);
    ctx.req.audit_mode = AuditMode::Block;
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        axum::http::HeaderMap::new(),
        br#"{"model":"m","input":"hi"}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    let NonstreamOutcome::Responded(resp) = outcome else {
        panic!("阻断须直接响应");
    };
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("阻断体须可读");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("[blocked:"),
        "危险检索查询须合成阻断体: {text}"
    );
    assert!(
        !text.contains("rm -rf"),
        "危险查询明文不得出现在下游: {text}"
    );
}
