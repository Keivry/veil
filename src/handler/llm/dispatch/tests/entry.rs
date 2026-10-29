//! `dispatch.rs` 入口单元测试（`entry`）：URL 拼接、入口端口解析、协议分派、
//! 与出站头透传基线等子模块测试（`dispatch/tests/` 目录约定）。

use super::super::{
    super::super::{
        AUDIT_SUBLIMIT_CEILING_BYTES,
        GATEWAY_BODY_LIMIT_BYTES,
        audit_scan_body_over_limit,
        is_event_stream,
        should_pump_stream,
    },
    *,
};

#[test]
fn shared_ctx_equivalence() {
    // 流式/非流共享同一请求上下文——重叠 14 字段取值等价。
    let req = RequestCtx {
        protocol: Protocol::Chat,
        scope: Arc::new(crate::service::redaction::Scope::new()),
        vault: Arc::new(crate::service::credential_vault::CredentialVault::new()),
        detector: Arc::new(crate::service::pii::PiiDetector::new()),
        audit_mode: crate::config::AuditMode::Off,
        audit_policy: Arc::new(crate::service::audit::AuditPolicy::default_policy()),
        approval_whitelist: vec!["@a:b".to_string()],
        audit_sink: crate::service::audit::AuditSink::test_arc(),
        gateway_metrics: Arc::new(llm_gateway::GatewayMetrics::default()),
        admin_metrics: Arc::new(crate::service::metrics::MetricsStore::new(
            std::path::PathBuf::from("/tmp/veil-shared-ctx.sqlite"),
        )),
        sqlite_precise: true,
        req_start: Instant::now(),
        pending: Arc::new(crate::approval::PendingApprovals::default()),
        normalized_out: true,
        redact_only: false,
        redaction_tally: Default::default(),
    };
    let stream = StreamPumpCtx {
        req: req.clone(),
        hold_max: 4096,
        hold_max_frames: crate::config::AUDIT_HOLD_MAX_FRAMES_DEFAULT as usize,
        sse_frame_hard_bytes: crate::config::SSE_FRAME_HARD_BYTES,
        init_conv: None,
        req_model: "m".to_string(),
        stream_log: None,
    };
    let nonstream = NonstreamCtx {
        req,
        stream_flag: true,
        nonstream_max_bytes: 8,
        overrides: None,
        expand: crate::handler::llm::test_support::no_expand(),
    };
    assert_eq!(stream.req.protocol, nonstream.req.protocol);
    assert_eq!(stream.req.audit_mode, nonstream.req.audit_mode);
    assert_eq!(
        stream.req.approval_whitelist,
        nonstream.req.approval_whitelist
    );
    assert_eq!(stream.req.sqlite_precise, nonstream.req.sqlite_precise);
    assert_eq!(stream.req.req_start, nonstream.req.req_start);
    assert_eq!(stream.req.normalized_out, nonstream.req.normalized_out);
    assert!(Arc::ptr_eq(&stream.req.scope, &nonstream.req.scope));
    assert!(Arc::ptr_eq(&stream.req.vault, &nonstream.req.vault));
    assert!(Arc::ptr_eq(&stream.req.detector, &nonstream.req.detector));
    assert!(Arc::ptr_eq(
        &stream.req.audit_policy,
        &nonstream.req.audit_policy
    ));
    assert!(Arc::ptr_eq(
        &stream.req.audit_sink,
        &nonstream.req.audit_sink
    ));
    assert!(Arc::ptr_eq(
        &stream.req.gateway_metrics,
        &nonstream.req.gateway_metrics
    ));
    assert!(Arc::ptr_eq(
        &stream.req.admin_metrics,
        &nonstream.req.admin_metrics
    ));
    assert!(Arc::ptr_eq(&stream.req.pending, &nonstream.req.pending));
}

#[test]
fn build_upstream_url_query_join_and_absent() {
    // 无 query 不追加 `?`；有 query 原样拼接；基址自带 query 以 `&` 合并。
    assert_eq!(
        super::super::build_upstream_url("http://up:1", "/v1/models", None),
        "http://up:1/v1/models"
    );
    assert_eq!(
        super::super::build_upstream_url(
            "http://up:1",
            "/v1/models",
            Some("limit=&tag=a&tag=b&q=a+b&x=a%2Fb")
        ),
        "http://up:1/v1/models?limit=&tag=a&tag=b&q=a+b&x=a%2Fb"
    );
    assert_eq!(
        super::super::build_upstream_url("http://up:1?base=1", "/v1/models", Some("limit=")),
        "http://up:1/v1/models?base=1&limit="
    );
    assert_eq!(
        super::super::build_upstream_url("http://up:1/?base=1", "/v1/models", None),
        "http://up:1/v1/models?base=1"
    );
}

#[test]
fn ingress_port_bracketed_ipv6_and_bare_fallback_a1() {
    // 方括号 IPv6 取端口；裸 IPv6 回退 None（不误取尾段）。
    assert_eq!(super::super::parse_ingress_port("[::1]:8878"), Some(8878));
    assert_eq!(
        super::super::parse_ingress_port("[2001:db8::1]:8879"),
        Some(8879)
    );
    assert_eq!(super::super::parse_ingress_port("::1"), None);
    assert_eq!(super::super::parse_ingress_port("[::1]"), None);
    assert_eq!(super::super::parse_ingress_port("[::1]:abc"), None);
    assert_eq!(
        super::super::parse_ingress_port("127.0.0.1:8878"),
        Some(8878)
    );
    assert_eq!(super::super::parse_ingress_port("example.com"), None);
}

#[test]
fn ingress_port_declared_listener_wins_over_host_header() {
    // 专用监听承载 8879 且已声明：即使 `Host` 指 8878，也按 8879 选路上游。
    let (state, dir) = super::test_app_state(&[
        ("LLM_8878", "https://up-8878.example.com"),
        ("LLM_8879", "https://up-8879.example.com"),
    ]);
    let effective = super::super::resolve_ingress_port(&state.config, Some(8879), Some(8878));
    assert_eq!(effective, Some(8879), "已声明的专用监听端口恒胜 Host");
    let target = crate::service::llm_gateway::resolve_target(&state.config, effective)
        .expect("须命中 8879 上游");
    assert_eq!(target.base_url, "https://up-8879.example.com");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ingress_port_host_header_used_on_primary_without_declaration() {
    // 主监听（无专用端口）承载体旧部署：端口未声明，仍按 `Host: example.test:8878` 选路。
    let (state, dir) = super::test_app_state(&[("LLM_8878", "https://up-8878.example.com")]);
    let host_port = super::super::parse_ingress_port("example.test:8878");
    let effective = super::super::resolve_ingress_port(&state.config, None, host_port);
    assert_eq!(effective, Some(8878), "主监听须按 Host 派生端口选路");
    let target = crate::service::llm_gateway::resolve_target(&state.config, effective)
        .expect("须命中 8878 上游");
    assert_eq!(target.base_url, "https://up-8878.example.com");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ingress_port_undeclared_listener_port_falls_back_to_host() {
    // 专用监听端口未被声明（配置漂移）：不以其为准，回退 `Host` 派生值。
    let (state, dir) = super::test_app_state(&[("LLM_8878", "https://up-8878.example.com")]);
    let effective = super::super::resolve_ingress_port(&state.config, Some(9000), Some(8878));
    assert_eq!(effective, Some(8878), "未声明端口不得参与选路");
    let none = super::super::resolve_ingress_port(&state.config, None, None);
    assert_eq!(none, None, "两者皆无时回退缺省上游");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn stream_flag_with_json_combo_routes_to_pump() {
    assert!(should_pump_stream("text/event-stream", false));
    assert!(should_pump_stream("text/event-stream", true));
    assert!(should_pump_stream("application/json", true));
    assert!(!should_pump_stream("application/json", false));
    assert!(!should_pump_stream("", false));
}

#[test]
fn content_type_event_stream_case_insensitive() {
    // `;` 前段 + trim + 大小写不敏感；前缀相近值不误判，
    // `should_pump_stream` 与派发点（`:258`）共用同一谓词。
    assert!(is_event_stream("text/event-stream"));
    assert!(is_event_stream("TEXT/EVENT-STREAM"));
    assert!(is_event_stream(" text/event-stream "));
    assert!(is_event_stream("text/event-stream; charset=utf-8"));
    assert!(is_event_stream("Text/Event-Stream;charset=utf-8"));
    assert!(!is_event_stream("application/json"));
    assert!(!is_event_stream("application/json; text/event-stream"));
    assert!(!is_event_stream("text/event-streaming"));
    assert!(!is_event_stream(""));
    assert!(should_pump_stream(
        "TEXT/EVENT-STREAM; charset=utf-8",
        false
    ));
    assert!(!should_pump_stream("application/json", false));
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn body_limits_tiered_values_match_spec() {
    assert_eq!(GATEWAY_BODY_LIMIT_BYTES, 10 * 1024 * 1024);
    assert_eq!(AUDIT_SUBLIMIT_CEILING_BYTES, 8 * 1024 * 1024);
    assert!(GATEWAY_BODY_LIMIT_BYTES > AUDIT_SUBLIMIT_CEILING_BYTES);
    assert!(!audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES));
    assert!(audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES + 1));
}

#[test]
fn forward_headers_baseline_preserves_whole_session_chain() {
    // D1 出站基线：不再隐式剔除会话头链——客户端五个回退链头与自定义会话键头
    // 均原样转发上游（含多值）；仅协议必要头与 `x-veil-*` 内部命名空间被剔除。
    let mut client = HeaderMap::new();
    for name in crate::service::request_log::SESSION_HEADER_FALLBACKS {
        client.insert(name, axum::http::HeaderValue::from_static("client-leak"));
    }
    client.insert(
        "x-custom-conv",
        axum::http::HeaderValue::from_static("custom-keep"),
    );
    client.insert(
        "x-veil-conversation-id",
        axum::http::HeaderValue::from_static("internal"),
    );
    client.insert("host", axum::http::HeaderValue::from_static("example.com"));
    let metrics = llm_gateway::GatewayMetrics::default();
    let fwd = forward_headers(
        &client,
        &metrics,
        None,
        &crate::handler::llm::test_support::no_expand(),
    );
    for name in crate::service::request_log::SESSION_HEADER_FALLBACKS {
        assert_eq!(
            fwd.get(name).and_then(|v| v.to_str().ok()),
            Some("client-leak"),
            "回退链头 {name} 须原样转发上游"
        );
    }
    assert_eq!(
        fwd.get("x-custom-conv").and_then(|v| v.to_str().ok()),
        Some("custom-keep"),
        "自定义会话键头须原样转发上游"
    );
    assert!(
        fwd.get("x-veil-conversation-id").is_none(),
        "x-veil-* 内部头须剔除"
    );
    assert!(fwd.get("host").is_none(), "host 属协议必要剔除项");
}

#[tokio::test]
async fn oversized_body_returns_413_with_error_code() {
    let resp = payload_too_large(GATEWAY_BODY_LIMIT_BYTES);
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "E_PAYLOAD_TOO_LARGE");
}

#[tokio::test]
async fn panic_in_spawned_task_maps_to_500_not_connection_abort() {
    let resp = super::super::spawn_contained(async { panic!("注入 panic") }).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "E_INTERNAL");
    let ok = super::super::spawn_contained(async { (StatusCode::OK, "ok").into_response() }).await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[test]
fn bom_prefixed_request_body_parses_via_json_walk() {
    // BOM 前缀体经中央 `strip_bom`/`jloads` 正常解析（原为解析失败回退）。
    let body = "\u{feff}{\"model\":\"m\",\"messages\":[]}".as_bytes();
    let v = super::super::parse_request_json(body).expect("BOM 前缀体须解析");
    assert_eq!(v["model"], "m");
    assert!(
        super::super::parse_request_json(b"not json").is_none(),
        "非 JSON 仍回退 None"
    );
    assert!(
        super::super::parse_request_json(&[0xff, 0xfe]).is_none(),
        "非 UTF-8 仍回退 None"
    );
}

#[tokio::test]
async fn request_side_pii_unavailable_fails_closed_502() {
    // 请求侧熵源故障守门——502 + E_PII_UNAVAILABLE，且健康 scope 不守门。
    let scope = crate::service::redaction::Scope::with_opts(false);
    scope.pii_scope().force_entropy_failure(true);
    let vault = crate::service::credential_vault::CredentialVault::new();
    let detector = crate::service::pii::PiiDetector::new();
    let _ = scope
        .redact_request_with_report(&vault, &detector, "call 13812345678")
        .await;
    assert!(scope.pii_unavailable(), "熵源故障须置失败信号");
    let resp = super::super::pii_fail_closed(&scope).expect("故障须 fail-closed 守门");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .expect("错误体须可读");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("错误体须为 JSON");
    assert_eq!(value["error"]["code"], "E_PII_UNAVAILABLE");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("13812345678"),
        "错误体不得含明文"
    );
    assert!(
        super::super::pii_fail_closed(&crate::service::redaction::Scope::new()).is_none(),
        "健康 scope 不得守门"
    );
}

#[tokio::test]
async fn oversized_body_rejected_by_to_bytes_not_silent_empty() {
    let over = vec![b'x'; 64];
    let err = axum::body::to_bytes(axum::body::Body::from(over), 16).await;
    assert!(err.is_err());
    // 恰达上限放行：结果体内容与长度精确对拍，不得静默为空。
    let ok = axum::body::to_bytes(axum::body::Body::from(vec![b'x'; 16]), 16)
        .await
        .expect("恰达上限须放行");
    assert_eq!(ok.len(), 16, "结果体长度须等于输入: {ok:?}");
    assert_eq!(&ok[..], &[b'x'; 16][..], "结果体内容须逐字节保留");
    // 超限一字节即报错（非 Ok 空体），不静默截断。
    let over_by_one = axum::body::to_bytes(axum::body::Body::from(vec![b'y'; 17]), 16).await;
    assert!(over_by_one.is_err(), "17 字节超 16 上限须报错而非静默");
}
