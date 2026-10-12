mod retry;

use super::{
    metrics::{CONV_MISSING_KEYS, HOP_DIR_KEYS, LENIENT_TAIL_KEYS, TRUNCATED_MODE_KEYS},
    *,
};

/// 取 `HeaderValueSpec` 的静态值文本（模板返回 `None`）。
fn static_text(spec: &crate::config::HeaderValueSpec) -> Option<&str> {
    match spec {
        crate::config::HeaderValueSpec::Static(value) => value.to_str().ok(),
        crate::config::HeaderValueSpec::Template(_) => None,
    }
}

#[test]
fn empty_body_502_three_branches() {
    // is_stream 分支已删；流式空流唯一策略见 should_synthesize_empty_stream。
    assert_eq!(
        classify_empty(true, 0, false, 200),
        EmptyAction::NonStreamTo502
    );
    assert_eq!(
        classify_empty(true, 10, false, 200),
        EmptyAction::NonStreamTo502
    );
    assert_eq!(
        classify_empty(true, 10, true, 502),
        EmptyAction::PassthroughErrorStatus
    );
    assert_eq!(
        classify_empty(true, 5, true, 401),
        EmptyAction::PassthroughErrorStatus
    );
    assert_eq!(
        classify_empty(false, 0, false, 200),
        EmptyAction::NonDialogExempt
    );
    assert_eq!(
        classify_empty(true, 10, true, 200),
        EmptyAction::PassthroughOk
    );
}

#[test]
fn upstream_port_mapping_resolves() {
    use std::collections::HashMap;
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://m.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        (
            "LLM_8877".to_string(),
            "https://up-a.example.com".to_string(),
        ),
        (
            "LLM_8878".to_string(),
            "https://up-b.example.com".to_string(),
        ),
    ]);
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        resolve_upstream(&cfg, Some(8877)).as_deref(),
        Some("https://up-a.example.com")
    );
    assert_eq!(
        resolve_upstream(&cfg, Some(8878)).as_deref(),
        Some("https://up-b.example.com")
    );
    assert!(resolve_upstream(&cfg, Some(9999)).is_some());
}

#[test]
fn resolve_upstream_default_fallback_picks_lowest_port_deterministically() {
    use std::collections::HashMap;
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://m.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        (
            "LLM_8879".to_string(),
            "https://up-high.example.com".to_string(),
        ),
        (
            "LLM_8878".to_string(),
            "https://up-low.example.com".to_string(),
        ),
    ]);
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        resolve_upstream(&cfg, None).as_deref(),
        Some("https://up-low.example.com"),
        "双端口缺省须取最小端口"
    );
    for _ in 0..10 {
        assert_eq!(
            resolve_upstream(&cfg, None).as_deref(),
            Some("https://up-low.example.com"),
            "重复运行须一致（端口升序最小，不依赖 HashMap 迭代序）"
        );
    }
}

/// 构造含文件专属 `[llm.targets]` 的测试配置：`targets_toml` 为完整文件层 TOML 文本。
fn config_with_targets(extra: &[(&str, &str)], targets_toml: &str) -> Config {
    use std::collections::HashMap;
    let mut env: HashMap<String, String> = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://m.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
    ]);
    for (key, value) in extra {
        env.insert((*key).to_string(), (*value).to_string());
    }
    let file: crate::config::FileConfig = toml::from_str(targets_toml).expect("覆盖片段须可解析");
    let raw = file
        .llm
        .and_then(|section| section.targets)
        .expect("片段须含 [llm.targets]");
    let targets = crate::config::validate_targets(Some(&raw)).expect("覆盖须合法");
    Config::load_from_with_targets(&env, targets).expect("测试配置须合法")
}

#[test]
fn resolve_target_port_hit_returns_port_overrides() {
    let cfg = config_with_targets(
        &[
            ("LLM_8878", "https://up-b.example.com"),
            ("LLM_UPSTREAM", "https://up-default.example.com"),
        ],
        "[llm.targets.\"8878\".headers]\nanthropic-version = \"2023-06-01\"\n\
         [llm.targets.default.headers]\nx-default = \"1\"\n",
    );
    let target = resolve_target(&cfg, Some(8878)).expect("端口专用上游须命中");
    assert_eq!(target.base_url, "https://up-b.example.com");
    let overrides = target.overrides.expect("端口目标覆盖须随同源解析返回");
    assert_eq!(
        overrides
            .headers
            .get("anthropic-version")
            .and_then(static_text),
        Some("2023-06-01")
    );
    assert!(
        overrides.headers.get("x-default").is_none(),
        "不得命中 default 覆盖"
    );
}

#[test]
fn resolve_target_default_fallback_returns_default_overrides() {
    let cfg = config_with_targets(
        &[
            ("LLM_8878", "https://up-b.example.com"),
            ("LLM_UPSTREAM", "https://up-default.example.com"),
        ],
        "[llm.targets.\"8878\".headers]\nx-port = \"1\"\n\
         [llm.targets.default.headers]\nx-default = \"1\"\n",
    );
    for port in [Some(8877), None] {
        let target = resolve_target(&cfg, port).expect("须回退缺省上游");
        assert_eq!(target.base_url, "https://up-default.example.com");
        let overrides = target.overrides.expect("default 覆盖须命中");
        assert_eq!(
            overrides.headers.get("x-default").and_then(static_text),
            Some("1")
        );
        assert!(
            overrides.headers.get("x-port").is_none(),
            "不得命中端口覆盖"
        );
    }
}

#[test]
fn resolve_target_without_declared_overrides_is_none() {
    // env-only 配置（无 `[llm.targets]`）：端口命中与缺省回退均无覆盖（零行为变化）。
    use std::collections::HashMap;
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://m.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        (
            "LLM_8878".to_string(),
            "https://up-b.example.com".to_string(),
        ),
        (
            "LLM_UPSTREAM".to_string(),
            "https://up-default.example.com".to_string(),
        ),
    ]);
    let cfg = Config::load_from(&env).unwrap();
    for port in [Some(8878), Some(9999), None] {
        let target = resolve_target(&cfg, port).expect("须有上游");
        assert!(
            target.overrides.is_none(),
            "未声明覆盖须为 None（port={port:?}）"
        );
    }
}

#[test]
fn resolve_target_port_ascending_fallback_has_no_overrides() {
    // 无缺省上游时按端口升序回退：URL 取自端口上游，但不命中其端口覆盖
    //（仅「入口端口命中」与「缺省回退」两个分支命中覆盖，见 design D3）。
    let cfg = config_with_targets(
        &[("LLM_8878", "https://up-b.example.com")],
        "[llm.targets.\"8878\".headers]\nx-port = \"1\"\n",
    );
    let target = resolve_target(&cfg, None).expect("须回退端口升序首个");
    assert_eq!(target.base_url, "https://up-b.example.com");
    assert!(target.overrides.is_none(), "端口升序回退不命中端口覆盖");
}

#[test]
fn resolve_target_single_call_matches_resolve_upstream() {
    // 单次调用同时给出 URL 与覆盖，且 URL 与兼容入口 `resolve_upstream` 逐项一致
    //（不存在第二条覆盖查询路径）。
    let cfg = config_with_targets(
        &[
            ("LLM_8878", "https://up-b.example.com"),
            ("LLM_UPSTREAM", "https://up-default.example.com"),
        ],
        "[llm.targets.\"8878\".headers]\nx-port = \"1\"\n\
         [llm.targets.default.headers]\nx-default = \"1\"\n",
    );
    for port in [Some(8878), Some(9999), None] {
        let target = resolve_target(&cfg, port).expect("须有上游");
        assert_eq!(
            Some(target.base_url.to_string()),
            resolve_upstream(&cfg, port),
            "同源解析的 URL 须与兼容入口逐项一致（port={port:?}）"
        );
    }
    let port_hit = resolve_target(&cfg, Some(8878)).expect("须命中");
    assert!(
        port_hit
            .overrides
            .expect("单次调用须同时得到覆盖")
            .headers
            .get("x-port")
            .is_some(),
        "端口分支覆盖须命中"
    );
    let fallback = resolve_target(&cfg, Some(9999)).expect("须回退缺省");
    assert!(
        fallback
            .overrides
            .expect("缺省回退须带 default 覆盖")
            .headers
            .get("x-default")
            .is_some()
    );
}

#[test]
fn retry_backoff_curve() {
    assert_eq!(retry_delay(0), Duration::from_millis(500));
    assert_eq!(retry_delay(1), Duration::from_millis(1000));
    assert_eq!(retry_delay(2), Duration::from_millis(2000));
}

#[tokio::test]
async fn disconnect_retries_capped_then_fails() {
    use axum::http::HeaderMap;
    assert_eq!(retry_delay(3), Duration::from_millis(2000));
    assert_eq!(retry_delay(99), Duration::from_millis(2000));
    assert_eq!(MAX_RETRY_ATTEMPTS, 3);
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    let err = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        "http://127.0.0.1:9/v1/chat/completions",
        HeaderMap::new(),
        b"{}".to_vec(),
    )
    .await
    .unwrap_err();
    assert!(
        start.elapsed() >= Duration::from_millis(3000),
        "三次退避(500+1000+2000)须走完，实测 {:?}",
        start.elapsed()
    );
    assert!(!err.to_string().is_empty());
}

#[tokio::test]
async fn first_refused_then_retry_succeeds() {
    use axum::http::HeaderMap;
    // 预留端口后释放：首连 ECONNREFUSED（可重试类），600ms 后起真服务；
    // 两次退避（500+1000）后第三次命中，验证首连失败仍能恢复。
    let port = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("预留端口须成功")
        .local_addr()
        .expect("回环地址须可读")
        .port();
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(600)).await;
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("延迟服务须监听成功");
        let (mut sock, _) = listener.accept().await.expect("须收到重试连接");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 65536];
        let _ = sock.read(&mut buf).await;
        let body = br#"{"ok":true}"#;
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body).await;
    });
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    let resp = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        &url,
        HeaderMap::new(),
        b"{}".to_vec(),
    )
    .await
    .expect("退避后服务就绪须成功");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        start.elapsed() >= Duration::from_millis(1200),
        "须走完两次退避才成功，实测 {:?}",
        start.elapsed()
    );
    server.abort();
}

#[test]
fn fix4_lenient_count_and_models_zero_stats() {
    let m = GatewayMetrics::default();
    for p in [
        "/v1/models",
        "/v1/models/",
        "/v1/models/extra",
        "/v1/fake-chat/completions-extra",
    ] {
        let (hit, _) = is_chat_tail(p, Some(&m));
        assert!(!hit, "{p}");
    }
    assert_eq!(m.lenient_count("chat/completions"), 0);
    assert_eq!(m.lenient_count("v1/messages"), 0);
    assert_eq!(m.lenient_count("v1/responses"), 0);
    let (hit, _) = is_chat_tail("/v1/chat/completions/", Some(&m));
    assert!(hit);
    assert_eq!(m.lenient_count("chat/completions"), 1);
}

#[tokio::test]
async fn business_500_returns_without_retry() {
    use axum::http::HeaderMap;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock 须监听成功");
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("须收到连接");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 65536];
        let _ = sock.read(&mut buf).await;
        let body = br#"{"error":"synthetic"}"#;
        let head = format!(
            "HTTP/1.1 500 Internal Server Error\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(body).await;
    });
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    let resp = fetch_upstream_with_retry(
        &client,
        reqwest::Method::POST,
        &format!("http://127.0.0.1:{port}/v1/chat/completions"),
        HeaderMap::new(),
        b"{}".to_vec(),
    )
    .await
    .expect("业务 500 是合法响应体，不得转为 Err");
    assert_eq!(resp.status().as_u16(), 500);
    assert!(
        start.elapsed() < Duration::from_millis(3000),
        "业务错误不得走退避重试，实测 {:?}",
        start.elapsed()
    );
    server.abort();
}

#[test]
fn truncated_tool_dropped_counter_accumulates() {
    // 截断丢弃计数可查询（泵内截断路径经此计数）。
    let m = GatewayMetrics::default();
    assert_eq!(m.truncated_tool_dropped_count(), 0);
    m.record_truncated_tool_dropped(2);
    m.record_truncated_tool_dropped(1);
    assert_eq!(m.truncated_tool_dropped_count(), 3);
}

#[test]
fn nondialog_passthrough_counter_accumulates() {
    // NonDialog 透传计数可查询（非流臂经此计数）。
    let m = GatewayMetrics::default();
    assert_eq!(m.nondialog_passthrough_count(), 0);
    m.record_nondialog_passthrough();
    assert_eq!(m.nondialog_passthrough_count(), 1);
}

#[test]
fn sse_and_hop_counters_queryable_and_count_on_strip() {
    let m = GatewayMetrics::default();
    assert_eq!(m.sse_event_total(), 0);
    m.add_sse_event();
    m.add_sse_event();
    assert_eq!(m.sse_event_total(), 2);
    assert_eq!(m.hop_filtered_count("upstream"), 0);
    m.record_hop_filtered("upstream", 0);
    assert_eq!(m.hop_filtered_count("upstream"), 0, "零剥离不计数");
    m.record_hop_filtered("upstream", 3);
    assert_eq!(m.hop_filtered_count("upstream"), 3);
    assert_eq!(m.hop_filtered_count("downstream"), 0, "方向隔离");
}

#[test]
fn gateway_metrics_atomic_keys() {
    let m = GatewayMetrics::default();
    for key in LENIENT_TAIL_KEYS {
        assert_eq!(m.lenient_count(key), 0);
        m.record_lenient(key);
        assert_eq!(m.lenient_count(key), 1, "{key}");
    }
    for key in TRUNCATED_MODE_KEYS {
        m.record_truncated(key);
        assert_eq!(m.truncated_count(key), 1, "{key}");
    }
    for key in HOP_DIR_KEYS {
        m.record_hop_filtered(key, 2);
        assert_eq!(m.hop_filtered_count(key), 2, "{key}");
    }
    for key in CONV_MISSING_KEYS {
        m.record_conv_missing(key);
        assert_eq!(m.conv_missing_count(key), 1, "{key}");
    }
}

#[test]
fn gateway_metrics_oversize_counters() {
    let m = GatewayMetrics::default();
    assert_eq!(m.oversize_frames_count(), 0);
    assert_eq!(m.oversize_frame_bytes_count(), 0);
    m.record_oversize_frames(2, 4096);
    assert_eq!(m.oversize_frames_count(), 2);
    assert_eq!(m.oversize_frame_bytes_count(), 4096);
    m.record_oversize_frames(0, 0);
    assert_eq!(m.oversize_frames_count(), 2, "零不写入");
}

#[test]
fn gateway_metrics_unknown_key_other() {
    let m = GatewayMetrics::default();
    m.record_lenient("unknown-tail");
    m.record_lenient("unknown-tail");
    assert_eq!(
        m.lenient_count("chat/completions"),
        0,
        "未知键不影响已知键读数"
    );
    assert_eq!(m.lenient_count("another-unknown"), 2, "未知键共享 other 桶");
    m.record_lenient("chat/completions");
    assert_eq!(m.lenient_count("chat/completions"), 1);
}

#[test]
fn admin_metrics_keys_unchanged() {
    let m = GatewayMetrics::default();
    for k in ["chat/completions", "v1/messages", "v1/responses"] {
        m.record_lenient(k);
    }
    for k in ["chat/completions", "v1/messages", "v1/responses"] {
        assert_eq!(m.lenient_count(k), 1, "{k}");
    }
    assert_eq!(m.sse_event_total(), 0);
    m.add_sse_event();
    assert_eq!(m.sse_event_total(), 1);
    for k in TRUNCATED_MODE_KEYS {
        m.record_truncated(k);
        assert_eq!(m.truncated_count(k), 1, "{k}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_metrics_concurrent_count() {
    use std::sync::Arc;
    let m = Arc::new(GatewayMetrics::default());
    const TASKS: u64 = 8;
    const PER_TASK: u64 = 1_000;
    let mut handles = Vec::new();
    for _ in 0..TASKS {
        let m = m.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..PER_TASK {
                m.record_lenient("chat/completions");
                m.record_truncated("open_ended");
                m.record_hop_filtered("upstream", 1);
                m.record_conv_missing("failed");
            }
        }));
    }
    for h in handles {
        h.await.expect("并发任务须完成");
    }
    assert_eq!(m.lenient_count("chat/completions"), TASKS * PER_TASK);
    assert_eq!(m.truncated_count("open_ended"), TASKS * PER_TASK);
    assert_eq!(m.hop_filtered_count("upstream"), TASKS * PER_TASK);
    assert_eq!(m.conv_missing_count("failed"), TASKS * PER_TASK);
    assert_eq!(m.hop_filtered_count("downstream"), 0, "方向隔离");
    assert_eq!(m.truncated_count("synthesized_failed"), 0, "模式隔离");
}

#[test]
fn admin_rate_evicted_counter_accumulates() {
    let m = GatewayMetrics::default();
    assert_eq!(m.admin_rate_evicted_count(), 0);
    m.record_admin_rate_evicted(3);
    m.record_admin_rate_evicted(1);
    assert_eq!(m.admin_rate_evicted_count(), 4);
    m.record_admin_rate_evicted(0);
    assert_eq!(m.admin_rate_evicted_count(), 4, "零驱逐不递增");
}

#[test]
fn upstream_read_error_counter_accumulates() {
    let m = GatewayMetrics::default();
    assert_eq!(m.upstream_read_error_count(), 0);
    m.record_upstream_read_error();
    assert_eq!(m.upstream_read_error_count(), 1, "一次失败递增 1");
    m.record_nondialog_passthrough();
    m.add_sse_event();
    assert_eq!(m.upstream_read_error_count(), 1, "成功路径不递增");
    m.record_upstream_read_error();
    assert_eq!(m.upstream_read_error_count(), 2);
}

#[test]
fn upstream_status_constrained() {
    // 状态码经受约束类型——合法区间接受，非法值拒绝（不 panic）。
    assert_eq!(
        UpstreamStatus::new(200).map(UpstreamStatus::as_u16),
        Some(200)
    );
    assert_eq!(
        UpstreamStatus::new(599).map(UpstreamStatus::as_u16),
        Some(599)
    );
    assert!(UpstreamStatus::new(99).is_none(), "低于 100 非法");
    assert!(UpstreamStatus::new(600).is_none(), "高于 599 非法");
    assert!(!UpstreamStatus::new(200).expect("合法").is_error());
    assert!(UpstreamStatus::new(200).expect("合法").is_success());
    assert!(UpstreamStatus::new(500).expect("合法").is_error());
    assert!(!UpstreamStatus::new(500).expect("合法").is_success());
}

#[test]
fn strip_veil_internal_headers_case_insensitive_and_selective() {
    // 单一定义——全部 `x-veil-*`（大小写归一）剔除，他头保留。
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-protocol", "chat".parse().expect("合法头值"));
    headers.insert("X-Veil-Normalized", "1".parse().expect("合法头值"));
    headers.insert(
        "content-type",
        "text/event-stream".parse().expect("合法头值"),
    );
    assert_eq!(headers.len(), 3, "归一后 `x-veil-*` 两项 + 他头一项");
    strip_veil_internal_headers(&mut headers);
    assert!(headers.get("x-veil-protocol").is_none());
    assert!(headers.get("x-veil-normalized").is_none());
    assert_eq!(
        headers.get("content-type").and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(headers.len(), 1, "仅非 x-veil-* 头保留");
}
