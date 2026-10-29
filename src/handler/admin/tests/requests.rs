//! `/_admin/requests` 端点单测：参数校验、分页收敛、范围键省略/覆盖与 SSE 形状。

use {
    super::{
        ADMIN_TOKEN_T,
        HashMap,
        HeaderMap,
        PeerIp,
        Query,
        State,
        StatusCode,
        admin_test_state,
        body_json,
        build_metrics_sse_payload,
        headers_with,
        metrics_test_dir,
    },
    crate::{
        config::Config,
        handler::admin::admin_requests,
        service::request_log::{RequestRow, SessionScope},
        state::{AppState, SqliteOutcome},
    },
    axum::response::IntoResponse,
    serde_json::Value,
    std::net::IpAddr,
};

/// 逐请求行夹具：`ts` 相对当前时刻偏移 `ago_secs` 秒。
fn row(ago_secs: i64, cached_read: u64, cache_input: u64) -> RequestRow {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    RequestRow {
        ts_secs: now - ago_secs,
        request_id: format!("req-{ago_secs}"),
        protocol: "chat".to_string(),
        model: "m-1".to_string(),
        upstream: Some("127.0.0.1:11434".to_string()),
        stream: false,
        is_chat: true,
        counted_metrics: true,
        status: Some(200),
        latency_ms: 42,
        prompt_tokens: 100,
        completion_tokens: 20,
        total_tokens: 120,
        cached_read,
        cache_input_tokens: cache_input,
        session_id: Some("9f2c000000000000".to_string()),
        session_source: "header".to_string(),
        session_scope: "session".to_string(),
        req_summary: Some("摘要".to_string()),
        ..RequestRow::default()
    }
}

/// 逐请求写入 + 同步刷盘（被测端点只读已落库行）。
fn seed(state: &AppState, rows: Vec<RequestRow>) {
    for row in rows {
        state.request_log.record(row);
    }
    state.request_log.flush_blocking().expect("刷盘须成功");
}

/// 以独立源 IP 调用端点（规避 10/min 限流对本用例的干扰）。
async fn call(state: &AppState, ip_last: u8, query: &[(&str, &str)]) -> (StatusCode, Value) {
    let q: HashMap<String, String> = query
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let resp = admin_requests(
        State(state.clone()),
        PeerIp(Some(IpAddr::from([127, 0, 0, ip_last]))),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q),
    )
    .await
    .into_response();
    let status = resp.status();
    (status, body_json(resp).await)
}

async fn call_unauth(state: &AppState, ip_last: u8) -> (StatusCode, Value) {
    let resp = admin_requests(
        State(state.clone()),
        PeerIp(Some(IpAddr::from([127, 0, 0, ip_last]))),
        HeaderMap::new(),
        Query(HashMap::new()),
    )
    .await
    .into_response();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn invalid_filters_return_400_with_code() {
    let dir = metrics_test_dir("requests-invalid");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(&state, vec![row(60, 0, 100)]);
    // 每例独立源 IP，互不影响限流桶。
    let cases: [(&str, &str); 7] = [
        ("range", "2h"),
        ("status", "3xx"),
        ("scope", "tenant"),
        ("session", "abc"),
        ("limit", "abc"),
        ("offset", "abc"),
        ("llm", "yes"),
    ];
    let mut ip = 20u8;
    for (key, value) in cases {
        ip += 1;
        let (status, body) = call(&state, ip, &[(key, value)]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{key}={value}: {body}");
        assert_eq!(body["error"]["code"], "E_BAD_REQUEST", "{key}={value}");
    }
    // 非法 range 的消息须列明四档合法取值。
    let (_, body) = call(&state, 40, &[("range", "2h")]).await;
    let message = body["error"]["message"].as_str().unwrap_or("");
    for label in ["1h", "24h", "7d", "30d"] {
        assert!(message.contains(label), "消息须列明 {label}: {message}");
    }
    // 非法 llm 的消息须列明全部四个合法取值（含与 `1|true` 等价的 `0|false`）。
    let (status, body) = call(&state, 42, &[("llm", "yes")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or("");
    for label in ["1", "true", "0", "false"] {
        assert!(
            message.contains(label),
            "llm 非法取值的消息须列明 {label}: {message}"
        );
    }
    let (_, body) = call(&state, 41, &[("session", "abc")]).await;
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains('4'),
        "session 前缀不足须提示最少字符数: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn limit_clamps_and_offset_has_upper_bound() {
    let dir = metrics_test_dir("requests-paging");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(
        &state,
        (0..3).map(|i| row(60 + i, 0, 100)).collect::<Vec<_>>(),
    );
    // `limit=500` 收敛为 200（回显生效值，且不超过 200 行）。
    let (status, body) = call(&state, 60, &[("limit", "500")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["limit"], 200, "limit 须收敛至上限: {body}");
    assert_eq!(body["total"], 3);
    assert!(body["rows"].as_array().unwrap().len() <= 200);
    // 默认 50。
    let (status, body) = call(&state, 61, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["limit"], 50, "缺省 limit 须为 50: {body}");
    assert_eq!(body["offset"], 0);
    // offset 上限 10000：超限 400，等于上限放行。
    let (status, body) = call(&state, 62, &[("offset", "20000")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = call(&state, 63, &[("offset", "10000")]).await;
    assert_eq!(status, StatusCode::OK, "offset=10000 须放行: {body}");
    assert_eq!(body["offset"], 10000);
    assert_eq!(body["rows"].as_array().unwrap().len(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn absent_range_omits_three_keys_and_reports_full_coverage() {
    let dir = metrics_test_dir("requests-unranged");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(&state, vec![row(1_000, 0, 100)]);
    let (status, body) = call(&state, 70, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for absent in ["range", "since_ts", "boundary_slack_secs"] {
        assert!(
            body.get(absent).is_none(),
            "无 range 时不得出现 {absent}: {body}"
        );
    }
    assert_eq!(body["partial"], false, "{body}");
    let coverage = body["coverage_secs"]
        .as_u64()
        .expect("coverage_secs 须数值");
    assert!(
        (990..=1_100).contains(&coverage),
        "coverage_secs 须为 now - 最早记录: {body}"
    );
    // 无数据时覆盖为 0 且仍不带 range 键。
    let empty_dir = metrics_test_dir("requests-unranged-empty");
    let empty = admin_test_state(empty_dir.clone(), empty_dir.join("m.sqlite"));
    let (status, body) = call(&empty, 71, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["coverage_secs"], 0);
    assert_eq!(body["partial"], false);
    assert!(body.get("range").is_none());
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&empty_dir).ok();
}

#[tokio::test]
async fn range_30d_reports_partial_coverage() {
    let dir = metrics_test_dir("requests-range-30d");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(&state, vec![row(600, 0, 100)]);
    let (status, body) = call(&state, 80, &[("range", "30d")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["range"], "30d", "{body}");
    assert!(body["since_ts"].as_i64().is_some(), "{body}");
    // 记录按 ts_secs 精确过滤，故窗口对齐误差上界为 0。
    assert_eq!(body["boundary_slack_secs"], 0, "{body}");
    assert_eq!(body["partial"], true, "600s 覆盖远短于 30d: {body}");
    let coverage = body["coverage_secs"].as_u64().expect("coverage_secs");
    assert!(
        (590..=700).contains(&coverage),
        "coverage 须为 now - 最早记录: {body}"
    );
    // 校验 range 过滤确实生效：远端行被排除，近端行保留。
    let ranged_dir = metrics_test_dir("requests-range-filter");
    let ranged = admin_test_state(ranged_dir.clone(), ranged_dir.join("m.sqlite"));
    seed(&ranged, vec![row(60, 0, 100), row(7_200, 0, 100)]);
    let (status, body) = call(&ranged, 81, &[("range", "1h")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 1, "1h 须排除 2h 前记录: {body}");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&ranged_dir).ok();
}

#[tokio::test]
async fn hit_rate_is_sum_over_sum_not_row_mean() {
    let dir = metrics_test_dir("requests-hit-rate");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    // 行级 0/1 与 100/100：SUM 口径 100/101≈0.9901，行均口径为 0.5。
    seed(&state, vec![row(60, 0, 1), row(120, 100, 100)]);
    let (status, body) = call(&state, 90, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sum_cached_read"], 100, "{body}");
    assert_eq!(body["sum_cache_input_tokens"], 101, "{body}");
    let hit_rate = body["hit_rate"].as_f64().expect("hit_rate 须数值");
    assert!(
        (hit_rate - 100.0 / 101.0).abs() < 1e-9,
        "hit_rate 须为 SUM/SUM: {body}"
    );
    // 行级字段同源，且分母为 0 时为空值。
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|r| r["cache_hit_rate"].as_f64() == Some(0.0)),
        "{body}"
    );
    let zero_dir = metrics_test_dir("requests-hit-rate-null");
    let zero = admin_test_state(zero_dir.clone(), zero_dir.join("m.sqlite"));
    seed(&zero, vec![row(60, 0, 0)]);
    let (status, body) = call(&zero, 91, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["hit_rate"].is_null(), "分母 0 须为 null: {body}");
    assert!(
        body["rows"][0]["cache_hit_rate"].is_null(),
        "行级分母 0 须为 null: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&zero_dir).ok();
}

#[tokio::test]
async fn filters_by_status_session_prefix_and_scope() {
    let dir = metrics_test_dir("requests-filters");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let mut user_row = row(60, 0, 100);
    user_row.session_scope = "user".to_string();
    user_row.session_id = Some("9f2cffffffffffff".to_string());
    let mut failed = row(120, 0, 100);
    failed.status = None;
    failed.request_id = "req-failed".to_string();
    seed(&state, vec![row(180, 0, 100), user_row, failed]);
    let (status, body) = call(&state, 100, &[("status", "error")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 1, "error 须含无状态行: {body}");
    let (status, body) = call(&state, 101, &[("session", "9f2c")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 3, "四字前缀须命中同前缀会话: {body}");
    let (status, body) = call(&state, 102, &[("session", "9f2cffff")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1, "{body}");
    let (status, body) = call(&state, 103, &[("scope", "user")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1, "{body}");
    assert_eq!(body["rows"][0]["session_scope"], "user");
    let (status, body) = call(&state, 104, &[("scope", "session")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 2, "{body}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn disabled_log_short_circuits_to_empty_body() {
    let dir = metrics_test_dir("requests-disabled");
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN_T.to_string(),
        ),
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    let mut config = Config::load_from(&env).expect("测试配置须合法");
    config.request_log_enabled = false;
    let state = AppState::new(
        config,
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    );
    assert!(!state.request_log.enabled());
    let (status, body) = call(&state, 110, &[("limit", "500")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["enabled"], false);
    assert_eq!(body["total"], 0);
    assert_eq!(body["rows"].as_array().map(Vec::len), Some(0));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn disabled_log_validates_parameters_before_short_circuit() {
    // 日志关闭时仍须先校验 range/limit/offset：非法值 400，合法值才走
    // `enabled=false` 空回执。
    let dir = metrics_test_dir("requests-disabled-validate");
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN_T.to_string(),
        ),
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    let mut config = Config::load_from(&env).expect("测试配置须合法");
    config.request_log_enabled = false;
    let state = AppState::new(
        config,
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    );
    assert!(!state.request_log.enabled());
    for (ip, query) in [
        (111u8, vec![("range", "2h")]),
        (112, vec![("offset", "20000")]),
        (113, vec![("limit", "abc")]),
        (114, vec![("status", "3xx")]),
        (115, vec![("session", "abc")]),
        (116, vec![("scope", "tenant")]),
        // `llm` 的解析同样先于短路：非法取值在日志关闭时也须 400。
        (118, vec![("llm", "x")]),
    ] {
        let (status, body) = call(&state, ip, &query).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "日志关闭时 {query:?} 仍须 400: {body}"
        );
        assert_eq!(body["error"]["code"], "E_BAD_REQUEST", "{body}");
        assert!(body.get("rows").is_none(), "非法参数不得回显空行集: {body}");
    }
    // 合法参数：仍短接为 `enabled=false`。
    let (status, body) = call(&state, 117, &[("range", "1h"), ("limit", "500")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], false, "{body}");
    assert_eq!(body["total"], 0, "{body}");
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 6.3：`request_log_enabled=false` 时 `/_admin/metrics?range=24h` 仍须
/// 回退环样本分布并标 `per_model_partial=true`（不得静默返回空分布）。
#[tokio::test]
async fn disabled_request_log_marks_per_model_partial_at_handler_level() {
    let dir = metrics_test_dir("requests-disabled-per-model");
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN_T.to_string(),
        ),
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    let mut config = Config::load_from(&env).expect("测试配置须合法");
    config.request_log_enabled = false;
    let state = AppState::new(
        config,
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    );
    assert!(!state.request_log.enabled());
    use crate::service::credential::AppStateParts as _;
    // 环里有样本：记录功能关闭只影响 rollup 投影，不影响内存环。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    for i in 0..4 {
        state
            .admin_state()
            .metrics
            .record_chat(crate::service::metrics::ChatRecord {
                protocol: crate::service::llm_gateway::Protocol::Chat,
                model: "ring-model",
                latency_ms: 10,
                usage: None,
                truncated_mode: None,
                is_precise: true,
                ts_secs: now - 60 - i,
            });
    }
    let mut q = HashMap::new();
    q.insert("range".to_string(), "24h".to_string());
    let resp = crate::handler::admin::admin_metrics(
        State(state.clone()),
        PeerIp(Some(IpAddr::from([127, 0, 0, 140]))),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["range"], "24h", "{body}");
    assert_eq!(
        body["per_model_partial"], true,
        "记录关闭时分布必为降级口径: {body}"
    );
    assert!(body["requests"].as_u64().unwrap_or(0) > 0, "{body}");
    let per_model = body["per_model"].as_object().expect("per_model 须为对象");
    assert!(
        !per_model.is_empty(),
        "环有样本时须回退环分布而非空: {body}"
    );
    assert_eq!(
        per_model.get("ring-model").and_then(Value::as_u64),
        Some(4),
        "环回退须按模型分桶求和: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unauthenticated_returns_401_without_rows() {
    let dir = metrics_test_dir("requests-auth");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(&state, vec![row(60, 0, 100)]);
    let (status, body) = call_unauth(&state, 120).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "E_UNAUTHORIZED");
    assert!(body.get("rows").is_none(), "未鉴权不得返回记录: {body}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn sse_payload_keeps_six_keys_and_scopes_metrics() {
    let dir = metrics_test_dir("requests-sse-range");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let payload = build_metrics_sse_payload(
        &state,
        &crate::service::admin::SseFilter::default(),
        Some("1h"),
        "five_min",
    )
    .await;
    let keys: Vec<&String> = payload
        .as_object()
        .expect("payload 须对象")
        .keys()
        .collect();
    assert_eq!(
        keys.len(),
        6,
        "SSE data 须恰六键（范围字段只进 data.metrics）: {payload}"
    );
    for want in ["range", "model", "upstream", "metrics", "series", "health"] {
        assert!(payload.get(want).is_some(), "缺键 {want}: {payload}");
    }
    assert_eq!(payload["range"], "1h");
    assert_eq!(payload["metrics"]["range"], "1h", "{payload}");
    assert_eq!(payload["metrics"]["boundary_slack_secs"], 300, "{payload}");
    assert!(payload["metrics"]["partial"].is_boolean(), "{payload}");
    // 无 range：`data.range` 保持为 null，且 `data.metrics` 不出现 range 键。
    let plain = build_metrics_sse_payload(
        &state,
        &crate::service::admin::SseFilter::default(),
        None,
        "hourly",
    )
    .await;
    assert!(plain["range"].is_null(), "{plain}");
    assert!(
        plain["metrics"].get("range").is_none(),
        "无范围快照不得出现 range 键: {plain}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn session_scope_and_rows_shape_cover_design_keys() {
    let dir = metrics_test_dir("requests-shape");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    seed(&state, vec![row(60, 40, 100)]);
    let (status, body) = call(&state, 130, &[("range", "1h")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for key in [
        "ok",
        "enabled",
        "total",
        "limit",
        "offset",
        "range",
        "since_ts",
        "coverage_secs",
        "partial",
        "boundary_slack_secs",
        "sum_cached_read",
        "sum_cache_input_tokens",
        "hit_rate",
        "rows",
    ] {
        assert!(body.get(key).is_some(), "缺键 {key}: {body}");
    }
    let row = &body["rows"][0];
    for key in [
        "ts_secs",
        "request_id",
        "model",
        "protocol",
        "upstream",
        "ingress_port",
        "stream",
        "is_chat",
        "status",
        "latency_ms",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cached_read",
        "cache_input_tokens",
        "cache_hit_rate",
        "cache_write_rate",
        "session_id",
        "session_source",
        "session_scope",
        "upstream_id",
        "finish_reason",
        "summary",
        "truncated_mode",
        "error_kind",
        "ttft_ms",
        "tps",
    ] {
        assert!(row.get(key).is_some(), "行缺键 {key}: {row}");
    }
    // 前端展示前 12 位所需的原始摘要值仍为完整 16 hex（不截断在服务端）。
    assert_eq!(row["session_id"], "9f2c000000000000");
    // `any` 与缺省等价，`SessionScope` 导入用于显式断言取值集合。
    assert_eq!(SessionScope::Session.as_str(), "session");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn llm_param_filters_non_chat_rows_only() {
    let dir = metrics_test_dir("requests-llm-filter");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let mut passthrough = row(60, 0, 100);
    passthrough.request_id = "req-passthrough".to_string();
    passthrough.protocol = "passthrough".to_string();
    passthrough.model = "p-1".to_string();
    passthrough.is_chat = false;
    passthrough.counted_metrics = false;
    let mut count_tokens = row(60, 0, 100);
    count_tokens.request_id = "req-count-tokens".to_string();
    count_tokens.protocol = "anthropic".to_string();
    count_tokens.model = "c-1".to_string();
    count_tokens.is_chat = false;
    count_tokens.counted_metrics = false;
    seed(&state, vec![row(60, 40, 100), passthrough, count_tokens]);

    // 无 llm 参数：三行原样返回（含 is_chat=0 的 passthrough / count_tokens）。
    let (status, body) = call(&state, 140, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 3, "未带 llm 过滤时行数不变: {body}");
    assert_eq!(body["rows"].as_array().unwrap().len(), 3);
    assert_eq!(body["sum_cache_input_tokens"], 300, "{body}");

    // `llm=1`：只留 is_chat=1 行，聚合同 WHERE。
    for raw in ["1", "true"] {
        let (status, body) = call(&state, 141, &[("llm", raw)]).await;
        assert_eq!(status, StatusCode::OK, "llm={raw}: {body}");
        assert_eq!(body["total"], 1, "llm={raw} 须只留对话行: {body}");
        let rows = body["rows"].as_array().expect("rows 须为数组");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["request_id"], "req-60");
        assert_eq!(rows[0]["is_chat"], true);
        assert_eq!(body["sum_cache_input_tokens"], 100, "{body}");
    }
    // `llm=0|false` 与缺省等价：三行全留（合法取值须被接受而非 400）。
    for raw in ["0", "false"] {
        let (status, body) = call(&state, 143, &[("llm", raw)]).await;
        assert_eq!(status, StatusCode::OK, "llm={raw}: {body}");
        assert_eq!(body["total"], 3, "llm={raw} 须等价于不限: {body}");
        assert_eq!(body["sum_cache_input_tokens"], 300, "{body}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn row_json_exposes_ttft_and_tps() {
    let dir = metrics_test_dir("requests-ttft");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let mut measured = row(60, 40, 100);
    measured.completion_tokens = 100;
    measured.latency_ms = 5_000;
    measured.ttft_ms = Some(1_000);
    measured.tps = Some(25.0);
    let plain = row(120, 40, 100);
    seed(&state, vec![measured, plain]);
    let (status, body) = call(&state, 142, &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["rows"].as_array().expect("rows 须为数组");
    assert_eq!(rows[0]["ttft_ms"], 1_000, "{body}");
    assert_eq!(rows[0]["tps"], 25.0, "{body}");
    // 不可测时为 JSON null（不伪造 0）。
    assert!(rows[1]["ttft_ms"].is_null(), "{body}");
    assert!(rows[1]["tps"].is_null(), "{body}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn commands_range_filters_by_ts_and_reports_coverage() {
    // `/_admin/commands?range=` 按 `ts_secs` 下界过滤，响应带 coverage/partial；
    // 无 range 时保持既有键集（不出现 range 等范围键）。
    let dir = metrics_test_dir("commands-range");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let call_cmds = |ip: u8, q: Vec<(&str, &str)>| {
        let map: HashMap<String, String> = q
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let state = state.clone();
        async move {
            let resp = crate::handler::admin::admin_commands(
                State(state),
                PeerIp(Some(IpAddr::from([127, 0, 0, ip]))),
                headers_with(Some(ADMIN_TOKEN_T), None),
                Query(map),
            )
            .await
            .into_response();
            (resp.status(), body_json(resp).await)
        }
    };
    // 命令面默认关闭：仍须先校验 range/offset 参数（非法值 400）。
    let (status, body) = call_cmds(180, vec![("range", "5d")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "E_BAD_REQUEST");
    let (status, body) = call_cmds(181, vec![]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], 0);
    assert!(
        body.get("range").is_none(),
        "未启用分支不出现 range 键: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
