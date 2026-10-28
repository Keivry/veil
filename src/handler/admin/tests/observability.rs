//! 管理面 SSE 帧与观测回归：自 `admin/tests.rs` 拆分以守
//! 800 行红线；用例名与断言不变。

use {
    super::{
        ADMIN_TOKEN_T,
        admin_test_state,
        body_json,
        cache_control,
        events_body,
        headers_with,
        metrics_body,
        metrics_test_dir,
        test_ip,
    },
    crate::{
        config::Config,
        handler::{
            PeerIp,
            admin::{
                SseRecv,
                admin_done_frame,
                admin_event_frame,
                admin_events_stream,
                admin_series,
                classify_sse_recv,
            },
        },
        service::credential::AppStateParts,
        state::{AppState, SqliteOutcome},
    },
    axum::{
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    },
    std::collections::HashMap,
};

async fn render_sse_frame(ev: axum::response::sse::Event) -> String {
    let stream = async_stream::stream! {
        yield Ok::<_, std::convert::Infallible>(ev);
    };
    let resp = axum::response::sse::Sse::new(stream).into_response();
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

async fn sample_enabled_state(dir: &std::path::Path) -> AppState {
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
        ("PII_VALUE_SAMPLE_ENABLED".to_string(), "1".to_string()),
    ]);
    AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    )
}

#[tokio::test]
async fn admin_sse_event_and_done() {
    // 业务帧事件名 `event`（非 `message`）+ 收尾 `done` 终止帧。
    let ev = render_sse_frame(admin_event_frame("{\"x\":1}".to_string())).await;
    assert!(ev.contains("event: event"), "{ev}");
    assert!(!ev.contains("event: message"), "{ev}");
    let done = render_sse_frame(admin_done_frame()).await;
    assert!(done.contains("event: done"), "{done}");
    assert!(done.contains("data: {}"), "{done}");
}

#[tokio::test]
async fn admin_sse_frame_sequence() {
    // 帧序列契约锁定——业务 `event` / 周期 `metrics` / 收尾恰一 `done`。
    let seq = [
        render_sse_frame(admin_event_frame("{\"e\":1}".to_string())).await,
        render_sse_frame(
            axum::response::sse::Event::default()
                .event("metrics")
                .data("{}"),
        )
        .await,
        render_sse_frame(admin_done_frame()).await,
    ];
    assert!(seq[0].contains("event: event"), "{:?}", seq[0]);
    assert!(seq[1].contains("event: metrics"), "{:?}", seq[1]);
    assert!(seq[2].contains("event: done"), "{:?}", seq[2]);
    assert_eq!(
        seq.iter().filter(|s| s.contains("event: done")).count(),
        1,
        "done 终止帧恰一"
    );
}

#[tokio::test]
async fn pii_value_samples_shape() {
    // 样本以嵌套 dict 置于 metrics，events 不再挂扁平数组。
    let dir = metrics_test_dir("pii-samples-shape");
    let state = sample_enabled_state(&dir).await;
    assert!(
        state
            .admin_state()
            .sampler
            .sample("phone", "13800008000", true, "up-1")
            .is_some(),
        "采样开启须命中"
    );
    let v = metrics_body(state.clone()).await;
    let samples = &v["pii_value_samples"];
    assert!(samples.is_object(), "metrics 须嵌套对象携带样本: {v}");
    assert!(samples["phone"].is_object(), "按 kind 嵌套: {v}");
    assert!(
        samples["phone"]["138****8000"]["count"].is_u64(),
        "mask 下含 count: {v}"
    );
    assert!(
        samples["phone"]["138****8000"]["hash"].is_string(),
        "mask 下含 hash: {v}"
    );
    let ev = events_body(state.clone(), HashMap::new()).await;
    assert!(
        ev.get("pii_value_samples").is_none(),
        "events 不得挂扁平样本数组: {ev}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_events_limit_bounds() {
    // 默认 50、上限 200，越界钳位。
    assert_eq!(crate::service::admin::EVENT_DEFAULT_LIMIT, 50);
    assert_eq!(crate::service::admin::EVENT_MAX_LIMIT, 200);
    let dir = metrics_test_dir("events-limit");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    {
        let st = state.admin_state();
        for i in 0..250 {
            st.push_event("audit", &format!("e{i}"), None);
        }
    }
    let default = events_body(state.clone(), HashMap::new()).await;
    assert_eq!(default["events"].as_array().unwrap().len(), 50, "默认 50");
    let over = events_body(
        state.clone(),
        HashMap::from([("limit".to_string(), "999".to_string())]),
    )
    .await;
    assert_eq!(
        over["events"].as_array().unwrap().len(),
        200,
        "上限收敛 200"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn sse_lagged_recovers() {
    // broadcast Lagged 可恢复（跳帧续推），仅 Closed 终止。
    use tokio::sync::broadcast::error::RecvError;
    assert!(matches!(
        classify_sse_recv(Ok("e".to_string())),
        SseRecv::Event(_)
    ));
    assert!(matches!(
        classify_sse_recv(Err(RecvError::Closed)),
        SseRecv::Closed
    ));

    let (tx, mut rx) = tokio::sync::broadcast::channel::<String>(2);
    for i in 0..5 {
        let _ = tx.send(format!("e{i}"));
    }
    assert!(
        matches!(classify_sse_recv(rx.recv().await), SseRecv::Skip(_)),
        "订阅落后须判 Lagged"
    );
    tx.send("after".to_string()).unwrap();
    let mut got_after = false;
    for _ in 0..8 {
        match classify_sse_recv(rx.recv().await) {
            SseRecv::Event(m) if m == "after" => {
                got_after = true;
                break;
            }
            SseRecv::Event(_) | SseRecv::Skip(_) => continue,
            SseRecv::Closed => break,
        }
    }
    assert!(got_after, "Lagged 后连接须保持并继续推送后续事件");
}

#[tokio::test]
async fn granularity_invalid_rejected() {
    // SSE / series 非法 granularity 显式 4xx，不静默回退默认粒度。
    let dir = metrics_test_dir("granularity-invalid");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let q = || HashMap::from([("granularity".to_string(), "bogus".to_string())]);
    let resp = admin_events_stream(
        State(state.clone()),
        PeerIp(Some(test_ip())),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q()),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "SSE 须显式拒绝");
    let v = body_json(resp).await;
    assert_eq!(v["error"]["code"], "E_BAD_REQUEST");

    let sresp = admin_series(
        State(state.clone()),
        PeerIp(Some(test_ip())),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q()),
    )
    .await
    .into_response();
    assert_eq!(sresp.status(), StatusCode::BAD_REQUEST);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn sse_x_accel_buffering() {
    // SSE 响应含 X-Accel-Buffering: no 禁用反代缓冲。
    let dir = metrics_test_dir("sse-xaccel");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let resp = admin_events_stream(
        State(state.clone()),
        PeerIp(Some(test_ip())),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(HashMap::new()),
    )
    .await
    .into_response();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .and_then(|v| v.to_str().ok()),
        Some("no")
    );
    assert!(cache_control(&resp).contains("no-store"));
    std::fs::remove_dir_all(&dir).ok();
}

/// 四态截断白名单端到端落点行为断言——白名单齐备、
/// metrics/store/aggregate/admin 四类落点各态独立为 1 且互不串计、
/// 四态之外不落该指标。`tracing::warn!` 不可断言，故不作判据。
#[tokio::test]
async fn truncated_mode_four_state_labels() {
    use crate::service::{
        llm_gateway::{GatewayMetrics, Protocol, metrics::TRUNCATED_MODE_KEYS},
        metrics::{ChatRecord, MetricsStore, TRUNCATED_MODES, summarize::test_support::now},
    };
    const FOUR: [&str; 4] = [
        "silent_discard",
        "open_ended",
        "synthesized_failed",
        "upstream_error",
    ];
    assert_eq!(TRUNCATED_MODE_KEYS, FOUR, "网关白名单须四态齐备");
    assert_eq!(TRUNCATED_MODES, FOUR, "聚合白名单须四态齐备");

    // metrics 落点：四态各落具名键；四态之外仅落 other 桶，四态键不递增。
    let gm = GatewayMetrics::default();
    for mode in FOUR {
        gm.record_truncated(mode);
    }
    for mode in FOUR {
        assert_eq!(gm.truncated_count(mode), 1, "具名键 {mode} 须独立计 1");
    }
    assert_eq!(
        gm.truncated_count("__unknown_bucket__"),
        0,
        "四态具名记录不得落 other"
    );
    gm.record_truncated("bogus_mode");
    for mode in FOUR {
        assert_eq!(gm.truncated_count(mode), 1, "四态之外不得递增 {mode}");
    }
    assert_eq!(gm.truncated_count("upstream_error"), 1);
    assert_eq!(
        gm.truncated_count("__unknown_bucket__"),
        1,
        "未知键仅落 other"
    );

    // store/aggregate 落点：四态各记一次 → 快照四字段各为 1。
    let dir = metrics_test_dir("four-state");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let store = &state.admin_state().metrics;
    let ts = now();
    for mode in FOUR {
        assert!(
            store.record_chat(ChatRecord {
                protocol: Protocol::Chat,
                model: "four-state",
                latency_ms: 5,
                usage: None,
                truncated_mode: Some(mode),
                is_precise: true,
                ts_secs: ts,
            }),
            "对话端点须记录 {mode}"
        );
    }
    let snap = store.snapshot();
    assert_eq!(snap.truncated_silent_discard, 1);
    assert_eq!(snap.truncated_open_ended, 1);
    assert_eq!(snap.truncated_synthesized_failed, 1);
    assert_eq!(
        snap.truncated_upstream_error, 1,
        "upstream_error 须独立成列"
    );

    // 四态之外的值：四枚标签均不递增（warn 不可断言，仅桶可观测）。
    assert!(store.record_chat(ChatRecord {
        protocol: Protocol::Chat,
        model: "four-state",
        latency_ms: 5,
        usage: None,
        truncated_mode: Some("bogus_mode"),
        is_precise: true,
        ts_secs: ts,
    }));
    let snap2 = store.snapshot();
    assert_eq!(
        (
            snap2.truncated_silent_discard,
            snap2.truncated_open_ended,
            snap2.truncated_synthesized_failed,
            snap2.truncated_upstream_error,
        ),
        (1, 1, 1, 1),
        "四态之外不得落任一标签"
    );

    // 持久读取路径：flush 后 SeriesPoint 四字段各为 1（SELECT 列序对位）。
    store.flush().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1, "同一日/协议单行");
    assert_eq!(pts[0].truncated_silent_discard, 1);
    assert_eq!(pts[0].truncated_open_ended, 1);
    assert_eq!(pts[0].truncated_synthesized_failed, 1);
    assert_eq!(pts[0].truncated_upstream_error, 1, "series 列序须对位");

    // 回填路径：新 store 读旧库把 upstream_error 列还原进窗口累计（backfill 列序对位）。
    let store2 = MetricsStore::new(dir.join("m.sqlite"));
    store2.backfill_from_sqlite().await.unwrap();
    let restored = store2
        .aggs
        .lock()
        .expect("聚合锁无毒")
        .values()
        .map(|a| a.t_upstream_error)
        .max()
        .unwrap_or(0);
    assert_eq!(restored, 1, "回填须还原 upstream_error 列");

    // admin 落点：/_admin/metrics 的 truncated 对象四态齐备且各为 1。
    let body = metrics_body(state.clone()).await;
    for mode in FOUR {
        assert_eq!(
            body["truncated"][mode].as_u64(),
            Some(1),
            "admin 导出缺 {mode}: {body}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

fn pii_scope_conversation_state(dir: &std::path::Path) -> AppState {
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
        ("PII_SCOPE_MODE".to_string(), "conversation".to_string()),
    ]);
    AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    )
}

#[tokio::test]
async fn admin_metrics_expose_pii_scope_mode() {
    // `/_admin/metrics` 只读暴露当前作用域模式 + 复用/淘汰/回退三计数。
    let dir = metrics_test_dir("pii-scope-mode");
    let request_state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let body = metrics_body(request_state.clone()).await;
    assert_eq!(body["pii_scope"]["mode"], "request", "{body}");
    for k in [
        "conversation_reuse",
        "conversation_eviction",
        "request_fallback",
    ] {
        assert!(body["pii_scope"][k].is_u64(), "缺计数 {k}: {body}");
    }

    let conv_dir = metrics_test_dir("pii-scope-mode-conv");
    let conv_state = pii_scope_conversation_state(&conv_dir);
    let conv_body = metrics_body(conv_state.clone()).await;
    assert_eq!(
        conv_body["pii_scope"]["mode"], "conversation",
        "{conv_body}"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&conv_dir).ok();
}

#[tokio::test]
async fn admin_metrics_expose_oversize_and_key_removed() {
    // 超软限观测（帧/字节）在 /_admin/metrics 可见且随落账递增；
    // 响应侧 PII 分类键不在管理面观测内。
    // 键名在源码中拆写（字面量不得出现于 `src/`，归零门禁）；负断言语义不变。
    const REMOVED_PII_CLASSIFICATION_KEY: &str = concat!("pii_", "classification");
    let dir = metrics_test_dir("oversize-pii-classification");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let before = metrics_body(state.clone()).await;
    for k in ["oversize_frames", "oversize_frame_bytes"] {
        assert_eq!(before[k].as_u64(), Some(0), "空窗 {k} 须数值零: {before}");
    }
    assert!(
        before.as_object().is_some_and(|o| o
            .keys()
            .all(|k| !k.contains(REMOVED_PII_CLASSIFICATION_KEY))),
        "响应侧 PII 分类键须已移除: {before}"
    );
    state.gateway_metrics().record_oversize_frames(2, 4096);
    let after = metrics_body(state.clone()).await;
    assert_eq!(after["oversize_frames"].as_u64(), Some(2), "{after}");
    assert_eq!(
        after["oversize_frame_bytes"].as_u64(),
        Some(4096),
        "{after}"
    );
    assert!(
        after.as_object().is_some_and(|o| o
            .keys()
            .all(|k| !k.contains(REMOVED_PII_CLASSIFICATION_KEY))),
        "响应侧 PII 分类键须持续不存在: {after}"
    );
    assert!(
        after["truncated"]["open_ended"].is_u64(),
        "truncated 四态须与 oversize 并存: {after}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_metrics_existing_keys_unchanged() {
    // 新增 `pii_scope` 为只增项；既有键集合与语义（含嵌套形状）不变。
    let dir = metrics_test_dir("pii-scope-existing-keys");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let body = metrics_body(state.clone()).await;
    const EXISTING: [&str; 19] = [
        "ok",
        "is_precise",
        "requests",
        "tokens",
        "per_protocol",
        "per_model",
        "latency_buckets",
        "p95_ms",
        "truncated",
        "chat_tail_lenient",
        "sse_events",
        "ring_len",
        "dropped",
        "approval_decision_overflow_total",
        "decision_table_size",
        "upstream_read_errors",
        "admin_rate_evicted",
        "aggs_evicted",
        "pii_value_samples",
    ];
    for k in EXISTING {
        assert!(body.get(k).is_some(), "既有键 {k} 缺失: {body}");
    }
    for k in ["prompt", "completion", "total"] {
        assert!(body["tokens"][k].is_u64(), "tokens.{k} 语义变化: {body}");
    }
    for k in ["chat/completions", "v1/messages", "v1/responses"] {
        assert!(body["chat_tail_lenient"][k].is_u64(), "{body}");
    }
    for k in [
        "silent_discard",
        "open_ended",
        "synthesized_failed",
        "upstream_error",
    ] {
        assert!(body["truncated"][k].is_u64(), "truncated.{k}: {body}");
    }
    assert!(body["pii_scope"].is_object(), "新增项须为对象: {body}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_metrics_exposes_aux_totals() {
    // 快照顶层暴露三项脱敏计数总量（控制台 KPI 直接读取，不从 series 累加）。
    let dir = metrics_test_dir("aux-totals");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let before = metrics_body(state.clone()).await;
    for k in ["pii_hits", "pii_miss", "cred_hits"] {
        assert!(before[k].is_u64(), "缺快照总量 {k}: {before}");
    }
    state.admin_state().metrics.record_aux_counts_extended(
        crate::service::llm_gateway::Protocol::Chat,
        3_600,
        5,
        2,
        4,
        1,
    );
    let after = metrics_body(state.clone()).await;
    assert_eq!(after["pii_hits"].as_u64(), Some(5), "{after}");
    assert_eq!(after["pii_miss"].as_u64(), Some(2), "{after}");
    assert_eq!(after["cred_hits"].as_u64(), Some(4), "{after}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_metrics_scope_no_secret_leak() {
    // 指标层：模式/计数输出不含头值、会话键、明文或 token 原值。
    use crate::service::redaction::{derive_conversation_key, tenant_fingerprint};
    let dir = metrics_test_dir("pii-scope-noleak");
    let state = pii_scope_conversation_state(&dir);
    let upstream = "https://up.example.com/v1";
    let header_value = "conv-abcdef0123456789";
    let plaintext = "13812345678";
    let mut headers = HeaderMap::new();
    headers.insert("x-veil-conversation-id", header_value.parse().unwrap());
    let body = serde_json::json!({"messages": [{"role": "user", "content": plaintext}]});
    let scope = crate::handler::llm::dispatch::build_request_scope(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );
    let token = scope.pii_scope().register(plaintext).unwrap();
    // 第二轮命中同一会话键，确保复用计数路径确实执行（计数 > 0 才可断言无泄露）。
    let _ = crate::handler::llm::dispatch::build_request_scope(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Chat,
        upstream,
        Some(&body),
    );
    let secret = state.conversation_secret.as_ref();
    let fp = tenant_fingerprint(secret, upstream, &[]);
    let key = derive_conversation_key(
        secret,
        &fp,
        crate::service::llm_gateway::Protocol::Chat,
        Some(header_value),
        None,
        None,
        &serde_json::json!({}),
        &state.previous_response_map,
    )
    .unwrap();
    let v = metrics_body(state.clone()).await;
    let text = serde_json::to_string(&v).unwrap();
    assert!(
        v["pii_scope"]["conversation_reuse"].as_u64().unwrap() >= 1,
        "复用计数须可见: {v}"
    );
    assert!(!text.contains(header_value), "指标不得含头值: {text}");
    assert!(!text.contains(plaintext), "指标不得含明文: {text}");
    assert!(!text.contains(&token), "指标不得含 token: {text}");
    assert!(!text.contains(key.as_str()), "指标不得含会话键: {text}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_metrics_dispatches_range_and_rejects_invalid() {
    // `/_admin/metrics` 的 range 分派：合法四档回显窗口字段，非法值 400 且不返回快照。
    let dir = metrics_test_dir("metrics-range-dispatch");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let mut ip = 140u8;
    for (label, slack) in [
        ("1h", 300_u64),
        ("24h", 3_600),
        ("7d", 86_400),
        ("30d", 86_400),
    ] {
        ip += 1;
        let resp = crate::handler::admin::admin_metrics(
            State(state.clone()),
            PeerIp(Some(std::net::IpAddr::from([127, 0, 0, ip]))),
            headers_with(Some(ADMIN_TOKEN_T), None),
            Query(HashMap::from([("range".to_string(), label.to_string())])),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK, "{label}");
        let body = body_json(resp).await;
        assert_eq!(body["range"], label, "{label}: {body}");
        assert!(body["since_ts"].as_i64().is_some(), "{label}: {body}");
        // 空环时 1h 会走窗口兜底（slack=300），其余档位按映射粒度。
        assert_eq!(body["boundary_slack_secs"], slack, "{label}: {body}");
        assert_eq!(body["partial"], true, "空环必然覆盖不足: {label}");
        assert!(body["coverage_secs"].is_u64(), "{label}: {body}");
    }
    // 非法 range：400 + E_BAD_REQUEST，且响应体不含快照键。
    let resp = crate::handler::admin::admin_metrics(
        State(state.clone()),
        PeerIp(Some(std::net::IpAddr::from([127, 0, 0, 150]))),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(HashMap::from([("range".to_string(), "2h".to_string())])),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], "E_BAD_REQUEST", "{body}");
    assert!(body.get("requests").is_none(), "非法参数不返回快照: {body}");
    // 无 range：保持旧全局口径（既有键集不变，不出现 range/partial 等范围键）。
    let plain = metrics_body(state.clone()).await;
    for absent in [
        "range",
        "since_ts",
        "coverage_secs",
        "partial",
        "boundary_slack_secs",
    ] {
        assert!(
            plain.get(absent).is_none(),
            "无 range 不得出现 {absent}: {plain}"
        );
    }
    assert!(plain["requests_dropped"].is_u64(), "{plain}");
    assert!(plain["requests_aborted"].is_u64(), "{plain}");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_series_range_folds_into_since_window() {
    // `range` 折算 `[dhm]<整数>` 窗口键下界：与显式 since 同口径等价；
    // 非法 range 400，且不改变 since 的合法形态集合。
    let dir = metrics_test_dir("series-range-since");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let call_series = |ip: u8, q: Vec<(&str, &str)>| {
        let map: HashMap<String, String> = q
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let state = state.clone();
        async move {
            let resp = admin_series(
                State(state),
                PeerIp(Some(std::net::IpAddr::from([127, 0, 0, ip]))),
                headers_with(Some(ADMIN_TOKEN_T), None),
                Query(map),
            )
            .await
            .into_response();
            (resp.status(), body_json(resp).await)
        }
    };
    let (status, ranged) = call_series(160, vec![("range", "24h")]).await;
    assert_eq!(status, StatusCode::OK, "{ranged}");
    assert_eq!(ranged["granularity"], "hourly");
    let (status, found) = call_series(161, vec![("granularity", "hourly")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ranged["points"], found["points"],
        "range=24h 须与全量 hourly 在空库上等价（下界不排除未来窗口）: {ranged}"
    );
    // 非法 range：400，且与非法 granularity 同错误码。
    let (status, body) = call_series(162, vec![("range", "90d")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "E_BAD_REQUEST");
    // `since` 的合法形态集合未变：epoch 形态仍被拒。
    let (status, _) = call_series(163, vec![("since", "1730000000")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "epoch 形态须仍被拒");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_events_echoes_effective_later_since() {
    // `range` + 更晚的显式 `since`：过滤用较晚者，响应 `since_ts` 必须回显同一
    // 生效下界（不得回显 `range_start`）。
    let dir = metrics_test_dir("events-effective-since");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    state.admin_state().push_event("audit", "刚刚的事件", None);
    let q = |kv: &[(&str, &str)]| -> HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let future = now + 3_600;
    let body = events_body(
        state.clone(),
        q(&[("range", "1h"), ("since", &future.to_string())]),
    )
    .await;
    assert_eq!(
        body["since_ts"].as_i64(),
        Some(future),
        "since_ts 须回显实际生效的较晚下界: {body}"
    );
    assert_ne!(
        body["since_ts"].as_i64(),
        Some(now - 3_600),
        "不得回显 range_start: {body}"
    );
    assert_eq!(
        body["coverage_secs"].as_u64(),
        Some(0),
        "下界在未来时覆盖为 0: {body}"
    );
    // 仅 range（无 since）：仍回显 range 推导下界。
    let body = events_body(state.clone(), q(&[("range", "1h")])).await;
    let since_ts = body["since_ts"].as_i64().expect("since_ts");
    assert!(
        (now - 3_600 - 5..=now - 3_600 + 5).contains(&since_ts),
        "仅 range 时 since_ts = now - span: {body}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_series_range_granularity_conflict_uses_final_granularity() {
    // `range=1h&granularity=daily`：下界键须按**最终**粒度（`d…`）折算，
    // 否则与 `d…` 窗口做字符串序比较恒空。
    let dir = metrics_test_dir("series-range-gran-conflict");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    assert!(
        state
            .admin_state()
            .metrics
            .record_chat(crate::service::metrics::ChatRecord {
                protocol: crate::service::llm_gateway::Protocol::Chat,
                model: "gran-conflict",
                latency_ms: 5,
                usage: None,
                truncated_mode: None,
                is_precise: true,
                ts_secs: now,
            })
    );
    state.admin_state().metrics.flush().await.expect("刷盘");
    let call = |ip: u8, q: Vec<(&str, &str)>| {
        let map: HashMap<String, String> = q
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let state = state.clone();
        async move {
            let resp = admin_series(
                State(state),
                PeerIp(Some(std::net::IpAddr::from([127, 0, 0, ip]))),
                headers_with(Some(ADMIN_TOKEN_T), None),
                Query(map),
            )
            .await
            .into_response();
            (resp.status(), body_json(resp).await)
        }
    };
    let (status, body) = call(172, vec![("range", "1h"), ("granularity", "daily")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["granularity"], "daily", "{body}");
    assert!(
        !body["points"].as_array().unwrap().is_empty(),
        "range+granularity 冲突不得返回空点集: {body}"
    );
    for p in body["points"].as_array().unwrap() {
        let window = p["window"].as_str().unwrap_or("");
        assert!(
            window.starts_with('d'),
            "daily 口径的窗口键须为 d…: {window}"
        );
    }
    // 同参数基线：仅 granularity=daily 也必须返回同一组点。
    let (status, baseline) = call(173, vec![("granularity", "daily")]).await;
    assert_eq!(status, StatusCode::OK, "{baseline}");
    assert_eq!(
        body["points"], baseline["points"],
        "range=1h 的窗口下界不排除当天的 daily 窗口: {body} vs {baseline}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_series_bad_requests_carry_security_headers() {
    // series 的每一条 400 分支都须经统一 helper，带上 `Cache-Control: no-store`。
    let dir = metrics_test_dir("series-400-headers");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let cases: [Vec<(&str, &str)>; 4] = [
        vec![("granularity", "bogus")],
        vec![("range", "90d")],
        vec![("since", "1730000000")],
        vec![("range", "5d")],
    ];
    let mut ip = 180u8;
    for case in cases {
        ip += 1;
        let map: HashMap<String, String> = case
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let resp = admin_series(
            State(state.clone()),
            PeerIp(Some(std::net::IpAddr::from([127, 0, 0, ip]))),
            headers_with(Some(ADMIN_TOKEN_T), None),
            Query(map),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{case:?}");
        assert!(
            cache_control(&resp).contains("no-store"),
            "400 响应须带 no-store: {case:?}"
        );
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
            "400 响应须带统一安全头: {case:?}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn sse_replay_respects_connection_range() {
    // 回放：`since` 由连接 `range` 导出，越界事件不得回放；
    // 实时：`event_within_since` 丢弃早于下界的事件。
    use crate::{handler::admin::stream::replay_backlog, service::admin::SseFilter};
    let dir = metrics_test_dir("sse-replay-range");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let admin_state = state.admin_state();
    // 两条事件：一条 ts 远早于 1h 下界，一条就在当下（直接落环以控制时间戳）。
    {
        let mut ring = admin_state.events.lock().unwrap();
        ring.push_back(crate::service::admin::AdminEvent {
            id: 1,
            ts_secs: now - 7_200,
            kind: "audit".to_string(),
            summary: "旧事件".to_string(),
            protocol: None,
        });
        ring.push_back(crate::service::admin::AdminEvent {
            id: 2,
            ts_secs: now,
            kind: "audit".to_string(),
            summary: "新事件".to_string(),
            protocol: None,
        });
    }
    let since = now - 3_600;
    let back = replay_backlog(admin_state, &SseFilter::default(), Some(since));
    assert_eq!(back.len(), 1, "越界旧事件不得回放: {back:?}");
    assert!(back[0].contains("新事件"), "{back:?}");
    // 无 since：两条都回放。
    let all = replay_backlog(admin_state, &SseFilter::default(), None);
    assert_eq!(all.len(), 2, "{all:?}");
    // 实时过滤：早于下界丢弃，晚于下界放行，无 ts 直通。
    let stale = serde_json::json!({"ts_secs": now - 7_200, "summary": "old"}).to_string();
    let fresh = serde_json::json!({"ts_secs": now, "summary": "new"}).to_string();
    assert!(
        !crate::handler::admin::stream::event_within_since(&stale, Some(since)),
        "早于下界的实时事件须丢弃"
    );
    assert!(crate::handler::admin::stream::event_within_since(
        &fresh,
        Some(since)
    ));
    assert!(
        crate::handler::admin::stream::event_within_since("not-json", Some(since)),
        "形态不符直通不丢事件"
    );
    assert!(crate::handler::admin::stream::event_within_since(
        &stale, None
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_events_range_takes_later_bound_and_reports_coverage() {
    // `range` 与显式 `since`（epoch 秒）同给时取较晚下界；响应带覆盖字段。
    let dir = metrics_test_dir("events-range");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    state.admin_state().push_event("audit", "刚刚的事件", None);
    let two_hours_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        - 7_200;
    let q = |kv: &[(&str, &str)]| -> HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    // range=1h 的推导下界（now-3600）晚于 2 小时前的 since → 保留该事件。
    let body = events_body(
        state.clone(),
        q(&[("range", "1h"), ("since", &two_hours_ago.to_string())]),
    )
    .await;
    assert_eq!(body["events"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["range"], "1h", "{body}");
    assert_eq!(body["boundary_slack_secs"], 0, "{body}");
    assert_eq!(body["partial"], true, "事件环仅覆盖数秒: {body}");
    assert!(body["coverage_secs"].is_u64(), "{body}");
    // 显式 since 更晚（未来时刻）→ 取 since，结果为空。
    let future = (two_hours_ago + 86_400 * 365).to_string();
    let body = events_body(state.clone(), q(&[("range", "1h"), ("since", &future)])).await;
    assert_eq!(body["events"].as_array().unwrap().len(), 0, "{body}");
    // 无 range：不出现 range 键，仍带 coverage/partial 观测。
    let body = events_body(state.clone(), HashMap::new()).await;
    assert!(body.get("range").is_none(), "{body}");
    assert_eq!(body["partial"], false, "{body}");
    // 非法 range → 400。
    let resp = crate::handler::admin::admin_events(
        State(state.clone()),
        PeerIp(Some(std::net::IpAddr::from([127, 0, 0, 170]))),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q(&[("range", "3d")])),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"]["code"], "E_BAD_REQUEST", "{body}");
    std::fs::remove_dir_all(&dir).ok();
}
