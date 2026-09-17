//! 管理面 SSE 帧与观测回归（OPS-3/5/6/7/9）：自 `admin/tests.rs` 拆分以守
//! 800 行红线；纯迁移，用例名与断言不变。

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
    // OPS-3：业务帧事件名 `event`（非 `message`）+ 收尾 `done` 终止帧。
    let ev = render_sse_frame(admin_event_frame("{\"x\":1}".to_string())).await;
    assert!(ev.contains("event: event"), "{ev}");
    assert!(!ev.contains("event: message"), "{ev}");
    let done = render_sse_frame(admin_done_frame()).await;
    assert!(done.contains("event: done"), "{done}");
    assert!(done.contains("data: {}"), "{done}");
}

#[tokio::test]
async fn admin_sse_frame_sequence() {
    // OPS-3：帧序列契约锁定——业务 `event` / 周期 `metrics` / 收尾恰一 `done`。
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
    // OPS-5：样本以 Python 同形嵌套 dict 置于 metrics，events 不再挂扁平数组。
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
    // OPS-6：默认 50、上限 200，越界钳位。
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
    // OPS-7：broadcast Lagged 可恢复（跳帧续推），仅 Closed 终止。
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
    // OPS-9：SSE / series 非法 granularity 显式 4xx，不静默回退默认粒度。
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
    // OPS-9：SSE 响应含 X-Accel-Buffering: no 禁用反代缓冲。
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

/// N/10.4（M-3/M-5）：四态截断白名单端到端落点行为断言——白名单齐备、
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
    // D12：`/_admin/metrics` 只读暴露当前作用域模式 + 复用/淘汰/回退三计数。
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
async fn admin_metrics_existing_keys_unchanged() {
    // D12：新增 `pii_scope` 为只增项；既有键集合与语义（含嵌套形状）不变。
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
async fn admin_metrics_scope_no_secret_leak() {
    // D12 指标层：模式/计数输出不含头值、会话键、明文或 token 原值。
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
    let token = scope.pii_scope().register(plaintext, false).unwrap();
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
