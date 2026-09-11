//! T-M1 series 筛选与空窗快照 e2e（`veil-review-followup-test-gap` T1.2）：
//! `granularity` 三粒度 + `protocol` 过滤 + `since` 过滤 + `model/upstream`
//! 弃用兼容回显 + 空窗形状不断言崩溃。种子经 `AppState` 直写指标存储，
//! 查询走真实 HTTP，覆盖网关出口行为。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::atomic::AtomicU64,
        time::{SystemTime, UNIX_EPOCH},
    },
    veil::{
        config::Config,
        router::build_router,
        service::{
            credential::AppStateParts,
            llm_gateway::{Protocol, Usage},
            metrics::ChatRecord,
        },
        state::SqliteOutcome,
    },
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn usage(p: u64, c: u64, t: u64) -> Usage {
    Usage {
        prompt_tokens: p,
        completion_tokens: c,
        total_tokens: t,
        cached_read: 0,
        cached_write: 0,
    }
}

fn test_app() -> (axum::Router, veil::state::AppState) {
    let env = HashMap::from([
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
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = PathBuf::from(format!("/tmp/veil-e2e-metrics-filter-{n}.sqlite"));
    let _ = std::fs::remove_file(&db);
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: db,
        },
    )
    .with_keepass(std::sync::Arc::new(veil::keepass::MockKeePass::unlocked()));
    let router = build_router(state.clone());
    (router, state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

async fn get_json(client: &reqwest::Client, base: &str, path: &str) -> (u16, serde_json::Value) {
    let resp = client
        .get(format!("{base}{path}"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();
    (status, body)
}

#[tokio::test]
async fn t1_2_series_granularity_protocol_since_and_compat_e2e() {
    let (app, state) = test_app();
    // 种子：chat 与 responses 各一条，同窗不同协议。
    let ts = now_secs();
    let u1 = usage(10, 5, 15);
    let u2 = usage(4, 2, 6);
    state.admin_state().metrics.record_chat(ChatRecord {
        protocol: Protocol::Chat,
        model: "filter-m",
        latency_ms: 12,
        usage: Some(&u1),
        truncated_mode: None,
        is_precise: true,
        ts_secs: ts,
    });
    state.admin_state().metrics.record_chat(ChatRecord {
        protocol: Protocol::Responses,
        model: "filter-m",
        latency_ms: 20,
        usage: Some(&u2),
        truncated_mode: None,
        is_precise: true,
        ts_secs: ts,
    });
    state.admin_state().metrics.flush().await.unwrap();

    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // 三粒度均 200 且两协议行齐全。
    for granularity in ["daily", "hourly", "five_min"] {
        let (status, body) = get_json(
            &client,
            &base,
            &format!("/_admin/series?granularity={granularity}"),
        )
        .await;
        assert_eq!(status, 200, "{granularity}");
        assert_eq!(body["ok"], true);
        assert_eq!(body["granularity"], granularity);
        let points = body["points"].as_array().unwrap();
        assert_eq!(points.len(), 2, "{granularity} 须两协议行: {body}");
        let total: u64 = points.iter().map(|p| p["requests"].as_u64().unwrap()).sum();
        assert_eq!(total, 2);
    }

    // protocol 过滤：仅 chat 行。
    let (status, body) = get_json(
        &client,
        &base,
        "/_admin/series?granularity=daily&protocol=chat/completions",
    )
    .await;
    assert_eq!(status, 200);
    let points = body["points"].as_array().unwrap();
    assert_eq!(points.len(), 1);
    assert_eq!(points[0]["protocol"], "chat/completions");
    assert_eq!(points[0]["requests"], 1);
    assert_eq!(points[0]["total_tokens"], 15);

    // since 过滤：未来窗口返回空数组，不断言崩溃。
    let (status, body) = get_json(
        &client,
        &base,
        "/_admin/series?granularity=daily&since=d999999999",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["points"].as_array().unwrap().is_empty());

    // model/upstream 弃用兼容：200 + deprecated 标注 + compat 回显，不过滤。
    let (status, body) = get_json(
        &client,
        &base,
        "/_admin/series?granularity=daily&model=filter-m&upstream=https://up.example",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("deprecated").is_some(), "须弃用标注: {body}");
    assert_eq!(body["compat"]["model"], "filter-m");
    assert_eq!(body["points"].as_array().unwrap().len(), 2);

    // range 旧查询兼容：24h 映射 hourly 且附 deprecated。
    let (status, body) = get_json(&client, &base, "/_admin/series?range=24h").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["granularity"], "hourly");
    assert!(body.get("deprecated").is_some());

    // 非法 granularity 恒 400。
    let (status, _) = get_json(&client, &base, "/_admin/series?granularity=weekly").await;
    assert_eq!(status, 400);

    handle.abort();
}

#[tokio::test]
async fn t1_2_empty_window_snapshot_shape_ok() {
    // 空窗：metrics 快照零值 + series 空数组，形状不断言崩溃。
    let (app, _state) = test_app();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let (status, body) = get_json(&client, &base, "/_admin/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(body["ok"], true);
    assert_eq!(body["requests"], 0);
    let (status, body) = get_json(&client, &base, "/_admin/series?granularity=hourly").await;
    assert_eq!(status, 200);
    assert!(body["points"].as_array().unwrap().is_empty());
    handle.abort();
}
