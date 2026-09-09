//! 指标快照形状 e2e（B5.3）：`/_admin/metrics` 字段集与 `series` 一致，空窗不崩溃。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_app() -> axum::Router {
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
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-metrics-snap-{n}.sqlite")),
            memory_only: true,
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    build_router(state)
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

#[tokio::test]
async fn b5_snapshot_shape_matches_series_and_empty_window_ok() {
    let (base, handle) = serve(test_app()).await;
    let client = reqwest::Client::new();
    // 空窗快照：200 且零值，不崩溃。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["requests"], 0);
    for field in [
        "is_precise",
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
    ] {
        assert!(body.get(field).is_some(), "快照缺字段 {field}: {body}");
    }
    for field in [
        "prompt",
        "completion",
        "total",
        "cached_read",
        "cached_write",
        "unknown",
    ] {
        assert!(
            body["tokens"].get(field).is_some(),
            "tokens 缺 {field}: {body}"
        );
    }
    for field in ["silent_discard", "open_ended", "synthesized_failed"] {
        assert!(
            body["truncated"].get(field).is_some(),
            "truncated 缺 {field}: {body}"
        );
    }
    // series 空窗同样 200（形状不断言崩溃）。
    for granularity in ["daily", "hourly", "five_min"] {
        let series = client
            .get(format!("{base}/_admin/series?granularity={granularity}"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(series.status().as_u16(), 200, "{granularity}");
        let _arr: serde_json::Value = series.json().await.unwrap();
    }
    handle.abort();
}
