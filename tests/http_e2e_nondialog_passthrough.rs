//! T-M2 NonDialog 透传 e2e（`veil-review-followup-test-gap` T2.1）：
//! `GET /v1/models` 经网关到 mock 上游，断言字节透传 + `nondialog_passthrough`
//! 计数 + 无用量/审计/还原（含原文 phone 未脱敏证明）。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{
        config::Config,
        router::build_router,
        service::credential::AppStateParts,
        state::SqliteOutcome,
    },
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

/// 上游原文：含 phone 形态字符串，透传臂不得脱敏。
const UPSTREAM_BODY: &str =
    r#"{"object":"list","data":[{"id":"gpt-4o","object":"model"}],"note":"13812345678"}"#;

fn test_app(extra: &[(&str, &str)]) -> (axum::Router, veil::state::AppState) {
    let mut env = HashMap::from([
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
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-nondialog-{n}.sqlite")),
            memory_only: true,
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
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

async fn mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                UPSTREAM_BODY,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

#[tokio::test]
async fn t2_1_nondialog_models_passthrough_with_count_and_no_side_effects() {
    let (upstream, uhandle) = mock_upstream().await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.unwrap();
    // 字节透传：下游体与上游原文一致。
    assert_eq!(body, UPSTREAM_BODY, "NonDialog 臂须字节透传");
    // 无还原/脱敏：原文 phone 形态原样透出，未被占位符替换。
    assert!(body.contains("13812345678"), "透传臂不得脱敏: {body}");
    assert!(!body.contains("__PII_"), "透传臂不得注入占位符: {body}");

    // 计数：透传臂 +1。
    assert_eq!(
        state.gateway_metrics().nondialog_passthrough_count(),
        1,
        "每次透传须计数"
    );

    // 无用量：对话指标快照 requests 恒零。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let metrics_body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(
        metrics_body["requests"], 0,
        "透传不得记录用量: {metrics_body}"
    );

    // 无审计：事件环为空。
    let events = client
        .get(format!("{base}/_admin/events?limit=100"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(events.status().as_u16(), 200);
    let events_body: serde_json::Value = events.json().await.unwrap();
    assert!(
        events_body["events"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "透传不得产生审计事件: {events_body}"
    );

    uhandle.abort();
    handle.abort();
}
