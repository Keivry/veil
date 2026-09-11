//! T-M2 NonDialog 透传 e2e（`veil-review-followup-test-gap` T2.1）：
//! `GET /v1/models` 经网关到 mock 上游，断言字节透传 + `nondialog_passthrough`
//! 计数 1→2→3 + hop 方向计数 + 上游收到的路径/方法/头 + 无用量/审计/还原
//! （含原文 phone 未脱敏证明）。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, Mutex, atomic::AtomicU64},
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

/// 上游收到的请求快照（方法/路径/头），供透传路径断言。
#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

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

async fn mock_upstream(
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move |req: axum::extract::Request| {
            let captured = captured.clone();
            async move {
                captured.lock().unwrap().push(CapturedRequest {
                    method: req.method().to_string(),
                    path: req.uri().path().to_string(),
                    headers: req
                        .headers()
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_string(),
                                v.to_str().unwrap_or("<bin>").to_string(),
                            )
                        })
                        .collect(),
                });
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    UPSTREAM_BODY,
                )
            }
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
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(captured.clone()).await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let up_before = state.gateway_metrics().hop_filtered_count("upstream");
    let down_before = state.gateway_metrics().hop_filtered_count("downstream");

    // 连续三次透传：每次状态码/内容类型不改写、字节一致、零注入、计数递增。
    for n in 1..=3u64 {
        let resp = client
            .get(format!("{base}/v1/models"))
            .header("X-Probe-Keep", "keep-me")
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=5")
            .header("TE", "trailers")
            .header("Proxy-Authorization", "Basic hop")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "第 {n} 次透传状态码不改写");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "第 {n} 次 content-type 不被改写"
        );
        assert!(
            resp.headers().get("x-veil-normalized").is_none(),
            "第 {n} 次透传臂不得声明归一化头"
        );
        let body = resp.text().await.unwrap();
        assert_eq!(body, UPSTREAM_BODY, "第 {n} 次须字节透传");
        assert!(
            body.contains("13812345678"),
            "第 {n} 次透传臂不得脱敏: {body}"
        );
        assert!(
            !body.contains("__PII_") && !body.contains("__VG_CRED_"),
            "第 {n} 次透传臂不得注入占位符: {body}"
        );
        assert_eq!(
            state.gateway_metrics().nondialog_passthrough_count(),
            n,
            "透传计数须 1→2→3 递增"
        );
    }

    // 上游收到：方法/路径正确、非 hop 头保留、hop 头被剥离。
    let upstream_authority = upstream.trim_start_matches("http://").to_string();
    let seen = captured.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "上游须收到 3 次");
    for (idx, req) in seen.iter().enumerate() {
        let nth = idx + 1;
        assert_eq!(req.method, "GET", "第 {nth} 次方法须透传");
        assert_eq!(req.path, "/v1/models", "第 {nth} 次路径须透传");
        let has = |name: &str| req.headers.iter().any(|(k, _)| k == name);
        for hop in ["connection", "keep-alive", "te", "proxy-authorization"] {
            assert!(
                !has(hop),
                "hop 头 {hop} 不得达上游（第 {nth} 次）: {:?}",
                req.headers
            );
        }
        assert_eq!(
            req.headers
                .iter()
                .find(|(k, _)| k == "host")
                .map(|(_, v)| v.as_str()),
            Some(upstream_authority.as_str()),
            "下游 host 不得透传；上游 host 须由 reqwest 按上游地址注入（第 {nth} 次）"
        );
        assert!(has("x-probe-keep"), "非 hop 头须保留（第 {nth} 次）");
        assert!(
            has("accept-encoding"),
            "downstream accept-encoding 剥离后 reqwest 须注入支持编码集（第 {nth} 次）"
        );
    }

    // hop_filtered 方向计数：upstream 每次剥 4 头；downstream 每次响应剥 1 头。
    let up_delta = state.gateway_metrics().hop_filtered_count("upstream") - up_before;
    assert_eq!(
        up_delta, 12,
        "upstream 方向 3 次 ×4 头（connection/keep-alive/te/proxy-authorization）"
    );
    let down_delta = state.gateway_metrics().hop_filtered_count("downstream") - down_before;
    assert_eq!(
        down_delta, 3,
        "downstream 方向 3 次响应各剥 1 头（content-length 解码配对）"
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
