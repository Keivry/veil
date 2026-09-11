//! 限流三语义 e2e（B7）：TCP 远端计数不采信代理头、`unknown` 模型桶隔离、
//! SSE 并发槽断开清理。每个用例独立建 app（限流器隔离），经真 HTTP 回环。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_app(extra: &[(&str, &str)]) -> axum::Router {
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
            db_path: PathBuf::from(format!("/tmp/veil-e2e-ratelimit-{n}.sqlite")),
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

// B7.1：伪造代理头不改变计数——11 个请求各带不同 X-Forwarded-For/X-Real-IP，
// 仍按同一 TCP 远端累计，第 11 次 429。
#[tokio::test]
async fn b7_forged_proxy_headers_still_counted_by_tcp_remote() {
    let (base, handle) = serve(test_app(&[])).await;
    let client = reqwest::Client::new();
    let mut last = 0;
    for i in 0..11 {
        let resp = client
            .get(format!("{base}/_admin/metrics"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .header("X-Forwarded-For", format!("9.9.9.{i}"))
            .header("X-Real-IP", format!("8.8.4.{i}"))
            .send()
            .await
            .unwrap();
        last = resp.status().as_u16();
        if last == 429 {
            assert!(resp.headers().contains_key("retry-after"));
            break;
        }
        assert_eq!(last, 200, "第 {i} 次须放行");
    }
    assert_eq!(last, 429, "伪造头不得开辟独立桶：第 11 次须按 TCP 远端拒绝");
    handle.abort();
}

async fn mock_upstream(body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move || async move {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body.clone(),
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

// B7.1：缺 model 上游回体落 unknown 桶且计数隔离。
#[tokio::test]
async fn b7_missing_model_falls_into_unknown_bucket_isolated() {
    let (up_naked, uh1) =
        mock_upstream(br#"{"choices":[{"message":{"content":"hi"}}]}"#.to_vec()).await;
    let (base, handle) = serve(test_app(&[("LLM_UPSTREAM", up_naked.as_str())])).await;
    let client = reqwest::Client::new();
    let llm = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"m","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(llm.status().as_u16(), 200);
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let body: serde_json::Value = metrics.json().await.unwrap();
    assert!(
        body["per_model"]["unknown_model"].as_u64().unwrap_or(0) >= 1,
        "缺 model 须落 unknown 桶: {body}"
    );
    handle.abort();
    uh1.abort();
    // 对照：带 model 回体进自有桶，不污染 unknown。
    let (up_named, uh2) =
        mock_upstream(br#"{"model":"b7-m2","choices":[{"message":{"content":"hi"}}]}"#.to_vec())
            .await;
    let (base2, handle2) = serve(test_app(&[("LLM_UPSTREAM", up_named.as_str())])).await;
    let llm2 = client
        .post(format!("{base2}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"b7-m2","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(llm2.status().as_u16(), 200);
    let metrics2 = client
        .get(format!("{base2}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let body2: serde_json::Value = metrics2.json().await.unwrap();
    assert_eq!(body2["per_model"]["b7-m2"], 1, "{body2}");
    assert!(
        body2["per_model"].get("unknown_model").is_none(),
        "具名桶不得串扰 unknown: {body2}"
    );
    handle2.abort();
    uh2.abort();
}

// B7.2：并发打满 5 后第 6 建连被拒，已建 5 连接不受影响（保持开启空闲）。
#[tokio::test]
async fn b7_sse_full_rejects_sixth_keeps_existing() {
    let (base, handle) = serve(test_app(&[])).await;
    let client = reqwest::Client::new();
    let mut held = Vec::new();
    for _ in 0..5 {
        let resp = client
            .get(format!(
                "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
            ))
            .header("Accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        held.push(resp);
    }
    let sixth = client
        .get(format!(
            "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
        ))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sixth.status().as_u16(), 429);
    assert!(sixth.headers().contains_key("retry-after"));
    drop(sixth);
    // 已建连接不受影响：空闲流 2s 内无数据（超时）而非关闭（None 即关闭）。
    for resp in held.iter_mut() {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(2), resp.chunk()).await;
        match chunk {
            Err(_) => {}
            Ok(Ok(_)) => {}
            Ok(Err(e)) => panic!("已建连接不应出错: {e}"),
        }
    }
    handle.abort();
}

async fn poll_sse_connect(client: &reqwest::Client, base: &str) -> bool {
    for _ in 0..50 {
        let resp = client
            .get(format!(
                "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
            ))
            .header("Accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        drop(resp);
        if status == 200 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    false
}

// B7.2：SSE 正常断开后并发槽释放，新连接可建连。
#[tokio::test]
async fn b7_sse_graceful_disconnect_releases_slot() {
    let (base, handle) = serve(test_app(&[])).await;
    let client = reqwest::Client::new();
    let mut held = Vec::new();
    for _ in 0..5 {
        let resp = client
            .get(format!(
                "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
            ))
            .header("Accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        held.push(resp);
    }
    drop(held);
    assert!(poll_sse_connect(&client, &base).await, "正常断开后槽须释放");
    handle.abort();
}

// B7.2 边缘：客户端异常断开（建连即弃）同样释放槽位。
#[tokio::test]
async fn b7_sse_abrupt_disconnect_releases_slot() {
    let (base, handle) = serve(test_app(&[])).await;
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let resp = client
            .get(format!(
                "{base}/_admin/events/stream?access_token={ADMIN_TOKEN}"
            ))
            .header("Accept", "text/event-stream")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        drop(resp);
    }
    assert!(poll_sse_connect(&client, &base).await, "异常断开后槽须释放");
    handle.abort();
}
