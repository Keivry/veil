//! T-M3 PII 100 并发 e2e（`veil-review-followup-test-gap` T3.1）：
//! 对标原仓 `pii_concurrency` + `stream_restore_lock`。100 路并发非流
//! chat 请求经网关到回声上游（上游原样回显收到的脱敏体），各路断言
//! 还原本路号码且全矩阵无串扰（下标无冲突）。
//!
//! flaky 隔离策略：失败即加 `#[ignore]` 并在 tasks 登记，不阻塞门禁；
//! 超时预算 120s，mock 回声零外部依赖。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

const CONCURRENCY: usize = 100;

fn phone(i: usize) -> String { format!("138{:08}", 1000 + i) }

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
            db_path: PathBuf::from(format!("/tmp/veil-e2e-pii-conc-{n}.sqlite")),
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

/// 回声上游：把收到的请求体原文嵌入 chat completion 的 `content` 回显。
async fn mock_upstream_echo() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|body: bytes::Bytes| async move {
            let echoed = String::from_utf8_lossy(&body).into_owned();
            let resp = serde_json::json!({
                "id": "chatcmpl-echo",
                "object": "chat.completion",
                "model": "echo-m",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": echoed},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
            });
            (axum::http::StatusCode::OK, axum::Json(resp))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn t3_1_pii_100_concurrent_restore_isolated_no_crosstalk() {
    let (upstream, uhandle) = mock_upstream_echo().await;
    let (base, handle) = serve(test_app(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();

    let mut tasks = Vec::with_capacity(CONCURRENCY);
    for i in 0..CONCURRENCY {
        let client = client.clone();
        let base = base.clone();
        let mine = phone(i);
        tasks.push(tokio::spawn(async move {
            let req_body = serde_json::json!({
                "model": "echo-m",
                "messages": [{"role": "user", "content": format!("我的电话是{mine}请记住")}]
            });
            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                client
                    .post(format!("{base}/v1/chat/completions"))
                    .header("Content-Type", "application/json")
                    .json(&req_body)
                    .send(),
            )
            .await
            .expect("单路须在 120s 内返回")
            .unwrap();
            assert_eq!(resp.status().as_u16(), 200, "第 {i} 路须 200");
            let text = resp.text().await.unwrap();
            (i, text)
        }));
    }
    let mut bodies = vec![String::new(); CONCURRENCY];
    for t in tasks {
        let (i, text) = t.await.expect("并发任务须成功");
        bodies[i] = text;
    }

    // 本路还原：每路响应含本路号码（回声占位符经本路 scope 还原）。
    for (i, body) in bodies.iter().enumerate() {
        assert!(
            body.contains(&phone(i)),
            "第 {i} 路须还原本路号码 {}: {body}",
            phone(i)
        );
    }
    // 全矩阵无串扰：任一路不得含他路号码。
    for (i, body) in bodies.iter().enumerate() {
        for j in 0..CONCURRENCY {
            if i != j {
                assert!(
                    !body.contains(&phone(j)),
                    "第 {i} 路串扰他路号码 {}: {body}",
                    phone(j)
                );
            }
        }
    }

    uhandle.abort();
    handle.abort();
}
