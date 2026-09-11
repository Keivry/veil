//! 管理面筛选 e2e（`veil-test-coverage-fill` T4/D4）：SSE 建连
//! `?model=&upstream=` 实际筛选（命中/未命中/交集/空值）与 metrics/events
//! 旧 `?model=&upstream=` 的「忽略过滤 + deprecated 标注」口径。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
        time::{Duration, SystemTime, UNIX_EPOCH},
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

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

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
            ADMIN_TOKEN.to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = PathBuf::from(format!("/tmp/veil-e2e-admin-stream-{n}.sqlite"));
    let _ = std::fs::remove_file(&db);
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: db,
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

async fn connect_sse(client: &reqwest::Client, base: &str, query: &str) -> reqwest::Response {
    let resp = client
        .get(format!("{base}/_admin/events/stream{query}"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "SSE 建连须 200: {query}");
    resp
}

/// 有界读取 SSE `data:` 载荷：收满 `want` 条或到达窗口截止即返回；
/// 未命中场景传 `want=1` 并在窗口内零事件返回空数组（超时不 panic）。
async fn read_sse_data(mut resp: reqwest::Response, want: usize, window: Duration) -> Vec<String> {
    let mut buf = String::new();
    let mut msgs = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while msgs.len() < want {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                buf.push_str(&String::from_utf8_lossy(&chunk));
                while let Some(pos) = buf.find("\n\n") {
                    let frame: String = buf.drain(..pos + 2).collect();
                    for line in frame.lines() {
                        if let Some(payload) = line.strip_prefix("data:") {
                            msgs.push(payload.trim().to_string());
                        }
                    }
                }
            }
            _ => break,
        }
    }
    msgs
}

#[tokio::test]
async fn sse_stream_model_upstream_filter() {
    // T4/D4：SSE 建连 `?model=` 按事件 protocol 子串、`?upstream=` 按摘要子串
    // 过滤；命中流非零事件、未命中流零事件、双条件取交集、空值不过滤。
    let (app, state) = test_app();
    state.admin_state().push_event(
        "audit",
        "up-A 命中摘要",
        Some("chat/completions".to_string()),
    );
    state.admin_state().push_event(
        "audit",
        "up-A 其他协议摘要",
        Some("v1/responses".to_string()),
    );
    state.admin_state().push_event(
        "audit",
        "up-B 其他上游摘要",
        Some("chat/completions".to_string()),
    );
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    // 双条件交集：model=chat 且 upstream=up-A → 仅 id=1。
    let msgs = read_sse_data(
        connect_sse(&client, &base, "?model=chat&upstream=up-A").await,
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(msgs.len(), 1, "交集须恰命中 1 条: {msgs:?}");
    assert!(msgs[0].contains("up-A 命中摘要"), "{msgs:?}");
    assert!(msgs[0].contains("\"id\":1"), "{msgs:?}");

    // 单条件命中：model=responses → 仅 id=2。
    let msgs = read_sse_data(
        connect_sse(&client, &base, "?model=responses").await,
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(msgs.len(), 1, "model 命中须恰 1 条: {msgs:?}");
    assert!(msgs[0].contains("up-A 其他协议摘要"), "{msgs:?}");

    // 单条件命中：upstream=up-B → 仅 id=3。
    let msgs = read_sse_data(
        connect_sse(&client, &base, "?upstream=up-B").await,
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(msgs.len(), 1, "upstream 命中须恰 1 条: {msgs:?}");
    assert!(msgs[0].contains("up-B 其他上游摘要"), "{msgs:?}");

    // 未命中：窗口内有界读取须零事件。
    let msgs = read_sse_data(
        connect_sse(&client, &base, "?model=nomatch-model").await,
        1,
        Duration::from_millis(600),
    )
    .await;
    assert!(msgs.is_empty(), "未命中流须零事件: {msgs:?}");

    // 空值不过滤：`?model=&upstream=` 等同无过滤，三条全出。
    let msgs = read_sse_data(
        connect_sse(&client, &base, "?model=&upstream=").await,
        3,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(msgs.len(), 3, "空值不得过滤: {msgs:?}");

    handle.abort();
}

#[tokio::test]
async fn metrics_events_deprecated_ignore() {
    // T4/D4：metrics/events 旧 `?model=&upstream=` 忽略过滤 + deprecated 标注，
    // 结果与全局口径一致（不做空结果误导）。
    let (app, state) = test_app();
    let ts = now_secs();
    let u = usage(10, 5, 15);
    state.admin_state().metrics.record_chat(ChatRecord {
        protocol: Protocol::Chat,
        model: "dep-m",
        latency_ms: 12,
        usage: Some(&u),
        truncated_mode: None,
        is_precise: true,
        ts_secs: ts,
    });
    state.admin_state().push_event(
        "audit",
        "去重前事件摘要",
        Some("chat/completions".to_string()),
    );
    state.admin_state().metrics.flush().await.unwrap();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let (_, global_metrics) = get_json(&client, &base, "/_admin/metrics").await;
    let (_, global_events) = get_json(&client, &base, "/_admin/events?limit=100").await;

    let (status, legacy_metrics) = get_json(
        &client,
        &base,
        "/_admin/metrics?model=m1&upstream=https://up.example",
    )
    .await;
    assert_eq!(status, 200, "{legacy_metrics}");
    assert!(
        legacy_metrics.get("deprecated").is_some(),
        "metrics 旧参数须 deprecated 标注: {legacy_metrics}"
    );
    assert_eq!(legacy_metrics["compat"]["model"], "m1");
    assert_eq!(legacy_metrics["compat"]["upstream"], "https://up.example");
    for key in [
        "requests",
        "tokens",
        "per_protocol",
        "per_model",
        "latency_buckets",
        "p95_ms",
        "truncated",
        "sse_events",
        "ring_len",
        "dropped",
    ] {
        assert_eq!(
            legacy_metrics[key], global_metrics[key],
            "metrics 旧参数须忽略过滤、与全局一致: {key}"
        );
    }

    let (status, legacy_events) = get_json(
        &client,
        &base,
        "/_admin/events?model=m1&upstream=https://up.example&limit=100",
    )
    .await;
    assert_eq!(status, 200, "{legacy_events}");
    assert!(
        legacy_events.get("deprecated").is_some(),
        "events 旧参数须 deprecated 标注: {legacy_events}"
    );
    assert_eq!(legacy_events["compat"]["model"], "m1");
    assert_eq!(legacy_events["compat"]["upstream"], "https://up.example");
    assert_eq!(
        legacy_events["events"], global_events["events"],
        "events 旧参数须忽略过滤、与全局一致"
    );

    handle.abort();
}
