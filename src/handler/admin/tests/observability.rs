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
        http::StatusCode,
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
