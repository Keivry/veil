//! NLP-2/3.9 + ARH-2（7.1）：流式模型分桶回退与单帧单次解析回归
//! （自 `spawn_tests.rs` 外迁，避免 800 行红线）。

use {
    crate::{
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{llm_gateway::Protocol, metrics::MetricsStore},
    },
    std::{path::PathBuf, sync::Arc},
};

#[test]
fn single_parse_per_frame() {
    // ARH-2（7.1）：每帧 `ev.data` 的全量 JSON 解析点唯一——源码级锁定，防复发。
    const EVENT_LOOP_SRC: &str = include_str!("spawn/event_loop.rs");
    let parses = EVENT_LOOP_SRC
        .matches("from_str::<Value>(strip_bom(&ev.data))")
        .count();
    assert_eq!(
        parses, 1,
        "每帧 `ev.data` 须仅解析一次（当前 {parses} 处），复用解析产物"
    );
}

#[tokio::test]
async fn stream_missing_model_falls_back_to_request() {
    // NLP-2/3.9：流式帧缺失有效 model 时按请求 model 分桶，不落 unknown_model。
    let sse =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
            .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let admin = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-stream-model-fallback.sqlite",
    )));
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req_model = "req-model-fallback".to_string();
    ctx.req.admin_metrics = admin.clone();
    let _ = collect_pump(upstream, ctx).await;
    server.abort();
    let snap = admin.snapshot();
    assert_eq!(
        snap.per_model.get("req-model-fallback"),
        Some(&1),
        "流式帧缺 model 须回退请求 model 分桶: {:?}",
        snap.per_model
    );
    assert!(
        !snap.per_model.contains_key("unknown_model"),
        "有请求 model 时不得落 unknown_model: {:?}",
        snap.per_model
    );
}

#[tokio::test]
async fn stream_model_unknown_only_when_both_absent() {
    // NLP-2/3.9：请求与响应均无有效 model 时才落 unknown_model。
    let sse =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
            .to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let admin = Arc::new(MetricsStore::new(PathBuf::from(
        "/tmp/veil-stream-model-both-absent.sqlite",
    )));
    let mut ctx = pump_ctx(Protocol::Chat, scope, vault, detector);
    ctx.req_model = String::new();
    ctx.req.admin_metrics = admin.clone();
    let _ = collect_pump(upstream, ctx).await;
    server.abort();
    let snap = admin.snapshot();
    assert_eq!(
        snap.per_model.get("unknown_model"),
        Some(&1),
        "双侧均无 model 才落 unknown_model: {:?}",
        snap.per_model
    );
}
