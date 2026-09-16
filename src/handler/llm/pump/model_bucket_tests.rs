//! NLP-2/3.9 + ARH-2（7.1）：流式模型分桶回退与单帧单次解析回归
//! （自 `spawn_tests.rs` 外迁，避免 800 行红线）。

use {
    crate::{
        handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
        service::{
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
        },
    },
    std::{path::PathBuf, sync::Arc},
};

#[test]
fn single_parse_per_frame() {
    // ARH-2（6.1/7.1）：每帧 `ev.data` 的全量解析点唯一——泵主循环仅经
    // `event::parse_event_data` 单点解析一次，源码级锁定防复发。
    const EVENT_LOOP_SRC: &str = include_str!("spawn/event_loop.rs");
    let funnel = EVENT_LOOP_SRC.matches("parse_event_data(&ev.data)").count();
    assert_eq!(funnel, 1, "每帧须经单点解析恰一次（当前 {funnel} 处）");
    let adhoc = EVENT_LOOP_SRC.matches("from_str").count();
    assert_eq!(
        adhoc, 0,
        "泵主循环不得内联帧解析（当前 {adhoc} 处），须走单点"
    );
}

#[test]
fn event_rs_production_prefix_no_from_str() {
    // ARH-2（6.2）：`event.rs` 生产段（首个 `#[cfg(test)]` 之前）零 `from_str`——
    // 唯一解析点 `parse_event_data` 内部走 `json_walk::jloads`；历史三处
    // 重复解析的复发形态在本守护下直接判败。
    const EVENT_SRC: &str = include_str!("event.rs");
    let prefix = EVENT_SRC.split("#[cfg(test)]").next().unwrap_or("");
    // 计数令牌取 `from_str(`（函数调用形态）：避开 `Body::from_stream(` 与
    // 用例名注释中的子串假阳性，仍覆盖任何 JSON 解析调用。
    let parses = prefix.matches("from_str(").count();
    assert_eq!(
        parses, 0,
        "event.rs 生产段不得出现 from_str 调用（当前 {parses} 处）"
    );
}

#[tokio::test]
async fn parse_event_data_single_parse() {
    // ARH-2（6.1/6.2）覆盖缺口：每帧恰 1 次全量解析（线程本地计数，泵任务与
    // 用例同线程）；fallback metric 语义与改造前逐一致——非法 JSON 帧与
    // `[DONE]` 帧各记 1（均非 JSON，走 contains 兜底分支），合法帧不记。
    use crate::handler::llm::pump::event::take_parse_count;
    let _ = take_parse_count();
    let sse = b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"a\"}\n\ndata: not-json raw frame\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"b\"}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let upstream = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let metrics = Arc::new(GatewayMetrics::default());
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.req.gateway_metrics = metrics.clone();
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    server.abort();
    assert_eq!(
        take_parse_count(),
        3,
        "三数据帧须恰三次解析（空帧与 `[DONE]` 不解析）: {}",
        frames.join("")
    );
    assert_eq!(
        metrics.terminal_fallback_count(),
        2,
        "非法 JSON 帧 1 + `[DONE]` 帧 1，合法帧不记"
    );
    assert!(
        frames.join("").contains("not-json raw frame"),
        "非法帧按文本透传不丢"
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
