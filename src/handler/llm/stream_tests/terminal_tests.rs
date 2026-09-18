//! 终端帧出口/收尾 E2E（自 `stream_tests.rs` 拆出，测试名与断言不变）。

use {
    super::*,
    crate::{handler::llm::pump::build_sse_response, service::block_inject},
    axum::http::{StatusCode, header},
};

#[tokio::test]
async fn stream_pump_clean_finish_emits_exactly_one_terminal_frame() {
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    assert!(!outcome.block_injected);
    let joined = frames.join("");
    assert!(joined.contains("hi"), "录制流内容须泵到下游");
    let done_count = frames.iter().filter(|f| f.contains("data: [DONE]")).count();
    assert_eq!(done_count, 1, "正常收尾恰一个终止帧，不追加多余终止");
    assert!(
        frames.last().is_some_and(|f| f.contains("data: [DONE]")),
        "下游须以终止帧收尾"
    );
    server.abort();
}

#[tokio::test]
async fn upstream_terminal_delivered_without_upstream_eof() {
    // R8-06：Anthropic/Responses 上游终端帧发出后不 EOF（连接保持）时，下游仍
    // 立即收到终端并闭合（泵经 finish→finalize flush 后结束，不无限期挂起）。
    let cases: [(Protocol, &[u8]); 2] = [
        (
            Protocol::Responses,
            b"data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"r1\",\"status\":\"completed\"}}\n\n",
        ),
        (
            Protocol::Anthropic,
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ),
    ];
    for (protocol, body) in cases {
        let (url, server) = loopback_server_hold_open("text/event-stream", body.to_vec()).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            collect_pump(upstream, pump_ctx(protocol, scope, vault, detector)),
        )
        .await
        .expect("上游不 EOF 时终端须即时送达并闭合，不得挂起");
        server.abort();
        let joined = frames.join("");
        assert_eq!(
            block_inject::terminal_count(&frames, protocol.wire_name()),
            1,
            "case {protocol:?} 终端恰一: {joined}"
        );
        assert!(
            outcome.forwarded >= 1,
            "case {protocol:?} 终端须经泵下发: {joined}"
        );
        let terminal_token = if protocol.is_responses() {
            "response.completed"
        } else {
            "message_stop"
        };
        assert!(
            joined.contains(terminal_token),
            "case {protocol:?} 终端须送达: {joined}"
        );
    }
}

#[tokio::test]
async fn stream_pump_residue_sent_skips_secondary_empty_stream_frame() {
    // 无尾空行半帧：事件循环无分发（`forwarded==0`），残余路径直发下游。
    // 旧守门（`forwarded==0`）误触发二次空流合成；新守门以状态位为准跳过。
    let half = b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", half).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let (outcome, frames) =
        collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
    let joined = frames.join("");
    assert!(joined.contains("hi"), "残余半帧须送达下游");
    assert!(!outcome.block_injected, "残余已发不得再合成空流阻断帧");
    assert!(!joined.contains("empty-stream"), "全流不得出现二次空流合成");
    server.abort();
}

#[tokio::test]
async fn pump_terminal_reuses_request_conv_e12() {
    // E12/D7 + P4：泵内 `error` 合成单帧 failed 时复用请求会话而非合成随机值。
    let sse = b"data: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
    let (url, server) = loopback_server(200, "text/event-stream", sse).await;
    let client = reqwest::Client::new();
    let upstream = client.get(&url).send().await.expect("回环上游须可达");
    let (scope, vault, detector) = fresh_arcs();
    let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
    ctx.init_conv = Some("resp_req_9".to_string());
    let (_outcome, frames) = collect_pump(upstream, ctx).await;
    let joined = frames.join("");
    assert!(
        joined.contains("resp_req_9"),
        "终端帧须复用请求会话: {joined}"
    );
    server.abort();
}

#[tokio::test]
async fn sse_response_builder_headers_compliant() {
    let (_tx, rx) = tokio::sync::mpsc::channel::<String>(64);
    let pump = tokio::spawn(async { std::future::pending::<PumpOutcome>().await });
    let resp = build_sse_response(rx, true, pump, StatusCode::OK);
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|v| v.to_str().ok()),
        Some("json-whitespace")
    );
}
