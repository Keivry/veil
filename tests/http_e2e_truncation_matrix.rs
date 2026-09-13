//! 截断矩阵 E2E（test-parity-close D1）：TSS01 静默丢弃 / TSS02 开环（本文件断言
//! 开环语义，与 `http_e2e_truncation.rs` 的既有两用例互补）/ TSS03 tool 中截断丢弃 /
//! TSS04 Responses 截断合成 `failed` + 真实 reasoning 开环 + 真实 toolcalls 开环无伪造。
//! 全部夹具为合成数据，无真实 PII。

use common::{serve, test_app_db};

mod common;

/// 通用 mock 上游：按给定帧序列发送后直接断流（无 `[DONE]`/终止帧）。
async fn mock_upstream(frames: Vec<String>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move || {
            let frames = frames.clone();
            async move {
                let stream = async_stream::stream! {
                    // B10 等待策略：mock 单向推送无客户端 readiness 可轮询，取 20ms
                    // 固定有界等待（慢机安全；增量 15ms×帧数，总时长增量有界）。
                    for f in frames {
                        yield Ok::<_, anyhow::Error>(bytes::Bytes::from(f.into_bytes()));
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                };
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    axum::body::Body::from_stream(stream),
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

/// 中途报错 mock 上游：发送给定帧后以流错误终止（触发网关 `chunk()` Err）。
async fn mock_upstream_error(frames: Vec<String>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move || {
            let frames = frames.clone();
            async move {
                let stream = async_stream::stream! {
                    for f in frames {
                        yield Ok::<_, anyhow::Error>(bytes::Bytes::from(f.into_bytes()));
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    yield Err(anyhow::anyhow!("mock upstream mid-stream failure"));
                };
                (
                    [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                    axum::body::Body::from_stream(stream),
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

async fn post_stream(base: &str, path: &str, body: &str) -> (u16, String) {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}{path}"))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let text = tokio::time::timeout(std::time::Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    (status, text)
}

const CHAT_STREAM_BODY: &str =
    "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}";

// —— 1.1 TSS01：完整残余静默丢弃（有效分片 + 截断垃圾尾），无成功终端伪造 ——

#[tokio::test]
async fn tss01_truncated_tail_silently_dropped_without_success_terminal() {
    let frames = vec![
        "data: {\"choices\":[{\"delta\":{\"content\":\"有效分片\"}}]}\n\n".to_string(),
        // 截断垃圾尾：非 JSON 残余，不得被合成为成功终端。
        "data: {\"choices\":[{\"delta\":{\"content\":\"未完".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss01.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/chat/completions", CHAT_STREAM_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains("有效分片"), "已收分片须保留: {body}");
    assert!(
        !body.contains("response.completed"),
        "不得伪造成功终端: {body}"
    );
    assert!(
        !body.contains("[blocked:"),
        "开环截断不得合成阻断帧: {body}"
    );
    assert!(
        !body.contains("\"status\":\"completed\""),
        "不得伪造 completed 状态: {body}"
    );
    handle.abort();
    uhandle.abort();
}

// —— 1.1 TSS02：文本中截断开环（保留已收分片；D6 补恰一 DONE） ——

#[tokio::test]
async fn tss02_midtext_truncation_keeps_open_loop_fragments() {
    let frames = vec![
        "data: {\"choices\":[{\"delta\":{\"content\":\"甲\"}}]}\n\n".to_string(),
        "data: {\"choices\":[{\"delta\":{\"content\":\"乙\"}}]}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss02.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/chat/completions", CHAT_STREAM_BODY).await;
    assert_eq!(status, 200);
    assert!(
        body.contains('甲') && body.contains('乙'),
        "已收分片须保留: {body}"
    );
    assert_eq!(
        body.matches("data: [DONE]").count(),
        1,
        "D6：Chat 中途断流须补恰一 DONE 载荷: {body}"
    );
    assert!(!body.contains("[blocked:"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 1.2 TSS03：tool_calls 参数截断不全则整把丢弃，不伪造 success ——

#[tokio::test]
async fn tss03_truncated_tool_call_dropped_without_fake_success() {
    let frames = vec![
        // 首帧声明 tool_call（参数仅一半），随后断流。
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_time\",\"arguments\":\"{\\\"tz\\\":\\\"\"}}]}}]}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss03.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/chat/completions", CHAT_STREAM_BODY).await;
    assert_eq!(status, 200);
    assert!(
        !body.contains("\"status\":\"completed\""),
        "截断 tool 不得伪造 completed: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "截断 tool 不得伪造成功终端: {body}"
    );
    assert!(!body.contains("[blocked:"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 1.2 真实 toolcalls 开环：多 index 聚合形态 fixture，无伪造 ——

#[tokio::test]
async fn real_tool_calls_open_loop_multi_index_without_fabrication() {
    // 合成 fixture：两把完整 tool_call（多 index 聚合）+ 正常 [DONE]。
    let frames = vec![
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"k\\\":\\\"v\\\"}\"}}]}}]}\n\n".to_string(),
        "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"function\":{\"name\":\"calc\",\"arguments\":\"{\\\"x\\\":1}\"}}]}}]}\n\n".to_string(),
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n".to_string(),
        "data: [DONE]\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss03b.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/chat/completions", CHAT_STREAM_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains("call_a"), "tool index:0 须透传: {body}");
    assert!(body.contains("call_b"), "tool index:1 须透传: {body}");
    assert!(
        !body.contains("\"status\":\"completed\""),
        "不得伪造 success/completed 状态: {body}"
    );
    assert!(!body.contains("response.completed"), "{body}");
    handle.abort();
    uhandle.abort();
}

// —— 1.3 TSS04：Responses 空流截断合成 failed（与 completed 互斥） ——

#[tokio::test]
async fn tss04_responses_truncation_synthesizes_failed_excluding_completed() {
    // 空流：上游立即断流（零帧），网关合成截断序列。
    let (upstream, uhandle) = mock_upstream(vec![]).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss04.sqlite",
    ))
    .await;
    let (status, body) = post_stream(
        &base,
        "/v1/responses",
        "{\"model\":\"m\",\"input\":\"hi\",\"stream\":true}",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains("response.failed"),
        "Responses 截断须合成 failed: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "failed 与 completed 互斥: {body}"
    );
    handle.abort();
    uhandle.abort();
}

// —— 1.3 真实 reasoning 开环：分片保留，无伪造完成 ——

#[tokio::test]
async fn real_reasoning_open_loop_keeps_fragments_without_fabrication() {
    let frames = vec![
        "event: response.reasoning_text.delta\ndata: {\"type\":\"response.reasoning_text.delta\",\"item_id\":\"r1\",\"output_index\":0,\"content_index\":0,\"delta\":\"合成推理甲\"}\n\n".to_string(),
        "event: response.reasoning_text.delta\ndata: {\"type\":\"response.reasoning_text.delta\",\"item_id\":\"r1\",\"output_index\":0,\"content_index\":0,\"delta\":\"合成推理乙\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss04b.sqlite",
    ))
    .await;
    let (status, body) = post_stream(
        &base,
        "/v1/responses",
        "{\"model\":\"m\",\"input\":\"hi\",\"stream\":true}",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains("合成推理甲") && body.contains("合成推理乙"),
        "reasoning 分片须保留: {body}"
    );
    assert_eq!(
        body.matches("\"type\":\"response.failed\"").count(),
        1,
        "D6：Responses 中途断流须合成恰一 failed: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "开环不得伪造 completed: {body}"
    );
    handle.abort();
    uhandle.abort();
}

// —— 1.3 Anthropic 截断：不合成 message_stop / failed ——

#[tokio::test]
async fn anthropic_truncation_closes_cleanly_without_failed() {
    let frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"分片甲\"}}\n\n".to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"分片乙\"}}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-tss04c.sqlite",
    ))
    .await;
    let (status, body) = post_stream(
        &base,
        "/v1/messages",
        "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("分片甲") && body.contains("分片乙"), "{body}");
    assert_eq!(
        body.matches("\"type\":\"message_stop\"").count(),
        0,
        "D6：Anthropic 中途断流不得合成 message_stop: {body}"
    );
    assert!(
        !body.contains("response.failed"),
        "Anthropic 不合成 failed: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "Anthropic 不合成 completed: {body}"
    );
    handle.abort();
    uhandle.abort();
}

// —— 5.3 S5/D6：chunk() 报错形态三协议终端口径矩阵 ——

#[tokio::test]
async fn chunk_err_chat_backfills_single_done() {
    let frames = vec!["data: {\"choices\":[{\"delta\":{\"content\":\"甲\"}}]}\n\n".to_string()];
    let (upstream, uhandle) = mock_upstream_error(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-err-chat.sqlite",
    ))
    .await;
    let (status, body) = post_stream(&base, "/v1/chat/completions", CHAT_STREAM_BODY).await;
    assert_eq!(status, 200);
    assert!(body.contains('甲'), "已收分片须保留: {body}");
    assert_eq!(
        body.matches("data: [DONE]").count(),
        1,
        "chunk Err 须按 D6 补恰一 DONE: {body}"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn chunk_err_anthropic_never_synthesizes_message_stop() {
    let frames = vec![
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"甲\"}}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream_error(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-err-anth.sqlite",
    ))
    .await;
    let (status, body) = post_stream(
        &base,
        "/v1/messages",
        "{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains('甲'), "已收分片须保留: {body}");
    assert_eq!(
        body.matches("\"type\":\"message_stop\"").count(),
        0,
        "chunk Err 不得合成 message_stop: {body}"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn chunk_err_responses_synthesizes_single_failed() {
    let frames = vec![
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"甲\"}\n\n".to_string(),
    ];
    let (upstream, uhandle) = mock_upstream_error(frames).await;
    let (base, handle) = serve(test_app_db(
        &[("LLM_UPSTREAM", upstream.as_str())],
        "/tmp/veil-e2e-err-resp.sqlite",
    ))
    .await;
    let (status, body) = post_stream(
        &base,
        "/v1/responses",
        "{\"model\":\"m\",\"input\":\"hi\",\"stream\":true}",
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains('甲'), "已收分片须保留: {body}");
    assert_eq!(
        body.matches("\"type\":\"response.failed\"").count(),
        1,
        "chunk Err 须合成恰一 failed: {body}"
    );
    assert!(
        !body.contains("response.completed"),
        "不得伪造 completed: {body}"
    );
    handle.abort();
    uhandle.abort();
}
