//! 「恰好一行」矩阵测试（tasks 4.1–4.7）：每个终态分支恰一行 + 负向零行 +
//! 会话作用域/来源 + 摘要隐私边界 + 流式 aborted 计数。
//!
//! 夹具复用父模块 `dispatch::tests` 的 `test_app_state` / 回环上游（祖模块私有项对
//! 子模块可见），不重复装配 `AppState`。

use {
    super::{capture_loopback_complete, test_app_state},
    crate::{
        handler::llm::llm_proxy_handler,
        service::request_log::{RequestFilter, RequestRow},
        state::AppState,
    },
    axum::http::StatusCode,
};

/// 刷盘后读取全部行（时间倒序）。
fn rows(state: &AppState) -> Vec<RequestRow> {
    state.request_log.flush_blocking().expect("刷盘须成功");
    state
        .request_log
        .query(&RequestFilter {
            limit: Some(200),
            ..RequestFilter::default()
        })
        .expect("查询须成功")
        .rows
}

fn row_count(state: &AppState) -> usize { rows(state).len() }

fn only_row(state: &AppState) -> RequestRow {
    let mut all = rows(state);
    assert_eq!(all.len(), 1, "须恰好一行: {all:?}");
    all.remove(0)
}

#[tokio::test]
async fn nonstream_success_writes_exactly_one_row() {
    let up_body = br#"{"id":"chatcmpl-abc","model":"echo-model","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18,"prompt_tokens_details":{"cached_tokens":4}}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("host", "127.0.0.1:8877")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"req-model","messages":[{"role":"user","content":"hi"}]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    server.abort();

    let row = only_row(&state);
    assert_eq!(row.status, Some(200));
    assert_eq!(row.error_kind, None, "成功路径不得有 error_kind");
    assert_eq!(row.protocol, "chat");
    assert_eq!(row.model, "echo-model", "model 须取响应回显");
    let upstream = row.upstream.as_deref().expect("须记上游 host:port");
    assert!(
        upstream.starts_with("127.0.0.1:"),
        "upstream 须为 host:port 形态（无路径/查询串）: {upstream}"
    );
    assert!(!upstream.contains('/'), "upstream 不得含路径: {upstream}");
    assert_eq!(row.ingress_port, Some(8877));
    assert!(!row.stream);
    assert!(row.is_chat);
    assert!(row.counted_metrics, "成功对话样本须计入 metrics");
    assert_eq!(row.upstream_id.as_deref(), Some("chatcmpl-abc"));
    assert_eq!(row.finish_reason.as_deref(), Some("stop"));
    assert_eq!(row.prompt_tokens, 11);
    assert_eq!(row.completion_tokens, 7);
    assert_eq!(row.cached_read, 4);
    assert_eq!(row.cache_input_tokens, 11, "Chat 分母即输入 token");
    assert!(!row.request_id.is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nonstream_upstream_error_writes_row_with_status_and_kind() {
    let up_body = br#"{"error":{"message":"boom","type":"server_error"}}"#.to_vec();
    let (url, server) =
        crate::handler::llm::tests::loopback_server(500, "application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let row = only_row(&state);
    assert_eq!(row.status, Some(500), "须记上游真实状态");
    assert_eq!(row.error_kind.as_deref(), Some("upstream_status"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nonstream_unreachable_writes_502_row() {
    // 回环端口未监听：fetch 失败 → 502 `upstream_unreachable`。
    let url = "http://127.0.0.1:9/v1/chat/completions";
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url)]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("upstream_unreachable"));
    assert_eq!(row.model, "m", "无响应回显时回退请求侧 model");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nonstream_non_json_200_writes_non_json_row() {
    let (url, _captured, server) =
        capture_loopback_complete("text/plain", b"not json".to_vec()).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("non_json"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nonstream_empty_body_writes_empty_body_row() {
    let (url, _captured, server) = capture_loopback_complete("application/json", Vec::new()).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("empty_body"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nonstream_oversize_writes_oversize_row() {
    // 上游正文严格超 `NONSTREAM_MAX_BYTES`（配 1 字节上限，正文 2 字节）。
    let (url, _captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) =
        test_app_state(&[("LLM_UPSTREAM", url.as_str()), ("NONSTREAM_MAX_BYTES", "1")]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("response_too_large"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn redact_only_writes_row_without_error_kind() {
    let up_body = br#"{"input_tokens":3}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/messages/count_tokens",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.status, Some(200));
    assert_eq!(row.error_kind, None);
    assert_eq!(row.protocol, "anthropic");
    assert!(!row.counted_metrics, "redact_only 不计入 metrics");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn nondialog_passthrough_writes_row_with_is_chat_false() {
    let (url, _captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/v1/models")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp =
        crate::handler::llm::dispatch::gateway_serve(&state, &mut parts, "/v1/models", Vec::new())
            .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.status, Some(200));
    assert_eq!(row.error_kind, None);
    assert_eq!(row.protocol, "passthrough");
    assert!(!row.is_chat);
    assert!(!row.stream);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn pii_fail_closed_writes_row_and_forwards_nothing() {
    let up_body = br#"{"id":"x","choices":[]}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_SCOPE_MODE", "conversation"),
    ]);
    // 预置同键作用域并注入熵源故障（`gateway_serve` 复用同一实例）。
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        "conv-log-e2e".parse().expect("头值须合法"),
    );
    let scope = crate::handler::llm::dispatch::build_request_scope(
        &state,
        &headers,
        crate::service::llm_gateway::Protocol::Chat,
        url.as_str(),
        Some(&serde_json::json!({"messages": []})),
    );
    scope.pii_scope().force_entropy_failure(true);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-log-e2e")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(
        captured.lock().expect("捕获锁不得中毒").is_empty(),
        "fail-closed 须零转发上游"
    );
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("pii_fail_closed"));
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn unparseable_request_body_still_writes_exactly_one_row() {
    // 请求体不可解析时网关**不拒绝**（按字节透传，见
    // `rewrite_invalid_json_passthrough_byte_identical`）， 400 来自上游；该族分支同样只落一行。
    let (url, server) = crate::handler::llm::tests::loopback_server(
        400,
        "application/json",
        br#"{"error":{"message":"invalid json","type":"invalid_request_error"}}"#.to_vec(),
    )
    .await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        b"not json at all {{{".to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let row = only_row(&state);
    assert_eq!(row.status, Some(400));
    assert_eq!(row.error_kind.as_deref(), Some("upstream_status"));
    std::fs::remove_dir_all(&dir).ok();
}

/// tasks 4.3：非流 `POST /v1/responses` 落行的 `upstream_id` 取上游响应 `id`，
/// 协议标 `responses`（不使用上游 id 冒充会话标识）。
#[tokio::test]
async fn responses_nonstream_records_upstream_id() {
    let up_body = br#"{"id":"resp_abc123","object":"response","model":"resp-model","status":"completed","output":[],"usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/responses",
        br#"{"model":"req-model","input":"hi"}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.protocol, "responses", "须标 Responses 协议线");
    assert_eq!(
        row.upstream_id.as_deref(),
        Some("resp_abc123"),
        "须记录上游响应 id 作为展示锚点"
    );
    assert_eq!(row.model, "resp-model", "model 须取响应回显");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn streaming_success_writes_one_row_with_upstream_status() {
    let sse = b"data: {\"id\":\"chatcmpl-s1\",\"model\":\"stream-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\ndata: [DONE]\n\n".to_vec();
    let (url, _captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"req-model","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    // 读完 SSE 体：帧通道闭合即泵任务已收尾（落行在 finish 内完成）。
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("SSE 响应体须可读");
    assert!(String::from_utf8_lossy(&body).contains("[DONE]"));
    server.abort();

    let row = only_row(&state);
    assert!(row.stream, "流式行须标 stream");
    assert_eq!(row.status, Some(200), "须记真实上游状态");
    assert_eq!(row.error_kind, None);
    assert_eq!(row.upstream_id.as_deref(), Some("chatcmpl-s1"));
    assert_eq!(row.finish_reason.as_deref(), Some("stop"));
    assert_eq!(row.prompt_tokens, 5);
    assert_eq!(row.completion_tokens, 2);
    assert!(row.counted_metrics, "流式成功须计入 metrics");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn streaming_upstream_5xx_writes_row_with_upstream_status() {
    let (url, server) = crate::handler::llm::tests::loopback_server(
        500,
        "application/json",
        br#"{"error":"bad"}"#.to_vec(),
    )
    .await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let row = only_row(&state);
    assert_eq!(row.status, Some(500), "流式 passthrough 须记上游真实状态");
    assert_eq!(row.error_kind.as_deref(), Some("upstream_status"));
    assert!(row.stream, "客户端要求流式时行须标 stream");
    assert!(row.is_chat);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn streaming_fetch_error_writes_502_unreachable_row() {
    let (state, dir) =
        test_app_state(&[("LLM_UPSTREAM", "http://127.0.0.1:9/v1/chat/completions")]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let row = only_row(&state);
    assert_eq!(row.status, Some(502));
    assert_eq!(row.error_kind.as_deref(), Some("upstream_unreachable"));
    assert!(row.stream);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn streaming_truncation_writes_one_row_with_truncated_mode() {
    // 中途断流（无 finish_reason、无 [DONE]）→ `open_ended`，仍恰一行。
    let sse =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n".to_vec();
    let (url, _captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("SSE 响应体须可读");
    server.abort();
    let row = only_row(&state);
    assert_eq!(row.status, Some(200));
    assert_eq!(row.truncated_mode.as_deref(), Some("open_ended"));
    assert!(row.stream);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn duplicate_finish_writes_single_row() {
    // 同一守卫两次 finish：只落一行（design §10「重复回调不产生第二行」）。
    let (state, dir) = test_app_state(&[]);
    let guard = state.request_log.stream_guard(
        crate::handler::llm::trace::RequestTrace::new(
            "req-dup".to_string(),
            crate::service::llm_gateway::Protocol::Chat,
            Some(8877),
            true,
            std::time::Instant::now(),
        )
        .into_row(),
    );
    let outcome = crate::service::request_log::StreamOutcome {
        status: Some(200),
        ..Default::default()
    };
    if let Some(row) = guard.finish(&outcome) {
        state.request_log.record(row);
    }
    assert!(
        guard.finish(&outcome).is_none(),
        "二次 finish 须为空（幂等）"
    );
    assert_eq!(row_count(&state), 1, "重复 finish 不得产生第二行");
    assert_eq!(state.request_log.aborted_total(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn dropped_stream_guard_writes_client_aborted_row_and_counts_aborted() {
    // 未 finish 直接 drop：`aborted` +1 且补写一行 `client_aborted`（守卫 Drop 落行）。
    let (state, dir) = test_app_state(&[]);
    let before = state.request_log.aborted_total();
    let guard = state.request_log.stream_guard(
        crate::handler::llm::trace::RequestTrace::new(
            "req-aborted".to_string(),
            crate::service::llm_gateway::Protocol::Chat,
            Some(8877),
            true,
            std::time::Instant::now(),
        )
        .into_row(),
    );
    drop(guard);
    assert_eq!(state.request_log.aborted_total(), before + 1);
    let all = rows(&state);
    assert_eq!(all.len(), 1, "drop 须补写恰一行: {all:?}");
    assert_eq!(all[0].request_id, "req-aborted");
    assert_eq!(all[0].error_kind.as_deref(), Some("client_aborted"));
    assert_eq!(all[0].status, None);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn session_header_derives_session_scope() {
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "session-test-key"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-header-raw-value")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.session_source, "header");
    assert_eq!(row.session_scope, "session");
    let session_id = row.session_id.as_deref().expect("有密钥须派生会话");
    assert_eq!(session_id.len(), 16, "会话摘要为 16 hex");
    // 原文不得落库（sqlite 文件字节级反证）。
    drop(state);
    let db = dir.join("m.sqlite");
    let bytes = std::fs::read(&db).expect("库文件须可读");
    let raw = String::from_utf8_lossy(&bytes);
    assert!(!raw.contains("conv-header-raw-value"), "会话原文不得落库");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn user_level_source_is_marked_user_scope() {
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "session-test-key"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","user":"user-raw-7","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.session_source, "user");
    assert_eq!(row.session_scope, "user", "用户级标识不得标为会话");
    assert!(row.session_id.is_some());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn missing_hmac_key_leaves_session_null_and_source_none() {
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    assert!(
        state.config.pii_value_sample_hmac_key.is_none(),
        "夹具须无 HMAC 密钥"
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-no-key")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    assert_eq!(row.session_id, None, "无密钥不得派生会话");
    assert_eq!(row.session_source, "none");
    assert_eq!(row.session_scope, "none");
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn summary_is_redacted_and_excludes_identifier_fields() {
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_VALUE_SAMPLE_HMAC_KEY", "summary-test-key"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-summary-raw")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        serde_json::to_vec(&serde_json::json!({
            "model": "m",
            "prompt_cache_key": "cache-key-raw-9",
            "metadata": {"user_id": "meta-user-raw-9"},
            "user": "user-raw-9",
            "safety_identifier": "safety-raw-9",
            "messages": [{"role": "user", "content": "我的电话是13812345678"}],
        }))
        .expect("请求体序列化须成功"),
    )
    .await;
    server.abort();
    assert_eq!(resp.status(), StatusCode::OK);
    let row = only_row(&state);
    let summary = row.req_summary.as_deref().expect("脱敏启用时须有摘要");
    assert!(summary.contains("__PII_"), "摘要须含脱敏占位符: {summary}");
    assert!(
        !summary.contains("13812345678"),
        "摘要不得含明文手机号: {summary}"
    );
    for forbidden in [
        "prompt_cache_key",
        "cache-key-raw-9",
        "metadata",
        "meta-user-raw-9",
        "safety_identifier",
        "safety-raw-9",
        "conv-summary-raw",
    ] {
        assert!(
            !summary.contains(forbidden),
            "摘要不得含标识字段 {forbidden}: {summary}"
        );
    }
    assert!(
        summary.chars().count() <= 512,
        "摘要长度须 ≤512: {}",
        summary.chars().count()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn summary_null_when_redaction_disabled() {
    // `[redaction].enabled=false` → 摘要恒 `NULL`（design §6）。此处直接以
    // 关闭态追踪对象断言，避免为单一断言搭文件层装配。
    let config = crate::handler::llm::test_support::test_config(&[("REDACTION_ENABLED", "0")]);
    assert!(!config.redaction_enabled, "夹具须关闭脱敏");
    let mut trace = crate::handler::llm::trace::RequestTrace::new(
        "req-no-summary".to_string(),
        crate::service::llm_gateway::Protocol::Chat,
        Some(8877),
        config.redaction_enabled,
        std::time::Instant::now(),
    );
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "plain text"}],
    });
    trace.attach_summary(Some(&body));
    let row = trace.into_row();
    assert_eq!(row.req_summary, None, "脱敏关闭时摘要须为 NULL");
}

#[tokio::test]
async fn row_request_id_matches_router_extension() {
    // tasks 2.4：`request_context` 写入的 `RequestId` 与落库行 `request_id` 一致，
    // 且不得回写响应头。
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let app = crate::router::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let addr = listener.local_addr().expect("回环地址须可读");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("x-request-id", "row-req-abc123")
        .body("{\"model\":\"m\",\"messages\":[]}")
        .send()
        .await
        .expect("LLM 代理须可达");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        !resp.headers().contains_key("x-request-id"),
        "不得回写 x-request-id 响应头"
    );
    let _ = resp.bytes().await;
    let row = only_row(&state);
    assert_eq!(row.request_id, "row-req-abc123");
    handle.abort();
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn upstream_authority_strips_scheme_path_query_and_userinfo() {
    use crate::handler::llm::trace::upstream_authority;
    assert_eq!(
        upstream_authority("http://127.0.0.1:11434/v1/chat?x=1").as_deref(),
        Some("127.0.0.1:11434")
    );
    assert_eq!(
        upstream_authority("https://api.example.com").as_deref(),
        Some("api.example.com")
    );
    assert_eq!(
        upstream_authority("http://user:pass@up.example.com:8080/v1").as_deref(),
        Some("up.example.com:8080"),
        "userinfo 不得行进"
    );
}

#[test]
fn finish_reason_extraction_is_protocol_aware() {
    use crate::handler::llm::trace::finish_reason_of;
    let chat = serde_json::json!({"choices": [{"finish_reason": "tool_calls"}]});
    assert_eq!(
        finish_reason_of(crate::service::llm_gateway::Protocol::Chat, &chat).as_deref(),
        Some("tool_calls")
    );
    let anthropic = serde_json::json!({"stop_reason": "end_turn"});
    assert_eq!(
        finish_reason_of(crate::service::llm_gateway::Protocol::Anthropic, &anthropic).as_deref(),
        Some("end_turn")
    );
    let responses = serde_json::json!({"incomplete_details": {"reason": "max_output_tokens"}});
    assert_eq!(
        finish_reason_of(crate::service::llm_gateway::Protocol::Responses, &responses).as_deref(),
        Some("max_output_tokens")
    );
    assert_eq!(
        finish_reason_of(
            crate::service::llm_gateway::Protocol::Chat,
            &serde_json::json!({})
        ),
        None
    );
}

#[tokio::test]
async fn admin_health_and_payload_too_large_do_not_record() {
    // 负向：`/health`、`/_admin/*` 与 413 均不产生行；同一测试的正常请求恰 +1
    //（防「全都不记」假通过）。
    let up_body = br#"{"model":"m","choices":[{"message":{"content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, _dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);

    // 413：体超过 `GATEWAY_BODY_LIMIT_BYTES`，在追踪点之前返回。
    let oversized = vec![b'x'; crate::handler::llm::GATEWAY_BODY_LIMIT_BYTES + 1];
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .body(axum::body::Body::from(oversized))
        .expect("请求构造须成功");
    let resp = llm_proxy_handler(axum::extract::State(state.clone()), req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(row_count(&state), 0, "413 不得产生行");

    // `/health` 与 `/_admin/metrics`（未鉴权 401 亦可）经真实 router。
    let app = crate::router::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let addr = listener.local_addr().expect("回环地址须可读");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let client = reqwest::Client::new();
    let health = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .expect("健康检查须可达");
    assert_eq!(health.status().as_u16(), 200);
    let admin = client
        .get(format!("http://{addr}/_admin/metrics"))
        .send()
        .await
        .expect("管理面须可达");
    assert_ne!(admin.status().as_u16(), 200, "未鉴权管理面不得 200");
    assert_eq!(row_count(&state), 0, "健康/管理面不得产生行");

    // 正常 LLM 请求经同一 router：恰 +1。
    let llm = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .header("content-type", "application/json")
        .body("{\"model\":\"m\",\"messages\":[]}")
        .send()
        .await
        .expect("LLM 代理须可达");
    assert_eq!(llm.status().as_u16(), 200);
    let _ = llm.bytes().await;
    assert_eq!(row_count(&state), 1, "正常请求须恰 +1 行");
    handle.abort();
    server.abort();
    std::fs::remove_dir_all(&_dir).ok();
}

#[tokio::test]
async fn count_tokens_row_is_not_marked_chat() {
    // `count_tokens` 走 Anthropic 协议线的对话臂（请求侧脱敏），但语义不是对话
    // 请求：落行 `is_chat` 须为 `false`，`protocol` 仍记 `anthropic`。
    let up_body = br#"{"input_tokens":1}"#.to_vec();
    let (url, _captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state(&[("LLM_UPSTREAM", url.as_str())]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = crate::handler::llm::dispatch::gateway_serve(
        &state,
        &mut parts,
        "/v1/messages/count_tokens",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    server.abort();
    let row = only_row(&state);
    assert_eq!(row.protocol, "anthropic");
    assert!(!row.is_chat, "count_tokens 不得标记为对话请求");
    assert!(!row.counted_metrics, "count_tokens 不计入 metrics");
    std::fs::remove_dir_all(&dir).ok();
}
