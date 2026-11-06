//! 出站配置头注入的 HTTP 级用例：对话非流/流式与 NonDialog 三路径共用同一
//! `forward_headers` 展开语义（含 `$conversation` 缺源跳过与字节保真）。

use super::*;

#[test]
fn nondialog_receives_configured_header_and_byte_identical_body() {
    // 与 NonDialog `params` 豁免 warn 的进程级去重位共享：持锁串行至请求结束，
    // 防并行用例抢先置位使「恰一次」断言 flaky（见 test_support 锁说明）。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("测试运行时须可构造");
    rt.block_on(nondialog_header_byte_identity_impl());
}

async fn nondialog_header_byte_identity_impl() {
    // task 3.2/5.1/3.1：NonDialog 透传路径仅注入配置头，动态头从会话键头展开；
    // 命中声明了 params 的目标时参数仍被忽略，请求体逐字节等于客户端原文。
    let (url, captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(PARAM_OVERRIDE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/models")
        .header("content-type", "application/json")
        .header("user-agent", "client-ua/9.9")
        .header("x-veil-conversation-id", "conv-nond-1")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"probe":"nondialog-original"}"#.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/models", client_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "上游须收到配置头: {text}"
    );
    assert!(
        text.contains("user-agent: opencode/1.18.33") && !text.contains("client-ua/9.9"),
        "NonDialog 上游须收到配置 UA（客户端 UA 被恒胜替换）: {text}"
    );
    assert!(
        text.contains("x-opencode-session: conv-nond-1"),
        "NonDialog 动态头须从会话键头展开: {text}"
    );
    assert!(
        !text.contains("temperature"),
        "NonDialog 不得注入 params: {text}"
    );
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "NonDialog 请求体须逐字节等于客户端原文"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_nonstream_receives_configured_header() {
    // task 3.2/3.1：对话非流路径须注入配置头与动态头（覆盖经单次 resolve_target 传递）。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("user-agent", "client-ua/9.9")
        .header("x-veil-conversation-id", "conv-ns-1")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "对话非流上游须收到配置头: {text}"
    );
    assert!(
        text.contains("user-agent: opencode/1.18.33") && !text.contains("client-ua/9.9"),
        "对话非流上游须收到配置 UA（客户端 UA 被恒胜替换）: {text}"
    );
    assert!(
        text.contains("x-opencode-session: conv-ns-1"),
        "对话非流上游须收到动态头展开值: {text}"
    );
    assert!(
        resp.headers().get("x-veil-normalized").is_none(),
        "未发生请求体改写时不得声明 x-veil-normalized"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_stream_receives_configured_header() {
    // task 3.2/5.1/3.1：对话流式分支须注入配置头、动态头与参数，且 SSE 帧序列保持
    // 既有语义（内容帧透出、恰一终止帧、不断流），响应带归一化声明。
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(PARAM_OVERRIDE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("user-agent", "client-ua/9.9")
        .header("x-veil-conversation-id", "conv-stream-1")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "流式分支须正常建流");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream"),
        "流式分支须回 SSE"
    );
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|value| value.to_str().ok()),
        Some("json-whitespace"),
        "参数注入实际改写须声明归一化"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "对话流式上游须收到配置头: {text}"
    );
    assert!(
        text.contains("user-agent: opencode/1.18.33") && !text.contains("client-ua/9.9"),
        "对话流式上游须收到配置 UA（客户端 UA 被恒胜替换）: {text}"
    );
    assert!(
        text.contains("x-opencode-session: conv-stream-1"),
        "对话流式上游须收到动态头展开值: {text}"
    );
    let sent: serde_json::Value =
        serde_json::from_slice(captured_body(&raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        sent["temperature"],
        serde_json::json!(0.7),
        "对话流式上游须收到注入参数"
    );
    // 帧序列保真：内容帧透出、恰一终止帧（无多余终止、无断流）。
    let sse_body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("SSE 响应体须可读");
    let sse_text = String::from_utf8_lossy(&sse_body);
    assert!(
        sse_text.contains("\"content\":\"hi\""),
        "内容帧须透出: {sse_text}"
    );
    assert_eq!(
        sse_text.matches("data: [DONE]").count(),
        1,
        "Chat 流须恰一终止帧: {sse_text}"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_nonstream_missing_conversation_source_skips_dynamic_header() {
    // task 3.1：声明了 `$conversation` 模板但客户端未提供会话键头时，该动态头
    // 须整条跳过（不写不改不删）——静态头照常注入。
    // D1 出站基线：客户端自带的 `x-opencode-session` 不再被隐式剔除，动态头跳过
    // 后按客户端原值转发上游。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-opencode-session", "client-dyn")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "静态头不受动态跳过影响: {text}"
    );
    assert!(
        text.contains("x-opencode-session: client-dyn"),
        "缺源动态头须整条跳过，客户端同名头按原值转发: {text}"
    );
    assert!(
        !text.contains("$conversation"),
        "未展开的模板字面量不得上行: {text}"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_stream_missing_conversation_source_skips_dynamic_header() {
    // task 3.1：对话流式缺动态源时整条跳过；静态头照常注入，SSE 帧序列保持既有语义。
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "流式分支须正常建流");
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "静态头照常注入: {text}"
    );
    assert!(
        !text.contains("x-opencode-session") && !text.contains("$conversation"),
        "缺源动态头须整条跳过: {text}"
    );
    let sse_body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("SSE 响应体须可读");
    let sse_text = String::from_utf8_lossy(&sse_body);
    assert_eq!(
        sse_text.matches("data: [DONE]").count(),
        1,
        "Chat 流须恰一终止帧: {sse_text}"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn nondialog_missing_conversation_source_skips_dynamic_header_with_byte_identity() {
    // task 3.1：NonDialog 缺动态源时整条跳过；请求体逐字节不变；静态头照常注入。
    // 与 NonDialog `params` 豁免 warn 的进程级去重位共享：持锁串行（同文件先例）。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("测试运行时须可构造");
    rt.block_on(nondialog_missing_dynamic_impl());
}

async fn nondialog_missing_dynamic_impl() {
    let (url, captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(PARAM_OVERRIDE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/models")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"probe":"nondialog-missing-dyn"}"#.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/models", client_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "静态头照常注入: {text}"
    );
    assert!(
        !text.contains("x-opencode-session") && !text.contains("$conversation"),
        "缺源动态头须整条跳过: {text}"
    );
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "NonDialog 请求体须逐字节等于客户端原文"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}
