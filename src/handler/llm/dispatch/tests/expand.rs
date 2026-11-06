//! `$conversation` 出站标识的 HTTP 级用例（tasks 4.4）：客户端原值 / 服务端 HMAC /
//! 跳过三形态，覆盖对话流式、对话非流与 NonDialog 三条路径及
//! `session_outbound_hmac` 计数。

use {
    super::{
        DEFAULT_HEADER_OVERRIDE,
        capture_loopback_complete,
        captured_body,
        gateway_serve,
        request_tenant_fingerprint,
        test_app_state_with_targets,
    },
    axum::http::{HeaderMap, StatusCode},
};

/// 从捕获的原始请求字节里取指定头（小写比较）的全部值。
fn captured_header(raw: &[u8], name: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
        .collect()
}

#[tokio::test]
async fn dialog_conversation_anchor_emits_domain_separated_hmac_and_counts() {
    // tasks 4.4 Verify：conversation 锚点 → `veil-outbound-v1` HMAC，
    // 既不等于上游 id 原值，也不等于 PII `ConversationKey`；计数恰一次。
    let up_body = br#"{"id":"resp_conv","object":"response","model":"m","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/responses",
        br#"{"model":"m","input":"hi","conversation":"conv_1"}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let emitted = captured_header(&raw, "x-opencode-session");
    assert_eq!(emitted.len(), 1, "须注入单一展开值: {emitted:?}");
    assert_ne!(emitted[0], "conv_1", "不得输出上游 id 原值");
    let fp = request_tenant_fingerprint(&state, &HeaderMap::new(), url.as_str());
    let canonical =
        crate::service::redaction::scoped_key(state.conversation_secret.as_ref(), &fp, "conv_1");
    assert_ne!(emitted[0], canonical.as_str(), "出站值不得等于 PII 会话键");
    assert!(!emitted[0].is_empty(), "不得注入空值");
    assert_eq!(
        state.gateway_metrics.session_outbound_hmac_count(),
        1,
        "服务端锚点成功展开须恰计一次"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_stream_conversation_anchor_counts_once() {
    // 流式分支同样在 identity 解析后构造 ExpandCtx 并按服务端锚点展开计数。
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/responses",
        br#"{"model":"m","stream":true,"input":"hi","conversation":"conv_stream"}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "流式分支须正常建流");
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let emitted = captured_header(&raw, "x-opencode-session");
    assert_eq!(emitted.len(), 1, "须注入单一展开值: {emitted:?}");
    assert_ne!(emitted[0], "conv_stream", "不得输出上游 id 原值");
    assert_eq!(
        state.gateway_metrics.session_outbound_hmac_count(),
        1,
        "流式路径须恰计一次"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn request_mode_still_expands_client_anchor_without_hmac_count() {
    // tasks 4.4 Verify：`request` 模式仍按客户端锚点原值展开；客户端原值不计数。
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
        .header("x-veil-conversation-id", "sess-req-1")
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
    assert_eq!(
        captured_header(&raw, "x-opencode-session"),
        vec!["sess-req-1".to_string()],
        "request 模式仍按客户端锚点原值展开"
    );
    assert_eq!(
        state.gateway_metrics.session_outbound_hmac_count(),
        0,
        "客户端原值不计数"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn empty_conversation_header_skips_entry_but_keeps_static_headers() {
    // tasks 4.4 Verify：空头不注入空值、不生成随机值；静态头与 `$header` 不受影响。
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
        .header("x-veil-conversation-id", "")
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
        "静态头须照常注入: {text}"
    );
    assert!(
        !text.contains("x-opencode-session") && !text.contains("$conversation"),
        "空锚点须整条跳过（不注入空值）: {text}"
    );
    assert_eq!(state.gateway_metrics.session_outbound_hmac_count(), 0);
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn nondialog_conversation_anchor_uses_client_value_and_bytes_stay_identical() {
    // tasks 4.4 Verify：NonDialog 路径 identity 仅由头解析（body=None），
    // `$conversation` 按客户端锚点原值展开，请求体逐字节不变，不计数。
    // 与 NonDialog `params` 豁免 warn 的进程级去重位共享：持锁串行（同文件先例）。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("测试运行时须可构造");
    rt.block_on(nondialog_conversation_anchor_impl());
}

async fn nondialog_conversation_anchor_impl() {
    let (url, captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) = test_app_state_with_targets(
        &[("LLM_UPSTREAM", url.as_str())],
        Some(DEFAULT_HEADER_OVERRIDE),
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/models")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-nond-9")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"probe":"nondialog-dyn"}"#.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/models", client_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    assert_eq!(
        captured_header(&raw, "x-opencode-session"),
        vec!["conv-nond-9".to_string()],
        "NonDialog 须按客户端锚点原值展开"
    );
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "NonDialog 请求体须逐字节等于客户端原文"
    );
    assert_eq!(
        state.gateway_metrics.session_outbound_hmac_count(),
        0,
        "客户端原值不计数"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}
