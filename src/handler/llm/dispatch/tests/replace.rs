//! 条件替换的 HTTP 级用例：对话路径 body/header 同时命中、模型门控、NonDialog 与
//! count_tokens 的豁免边界（body 逐字节不变、只走 header_replace + headers）。

use super::*;

/// 覆盖片段：条件替换 body（chat/anthropic）+ 静态头 + 不带 `models` 的 header 规则
/// + 带 `models` 的 header 规则。
const REPLACE_TOML: &str = r#"
[llm.targets.default.headers]
x-provider-version = "2023-06-01"

[[llm.targets.default.params.chat.replace]]
field = "reasoningEffort"
from = "none"
to = "off"

[[llm.targets.default.params.anthropic.replace]]
field = "reasoningEffort"
from = "none"
to = "off"

[[llm.targets.default.header_replace]]
name = "x-reasoning-effort"
from = "none"
to = "off"

[[llm.targets.default.header_replace]]
name = "x-gated-effort"
from = "none"
to = "off"
models = ["deepseek-chat"]
"#;

struct ChatRoundtrip {
    head_text: String,
    forwarded: serde_json::Value,
    body_bytes: Vec<u8>,
    normalized: Option<String>,
    dir: std::path::PathBuf,
    server: tokio::task::JoinHandle<()>,
}

async fn chat_roundtrip(headers: &[(&str, &str)], body: &[u8]) -> ChatRoundtrip {
    chat_roundtrip_with(Some(REPLACE_TOML), headers, body).await
}

/// `toml = None` 表示目标未声明任何覆盖规则（基线对照）。
async fn chat_roundtrip_with(
    toml: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> ChatRoundtrip {
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let (url, captured, server) =
        capture_loopback_complete("application/json", up_body.to_vec()).await;
    let (state, dir) = test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], toml);
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let sent_body = body.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/chat/completions", sent_body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let normalized = resp
        .headers()
        .get("x-veil-normalized")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let head_text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    let body_bytes = captured_body(&raw).to_vec();
    let forwarded: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("转发体须为合法 JSON");
    ChatRoundtrip {
        head_text,
        forwarded,
        body_bytes,
        normalized,
        dir,
        server,
    }
}

#[tokio::test]
async fn dialog_replaces_body_and_header_on_exact_match() {
    let out = chat_roundtrip(
        &[("x-reasoning-effort", "none")],
        br#"{"model":"m","reasoningEffort":"none","messages":[]}"#,
    )
    .await;
    assert_eq!(
        out.forwarded["reasoningEffort"],
        serde_json::json!("off"),
        "body 顶层标量须精确替换"
    );
    assert!(
        out.head_text.contains("x-reasoning-effort: off"),
        "header 须替换为 to: {}",
        out.head_text
    );
    assert!(
        out.head_text.contains("x-provider-version: 2023-06-01"),
        "静态头照常注入: {}",
        out.head_text
    );
    assert_eq!(
        out.normalized.as_deref(),
        Some("json-whitespace"),
        "条件替换实际改写须声明归一化"
    );
    out.server.abort();
    std::fs::remove_dir_all(&out.dir).ok();
}

#[tokio::test]
async fn dialog_value_mismatch_keeps_body_and_header() {
    let out = chat_roundtrip(
        &[("x-reasoning-effort", "high")],
        br#"{"model":"m","reasoningEffort":"high","messages":[]}"#,
    )
    .await;
    assert_eq!(
        out.forwarded["reasoningEffort"],
        serde_json::json!("high"),
        "值不等须 no-op"
    );
    assert!(
        out.head_text.contains("x-reasoning-effort: high"),
        "header 不命中须原样: {}",
        out.head_text
    );
    assert!(
        out.normalized.is_none(),
        "未实际改写不得声明 x-veil-normalized"
    );
    out.server.abort();
    std::fs::remove_dir_all(&out.dir).ok();
}

#[tokio::test]
async fn no_rules_keeps_body_and_headers_byte_identical() {
    let input = br#"{"model":"m","reasoningEffort":"none","messages":[]}"#;
    let out = chat_roundtrip_with(None, &[("x-reasoning-effort", "none")], input).await;
    assert_eq!(out.body_bytes, input, "未声明规则时转发体须逐字节不变");
    assert!(
        out.head_text.contains("x-reasoning-effort: none"),
        "未声明规则时 header 须原样: {}",
        out.head_text
    );
    assert!(
        out.normalized.is_none(),
        "未声明规则不得声明 x-veil-normalized"
    );
    out.server.abort();
    std::fs::remove_dir_all(&out.dir).ok();
}

#[tokio::test]
async fn dialog_gated_header_rule_follows_original_model() {
    let out = chat_roundtrip(
        &[("x-gated-effort", "none")],
        br#"{"model":"deepseek-chat","messages":[]}"#,
    )
    .await;
    assert!(
        out.head_text.contains("x-gated-effort: off"),
        "模型匹配须应用带 models 的规则: {}",
        out.head_text
    );
    out.server.abort();
    std::fs::remove_dir_all(&out.dir).ok();

    let out = chat_roundtrip(
        &[("x-gated-effort", "none")],
        br#"{"model":"deepseek-reasoner","messages":[]}"#,
    )
    .await;
    assert!(
        out.head_text.contains("x-gated-effort: none"),
        "模型不匹配须跳过带 models 的规则: {}",
        out.head_text
    );
    out.server.abort();
    std::fs::remove_dir_all(&out.dir).ok();
}

#[test]
fn nondialog_applies_header_replace_but_keeps_body_bytes() {
    // NonDialog：头被替换、体逐字节不变；params/params.replace 被忽略（warn 去重位共享）。
    // 去重位为进程级：持锁串行（同 `headers.rs` 先例），避免并行用例抢先置位。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("测试运行时须可构造");
    rt.block_on(nondialog_header_replace_impl());
}

async fn nondialog_header_replace_impl() {
    let (url, captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(REPLACE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/models")
        .header("content-type", "application/json")
        .header("x-reasoning-effort", "none")
        .header("x-gated-effort", "none")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"model":"deepseek-chat","reasoningEffort":"none"}"#.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/models", client_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-reasoning-effort: off"),
        "NonDialog 须应用不带 models 的 header_replace: {text}"
    );
    assert!(
        text.contains("x-gated-effort: none"),
        "NonDialog 模型为 None，带 models 的规则须跳过: {text}"
    );
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "NonDialog 请求体须逐字节等于客户端原文（params.replace 不适用）"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn count_tokens_skips_params_replace_but_applies_header_replace() {
    // count_tokens（redact-only）：body 不注入 params.replace，header_replace 照常。
    let up_body = br#"{"input_tokens":1}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(REPLACE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .header("x-reasoning-effort", "none")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"model":"m","reasoningEffort":"none","messages":[]}"#.to_vec();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/messages/count_tokens",
        client_body.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-reasoning-effort: off"),
        "count_tokens 的 header_replace 照常生效: {text}"
    );
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "count_tokens 请求体不得被 params.replace 改写"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}
