//! dispatch 入口集成单测（`mod tests`，见 `dispatch.rs` 声明）：
//! 会话键头无条件剔除与会话键可判定降级计数。

use {
    crate::{
        config::Config,
        handler::llm::dispatch::{build_request_scope, gateway_serve},
        service::llm_gateway::Protocol,
        state::{AppState, SqliteOutcome},
    },
    axum::http::{HeaderMap, StatusCode},
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, Mutex},
    },
};

mod entry;
mod request_log;

fn unique_temp_dir() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("veil-dispatch-tests-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("临时目录须可建");
    dir
}

fn test_app_state(extra: &[(&str, &str)]) -> (AppState, PathBuf) {
    test_app_state_with_targets(extra, None)
}

/// 同 [`test_app_state`]，可选并入文件专属 `[llm.targets]` 覆盖片段
/// （`targets_toml` 为完整文件层 TOML 文本）。
fn test_app_state_with_targets(
    extra: &[(&str, &str)],
    targets_toml: Option<&str>,
) -> (AppState, PathBuf) {
    let dir = unique_temp_dir();
    let mut env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "observability-admin-token-0123456789".to_string(),
        ),
        ("DATA_DIR".to_string(), dir.to_string_lossy().into_owned()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let config = match targets_toml {
        Some(text) => {
            let file: crate::config::FileConfig = toml::from_str(text).expect("覆盖片段须可解析");
            let raw = file
                .llm
                .and_then(|section| section.targets)
                .expect("片段须含 [llm.targets]");
            let targets = crate::config::validate_targets(Some(&raw)).expect("覆盖须合法");
            Config::load_from_with_targets(&env, targets).expect("测试配置须合法")
        }
        None => Config::load_from(&env).expect("测试配置须合法"),
    };
    let outcome = SqliteOutcome {
        sqlite_ok: true,
        sqlite_error: None,
        db_path: dir.join("m.sqlite"),
    };
    let state = AppState::try_new(config, outcome).expect("AppState 装配须成功");
    (state, dir)
}

/// 捕获请求字节的回环上游：可断言转发头集合（无条件剔除）。
async fn capture_loopback(
    body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<u8>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            if let Ok(n) = sock.read(&mut buf).await {
                cap.lock()
                    .expect("捕获锁不得中毒")
                    .extend_from_slice(&buf[..n]);
            }
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&body).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, captured, handle)
}

#[tokio::test]
async fn request_mode_custom_conversation_header_not_forwarded() {
    // 默认 `request` 模式下自定义非 `x-veil-` 会话键头（`x-my-conv`）
    // 亦须在转发前无条件剔除；键推导仍读原始头，不因剔除而失效。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback(up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_SCOPE_KEY_HEADER", "x-my-conv"),
    ]);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-my-conv", "conv-secret-value")
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
    let raw = String::from_utf8_lossy(&captured.lock().expect("捕获锁不得中毒")).to_string();
    assert!(raw.contains("content-type"), "请求须确实到达上游: {raw}");
    assert!(
        !raw.to_ascii_lowercase().contains("x-my-conv"),
        "会话键头须无条件剔除（request 模式亦剔除）: {raw}"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conversation_store_missing_counts_and_degrades() {
    // 可判定事件 ②：`conversation` 模式存储缺失——回退逐请求并计数，不报错。
    let (mut state, dir) = test_app_state(&[("PII_SCOPE_MODE", "conversation")]);
    state.conversation_scope_store = None;
    let _scope = build_request_scope(
        &state,
        &HeaderMap::new(),
        Protocol::Chat,
        "https://up.example.com/v1",
        Some(&serde_json::json!({})),
    );
    assert_eq!(state.gateway_metrics.conversation_store_missing_count(), 1);
    assert_eq!(state.gateway_metrics.request_fallback_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conversation_key_fallback_counts_and_degrades() {
    // 可判定事件 ①：键推导返 None（纯多轮 messages 缺 tools）落第 4 级。
    let (state, dir) = test_app_state(&[("PII_SCOPE_MODE", "conversation")]);
    let body = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let _scope = build_request_scope(
        &state,
        &HeaderMap::new(),
        Protocol::Chat,
        "https://up.example.com/v1",
        Some(&body),
    );
    assert_eq!(state.gateway_metrics.request_fallback_count(), 1);
    assert_eq!(state.gateway_metrics.conversation_store_missing_count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn conversation_header_invalid_counts_and_degrades() {
    // 可判定事件 ③：显式会话键头存在但非法（超 256 字节）被丢弃。
    let (state, dir) = test_app_state(&[("PII_SCOPE_MODE", "conversation")]);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        "a".repeat(300).parse().expect("头值须合法"),
    );
    let _scope = build_request_scope(
        &state,
        &headers,
        Protocol::Chat,
        "https://up.example.com/v1",
        Some(&serde_json::json!({})),
    );
    assert_eq!(state.gateway_metrics.conversation_header_invalid_count(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// 捕获完整请求（头 + `content-length` 声明的体）的回环上游：回固定响应，
/// 原始请求字节经共享句柄交回测试，供配置头注入与字节保真断言。
async fn capture_loopback_complete(
    content_type: &str,
    resp_body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<u8>>>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("回环监听须成功");
    let url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().expect("回环地址须可读")
    );
    let captured = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = Vec::new();
            let mut chunk = [0u8; 16384];
            loop {
                let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), sock.read(&mut chunk))
                        .await
                else {
                    break;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let Some(header_end) = buf
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|pos| pos + 4)
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
                let declared = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if declared == 0 || buf.len() >= header_end + declared {
                    break;
                }
            }
            cap.lock().expect("捕获锁不得中毒").extend_from_slice(&buf);
            if sock.write_all(head.as_bytes()).await.is_err() {
                continue;
            }
            if sock.write_all(&resp_body).await.is_err() {
                continue;
            }
            let _ = sock.shutdown().await;
        }
    });
    (url, captured, handle)
}

/// 捕获字节中 `\r\n\r\n` 之后的请求体切片。
fn captured_body(raw: &[u8]) -> &[u8] {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .expect("捕获须含头体分隔");
    &raw[header_end..]
}

/// 覆盖片段：`default` 目标单头 + UA 恒胜 + `$conversation` 动态头，
/// 验证 NonDialog / 对话两路径共用同一注入与插值展开。
const DEFAULT_HEADER_OVERRIDE: &str = "[llm.targets.default]\nuser_agent = \"opencode/1.18.33\"\n\
    [llm.targets.default.headers]\nx-provider-version = \"2023-06-01\"\nx-opencode-session = \"$conversation\"\n";

/// 覆盖片段：headers + UA 恒胜 + `$conversation` 动态头 + 双协议同名参数，
/// 验证参数注入与 redact-only 豁免。
const PARAM_OVERRIDE_TOML: &str = "[llm.targets.default]\nuser_agent = \"opencode/1.18.33\"\n\
    [llm.targets.default.headers]\n\
    x-provider-version = \"2023-06-01\"\n\
    x-opencode-session = \"$conversation\"\n\
    [llm.targets.default.params.chat]\noverride = { temperature = 0.7 }\n\
    [llm.targets.default.params.anthropic]\noverride = { temperature = 0.7 }\n";

/// 覆盖片段：端口目标（8878）与 `default` 目标各带头与参数，同名不同值，
/// 供选路与覆盖同源的端到端判别。
const PORT_AND_DEFAULT_TARGETS_TOML: &str = "[llm.targets.\"8878\".headers]\n\
    x-target = \"port-8878\"\n\
    [llm.targets.\"8878\".params.chat]\noverride = { temperature = 0.7 }\n\
    [llm.targets.default.headers]\n\
    x-target = \"default\"\n\
    [llm.targets.default.params.chat]\noverride = { temperature = 0.9 }\n";

/// 覆盖片段：default 目标合并模式（`override_existing = false`）——同名头/参数与缺失项同在。
const MERGE_MODE_TOML: &str = "[llm.targets.default]\noverride_existing = false\n\
    [llm.targets.default.headers]\nx-target = \"config\"\nx-new = \"added\"\n\
    [llm.targets.default.params.chat]\noverride = { temperature = 0.9 }\ndefault = { top_p = 0.5 }\n";

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
    // 同时锁定内部会话标识不外泄：客户端自带的 `x-opencode-session` 属回退链，
    // 转发前已被无条件剔除，不得因「动态头跳过」而原样透传上游。
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
        !text.contains("x-opencode-session") && !text.contains("client-dyn"),
        "缺源动态头须整条跳过，且客户端回退链头须被剔除（不泄漏内部会话标识）: {text}"
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

#[tokio::test]
async fn dialog_nonstream_param_injection_rewrites_body_and_declares_normalized() {
    // task 4.2：命中 params 的对话非流请求，转发体含注入参数且响应带
    // `x-veil-normalized: json-whitespace`（与 stream_options 注入同口径）。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(PARAM_OVERRIDE_TOML));
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
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
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
        "对话非流上游须收到配置头: {text}"
    );
    let sent: serde_json::Value =
        serde_json::from_slice(captured_body(&raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        sent["temperature"],
        serde_json::json!(0.7),
        "上游须收到注入参数"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn count_tokens_gets_headers_but_no_params_injection() {
    // task 4.3：redact-only（count_tokens）SHALL 不注入 params；headers 注入不受限。
    let up_body = br#"{"input_tokens":1}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(PARAM_OVERRIDE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/messages/count_tokens",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-provider-version: 2023-06-01"),
        "count_tokens headers 注入不受限: {text}"
    );
    assert!(
        !String::from_utf8_lossy(captured_body(&raw)).contains("temperature"),
        "count_tokens 不得注入 params"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn port_and_default_targets_resolve_same_source_overrides() {
    // task 5.1：入口端口命中端口目标（env URL + 文件覆盖组合）；无端口专用上游
    // 时回退缺省上游并命中 default 目标——两条链路各取同源 {URL, 覆盖}，
    // 头与参数按同一目标解析结果注入。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (port_url, port_captured, port_server) =
        capture_loopback_complete("application/json", up_body.clone()).await;
    let (default_url, default_captured, default_server) =
        capture_loopback_complete("application/json", up_body).await;
    let (state, dir) = test_app_state_with_targets(
        &[
            ("LLM_8878", port_url.as_str()),
            ("LLM_UPSTREAM", default_url.as_str()),
        ],
        Some(PORT_AND_DEFAULT_TARGETS_TOML),
    );

    // 请求 A：Host 声明入口端口 8878 → 端口专用上游 + 端口目标覆盖。
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("host", "127.0.0.1:8878")
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
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|value| value.to_str().ok()),
        Some("json-whitespace"),
        "端口目标参数注入须声明归一化"
    );
    let port_raw = port_captured.lock().expect("捕获锁不得中毒").clone();
    let port_text = String::from_utf8_lossy(&port_raw).to_ascii_lowercase();
    assert!(
        port_text.contains("x-target: port-8878"),
        "端口目标配置头须注入: {port_text}"
    );
    let port_sent: serde_json::Value =
        serde_json::from_slice(captured_body(&port_raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        port_sent["temperature"],
        serde_json::json!(0.7),
        "端口目标参数须注入"
    );
    assert!(
        default_captured.lock().expect("捕获锁不得中毒").is_empty(),
        "端口命中请求不得访问缺省上游"
    );

    // 请求 B：无 Host（缺省回退）→ LLM_UPSTREAM + default 目标覆盖。
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
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let default_raw = default_captured.lock().expect("捕获锁不得中毒").clone();
    let default_text = String::from_utf8_lossy(&default_raw).to_ascii_lowercase();
    assert!(
        default_text.contains("x-target: default"),
        "default 目标配置头须注入: {default_text}"
    );
    let default_sent: serde_json::Value =
        serde_json::from_slice(captured_body(&default_raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        default_sent["temperature"],
        serde_json::json!(0.9),
        "default 目标参数须注入"
    );
    port_server.abort();
    default_server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_nonstream_merge_mode_preserves_client_and_adds_missing() {
    // task 8.1：override_existing = false 对话非流——客户端同名头与参数值保留，
    // 缺失配置项新增；体实际改写 → 响应带 x-veil-normalized。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(MERGE_MODE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-target", "client")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"model":"m","temperature":0.5,"messages":[]}"#;
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        client_body.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|value| value.to_str().ok()),
        Some("json-whitespace"),
        "缺失参数新增已改写请求体，须声明归一化"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-target: client"),
        "客户端同名头须保留: {text}"
    );
    assert!(text.contains("x-new: added"), "缺失配置头须新增: {text}");
    let sent: serde_json::Value =
        serde_json::from_slice(captured_body(&raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        sent["temperature"],
        serde_json::json!(0.5),
        "客户端参数值须保留"
    );
    assert_eq!(
        sent["top_p"],
        serde_json::json!(0.5),
        "缺失参数（default 段）须新增"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_nonstream_merge_mode_noop_keeps_body_and_flag() {
    // task 8.1：合并模式下客户端已带全部同名头/参数——无实际变化：
    // 请求体逐字节保留、响应不带 x-veil-normalized。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(MERGE_MODE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-target", "client")
        .header("x-new", "client-new")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"model":"m","temperature":0.5,"top_p":0.7,"messages":[]}"#;
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        client_body.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-veil-normalized").is_none(),
        "无实际改写不得声明 x-veil-normalized"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "无变化须逐字节保留客户端原文"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn nondialog_merge_mode_header_merge_and_byte_identity() {
    // 与 NonDialog `params` 豁免 warn 的进程级去重位共享：持锁串行至请求结束，
    // 防并行用例抢先置位使「恰一次」断言 flaky（见 test_support 锁说明）。
    let _warn_guard = crate::test_support::nondialog_params_warn_lock();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("测试运行时须可构造");
    rt.block_on(nondialog_merge_mode_header_merge_impl());
}

async fn nondialog_merge_mode_header_merge_impl() {
    // task 8.1：NonDialog + override_existing = false——头按合并结果注入（同名保留、缺失新增），
    // 请求体逐字节等于客户端原文（params 被忽略）。
    let (url, captured, server) =
        capture_loopback_complete("application/json", b"{}".to_vec()).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(MERGE_MODE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/models")
        .header("content-type", "application/json")
        .header("x-target", "client")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let client_body = br#"{"probe":"nondialog-merge"}"#.to_vec();
    let resp = gateway_serve(&state, &mut parts, "/v1/models", client_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-target: client"),
        "NonDialog 客户端同名头须保留: {text}"
    );
    assert!(text.contains("x-new: added"), "缺失配置头须新增: {text}");
    assert_eq!(
        captured_body(&raw),
        client_body.as_slice(),
        "NonDialog 请求体须逐字节等于客户端原文"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn count_tokens_merge_mode_headers_merged_params_skipped() {
    // task 8.1：count_tokens（redact-only）+ override_existing = false——headers 按合并结果
    // 注入，params 仍不注入。
    let up_body = br#"{"input_tokens":1}"#.to_vec();
    let (url, captured, server) = capture_loopback_complete("application/json", up_body).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(MERGE_MODE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/messages/count_tokens")
        .header("content-type", "application/json")
        .header("x-target", "client")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/messages/count_tokens",
        br#"{"model":"m","messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-target: client"),
        "count_tokens 客户端同名头须保留: {text}"
    );
    assert!(text.contains("x-new: added"), "缺失配置头须新增: {text}");
    let body = String::from_utf8_lossy(captured_body(&raw)).into_owned();
    assert!(
        !body.contains("temperature") && !body.contains("top_p"),
        "count_tokens 不得注入 params: {body}"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn dialog_stream_merge_mode_preserves_client_and_declares_normalized() {
    // task 8.1（流式）：override_existing = false 对话流式——客户端参数值保留、缺失键新增、
    // SSE 帧序列不受影响（恰一终止帧）。
    let sse =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
    let (url, captured, server) = capture_loopback_complete("text/event-stream", sse).await;
    let (state, dir) =
        test_app_state_with_targets(&[("LLM_UPSTREAM", url.as_str())], Some(MERGE_MODE_TOML));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-target", "client")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(
        &state,
        &mut parts,
        "/v1/chat/completions",
        br#"{"model":"m","stream":true,"temperature":0.5,"messages":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "流式分支须正常建流");
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|value| value.to_str().ok()),
        Some("json-whitespace"),
        "缺失参数新增已改写请求体，须声明归一化"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let sent: serde_json::Value =
        serde_json::from_slice(captured_body(&raw)).expect("转发体须为合法 JSON");
    assert_eq!(
        sent["temperature"],
        serde_json::json!(0.5),
        "客户端参数值须保留"
    );
    assert_eq!(sent["top_p"], serde_json::json!(0.5), "缺失参数须新增");
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

#[tokio::test]
async fn gateway_serve_request_side_entropy_failure_fails_closed_before_upstream() {
    // Oracle weak-test ③：端到端覆盖 `gateway_serve` 调用点——conversation 模式下
    // 预置共享 `PiiScope` 熵源故障，`gateway_serve` 须 502 `E_PII_UNAVAILABLE`
    // 且零转发上游（若守门调用点被删除，本用例即失败）。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}]}"#.to_vec();
    let (url, captured, server) = capture_loopback(up_body).await;
    let (state, dir) = test_app_state(&[
        ("LLM_UPSTREAM", url.as_str()),
        ("PII_SCOPE_MODE", "conversation"),
        ("REDACTION_ENABLED", "1"),
    ]);
    let body = br#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-veil-conversation-id",
        "conv-e2e".parse().expect("头值须合法"),
    );
    let upstream = crate::service::llm_gateway::resolve_upstream(&state.config, None)
        .expect("测试配置须有上游");
    // 先以同一显式会话键建作用域（写入共享存储），再对共享 `PiiScope` 注故障；
    // `gateway_serve` 复用同一键即取回已预置故障的实例。
    let scope = build_request_scope(
        &state,
        &headers,
        Protocol::Chat,
        &upstream,
        Some(&serde_json::json!({"messages": []})),
    );
    scope.pii_scope().force_entropy_failure(true);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("x-veil-conversation-id", "conv-e2e")
        .body(())
        .expect("请求构造须成功");
    let (mut parts, ()) = request.into_parts();
    let resp = gateway_serve(&state, &mut parts, "/v1/chat/completions", body.to_vec()).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "请求侧熵源故障须 502 fail-closed"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .expect("错误体须可读");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("错误体须为 JSON");
    assert_eq!(value["error"]["code"], "E_PII_UNAVAILABLE");
    assert!(
        !String::from_utf8_lossy(&bytes).contains("13812345678"),
        "错误体不得含明文"
    );
    assert!(
        captured.lock().expect("捕获锁不得中毒").is_empty(),
        "fail-closed 须零转发上游"
    );
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}
