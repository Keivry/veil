//! dispatch 入口集成单测（sibling，`#[path]` 直连，见 `dispatch.rs` 声明）：
//! 会话键头无条件剔除（R5-36/D7）与会话键可判定降级计数（R5-08/D9）。

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

fn unique_temp_dir() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("veil-dispatch-tests-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("临时目录须可建");
    dir
}

fn test_app_state(extra: &[(&str, &str)]) -> (AppState, PathBuf) {
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
    let config = Config::load_from(&env).expect("测试配置须合法");
    let outcome = SqliteOutcome {
        sqlite_ok: true,
        sqlite_error: None,
        db_path: dir.join("m.sqlite"),
    };
    let state = AppState::try_new(config, outcome).expect("AppState 装配须成功");
    (state, dir)
}

/// 捕获请求字节的回环上游：可断言转发头集合（2.3 无条件剔除）。
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
    // R5-36/D7：默认 `request` 模式下自定义非 `x-veil-` 会话键头（`x-my-conv`）
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
    // R5-08/D9 可判定事件 ②：`conversation` 模式存储缺失——回退逐请求并计数，不报错。
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
    // R5-08/D9 可判定事件 ①：键推导返 None（纯多轮 messages 缺 tools）落第 4 级。
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
    // R5-08/D9 可判定事件 ③：显式会话键头存在但非法（超 256 字节）被丢弃。
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
