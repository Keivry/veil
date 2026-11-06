//! `models` 门控的数据通路径用例：`serve_detailed` 经 `forward_headers` 读取
//! `ExpandCtx.model`（dispatch 在脱敏/重写前快照的原始模型），不重新解析已改写的
//! `body`——即使转发体里的 `model` 不同，门控仍按原始模型判定。

use {
    super::test_ctx,
    crate::{
        config::{HeaderReplaceRule, UpstreamOverrides},
        handler::llm::{
            ExpandCtx,
            nonstream::{NonstreamCtx, NonstreamOutcome, serve_nonstream},
        },
        service::llm_gateway::Protocol,
    },
    axum::http::{HeaderMap, HeaderValue},
    std::sync::{Arc, Mutex},
};

/// 捕获请求头行的回环上游：回固定 JSON，原始请求字节交回测试。
async fn capture_loopback(
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
    let sink = captured.clone();
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    );
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            if let Ok(n) = sock.read(&mut buf).await {
                sink.lock()
                    .expect("捕获锁不得中毒")
                    .extend_from_slice(&buf[..n]);
            }
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

fn gated_overrides() -> UpstreamOverrides {
    UpstreamOverrides {
        header_replace: vec![HeaderReplaceRule {
            name: "x-gated-effort".to_string(),
            from: "none".to_string(),
            to: "off".to_string(),
            models: Some(vec!["original-model".to_string()]),
        }],
        ..UpstreamOverrides::default()
    }
}

#[tokio::test]
async fn header_models_gate_uses_expand_model_not_rewritten_body_model() {
    // 上游回显体与转发体均为 JSON，非流对话路径正常返回。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback(up_body).await;
    let client = reqwest::Client::new();
    let mut client_headers = HeaderMap::new();
    client_headers.insert("x-gated-effort", HeaderValue::from_static("none"));
    let expand_inbound = client_headers.clone();
    let expand = ExpandCtx {
        inbound: &expand_inbound,
        outbound_id: None,
        model: Some("original-model".to_string()),
    };
    let overrides = gated_overrides();
    let ctx = NonstreamCtx {
        overrides: Some(&overrides),
        expand,
        ..test_ctx(Protocol::Chat)
    };
    // 转发体里的 `model` 已被上游侧改写（与原始模型不同）——门控不得据此判定。
    let rewritten = br#"{"model":"renamed-model","messages":[]}"#.to_vec();
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        client_headers,
        rewritten,
        ctx,
    )
    .await;
    server.abort();
    assert!(
        matches!(outcome, NonstreamOutcome::Responded(_)),
        "回显 JSON 须走非流响应"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-gated-effort: off"),
        "门控须按 ExpandCtx.model（原始模型）命中: {text}"
    );
}

#[tokio::test]
async fn header_models_gate_skips_when_expand_model_is_none() {
    // NonDialog 语义：`model` 为 `None` 时带 `models` 的规则跳过。
    let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
    let (url, captured, server) = capture_loopback(up_body).await;
    let client = reqwest::Client::new();
    let mut client_headers = HeaderMap::new();
    client_headers.insert("x-gated-effort", HeaderValue::from_static("none"));
    let expand_inbound = client_headers.clone();
    let overrides = gated_overrides();
    let ctx = NonstreamCtx {
        overrides: Some(&overrides),
        expand: ExpandCtx {
            inbound: &expand_inbound,
            outbound_id: None,
            model: None,
        },
        ..test_ctx(Protocol::Chat)
    };
    let outcome = serve_nonstream(
        &client,
        reqwest::Method::POST,
        &url,
        client_headers,
        br#"{"model":"original-model","messages":[]}"#.to_vec(),
        ctx,
    )
    .await;
    server.abort();
    assert!(
        matches!(outcome, NonstreamOutcome::Responded(_)),
        "回显 JSON 须走非流响应"
    );
    let raw = captured.lock().expect("捕获锁不得中毒").clone();
    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(
        text.contains("x-gated-effort: none"),
        "模型缺失须跳过带 models 的规则（不得从 body 反推）: {text}"
    );
}
