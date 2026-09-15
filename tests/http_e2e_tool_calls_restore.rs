//! CHC-7 端到端：请求在 `tool_calls` 函数参数内携带 PII 时，网关以占位符替换，
//! 上游回显占位符后，响应侧还原为与请求逐字一致的原文。
//!
//! 现有真 SDK conformance 请求体不含 token，`tests/http_e2e_refusal_restore.rs`
//! 仅覆盖 refusal 帧；本文件独立构造含 PII 的工具参数并断言参数往返逐字一致。

use {
    common::{serve, test_app_router},
    std::time::Duration,
};

mod common;

const PHONE: &str = "13812345678";
const EXPECTED_ARGS: &str = "{\"phone\":\"13812345678\"}";

/// 从改写后请求体提取请求期 PII 占位符（网关已把明文替换为 token）。
fn extract_pii_token(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("token 形态正则恒合法");
    re.find(text).map(|m| m.as_str().to_string())
}

/// 上游把收到的占位符原样嵌入 `tool_calls.function.arguments` 后回显。
async fn mock_upstream_echo_tool_calls() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|body: axum::body::Bytes| async move {
            let text = String::from_utf8_lossy(&body).into_owned();
            let token = extract_pii_token(&text).unwrap_or_default();
            let args = format!("{{\\\"phone\\\":\\\"{token}\\\"}}");
            let frames = format!(
                "data: {{\"id\":\"chatcmpl-toolreq\",\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{{\"name\":\"lookup\",\"arguments\":\"{args}\"}}}}]}}}}]}}\n\n\
                 data: {{\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"tool_calls\"}}]}}\n\n\
                 data: [DONE]\n\n"
            );
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                frames,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

/// 从下游 SSE 体提取工具调用的 `arguments` 字符串（还原后）。
fn tool_call_arguments(body: &str) -> Option<String> {
    for line in body.lines() {
        let Some(payload) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
            continue;
        };
        if let Some(args) = value
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("delta"))
            .and_then(|d| d.get("tool_calls"))
            .and_then(|t| t.get(0))
            .and_then(|t| t.get("function"))
            .and_then(|f| f.get("arguments"))
            .and_then(|a| a.as_str())
        {
            return Some(args.to_string());
        }
    }
    None
}

#[tokio::test]
async fn tool_calls_redact_restore_e2e() {
    let (upstream, uhandle) = mock_upstream_echo_tool_calls().await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();
    let request_body = format!(
        "{{\"model\":\"m\",\"messages\":[{{\"role\":\"assistant\",\"content\":null,\
         \"tool_calls\":[{{\"id\":\"call_req\",\"type\":\"function\",\
         \"function\":{{\"name\":\"lookup\",\"arguments\":\"{{\\\"phone\\\":\\\"{PHONE}\\\"}}\"}}}}]}}],\
         \"stream\":true}}"
    );
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = tokio::time::timeout(Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    assert!(body.contains("tool_calls"), "工具调用帧须透传: {body}");
    assert!(
        !body.contains("__PII_"),
        "下游不得残留任何 PII 占位符: {body}"
    );
    assert!(body.contains(PHONE), "工具参数内占位符须还原为明文: {body}");
    let args = tool_call_arguments(&body).expect("下游须含工具调用 arguments");
    assert_eq!(args, EXPECTED_ARGS, "工具参数往返须逐字一致: {args}");
    assert_eq!(body.matches("data: [DONE]").count(), 1, "{body}");
    handle.abort();
    uhandle.abort();
}
