//! T1 入站 query 保序转发 e2e：经网关到 mock 上游，断言上游收到的
//! 请求目标（path + query）与入站逐字节一致（同序同编码、空值/重复键保留），
//! 无 query 时不追加 `?`，上游基址自带 query 时不产生双 `?`。

use {
    common::{serve, test_app_router},
    std::sync::{Arc, Mutex},
};

mod common;

const MODELS_BODY: &str =
    r#"{"object":"list","data":[{"id":"gpt-4o","object":"model"}],"note":"13812345678"}"#;
const CHAT_BODY: &str = r#"{"id":"cmpl-1","model":"m","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// 上游收到的完整请求目标（`path?query`，无 query 时仅 path）。
async fn mock_upstream(targets: Arc<Mutex<Vec<String>>>) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move |req: axum::extract::Request| {
            let targets = targets.clone();
            async move {
                let target = req
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_default();
                let is_chat = target.starts_with("/v1/chat/completions");
                targets.lock().unwrap().push(target);
                let body = if is_chat { CHAT_BODY } else { MODELS_BODY };
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
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

#[tokio::test]
async fn query_string_forwarded_raw() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(targets.clone()).await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();

    let models = client
        .get(format!("{base}/v1/models?limit=10&after=abc"))
        .send()
        .await
        .unwrap();
    assert_eq!(models.status().as_u16(), 200);

    let chat = client
        .post(format!("{base}/v1/chat/completions?trace=1&x=a%2Bb"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(chat.status().as_u16(), 200);

    let seen = targets.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            "/v1/models?limit=10&after=abc".to_string(),
            "/v1/chat/completions?trace=1&x=a%2Bb".to_string(),
        ],
        "入站 query 须同序同编码转发"
    );

    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn query_absent_no_question_mark() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(targets.clone()).await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();

    let models = client
        .get(format!("{base}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(models.status().as_u16(), 200);
    let chat = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(chat.status().as_u16(), 200);

    let seen = targets.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["/v1/models".to_string(), "/v1/chat/completions".to_string(),],
        "无 query 时不得追加 `?`"
    );

    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn query_empty_value_and_duplicate_keys() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(targets.clone()).await;
    let (base, handle) = serve(test_app_router(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();

    let raw = "/v1/models?limit=&tag=a&tag=b&q=a+b&x=a%2Fb";
    let resp = client.get(format!("{base}{raw}")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let seen = targets.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![raw.to_string()],
        "空值参数、重复键、`+`/`%2F` 编码须原样保留"
    );

    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn query_upstream_base_with_query_joins_with_ampersand() {
    let targets = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(targets.clone()).await;
    let base_with_query = format!("{upstream}?base=1");
    let (base, handle) = serve(test_app_router(&[(
        "LLM_UPSTREAM",
        base_with_query.as_str(),
    )]))
    .await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/v1/models?limit="))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    let seen = targets.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["/v1/models?base=1&limit=".to_string()],
        "基址自带 query 须以 `&` 合并，不得产生双 `?`"
    );

    handle.abort();
    uhandle.abort();
}
