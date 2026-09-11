//! T3/7.1 refusal 集成级独立还原 e2e：Chat 流式 refusal 帧内的请求期 PII 占位符
//! 经网关还原为明文（非原样透传、非占位残留），补 `src/service/sse.rs` 与
//! `src/handler/llm/pump/event.rs` 单元覆盖之外的集成锁定。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
        time::Duration,
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

const PHONE: &str = "13812345678";

fn test_app(extra: &[(&str, &str)]) -> axum::Router {
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
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-refusal-{n}.sqlite")),
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    build_router(state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

/// 从改写后请求体提取请求期 PII 占位符（网关已把明文替换为 token；
/// 说明注入文案里的 `__PII_*__` 字面量不匹配真实 token 形态）。
fn extract_pii_token(text: &str) -> Option<String> {
    let re = regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("token 形态正则恒合法");
    re.find(text).map(|m| m.as_str().to_string())
}

/// 上游把收到的占位符原样嵌入 refusal 帧（模拟模型拒绝话术里引用被脱敏值）。
async fn mock_upstream_echo_refusal() -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(|body: axum::body::Bytes| async move {
            let text = String::from_utf8_lossy(&body).into_owned();
            let token = extract_pii_token(&text).unwrap_or_default();
            let frames = format!(
                "data: {{\"id\":\"chatcmpl-refusal\",\"choices\":[{{\"delta\":{{\"refusal\":\"拒绝提供 {token}\"}}}}]}}\n\ndata: [DONE]\n\n"
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

#[tokio::test]
async fn refusal_frame_restores_pii_plaintext_not_placeholder() {
    let (upstream, uhandle) = mock_upstream_echo_refusal().await;
    let (base, handle) = serve(test_app(&[("LLM_UPSTREAM", upstream.as_str())])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(format!(
            "{{\"model\":\"m\",\"messages\":[{{\"role\":\"user\",\"content\":\"我的手机号是 {PHONE}\"}}],\"stream\":true}}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = tokio::time::timeout(Duration::from_secs(20), resp.text())
        .await
        .expect("下游 SSE 须在 20s 内闭合")
        .unwrap();
    assert!(body.contains("拒绝提供"), "refusal 帧须透传: {body}");
    assert!(
        body.contains(PHONE),
        "refusal 帧内占位符须还原为明文（非占位残留）: {body}"
    );
    assert!(
        !body.contains("__PII_"),
        "下游不得残留任何 PII 占位符: {body}"
    );
    assert_eq!(body.matches("data: [DONE]").count(), 1, "{body}");
    handle.abort();
    uhandle.abort();
}
