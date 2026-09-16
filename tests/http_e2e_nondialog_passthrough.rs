//! T-M2 NonDialog 透传 e2e（`veil-review-followup-test-gap` T2.1）：
//! `GET /v1/models` 经网关到 mock 上游，断言字节透传 + `nondialog_passthrough`
//! 计数 1→2→3 + hop 方向计数 + 上游收到的路径/方法/头 + 无用量/审计/还原
//! （含原文 phone 未脱敏证明）。

use {
    common::{serve, test_app},
    std::sync::{Arc, Mutex},
    veil::service::credential::AppStateParts,
};

mod common;

/// 上游原文：含 phone 形态字符串，透传臂不得脱敏。
const UPSTREAM_BODY: &str =
    r#"{"object":"list","data":[{"id":"gpt-4o","object":"model"}],"note":"13812345678"}"#;

/// 上游收到的请求快照（方法/路径/头），供透传路径断言。
#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn mock_upstream(
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move |req: axum::extract::Request| {
            let captured = captured.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
                    .await
                    .unwrap_or_default()
                    .to_vec();
                captured.lock().unwrap().push(CapturedRequest {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_string(),
                    headers: parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_string(),
                                v.to_str().unwrap_or("<bin>").to_string(),
                            )
                        })
                        .collect(),
                    body: body_bytes,
                });
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    UPSTREAM_BODY,
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

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

#[tokio::test]
async fn t2_1_nondialog_models_passthrough_with_count_and_no_side_effects() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(captured.clone()).await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let up_before = state.gateway_metrics().hop_filtered_count("upstream");
    let down_before = state.gateway_metrics().hop_filtered_count("downstream");

    // 连续三次透传：每次状态码/内容类型不改写、字节一致、零注入、计数递增。
    for n in 1..=3u64 {
        let resp = client
            .get(format!("{base}/v1/models"))
            .header("X-Probe-Keep", "keep-me")
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=5")
            .header("TE", "trailers")
            .header("Proxy-Authorization", "Basic hop")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "第 {n} 次透传状态码不改写");
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "第 {n} 次 content-type 不被改写"
        );
        assert!(
            resp.headers().get("x-veil-normalized").is_none(),
            "第 {n} 次透传臂不得声明归一化头"
        );
        let body = resp.text().await.unwrap();
        assert_eq!(body, UPSTREAM_BODY, "第 {n} 次须字节透传");
        assert!(
            body.contains("13812345678"),
            "第 {n} 次透传臂不得脱敏: {body}"
        );
        assert!(
            !body.contains("__PII_") && !body.contains("__VG_CRED_"),
            "第 {n} 次透传臂不得注入占位符: {body}"
        );
        assert_eq!(
            state.gateway_metrics().nondialog_passthrough_count(),
            n,
            "透传计数须 1→2→3 递增"
        );
    }

    // 上游收到：方法/路径正确、非 hop 头保留、hop 头被剥离。
    let upstream_authority = upstream.trim_start_matches("http://").to_string();
    let seen = captured.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "上游须收到 3 次");
    for (idx, req) in seen.iter().enumerate() {
        let nth = idx + 1;
        assert_eq!(req.method, "GET", "第 {nth} 次方法须透传");
        assert_eq!(req.path, "/v1/models", "第 {nth} 次路径须透传");
        let has = |name: &str| req.headers.iter().any(|(k, _)| k == name);
        for hop in ["connection", "keep-alive", "te", "proxy-authorization"] {
            assert!(
                !has(hop),
                "hop 头 {hop} 不得达上游（第 {nth} 次）: {:?}",
                req.headers
            );
        }
        assert_eq!(
            req.headers
                .iter()
                .find(|(k, _)| k == "host")
                .map(|(_, v)| v.as_str()),
            Some(upstream_authority.as_str()),
            "下游 host 不得透传；上游 host 须由 reqwest 按上游地址注入（第 {nth} 次）"
        );
        assert!(has("x-probe-keep"), "非 hop 头须保留（第 {nth} 次）");
        assert!(
            has("accept-encoding"),
            "downstream accept-encoding 剥离后 reqwest 须注入支持编码集（第 {nth} 次）"
        );
    }

    // hop_filtered 方向计数：upstream 每次剥 4 头；downstream 每次响应剥 1 头。
    let up_delta = state.gateway_metrics().hop_filtered_count("upstream") - up_before;
    assert_eq!(
        up_delta, 12,
        "upstream 方向 3 次 ×4 头（connection/keep-alive/te/proxy-authorization）"
    );
    let down_delta = state.gateway_metrics().hop_filtered_count("downstream") - down_before;
    assert_eq!(
        down_delta, 3,
        "downstream 方向 3 次响应各剥 1 头（content-length 解码配对）"
    );

    // 无用量：对话指标快照 requests 恒零。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let metrics_body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(
        metrics_body["requests"], 0,
        "透传不得记录用量: {metrics_body}"
    );

    // 无审计：事件环为空。
    let events = client
        .get(format!("{base}/_admin/events?limit=100"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(events.status().as_u16(), 200);
    let events_body: serde_json::Value = events.json().await.unwrap();
    assert!(
        events_body["events"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "透传不得产生审计事件: {events_body}"
    );

    uhandle.abort();
    handle.abort();
}

/// 上游错误 JSON（含危险 tool_call）：NonDialog 须原样透传，不得被合成阻断体替换。
const RESPONSES_ERR_BODY: &str = r#"{"error":{"message":"not found"},"output":[{"type":"function_call","id":"f1","name":"exec","arguments":"rm -rf /"}]}"#;

/// `count_tokens` 上游响应（redact-only 变体）：含 phone 形态 PII，用于证明
/// 响应侧**不还原、不做新 PII 扫描**（字节保真，phone 原样保留）。
const COUNT_TOKENS_UPSTREAM_BODY: &str = r#"{"input_tokens":42,"note":"13812345678"}"#;

/// `batches` 上游响应：仍为 `NonDialog` 字节透传。
const BATCHES_UPSTREAM_BODY: &str = r#"{"data":[],"has_more":false}"#;

/// T5 官方子资源专用上游：`count_tokens`/`batches` 回 200；`responses/{id}` 回 400 错误 JSON。
async fn mock_upstream_official(
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move |req: axum::extract::Request| {
            let captured = captured.clone();
            async move {
                let (parts, body) = req.into_parts();
                let body_bytes = axum::body::to_bytes(body, 1024 * 1024)
                    .await
                    .unwrap_or_default()
                    .to_vec();
                let path = parts.uri.path().to_string();
                captured.lock().unwrap().push(CapturedRequest {
                    method: parts.method.to_string(),
                    path: path.clone(),
                    headers: parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_string(),
                                v.to_str().unwrap_or("<bin>").to_string(),
                            )
                        })
                        .collect(),
                    body: body_bytes,
                });
                let (status, payload) = if path.ends_with("/count_tokens") {
                    (axum::http::StatusCode::OK, COUNT_TOKENS_UPSTREAM_BODY)
                } else if path.ends_with("/batches") {
                    (axum::http::StatusCode::OK, BATCHES_UPSTREAM_BODY)
                } else {
                    (axum::http::StatusCode::BAD_REQUEST, RESPONSES_ERR_BODY)
                };
                axum::response::Response::builder()
                    .status(status)
                    .header(axum::http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(payload))
                    .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
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
async fn official_subresource_passthrough() {
    // T5：`batches` 与 Responses 单段检索判 NonDialog——请求体不改写、响应字节透传、
    // 不记对话用量、不触发审计后处理（错误 JSON 不被合成阻断体替换）。
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_official(captured.clone()).await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str()), ("AUDIT_MODE", "block")]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let batches_body = br#"{"limit":10}"#.to_vec();
    let resp = client
        .post(format!("{base}/v1/messages/batches"))
        .header("content-type", "application/json")
        .body(batches_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "batches 状态须透传");
    assert!(
        resp.headers().get("x-veil-protocol").is_none(),
        "NonDialog 不得置 x-veil-protocol"
    );
    let body = resp.text().await.unwrap();
    assert_eq!(body, BATCHES_UPSTREAM_BODY, "batches 响应须字节透传");

    let resp = client
        .get(format!("{base}/v1/responses/abc123"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400, "错误 JSON 状态码须保留");
    assert!(
        resp.headers().get("x-veil-protocol").is_none(),
        "NonDialog 不得置 x-veil-protocol"
    );
    let body = resp.text().await.unwrap();
    assert_eq!(
        body, RESPONSES_ERR_BODY,
        "错误 JSON 须字节透传，不得被合成阻断体替换"
    );
    assert!(!body.contains("[blocked:"), "不得合成阻断体: {body}");

    // 请求体须字节透传（batches 体不得被改写）。
    let seen = captured.lock().unwrap().clone();
    let bt = seen
        .iter()
        .find(|r| r.path == "/v1/messages/batches")
        .expect("上游须收到 batches");
    assert_eq!(bt.method, "POST");
    assert_eq!(bt.body, batches_body, "batches 请求体须字节透传，不得改写");
    assert_eq!(
        state.gateway_metrics().nondialog_passthrough_count(),
        2,
        "batches 与 responses 两个官方子资源均须走 NonDialog 透传臂"
    );

    // 不记对话用量。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let metrics_body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(
        metrics_body["requests"], 0,
        "官方子资源不得记对话用量: {metrics_body}"
    );

    // 不触发审计后处理。
    let events = client
        .get(format!("{base}/_admin/events?limit=100"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let events_body: serde_json::Value = events.json().await.unwrap();
    assert!(
        events_body["events"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "官方子资源不得产生审计事件: {events_body}"
    );

    uhandle.abort();
    handle.abort();
}

#[tokio::test]
async fn count_tokens_redact_only() {
    // C/3.1+3.2：`POST /v1/messages/count_tokens` 收窄为 redact-only 对话变体——
    // 请求侧 `messages` 内 PII 被占位符替换（秘密不明文上行）；响应侧不还原/不
    // 做新 PII 扫描（字节保真）；不记 usage、不产审计事件、不计 NonDialog 透传。
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_official(captured.clone()).await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str()), ("AUDIT_MODE", "block")]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let ct_body =
        br#"{"model":"claude-3","messages":[{"role":"user","content":"13812345678"}]}"#.to_vec();
    let resp = client
        .post(format!("{base}/v1/messages/count_tokens"))
        .header("content-type", "application/json")
        .body(ct_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "count_tokens 状态须保留");
    assert_eq!(
        resp.headers()
            .get("x-veil-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("anthropic"),
        "redact-only 协议值须为 anthropic（不再为 passthrough）"
    );
    let body = resp.text().await.unwrap();
    assert_eq!(
        body, COUNT_TOKENS_UPSTREAM_BODY,
        "响应须字节保真（不还原、不做新 PII 扫描）"
    );
    assert!(
        body.contains("13812345678"),
        "响应侧不得扫描/掩码新 PII: {body}"
    );
    assert!(!body.contains("__PII_"), "响应字节不得被注入占位符: {body}");

    // 请求体：PII 已被占位符替换，秘密不明文上行。
    let seen = captured.lock().unwrap().clone();
    let ct = seen
        .iter()
        .find(|r| r.path == "/v1/messages/count_tokens")
        .expect("上游须收到 count_tokens");
    let req_text = String::from_utf8_lossy(&ct.body).into_owned();
    assert!(
        req_text.contains("__PII_"),
        "请求侧须脱敏并置占位符: {req_text}"
    );
    assert!(
        !req_text.contains("13812345678"),
        "请求体不得明文上行: {req_text}"
    );

    // count_tokens 不计 NonDialog 透传。
    assert_eq!(
        state.gateway_metrics().nondialog_passthrough_count(),
        0,
        "count_tokens 收窄后不计 NonDialog 透传"
    );

    // 无用量记录（跳过用量记账）。
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let metrics_body: serde_json::Value = metrics.json().await.unwrap();
    assert_eq!(
        metrics_body["requests"], 0,
        "redact-only 不得记对话用量: {metrics_body}"
    );

    // 无审计事件（跳过审计判定 + 阻断合成）。
    let events = client
        .get(format!("{base}/_admin/events?limit=100"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    let events_body: serde_json::Value = events.json().await.unwrap();
    assert!(
        events_body["events"]
            .as_array()
            .is_some_and(|a| a.is_empty()),
        "redact-only 不得产生审计事件: {events_body}"
    );

    uhandle.abort();
    handle.abort();
}

#[tokio::test]
async fn nondialog_custom_conversation_header_not_forwarded() {
    // FIX 1（spec `redaction` 会话键头 MUST NOT 转发上游）：`conversation` 模式下
    // 自定义（非 `x-veil-*`）会话键头在 NonDialog 透传路径同样必须剔除，不得达上游。
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream(captured.clone()).await;
    let (app, _state) = test_app(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("PII_SCOPE_MODE", "conversation"),
        ("PII_SCOPE_KEY_HEADER", "x-custom-conv-key"),
    ]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/v1/models"))
        .header("x-custom-conv-key", "conv-abc-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap(), UPSTREAM_BODY);

    let seen = captured.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "上游须收到 1 次");
    let headers = &seen[0].headers;
    assert!(
        !headers.iter().any(|(k, _)| k == "x-custom-conv-key"),
        "自定义会话键头名不得转发上游: {headers:?}"
    );
    assert!(
        headers.iter().all(|(_, v)| !v.contains("conv-abc-secret")),
        "自定义会话键头值不得转发上游: {headers:?}"
    );

    uhandle.abort();
    handle.abort();
}

#[tokio::test]
async fn nondialog_passthrough_batches_only() {
    // C/3.3（M-3）：NonDialog 单一计数——`count_tokens` 收窄后不计，
    // `batches` 仍计；计数 API 保持无参单原子（不新增端点维度）。
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_official(captured.clone()).await;
    let (app, state) = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/v1/messages/count_tokens"))
        .header("content-type", "application/json")
        .body(br#"{"model":"claude-3","messages":[{"role":"user","content":"hello"}]}"#.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        state.gateway_metrics().nondialog_passthrough_count(),
        0,
        "count_tokens 不得计 NonDialog 透传"
    );

    let resp = client
        .get(format!("{base}/v1/messages/batches"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        state.gateway_metrics().nondialog_passthrough_count(),
        1,
        "batches 仍须计 NonDialog 透传递增"
    );

    uhandle.abort();
    handle.abort();
}
