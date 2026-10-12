//! 管理控制台入口 `/_admin/`（含无尾斜杠双注册）的 `Accept` 协商端到端：
//! 浏览器（精确 `text/html`）得免鉴权 HTML 壳，API 客户端得 JSON 索引；
//! `Vary: Accept` 仅入口双路由携带；壳不下发 Set-Cookie。真实 HTTP 回环，
//! 每用例独立建 app（sqlite 与限流器隔离），无外网依赖。

use {
    common::{serve, test_app_router},
    serde_json::Value,
};

mod common;

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

/// 响应头取值（缺失即空串）。
fn header_value(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// 无凭证 + 浏览器 Accept → 200 HTML 壳（含 no-store 安全头），
// 且壳自包含（无外链脚本/样式）。
#[tokio::test]
async fn c1_browser_accept_serves_shell_without_credentials() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(header_value(&resp, "content-type").contains("text/html"));
    assert!(header_value(&resp, "cache-control").contains("no-store"));
    let body = resp.text().await.unwrap();
    assert!(body.contains("<html"), "须为 HTML 文档: {body:.80}");
    assert!(body.contains("<!DOCTYPE html"), "须携带 DOCTYPE");
    assert!(!body.contains("<script src="), "不得外链脚本");
    assert!(!body.contains("<link rel=\"stylesheet"), "不得外链样式");
    handle.abort();
}

// 无凭证 + 通配 Accept → 401 且错误码 `E_UNAUTHORIZED`（JSON 索引不放行匿名）。
#[tokio::test]
async fn c2_json_accept_without_credentials_401() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/"))
        .header("Accept", "*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("E_UNAUTHORIZED"), "未鉴权错误体: {body}");
    handle.abort();
}

// 有效头凭证 + 通配 Accept → 200 JSON 索引，六路由齐备。
#[tokio::test]
async fn c3_valid_token_serves_json_index_six_routes() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Accept", "*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["routes"].as_array().unwrap().len(), 6, "{v}");
    handle.abort();
}

// 入口带 query token 恒 401（非 SSE 不得以 query 传凭证），HTML Accept 亦不放行。
#[tokio::test]
async fn c4_query_token_on_index_401_with_html_accept() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/?access_token={ADMIN_TOKEN}"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let body = resp.text().await.unwrap();
    assert!(body.contains("E_UNAUTHORIZED"), "{body}");
    handle.abort();
}

// `OBSERVABILITY_DISABLE=1` 时入口亦 404，门控响应复用管理安全头（no-store）。
#[tokio::test]
async fn c5_disable_gate_404_keeps_security_headers() {
    let (base, handle) = serve(test_app_router(&[("OBSERVABILITY_DISABLE", "1")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin/"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    assert!(header_value(&resp, "cache-control").contains("no-store"));
    assert_eq!(header_value(&resp, "x-frame-options"), "DENY");
    handle.abort();
}

// 无尾斜杠 `/_admin` 与 `/_admin/` 双注册，浏览器 Accept 行为一致。
#[tokio::test]
async fn c7_no_trailing_slash_same_shell() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/_admin"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(header_value(&resp, "content-type").contains("text/html"));
    handle.abort();
}

// 无效头凭证不阻断免鉴权壳（HTML 判定先于鉴权），JSON 客户端仍 401。
#[tokio::test]
async fn c8_invalid_header_html_shell_wins_json_401() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let html = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", "wrong-token")
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(html.status().as_u16(), 200);
    assert!(header_value(&html, "content-type").contains("text/html"));
    let json = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", "wrong-token")
        .header("Accept", "*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(json.status().as_u16(), 401);
    handle.abort();
}

// 壳不下发 Set-Cookie（不经 `with_admin_cookie`）；health 有效头凭证下发登录 Cookie。
#[tokio::test]
async fn c9_shell_no_set_cookie_health_sets_cookie() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let shell = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(shell.status().as_u16(), 200);
    assert!(
        !shell.headers().contains_key("set-cookie"),
        "壳响应不得下发登录 Cookie"
    );
    let health = client
        .get(format!("{base}/_admin/health"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(health.status().as_u16(), 200);
    assert!(
        health.headers().contains_key("set-cookie"),
        "health 有效头凭证须下发登录 Cookie"
    );
    handle.abort();
}

// HEAD 探测入口（浏览器预检形态）：200 + text/html 且体为空。
#[tokio::test]
async fn c10_head_html_accept_empty_body() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let resp = client
        .head(format!("{base}/_admin/"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(header_value(&resp, "content-type").contains("text/html"));
    assert!(resp.text().await.unwrap().is_empty(), "HEAD 体须为空");
    handle.abort();
}

// `Vary: Accept` 仅入口双路由携带（两种协商结局均含）；其余管理路由不带。
#[tokio::test]
async fn c11_vary_accept_only_on_index() {
    let (base, handle) = serve(test_app_router(&[])).await;
    let client = reqwest::Client::new();
    let html = client
        .get(format!("{base}/_admin/"))
        .header("Accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(html.status().as_u16(), 200);
    assert_eq!(header_value(&html, "vary"), "Accept", "HTML 结局须 Vary");
    let json = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .header("Accept", "*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(json.status().as_u16(), 200);
    assert_eq!(header_value(&json, "vary"), "Accept", "JSON 结局须 Vary");
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    assert!(
        !metrics.headers().contains_key("vary"),
        "非入口路由不得携带 Vary"
    );
    handle.abort();
}
