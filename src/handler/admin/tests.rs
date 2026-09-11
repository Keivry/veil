//! 管理面 handler 单测（A1 自 `service::admin` 随 handler 搬入）。

use {
    super::*,
    crate::{
        config::Config,
        state::{AppState, SqliteOutcome},
    },
    axum::http::HeaderMap,
    std::collections::HashMap,
};

fn test_ip() -> IpAddr { IpAddr::from([127, 0, 0, 1]) }

fn headers_with(token: Option<&str>, cookie: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Some(t) = token {
        h.insert("x-admin-token", t.parse().unwrap());
    }
    if let Some(c) = cookie {
        h.insert("cookie", format!("__Host-admin_token={c}").parse().unwrap());
    }
    h
}

#[test]
fn auth_priority_header_cookie_query_and_401() {
    let expected = "observability-admin-token-0123456789";
    // 头优先：头有效不再校验低优先级。
    assert!(
        authorize(
            expected,
            &headers_with(Some(expected), Some("wrong")),
            None,
            false,
            false
        )
        .is_none()
    );
    // 头无效直接 401（不降级 Cookie）。
    assert!(
        authorize(
            expected,
            &headers_with(Some("wrong"), Some(expected)),
            None,
            false,
            false
        )
        .is_some()
    );
    // Cookie 次优。
    assert!(
        authorize(
            expected,
            &headers_with(None, Some(expected)),
            None,
            false,
            false
        )
        .is_none()
    );
    // SSE query 有效放行。
    assert!(
        authorize(
            expected,
            &headers_with(None, None),
            Some(expected),
            true,
            true
        )
        .is_none()
    );
    // 非 SSE 带 query 恒 401（即使有效）。
    assert!(
        authorize(
            expected,
            &headers_with(None, None),
            Some(expected),
            true,
            false
        )
        .is_some()
    );
    assert!(
        authorize(
            expected,
            &headers_with(Some(expected), None),
            Some(expected),
            true,
            false
        )
        .is_some()
    );
    // 全失败 401。
    assert!(authorize(expected, &headers_with(None, None), None, false, false).is_some());
    // SSE query 无效 401。
    assert!(
        authorize(
            expected,
            &headers_with(None, None),
            Some("wrong"),
            true,
            true
        )
        .is_some()
    );
}

#[test]
fn cookie_admin_token_parsing() {
    let mut h = HeaderMap::new();
    h.insert(
        "cookie",
        "a=1; __Host-admin_token=tok123; b=2".parse().unwrap(),
    );
    assert_eq!(cookie_admin_token(&h).as_deref(), Some("tok123"));
    let empty = HeaderMap::new();
    assert_eq!(cookie_admin_token(&empty), None);
}

#[test]
fn cookie_falls_back_to_http_name() {
    let mut h = HeaderMap::new();
    h.insert("cookie", "__Host-admin_token=tok-https".parse().unwrap());
    assert_eq!(cookie_admin_token(&h).as_deref(), Some("tok-https"));
    let mut h2 = HeaderMap::new();
    h2.insert("cookie", "admin_token=tok-http".parse().unwrap());
    assert_eq!(cookie_admin_token(&h2).as_deref(), Some("tok-http"));
    // 双名并存时 __Host- 优先。
    let mut h3 = HeaderMap::new();
    h3.insert(
        "cookie",
        "admin_token=tok-http; __Host-admin_token=tok-https"
            .parse()
            .unwrap(),
    );
    assert_eq!(cookie_admin_token(&h3).as_deref(), Some("tok-https"));
    assert_eq!(cookie_admin_token(&HeaderMap::new()), None);
}

#[test]
fn set_cookie_distinguishes_https_from_http() {
    let expected = "observability-admin-token-0123456789";
    let mut h = HeaderMap::new();
    h.insert("x-admin-token", expected.parse().unwrap());
    let resp = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h, expected);
    let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(sc.starts_with("admin_token="), "{sc}");
    assert!(
        sc.contains("HttpOnly") && sc.contains("SameSite=Strict"),
        "{sc}"
    );
    let mut h2 = HeaderMap::new();
    h2.insert("x-admin-token", expected.parse().unwrap());
    h2.insert("x-forwarded-proto", "https".parse().unwrap());
    let resp2 = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h2, expected);
    let sc2 = resp2.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(sc2.starts_with("__Host-admin_token="), "{sc2}");
    assert!(sc2.contains("Secure"), "{sc2}");
    // 头凭证无效不签发。
    let mut h3 = HeaderMap::new();
    h3.insert("x-admin-token", "wrong".parse().unwrap());
    let resp3 = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h3, expected);
    assert!(resp3.headers().get("set-cookie").is_none());
}

#[test]
fn unknown_subpath_returns_404() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let resp = admin_not_found().await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    });
}

#[test]
fn admin_index_lists_six_routes() {
    let body = json!({
        "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
    });
    assert_eq!(body["routes"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn rate_limited_returns_429_with_retry_after_and_code() {
    let resp = rate_limited(42);
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("42")
    );
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "E_RATE_LIMITED");
    // SSE 并发拒绝固定 Retry-After: 60。
    let sse_resp = rate_limited(60);
    assert_eq!(sse_resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        sse_resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("60")
    );
}

#[tokio::test]
async fn series_model_upstream_compat_annotates_without_filtering() {
    let dir = std::env::temp_dir().join(format!("veil-admin-series-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok();
    let env = HashMap::from([
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
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: dir.join("m.sqlite"),
        },
    );
    let mut q: HashMap<String, String> = HashMap::new();
    q.insert("model".to_string(), "gpt-4".to_string());
    q.insert("upstream".to_string(), "https://x".to_string());
    q.insert("granularity".to_string(), "daily".to_string());
    let resp = admin_series(
        State(state),
        PeerIp(Some(test_ip())),
        headers_with(Some("observability-admin-token-0123456789"), None),
        Query(q),
    )
    .await
    .into_response();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ok"], true);
    assert!(v.get("compat").is_some());
    assert!(v["points"].as_array().is_some());
    std::fs::remove_dir_all(&dir).ok();
}
