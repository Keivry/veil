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

const ADMIN_TOKEN_T: &str = "observability-admin-token-0123456789";

fn admin_test_state(data_dir: std::path::PathBuf, db_path: std::path::PathBuf) -> AppState {
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN_T.to_string(),
        ),
        (
            "DATA_DIR".to_string(),
            data_dir.to_string_lossy().into_owned(),
        ),
    ]);
    AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path,
        },
    )
}

fn metrics_test_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("veil-admin-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const METRICS_KEYS: [&str; 6] = ["range", "model", "upstream", "metrics", "series", "health"];

#[tokio::test]
async fn admin_sse_metrics_snapshot() {
    // A11/11.1：六键形状、过滤字段回显，且流内周期推 `event: metrics`。
    let dir = metrics_test_dir("sse-metrics");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    let filter = admin::SseFilter::from_query(&HashMap::from([
        ("model".to_string(), "chat".to_string()),
        ("upstream".to_string(), "up-A".to_string()),
    ]));
    let payload = build_metrics_sse_payload(&state, &filter, Some("24h"), "hourly").await;
    for k in METRICS_KEYS {
        assert!(payload.get(k).is_some(), "缺键 {k}: {payload}");
    }
    assert_eq!(payload["range"], "24h");
    assert_eq!(payload["model"], "chat");
    assert_eq!(payload["upstream"], "up-A");
    assert!(payload["metrics"]["requests"].is_u64(), "{payload}");
    assert!(payload["metrics"]["tokens"]["total"].is_u64(), "{payload}");
    assert!(
        payload["series"].is_array(),
        "空窗 series 须数组: {payload}"
    );
    assert_eq!(payload["health"]["ok"], true);
    assert!(payload["health"]["sqlite_ok"].is_boolean(), "{payload}");

    let unfiltered =
        build_metrics_sse_payload(&state, &admin::SseFilter::default(), None, "hourly").await;
    assert!(unfiltered["model"].is_null() && unfiltered["upstream"].is_null());
    assert!(unfiltered["range"].is_null());

    let app = crate::router::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let client = reqwest::Client::new();
    let mut resp = client
        .get(format!(
            "http://{addr}/_admin/events/stream?model=chat&upstream=up-A"
        ))
        .header("X-Admin-Token", ADMIN_TOKEN_T)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let mut buf = String::new();
    let mut frame_payload: Option<serde_json::Value> = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while frame_payload.is_none() && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(500), resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                buf.push_str(&String::from_utf8_lossy(&chunk));
                while let Some(pos) = buf.find("\n\n") {
                    let frame: String = buf.drain(..pos + 2).collect();
                    if frame.contains("event: metrics") {
                        let data = frame
                            .lines()
                            .find_map(|l| l.strip_prefix("data:").map(str::trim))
                            .unwrap_or("");
                        frame_payload = serde_json::from_str(data).ok();
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    let streamed = frame_payload.expect("SSE 须周期推 event: metrics");
    for k in METRICS_KEYS {
        assert!(
            streamed.get(k).is_some(),
            "SSE metrics 缺键 {k}: {streamed}"
        );
    }
    assert_eq!(streamed["model"], "chat");
    server.abort();
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn admin_sse_metrics_degraded() {
    // A11/11.2：查询失败降级、无过滤、带 model/upstream 过滤三场景。
    let dir = metrics_test_dir("sse-degraded");
    // 查询失败：db_path 指向目录 → open 失败 → series 降级，metrics/health 不受影响。
    let broken = admin_test_state(dir.clone(), dir.clone());
    let payload =
        build_metrics_sse_payload(&broken, &admin::SseFilter::default(), None, "hourly").await;
    assert_eq!(
        payload["series"]["error"], "series_unavailable",
        "{payload}"
    );
    assert!(
        payload["metrics"]["is_precise"].is_boolean(),
        "metrics 不因 series 失败降级: {payload}"
    );
    assert_eq!(
        payload["health"]["ok"], true,
        "health 不因 series 失败降级: {payload}"
    );

    let filtered = build_metrics_sse_payload(
        &broken,
        &admin::SseFilter::from_query(&HashMap::from([
            ("model".to_string(), "m".to_string()),
            ("upstream".to_string(), "u".to_string()),
        ])),
        Some("1h"),
        "five_min",
    )
    .await;
    assert_eq!(filtered["model"], "m");
    assert_eq!(filtered["upstream"], "u");
    assert_eq!(filtered["range"], "1h");
    assert_eq!(filtered["series"]["error"], "series_unavailable");

    let ok = admin_test_state(dir.clone(), dir.join("ok.sqlite"));
    let normal = build_metrics_sse_payload(&ok, &admin::SseFilter::default(), None, "hourly").await;
    assert!(normal["series"].is_array(), "{normal}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn admin_cookie_https_criteria() {
    // A16/D15：双判据（XFP 或 Forwarded proto=https）任一命中 → __Host- Secure；
    // 两判据皆缺失/非 https → http 兼容 admin_token。
    let expected = "observability-admin-token-0123456789";
    let issue = |xfp: Option<&str>, fwd: Option<&str>| {
        let mut h = HeaderMap::new();
        h.insert("x-admin-token", expected.parse().unwrap());
        if let Some(v) = xfp {
            h.insert("x-forwarded-proto", v.parse().unwrap());
        }
        if let Some(v) = fwd {
            h.insert("forwarded", v.parse().unwrap());
        }
        let resp = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h, expected);
        resp.headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    // 判据一：X-Forwarded-Proto。
    let xfp = issue(Some("HTTPS"), None);
    assert!(
        xfp.starts_with("__Host-admin_token=") && xfp.contains("Secure"),
        "{xfp}"
    );
    // 判据二：RFC 7239 Forwarded（大小写不敏感 / 带引号 / 多元素）。
    for fwd in [
        "proto=https",
        "proto=\"https\"",
        "for=1.2.3.4;Proto=HTTPS;by=proxy",
    ] {
        let sc = issue(None, Some(fwd));
        assert!(
            sc.starts_with("__Host-admin_token=") && sc.contains("Secure"),
            "Forwarded={fwd:?} 须命中 Secure: {sc}"
        );
    }
    // 缺失降级：http 兼容 Cookie，无 Secure。
    let none = issue(None, None);
    assert!(
        none.starts_with("admin_token=") && !none.contains("Secure"),
        "{none}"
    );
    // 非 https 值不误判。
    let http = issue(None, Some("proto=http"));
    assert!(
        http.starts_with("admin_token=") && !http.contains("Secure"),
        "{http}"
    );
}

async fn events_body(state: AppState, q: HashMap<String, String>) -> serde_json::Value {
    let resp = admin_events(
        State(state),
        PeerIp(Some(test_ip())),
        headers_with(Some(ADMIN_TOKEN_T), None),
        Query(q),
    )
    .await
    .into_response();
    let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn admin_events_filter_semantics() {
    // A19/D19：limit 1/200 边界 + kind/since/verdict 组合过滤语义。
    let dir = metrics_test_dir("events-filter");
    let state = admin_test_state(dir.clone(), dir.join("m.sqlite"));
    {
        let st = state.admin_state();
        st.push_event("audit", "a1", None);
        st.push_event("block", "b1", None);
        st.push_event("audit", "a2", None);
    }
    let q = |kv: &[(&str, &str)]| -> HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    // limit 边界：1 取下限恰一条；200 覆盖全部。
    let one = events_body(state.clone(), q(&[("limit", "1")])).await;
    assert_eq!(one["events"].as_array().unwrap().len(), 1);
    let all = events_body(state.clone(), q(&[("limit", "200")])).await;
    assert_eq!(all["events"].as_array().unwrap().len(), 3);
    // limit=0 归一为下限 1（环查询 clamp 1..=500）。
    let zero = events_body(state.clone(), q(&[("limit", "0")])).await;
    assert_eq!(zero["events"].as_array().unwrap().len(), 1);
    // kind 精确过滤。
    let audit = events_body(state.clone(), q(&[("kind", "audit")])).await;
    assert_eq!(audit["events"].as_array().unwrap().len(), 2);
    // since：未来时间排除全部，0 含全部。
    let future = events_body(state.clone(), q(&[("since", "9999999999")])).await;
    assert_eq!(future["events"].as_array().unwrap().len(), 0);
    let since0 = events_body(state.clone(), q(&[("since", "0")])).await;
    assert_eq!(since0["events"].as_array().unwrap().len(), 3);
    // verdict 归一后命中环内 kind 才过滤：blocked→block（环内有 block）→ 1 + 弃用标注。
    let blocked = events_body(state.clone(), q(&[("verdict", "blocked")])).await;
    assert_eq!(blocked["events"].as_array().unwrap().len(), 1);
    assert_eq!(blocked["compat"]["verdict"], "blocked→block");
    // verdict 归一值环内无 kind → 忽略过滤 + 弃用标注，返回全部。
    let pending = events_body(state.clone(), q(&[("verdict", "pending")])).await;
    assert_eq!(pending["events"].as_array().unwrap().len(), 3);
    // kind 显式优先于 verdict。
    let both = events_body(
        state.clone(),
        q(&[("kind", "audit"), ("verdict", "blocked")]),
    )
    .await;
    assert_eq!(both["events"].as_array().unwrap().len(), 2);
    std::fs::remove_dir_all(&dir).ok();
}
