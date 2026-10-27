use {
    super::*,
    crate::{
        config::Config,
        service::credential::test_support::{InjectSink, inject_sink},
        state::SqliteOutcome,
    },
    std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration},
};

fn test_app(extra: &[(&str, &str)]) -> Router { test_app_with_state(extra).0 }

/// 同一装配，但注入降级的 TPM 健康缓存（验证 `/health` 派生与 HTTP 状态码解耦）。
fn test_app_with_degraded_tpm(cache: Arc<crate::service::tpm::TpmHealthCache>) -> Router {
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
        ("VEILCTL_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    let state = AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from("/tmp/x.sqlite"),
        },
    )
    .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()))
    .with_tpm_health(cache);
    build_router(state)
}

fn test_app_with_state(extra: &[(&str, &str)]) -> (Router, AppState) {
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
        ("VEILCTL_SECRET".to_string(), "s3cr3t".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let state = inject_sink(
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()))
        .with_tpm_health(Arc::new(crate::service::tpm::TpmHealthCache::mock())),
        InjectSink::success(),
    );
    (build_router(state.clone()), state)
}

/// 缺 `OBSERVABILITY_ADMIN_TOKEN` 的装配：管理面须整体 404，LLM/健康面不受影响。
fn test_app_missing_admin_token() -> Router {
    let env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
    ]);
    let state = inject_sink(
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()))
        .with_tpm_health(Arc::new(crate::service::tpm::TpmHealthCache::mock())),
        InjectSink::success(),
    );
    build_router(state)
}

async fn serve_and_client(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn seven_routes_paths_and_status_codes() {
    let (base, handle) = serve_and_client(test_app(&[])).await;
    let client = reqwest::Client::new();

    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);

    let regs = client
        .get(format!("{base}/registrations"))
        .send()
        .await
        .unwrap();
    assert_eq!(regs.status().as_u16(), 401);

    let regs_auth = client
        .get(format!("{base}/registrations"))
        .header("X-Admin-Token", "observability-admin-token-0123456789")
        .send()
        .await
        .unwrap();
    assert_eq!(regs_auth.status().as_u16(), 200);

    // 三因子齐备的注册作为后续吊销/哈希变更的装配（未鉴权拒绝见
    // `router_credential_write_endpoints_require_auth`）。
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Veilctl-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/job.sh",
            "caller_hash": "routehash1",
            "source": "route-test-1",
            "auth": {"caller_hash": "routehash1", "caller_path": "/srv/job.sh"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202);

    let cred = client
        .post(format!("{base}/credential"))
        .header("X-Veilctl-Binary-Hash", "routehashX")
        .header("X-Veilctl-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "routehashX", "caller_path": "/srv/other.sh"},
            "entry": "网易",
            "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    // 未注册 `/credential` 默认转审批（202），不再兼容放行。
    assert_eq!(cred.status().as_u16(), 202);

    let cred_bad = client
        .post(format!("{base}/credential"))
        .json(&serde_json::json!({
            "auth": {"caller_hash": "routehashX", "caller_path": "/srv/other.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(cred_bad.status().as_u16(), 403);

    let revoke = client
        .post(format!("{base}/revoke"))
        .json(&serde_json::json!({ "caller_path": "/srv/job.sh" }))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status().as_u16(), 403);

    let emergency = client
        .post(format!("{base}/revoke/emergency"))
        .header("X-Admin-Token", "observability-admin-token-0123456789")
        .json(&serde_json::json!({ "caller_path": "/srv/job.sh" }))
        .send()
        .await
        .unwrap();
    assert_eq!(emergency.status().as_u16(), 200);

    let approve = client
        .post(format!("{base}/approve-hash-change"))
        .json(&serde_json::json!({
            "caller_path": "/srv/job.sh",
            "new_hash": "routehash2",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status().as_u16(), 403);

    handle.abort();
}

#[tokio::test]
async fn router_credential_write_endpoints_require_auth() {
    // 三写端点未鉴权一律非 2xx，且不落任何动作。
    let (app, state) = test_app_with_state(&[]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    for (path, body) in [
        (
            "/approve-hash-change",
            serde_json::json!({"caller_path": "/srv/x.sh", "new_hash": "nx"}),
        ),
        (
            "/register-caller",
            serde_json::json!({"caller_path": "/srv/x.sh", "caller_hash": "nx"}),
        ),
    ] {
        let resp = client
            .post(format!("{base}{path}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
            "{path} 未鉴权须 401/403，实得 {}",
            resp.status()
        );
    }
    let revoke = client
        .post(format!("{base}/revoke"))
        .json(&serde_json::json!({"caller_path": "/srv/x.sh"}))
        .send()
        .await
        .unwrap();
    assert!(
        revoke.status().as_u16() == 401 || revoke.status().as_u16() == 403,
        "revoke 未鉴权须 401/403"
    );
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/srv/x.sh")
            .is_none(),
        "未鉴权不得落注册条目"
    );
    handle.abort();
}

#[tokio::test]
async fn admin_exact_routes_before_wildcard_unknown_404() {
    let (base, handle) = serve_and_client(test_app(&[])).await;
    let client = reqwest::Client::new();
    let token = "observability-admin-token-0123456789";

    let index = client
        .get(format!("{base}/_admin/"))
        .header("X-Admin-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(index.status().as_u16(), 200);
    let body: serde_json::Value = index.json().await.unwrap();
    assert_eq!(body["routes"].as_array().unwrap().len(), 7);

    let health = client
        .get(format!("{base}/_admin/health"))
        .header("X-Admin-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(health.status().as_u16(), 200);

    let no_auth = client
        .get(format!("{base}/_admin/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status().as_u16(), 401);

    let query_non_sse = client
        .get(format!("{base}/_admin/metrics?access_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(query_non_sse.status().as_u16(), 401);

    let unknown = client
        .get(format!("{base}/_admin/nope"))
        .header("X-Admin-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status().as_u16(), 404);

    let sse = client
        .get(format!("{base}/_admin/events/stream?access_token={token}"))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(sse.status().as_u16(), 200);
    assert!(
        sse.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .contains("text/event-stream")
    );

    handle.abort();
}

#[tokio::test]
async fn admin_rate_limit_eleventh_returns_429_with_retry_after() {
    let (base, handle) = serve_and_client(test_app(&[])).await;
    let client = reqwest::Client::new();
    let token = "observability-admin-token-0123456789";
    // health 豁免限流（§6.2）：连续命中恒 200，不被误伤。
    for _ in 0..crate::service::admin::ADMIN_RATE_LIMIT + 1 {
        let ok = client
            .get(format!("{base}/_admin/health"))
            .header("X-Admin-Token", token)
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status().as_u16(), 200);
    }
    // 非豁免路由：10/min 后第 11 次 429 带 retry-after。
    for _ in 0..crate::service::admin::ADMIN_RATE_LIMIT {
        let ok = client
            .get(format!("{base}/_admin/metrics"))
            .header("X-Admin-Token", token)
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status().as_u16(), 200);
    }
    let limited = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status().as_u16(), 429);
    assert!(limited.headers().contains_key("retry-after"));
    handle.abort();
}

#[tokio::test]
async fn gateway_body_too_large_413() {
    let app = test_app(&[]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let over = vec![b'x'; crate::handler::GATEWAY_BODY_LIMIT_BYTES + 1];
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(over)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 413);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_PAYLOAD_TOO_LARGE");
    handle.abort();
}

#[tokio::test]
async fn credential_rate_limit_skips_pending_retry_but_caps_new_requests() {
    let (app, state) = test_app_with_state(&[]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "auth": {"caller_hash": "rlhash1", "caller_path": "/srv/rl.sh"},
        "entry": "网易",
        "field": "授权码"
    });
    let post = || {
        client
            .post(format!("{base}/credential"))
            .header("X-Veilctl-Binary-Hash", "rlhash1")
            .header("X-Veilctl-Secret", "s3cr3t")
            .json(&payload)
            .send()
    };
    let first = post().await.unwrap();
    assert_eq!(first.status().as_u16(), 202, "未注册转审批");
    // 同一 pending_key 已有在途票：幂等重试豁免 2s 限流，继续 202 而非 429。
    let retry = post().await.unwrap();
    assert_eq!(retry.status().as_u16(), 202, "在途重试须复用既有票");
    assert!(
        !retry.headers().contains_key("retry-after"),
        "豁免路径不得带 retry-after"
    );
    // 决策被消费后（批准动作已完成的等价状态），新请求重新受 2s 窗口约束。
    state
        .decisions()
        .lock()
        .unwrap()
        .consume("/srv/rl.sh:rlhash1");
    let fresh = post().await.unwrap();
    assert_eq!(fresh.status().as_u16(), 429, "无在途票的新请求仍受限流");
    assert!(fresh.headers().contains_key("retry-after"));
    handle.abort();
}

#[tokio::test]
async fn go_interop_mirror_and_entry_hint() {
    let (base, handle) = serve_and_client(test_app(&[])).await;
    let client = reqwest::Client::new();

    let go_ok = client
        .post(format!("{base}/credential"))
        .json(&serde_json::json!({
            "auth": {
                "caller_hash": "gohash9",
                "caller_path": "/srv/go.sh",
                "veilctl_binary_hash": "gohash9",
                "veilctl_secret": "s3cr3t"
            },
            "entry": "网易",
            "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(go_ok.status().as_u16(), 202, "未注册转审批");

    let no_entry = client
        .post(format!("{base}/credential"))
        .header("X-Veilctl-Binary-Hash", "gohash9")
        .header("X-Veilctl-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "gohash9", "caller_path": "/srv/go.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_entry.status().as_u16(), 400);
    let hint: serde_json::Value = no_entry.json().await.unwrap();
    assert!(
        hint["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("entry")
    );
    assert!(hint["error_detail"].is_string());

    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    let hbody: serde_json::Value = health.json().await.unwrap();
    assert_eq!(hbody["ok"], true);
    assert_eq!(hbody["sqlite_ok"], true);
    assert_eq!(hbody["status"], "ok");
    assert_eq!(hbody["unlocked"], true);

    let forbidden = client
        .post(format!("{base}/credential"))
        .json(&serde_json::json!({
            "auth": {"caller_hash": "gohash9", "caller_path": "/srv/go.sh"},
            "entry": "网易",
            "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status().as_u16(), 403);
    let ebody: serde_json::Value = forbidden.json().await.unwrap();
    assert!(ebody["error_detail"].is_string());

    handle.abort();
}

async fn mock_upstream_echo(
    seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new().route(
        "/{*tail}",
        axum::routing::any(move |body: axum::body::Bytes| async move {
            *seen.lock().unwrap() = body.to_vec();
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
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
async fn body_passthrough_byte_identical_by_default() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_echo(seen.clone()).await;
    let app = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let raw = b"{\"model\" :  \"m\" ,  \"messages\" : []}".to_vec();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(raw.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.headers().get("x-veil-normalized").is_none());
    assert_eq!(*seen.lock().unwrap(), raw);
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn normalize_enabled_sets_declared_header() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_echo(seen.clone()).await;
    let app = test_app(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("NORMALIZE_JSON_WHITESPACE", "1"),
    ]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body("{\"model\" :  \"m\" ,  \"messages\" : []}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "json-whitespace"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn json_redaction_declares_normalized_header_e2e() {
    // E2E：JSON 请求体脱敏重序列化 → 下游响应含 `x-veil-normalized`;
    // 上游收到脱敏体（键序保持，不含原文）。
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_echo(seen.clone()).await;
    let app = test_app(&[
        ("LLM_UPSTREAM", upstream.as_str()),
        ("PII_PLACEHOLDER_PROMPT", "0"),
    ]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"m","messages":[{"role":"user","content":"call 13812345678"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()
            .get("x-veil-normalized")
            .and_then(|v| v.to_str().ok()),
        Some("json-whitespace"),
        "JSON 脱敏重序列化须声明"
    );
    let forwarded = String::from_utf8_lossy(&seen.lock().unwrap().clone()).into_owned();
    assert!(
        forwarded.contains("__PII_"),
        "上游须收到脱敏体: {forwarded}"
    );
    assert!(
        !forwarded.contains("13812345678"),
        "不得外泄原文: {forwarded}"
    );
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn register_caller_go_shape_superset() {
    // Go 形态请求（`name/script_path/script_hash/entries/allow_mode`）
    // 注册成功；响应提供加性超集（顶层 + `registration` 内可解析），
    // 既有字段不删、重名 409 语义不变。注册经审批链，阻塞模式下批准后返回。
    let (app, state) = test_app_with_state(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "name": "check-mail",
        "script_path": "/srv/go-shape.sh",
        "script_hash": "gohash-shape-1",
        "entries": {"网易": ["授权码"]},
        "allow_mode": "true",
        "auth": {"caller_hash": "gohash-shape-1", "caller_path": "/srv/go-shape.sh"},
    });
    let request_client = client.clone();
    let request_body = body.clone();
    let request_base = base.clone();
    let request = tokio::spawn(async move {
        request_client
            .post(format!("{request_base}/register-caller"))
            .header("X-Veilctl-Secret", "s3cr3t")
            .json(&request_body)
            .send()
            .await
    });
    let event_id = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let ids = state.approval.pending_event_ids().await;
            if let Some(id) = ids.into_iter().next() {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("注册审批建单超时");
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    let resp = request.await.unwrap().unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["registration"]["caller_path"], "/srv/go-shape.sh");
    assert!(
        v["registration"]["status"].as_str().is_some(),
        "既有 status 字段须保留: {v}"
    );
    for ptr in [
        "/name",
        "/script_path",
        "/script_hash",
        "/entries",
        "/allow_mode",
    ] {
        assert!(v.pointer(ptr).is_some(), "顶层缺 {ptr}: {v}");
        assert!(
            v.pointer(&format!("/registration{ptr}")).is_some(),
            "registration 缺 {ptr}: {v}"
        );
    }
    assert_eq!(v["script_path"], "/srv/go-shape.sh");
    assert_eq!(v["script_hash"], "gohash-shape-1");
    assert_eq!(v["entries"]["网易"][0], "授权码");
    assert_eq!(v["allow_mode"], "true");
    let dup = client
        .post(format!("{base}/register-caller"))
        .header("X-Veilctl-Secret", "s3cr3t")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status().as_u16(), 409, "重名 409 语义不变");
    handle.abort();
}

#[tokio::test]
async fn non_stream_observation_persisted_and_queryable() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let (upstream, uhandle) = mock_upstream_echo(seen.clone()).await;
    let app = test_app(&[("LLM_UPSTREAM", upstream.as_str())]);
    let (base, handle) = serve_and_client(app).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/v1/chat/completions"))
        .header("Content-Type", "application/json")
        .body("{\"model\":\"m\",\"messages\":[]}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let metrics = client
        .get(format!("{base}/_admin/metrics"))
        .header("X-Admin-Token", "observability-admin-token-0123456789")
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status().as_u16(), 200);
    let body: serde_json::Value = metrics.json().await.unwrap();
    assert!(body["requests"].as_u64().unwrap_or(0) >= 1);
    handle.abort();
    uhandle.abort();
}

#[tokio::test]
async fn missing_admin_token_admin_surface_returns_404() {
    let (base, handle) = serve_and_client(test_app_missing_admin_token()).await;
    let client = reqwest::Client::new();
    for path in ["/_admin", "/_admin/", "/_admin/health", "/_admin/metrics"] {
        let resp = client
            .get(format!("{base}{path}"))
            .header("X-Admin-Token", "any")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "{path} 缺 token 须 404");
    }
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200, "健康检查不受影响");
    handle.abort();
}

#[tokio::test]
async fn health_returns_200_with_derived_ok_false_over_http() {
    // 契约：`/health` 恒 200，判活只看 `ok` 字段；容器 HEALTHCHECK 依赖
    // 「HTTP 200 但 ok=false」能被 `grep '"ok":true'` 判为不健康。
    let dir = std::env::temp_dir().join(format!(
        "veil-router-health-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("seal.pub"), b"pub").unwrap();
    std::fs::write(dir.join("seal.priv"), b"priv").unwrap();
    let cache = crate::service::tpm::TpmHealthCache::new(
        dir,
        crate::service::tpm::TpmHealth {
            ok: false,
            error: Some("tpm2_pcrread 不存在".to_string()),
        },
    );
    let app = test_app_with_degraded_tpm(Arc::new(cache));
    let (base, handle) = serve_and_client(app).await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "降级时仍须 HTTP 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false, "ok 须由 tpm_ok 派生: {body}");
    assert_eq!(body["tpm_ok"], false);
    assert_eq!(body["status"], "degraded");
    handle.abort();
}

/// `fmt` 写端：每行经 `MakeWriter` 取一个 `io::Write`，统一追加到进程内缓冲区。
#[derive(Clone, Default)]
struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl LogSink {
    fn log(&self) -> String { String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned() }

    /// 取第一条含 `needle` 的行，失败时打印全量捕获。
    fn line_with(&self, needle: &str) -> String {
        let log = self.log();
        log.lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("未捕获含 {needle:?} 的行:\n{log}"))
            .to_string()
    }

    /// 取 `key=` 之后的值（至空白或 `}` 止）。
    fn field(&self, line: &str, key: &str) -> Option<String> {
        let rest = line.split(&format!("{key}=")).nth(1)?;
        Some(
            rest.split([' ', '}'])
                .next()
                .unwrap_or_default()
                .to_string(),
        )
    }
}

impl std::io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer { self.clone() }
}

/// 线程局部安装真实 `fmt` 订阅者：`Span` 字段只在 `Registry` 内跨 `enter` 保留，
/// 事件字段抓取器（`test_support::with_capture_subscriber`）取不到 span 字段。
///
/// `FmtSpan::NEW` 让 span 建立本身也落一行（字段与后续事件行同格式），使「无任何
/// 事件的路由」（如 `/` 的 502、gate 的早期 404）也能被断言；若 `request_context`
/// 被错误地嵌在 gate 内侧，早期 404 会绕过它而不产生该行。
fn capture_fmt(sink: &LogSink) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
        .finish();
    tracing::subscriber::set_default(subscriber)
}

#[tokio::test(flavor = "current_thread")]
async fn request_span_logs_request_id_method_and_route() {
    let sink = LogSink::default();
    let _guard = capture_fmt(&sink);
    let (base, handle) = serve_and_client(test_app(&[])).await;
    // 空体：三因子校验立即失败为 4xx，`VeilError::into_response` 的 warn 行落在 span 内。
    let resp = reqwest::Client::new()
        .post(format!("{base}/credential"))
        .header("x-request-id", "abc123")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert!(
        !resp.headers().contains_key("x-request-id"),
        "不得回写 x-request-id 响应头: {:?}",
        resp.headers()
    );
    let span_line = sink.line_with("route=/credential");
    assert!(span_line.contains("request_id=abc123"), "{span_line}");
    assert!(span_line.contains("method=POST"), "{span_line}");
    let warn_line = sink.line_with("请求被拒绝");
    assert!(
        warn_line.contains("request_id=abc123") && warn_line.contains("route=/credential"),
        "4xx 行须继承请求 span: {warn_line}"
    );
    handle.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_or_absent_request_id_yields_generated_value() {
    let sink = LogSink::default();
    let _guard = capture_fmt(&sink);
    let (base, handle) = serve_and_client(test_app(&[])).await;
    let client = reqwest::Client::new();
    let post = |id: Option<&'static str>| {
        let mut req = client.post(format!("{base}/credential"));
        if let Some(id) = id {
            req = req.header("x-request-id", id);
        }
        req.json(&serde_json::json!({})).send()
    };
    // 非法头（含空格）→ 丢弃并生成；缺失头 → 同样生成。
    for (index, id) in [Some("a b"), None].into_iter().enumerate() {
        let seen_before = sink.log().lines().count();
        let resp = post(id).await.unwrap();
        assert_eq!(resp.status().as_u16(), 403, "{index}: {id:?}");
        assert!(!resp.headers().contains_key("x-request-id"), "{index}");
        let log = sink.log();
        let line = log
            .lines()
            .skip(seen_before)
            .find(|line| line.contains("route=/credential"))
            .unwrap_or_else(|| panic!("{index}: 第 {index} 次请求未产生 span 行:\n{log}"))
            .to_string();
        let request_id = sink
            .field(&line, "request_id")
            .unwrap_or_else(|| panic!("行缺 request_id: {line}"));
        assert!(
            !request_id.is_empty(),
            "{index} 生成的 request_id 不得为空: {line}"
        );
        if let Some(id) = id {
            assert_ne!(request_id, id, "{index} 非法头须被替换: {line}");
        }
        assert!(
            request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "{index} 生成值须限于安全字符集: {line}"
        );
    }
    handle.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn static_route_patterns_for_root_wildcard_and_admin() {
    let sink = LogSink::default();
    let _guard = capture_fmt(&sink);
    let (base, handle) = serve_and_client(test_app_missing_admin_token()).await;
    let client = reqwest::Client::new();

    let root = client.get(format!("{base}/")).send().await.unwrap();
    assert_eq!(root.status().as_u16(), 502, "`/` 无上游配置须 502");
    assert!(
        sink.line_with("route=/}").contains("method=GET"),
        "`GET /` 须记静态 route=/:\n{}",
        sink.log()
    );

    let llm = client
        .post(format!("{base}/v1/chat/completions"))
        .header("x-request-id", "llm-1")
        .json(&serde_json::json!({"model": "m"}))
        .send()
        .await
        .unwrap();
    assert_eq!(llm.status().as_u16(), 502);
    assert!(
        sink.line_with("request_id=llm-1")
            .contains("route=/{*tail}"),
        "LLM 通配路由须记静态模式:\n{}",
        sink.log()
    );

    // 管理面未启用：gate 的早期 404 仍须落在 span 内（否则该行根本不会出现）。
    let admin = client
        .get(format!("{base}/_admin/whatever"))
        .header("x-request-id", "admin-404")
        .send()
        .await
        .unwrap();
    assert_eq!(admin.status().as_u16(), 404, "管理面未启用须 404");
    let line = sink.line_with("request_id=admin-404");
    assert!(
        line.contains("route=/_admin/{*rest}"),
        "早期 404 须在 span 内且带静态 route: {line}"
    );
    handle.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn spawned_task_inherits_request_span() {
    let sink = LogSink::default();
    let _guard = capture_fmt(&sink);
    let span = tracing::error_span!(
        "http",
        request_id = %"derived",
        method = %"POST",
        route = %"/x",
    );
    async {
        crate::logging::spawn_in_request_span(async {
            tracing::warn!("waiter 落定");
        })
        .await
        .unwrap();
    }
    .instrument(span)
    .await;
    let line = sink.line_with("waiter 落定");
    assert!(
        line.contains("request_id=derived"),
        "派生任务须继承父 span: {line}"
    );
}

#[test]
fn request_id_validation_rejects_unsafe_values() {
    for value in ["", " ", "a b", "a=b", "a{b", "a\nb", &"x".repeat(65)] {
        assert!(!is_valid_request_id(value), "须拒绝 {value:?}");
    }
    for value in ["a", "abc123", "req-7", "a.b_c-9", &"y".repeat(64)] {
        assert!(is_valid_request_id(value), "须接受 {value:?}");
    }
}
