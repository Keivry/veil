//! 路由装配与入口中间件。
//!
//! `build_router` 将凭据 API（`/credential`、`/registrations`、注册/吊销/哈希变更）与 LLM
//! 代理通配路由（`/{*tail}` + fallback）及 `/_admin` 管理面装配到同一 `Router`；
//! `observability_gate` 中间件按 `OBSERVABILITY_DISABLE` 对 `/_admin*` 全返回 `404`
//! （与 token 有效性无关）。入口三态与监听端口语义见 `src/main.rs` 与 README §1。

use {
    crate::{
        handler::{self, admin},
        service::credential::AppStateParts,
        state::AppState,
    },
    axum::{
        Json,
        Router,
        extract::{Request, State},
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{any, get, post},
    },
    serde_json::json,
};

async fn observability_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.config().observability_disabled && req.uri().path().starts_with("/_admin") {
        // OPS/E-3：禁用期 404 复用管理面统一安全头（五项通用头，不泄露
        // 管理面存在性；与 `admin_not_found` 同语义）。
        return admin::with_security_headers(
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": {"code": "E_NOT_FOUND", "message": "管理面已禁用"}})),
            )
                .into_response(),
        );
    }
    next.run(req).await
}

pub fn build_router(state: AppState) -> Router {
    if state.config().observability_disabled {
        tracing::warn!("OBSERVABILITY_DISABLE=1：管理面已禁用，/_admin 全返回 404");
    }
    Router::new()
        .route("/_admin/", get(admin::admin_index))
        .route("/_admin", get(admin::admin_index))
        .route("/_admin/health", get(admin::admin_health))
        .route("/_admin/metrics", get(admin::admin_metrics))
        .route("/_admin/series", get(admin::admin_series))
        .route("/_admin/events", get(admin::admin_events))
        .route("/_admin/events/stream", get(admin::admin_events_stream))
        .route("/_admin/{*rest}", any(admin::admin_not_found))
        .route("/health", get(handler::health_handler))
        .route("/credential", post(handler::credential_handler))
        .route("/registrations", get(handler::registrations_handler))
        .route("/register-caller", post(handler::register_caller_handler))
        .route("/revoke", post(handler::revoke_handler))
        .route("/revoke/emergency", post(handler::emergency_revoke_handler))
        .route(
            "/approve-hash-change",
            post(handler::approve_hash_change_handler),
        )
        .route("/{*tail}", any(handler::llm_proxy_handler))
        .fallback(handler::llm_proxy_handler)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            observability_gate,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
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
            ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
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
            .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked())),
            InjectSink::success(),
        );
        (build_router(state.clone()), state)
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
            .header("X-Get-Binary-Secret", "s3cr3t")
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
            .header("X-Get-Binary-Hash", "routehashX")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&serde_json::json!({
                "auth": {"caller_hash": "routehashX", "caller_path": "/srv/other.sh"},
                "entry": "网易",
                "field": "授权码"
            }))
            .send()
            .await
            .unwrap();
        // AUTH-4：未注册 `/credential` 默认转审批（202），不再兼容放行。
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
        // AUTH-1/AUTH-3：三写端点未鉴权一律非 2xx，且不落任何动作。
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
        assert_eq!(body["routes"].as_array().unwrap().len(), 6);

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
    async fn credential_rate_limit_returns_429_with_retry_after() {
        let (base, handle) = serve_and_client(test_app(&[])).await;
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "auth": {"caller_hash": "rlhash1", "caller_path": "/srv/rl.sh"},
            "entry": "网易",
            "field": "授权码"
        });
        let first = client
            .post(format!("{base}/credential"))
            .header("X-Get-Binary-Hash", "rlhash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(first.status().as_u16(), 202, "AUTH-4：未注册转审批");
        let second = client
            .post(format!("{base}/credential"))
            .header("X-Get-Binary-Hash", "rlhash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(second.status().as_u16(), 429);
        assert!(second.headers().contains_key("retry-after"));
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
                    "get_binary_hash": "gohash9",
                    "get_binary_secret": "s3cr3t"
                },
                "entry": "网易",
                "field": "授权码"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(go_ok.status().as_u16(), 202, "AUTH-4：未注册转审批");

        let no_entry = client
            .post(format!("{base}/credential"))
            .header("X-Get-Binary-Hash", "gohash9")
            .header("X-Get-Binary-Secret", "s3cr3t")
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
        // H1/D3 E2E：JSON 请求体脱敏重序列化 → 下游响应含 `x-veil-normalized`;
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
        // GO/D8.3：Go 形态请求（`name/script_path/script_hash/entries/allow_mode`）
        // 注册成功；响应提供加性超集（顶层 + `registration` 内可解析），
        // 既有字段不删、重名 409 语义不变。C1/D1：注册经审批链，阻塞模式下批准后返回。
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
                .header("X-Get-Binary-Secret", "s3cr3t")
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
            .header("X-Get-Binary-Secret", "s3cr3t")
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
}
