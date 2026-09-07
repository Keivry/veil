use {
    crate::{handler, service::admin, state::AppState},
    axum::{
        Router,
        routing::{any, get, post},
    },
};

pub fn build_router(state: AppState) -> Router {
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
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Config, state::SqliteOutcome},
        std::{collections::HashMap, path::PathBuf, sync::Arc},
    };

    fn test_app(extra: &[(&str, &str)]) -> Router {
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
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        )
        .with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()));
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
    async fn 七路由路径拼写与状态码() {
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

        let reg = client
            .post(format!("{base}/register-caller"))
            .json(&serde_json::json!({
                "caller_path": "/srv/job.sh",
                "caller_hash": "routehash1",
                "source": "route-test-1",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(reg.status().as_u16(), 200);

        let cred = client
            .post(format!("{base}/credential"))
            .header("X-Get-Binary-Hash", "routehashX")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&serde_json::json!({
                "auth": {"caller_hash": "routehashX", "caller_path": "/srv/other.sh"}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(cred.status().as_u16(), 200);

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
        assert_eq!(revoke.status().as_u16(), 200);

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
        assert_eq!(approve.status().as_u16(), 200);

        handle.abort();
    }

    #[tokio::test]
    async fn admin精确路由先于通配未知子路径404() {
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
    async fn admin通用限流11连击429带retry_after() {
        let (base, handle) = serve_and_client(test_app(&[])).await;
        let client = reqwest::Client::new();
        let token = "observability-admin-token-0123456789";
        for _ in 0..crate::service::admin::ADMIN_RATE_LIMIT {
            let ok = client
                .get(format!("{base}/_admin/health"))
                .header("X-Admin-Token", token)
                .send()
                .await
                .unwrap();
            assert_eq!(ok.status().as_u16(), 200);
        }
        let limited = client
            .get(format!("{base}/_admin/health"))
            .header("X-Admin-Token", token)
            .send()
            .await
            .unwrap();
        assert_eq!(limited.status().as_u16(), 429);
        assert!(limited.headers().contains_key("retry-after"));
        handle.abort();
    }

    #[tokio::test]
    async fn 网关体超限413() {
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
    async fn 限流返回429带_retry_after() {
        let (base, handle) = serve_and_client(test_app(&[])).await;
        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "auth": {"caller_hash": "rlhash1", "caller_path": "/srv/rl.sh"}
        });
        let first = client
            .post(format!("{base}/credential"))
            .header("X-Get-Binary-Hash", "rlhash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert_eq!(first.status().as_u16(), 200);
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
    async fn 默认关闭请求体除替换外字节一致() {
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
    async fn 开启改写带声明头() {
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
    async fn 非流式观测落盘可查() {
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
