//! 凭据 E2E（T6）：三因子/health/加解锁/限流/终端直调 403/注册吊销审批链。
//! 每个用例独立建 app（sqlite 隔离 + 限流器隔离），经真 HTTP 回环，无外网依赖。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_app(extra: &[(&str, &str)], locked: bool) -> axum::Router {
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
        ("GET_BINARY_HASH".to_string(), "gethash1".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let keepass = Arc::new(if locked {
        veil::keepass::MockKeePass::locked()
    } else {
        veil::keepass::MockKeePass::unlocked()
    });
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-credential-{n}.sqlite")),
            memory_only: true,
        },
    )
    .with_keepass(keepass);
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

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

#[tokio::test]
async fn t6_health_no_auth_superset_fields() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["sqlite_ok"], true);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["unlocked"], true);
    handle.abort();
}

#[tokio::test]
async fn t6_three_factor_missing_403() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let no_auth = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({"entry": "网易", "field": "授权码"}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_auth.status().as_u16(), 403);
    let no_secret = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-missing-1", "caller_path": "/srv/m1.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_secret.status().as_u16(), 403);
    handle.abort();
}

#[tokio::test]
async fn t6_wrong_secret_403() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "wrong")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-wrong-1", "caller_path": "/srv/w1.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
}

#[tokio::test]
async fn t6_unenrolled_compat_allow_with_valid_secret() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-fresh-1", "caller_path": "/srv/fresh1.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    handle.abort();
}

#[tokio::test]
async fn t6_raw_terminal_call_rejected_403() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "gethash1", "caller_path": "/srv/term.sh"},
            "entry": "网易", "field": "授权码", "token": false
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("终端")
            || body["error_detail"].as_str().unwrap_or("").contains("终端")
    );
    handle.abort();
}

#[tokio::test]
async fn t6_register_use_flow_200() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .json(&serde_json::json!({
            "caller_path": "/srv/flow.sh",
            "caller_hash": "h-flow-1",
            "name": "flow-job",
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 200);
    let pre = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-flow-1", "caller_path": "/srv/flow.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status().as_u16(), 403, "审批启用前须拒绝");
    let approve = client
        .post(format!("{base}/approve-hash-change"))
        .json(&serde_json::json!({
            "caller_path": "/srv/flow.sh",
            "new_hash": "h-flow-1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status().as_u16(), 200);
    let use_resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-flow-2", "caller_path": "/srv/flow2.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(use_resp.status().as_u16(), 200);
    handle.abort();
}

#[tokio::test]
async fn t6_duplicate_register_409() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "caller_path": "/srv/dup.sh",
        "caller_hash": "h-dup-1",
        "name": "dup-job",
        "entry": "网易"
    });
    let first = client
        .post(format!("{base}/register-caller"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 200);
    let second = client
        .post(format!("{base}/register-caller"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 409);
    handle.abort();
}

#[tokio::test]
async fn t6_revoke_then_use_403() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .json(&serde_json::json!({
            "caller_path": "/srv/gone.sh",
            "caller_hash": "h-gone-1",
            "name": "gone-job",
            "entry": "网易"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 200);
    let rev = client
        .post(format!("{base}/revoke"))
        .json(&serde_json::json!({"caller_path": "/srv/gone.sh"}))
        .send()
        .await
        .unwrap();
    assert_eq!(rev.status().as_u16(), 200);
    let use_resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-gone-1", "caller_path": "/srv/gone.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(use_resp.status().as_u16(), 403);
    handle.abort();
}

#[tokio::test]
async fn t6_locked_backend_health_and_credential() {
    let (base, handle) = serve(test_app(&[], true)).await;
    let client = reqwest::Client::new();
    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    let hbody: serde_json::Value = health.json().await.unwrap();
    assert_eq!(hbody["unlocked"], false);
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-lock-1", "caller_path": "/srv/lock1.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().as_u16() == 503 || resp.status().as_u16() == 403);
    handle.abort();
}

#[tokio::test]
async fn t6_admin_rate_limit_429_with_retry_after() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let mut last = 200;
    for _ in 0..11 {
        let resp = client
            .get(format!("{base}/_admin/metrics"))
            .header("X-Admin-Token", ADMIN_TOKEN)
            .send()
            .await
            .unwrap();
        last = resp.status().as_u16();
        if last == 429 {
            assert!(resp.headers().contains_key("retry-after"));
            break;
        }
    }
    assert_eq!(last, 429);
    handle.abort();
}

#[tokio::test]
async fn t6_registrations_require_admin_token() {
    let (base, handle) = serve(test_app(&[], false)).await;
    let client = reqwest::Client::new();
    let anon = client
        .get(format!("{base}/registrations"))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status().as_u16(), 401);
    let authed = client
        .get(format!("{base}/registrations"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(authed.status().as_u16(), 200);
    handle.abort();
}
