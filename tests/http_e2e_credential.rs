//! 凭据 E2E（T6）：三因子/health/加解锁/限流/终端直调 403/注册吊销审批链。
//! 每个用例独立建 app（sqlite 隔离 + 限流器隔离），经真 HTTP 回环，无外网依赖。

use common::{TestOpts, serve, test_app, test_app_router};

mod common;

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";

#[tokio::test]
async fn t6_health_no_auth_superset_fields() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
async fn t6_unenrolled_defaults_to_pending() {
    // AUTH-4：未注册调用方默认转审批（202 + E_PENDING），不再兼容放行。
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
    assert_eq!(resp.status().as_u16(), 202);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_PENDING");
    handle.abort();
}

#[tokio::test]
async fn t6_raw_terminal_call_rejected_403() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/flow.sh",
            "caller_hash": "h-flow-1",
            "name": "flow-job",
            "entry": "网易", "field": "授权码",
            "auth": {"caller_hash": "h-flow-1", "caller_path": "/srv/flow.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202, "C1：注册默认转审批");
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
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/flow.sh",
            "new_hash": "h-flow-1",
            "auth": {"caller_hash": "h-flow-1", "caller_path": "/srv/flow.sh"}
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
            "auth": {"caller_hash": "h-flow-1", "caller_path": "/srv/flow.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(use_resp.status().as_u16(), 200, "批准后已注册调用方须可用");
    // TST-1 负例：审批仅对同一 caller 闭环生效——未注册 caller 不得借用他人审批放行。
    let other = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-flow-neg-1", "caller_path": "/srv/flow-neg.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_ne!(
        other.status().as_u16(),
        200,
        "未注册 caller 不得借用他人审批闭环放行（TST-1 负例）"
    );
    handle.abort();
}

#[tokio::test]
async fn t6_duplicate_register_409() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
    let client = reqwest::Client::new();
    let payload = serde_json::json!({
        "caller_path": "/srv/dup.sh",
        "caller_hash": "h-dup-1",
        "name": "dup-job",
        "entry": "网易",
        "auth": {"caller_hash": "h-dup-1", "caller_path": "/srv/dup.sh"}
    });
    let first = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 202);
    let second = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 409);
    handle.abort();
}

#[tokio::test]
async fn t6_revoke_then_use_403() {
    // C2：常规吊销经审批——批准前条目保持可用，批准后 `revoked` 生效。
    let (app, state) = test_app(TestOpts::from(&[(
        "APPROVAL_WHITELIST",
        "@admin:example.com",
    )]));
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/gone.sh",
            "caller_hash": "h-gone-1",
            "name": "gone-job",
            "entry": "网易",
            "auth": {"caller_hash": "h-gone-1", "caller_path": "/srv/gone.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202);
    let enable = client
        .post(format!("{base}/approve-hash-change"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/gone.sh",
            "new_hash": "h-gone-1",
            "auth": {"caller_hash": "h-gone-1", "caller_path": "/srv/gone.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(enable.status().as_u16(), 200);
    let cred_body = serde_json::json!({
        "auth": {"caller_hash": "h-gone-1", "caller_path": "/srv/gone.sh"},
        "entry": "网易", "field": "授权码"
    });
    let before = state.approval.pending_event_ids().await;
    let rev = client
        .post(format!("{base}/revoke"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/gone.sh",
            "auth": {"caller_hash": "h-gone-1", "caller_path": "/srv/gone.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rev.status().as_u16(), 202, "常规吊销须转审批");
    let use_before = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body)
        .send()
        .await
        .unwrap();
    assert_eq!(use_before.status().as_u16(), 200, "批准前条目保持原状");
    let event_id = wait_new_event_id(&state, &before).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_until_revoked(&state, "/srv/gone.sh").await;
    let use_resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body)
        .send()
        .await
        .unwrap();
    assert_eq!(use_resp.status().as_u16(), 403, "批准吊销后取用须拒绝");
    handle.abort();
}

async fn wait_new_event_id(state: &veil::state::AppState, before: &[String]) -> String {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let ids = state.approval.pending_event_ids().await;
        if let Some(id) = ids.into_iter().find(|id| !before.contains(id)) {
            return id;
        }
        assert!(tokio::time::Instant::now() < deadline, "审批建单超时");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn wait_until_revoked(state: &veil::state::AppState, path: &str) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if state
            .registry
            .read()
            .await
            .lookup_by_path(path)
            .is_some_and(|e| e.revoked)
        {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "吊销落定超时");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn t6_locked_backend_health_and_credential() {
    let (app, state) = test_app(TestOpts::default().locked(true));
    let (base, handle) = serve(app).await;
    common::enroll_allow(&state, "/srv/lock1.sh", "h-lock-1").await;
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
    assert_eq!(resp.status().as_u16(), 503, "已注册调用方在锁定后端须 503");
    handle.abort();
}

#[tokio::test]
async fn t6_admin_rate_limit_429_with_retry_after() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
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

// C5：未吊销重名注册 409（与既有 `t6_duplicate_register_409` 的 path 判重区分）。
#[tokio::test]
async fn t6_register_duplicate_name_409() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
    let client = reqwest::Client::new();
    let first = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/name1.sh",
            "caller_hash": "h-name-1",
            "name": "named-job",
            "entry": "网易",
            "auth": {"caller_hash": "h-name-1", "caller_path": "/srv/name1.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 202);
    let second = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/name2.sh",
            "caller_hash": "h-name-2",
            "name": "named-job",
            "entry": "网易",
            "auth": {"caller_hash": "h-name-2", "caller_path": "/srv/name2.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 409, "未吊销重名注册须 409");
    handle.abort();
}

// C5：`{"name":...}` 按名吊销命中，且吊销后同名可复用。
#[tokio::test]
async fn t6_revoke_by_name_and_reuse() {
    let (app, state) = test_app(TestOpts::from(&[(
        "APPROVAL_WHITELIST",
        "@admin:example.com",
    )]));
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/byname-a.sh",
            "caller_hash": "h-byname-a",
            "name": "check-mail",
            "source": "e2e-byname-a",
            "entry": "网易",
            "auth": {"caller_hash": "h-byname-a", "caller_path": "/srv/byname-a.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202);
    let enable = client
        .post(format!("{base}/approve-hash-change"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/byname-a.sh",
            "new_hash": "h-byname-a",
            "auth": {"caller_hash": "h-byname-a", "caller_path": "/srv/byname-a.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(enable.status().as_u16(), 200);
    let before = state.approval.pending_event_ids().await;
    let rev = client
        .post(format!("{base}/revoke"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "name": "check-mail",
            "auth": {"caller_hash": "h-byname-a", "caller_path": "/srv/byname-a.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rev.status().as_u16(), 202, "按名吊销须转审批");
    let event_id = wait_new_event_id(&state, &before).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_until_revoked(&state, "/srv/byname-a.sh").await;
    let reuse = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/byname-b.sh",
            "caller_hash": "h-byname-b",
            "name": "check-mail",
            "source": "e2e-byname-b",
            "entry": "网易",
            "auth": {"caller_hash": "h-byname-b", "caller_path": "/srv/byname-b.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reuse.status().as_u16(), 202, "吊销后同名须可复用");
    handle.abort();
}

// C15：`/credential` 成功信封形状锁定 `{"ok":true,"credential":{...}}`（README §5）。
#[tokio::test]
async fn t6_credential_envelope_ok_credential() {
    let (app, state) = test_app(TestOpts::default());
    let (base, handle) = serve(app).await;
    common::enroll_allow(&state, "/srv/env1.sh", "h-env-1").await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-env-1", "caller_path": "/srv/env1.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true, "成功信封须含 ok=true");
    assert!(
        body["credential"].is_object(),
        "成功信封须含 credential 对象"
    );
    assert!(
        body["credential"]["value"].is_string(),
        "credential.value 须为字符串"
    );
    handle.abort();
}

// C16：三因子双必填口径——缺 `caller_path` 或缺 `caller_hash` 各 403（有意收紧，README §6.8）。
#[tokio::test]
async fn t6_caller_path_required_403() {
    let (base, handle) = serve(test_app_router(TestOpts::default())).await;
    let client = reqwest::Client::new();
    let no_path = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_hash": "h-nopath-1"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_path.status().as_u16(), 403, "缺 caller_path 须 403");
    let no_hash = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "auth": {"caller_path": "/srv/nohash.sh"},
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_hash.status().as_u16(), 403, "缺 caller_hash 须 403");
    handle.abort();
}
