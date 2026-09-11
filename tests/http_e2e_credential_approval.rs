//! F1/T1 凭据审批双模 e2e（HTTP 层，真回环）：
//! 默认 `202 + E_PENDING` 不挂起、阻塞模式批准同请求返回凭据、阻塞模式超时按拒绝、
//! 客户端早断连幂等。每个用例独立建 app/state；测试内缩短审批超时（不真等 `300`s）。
//!
//! 与单测口径的分工：`src/service/credential/approval.rs` 已覆盖服务层双模；
//! 本文件补 HTTP 线级（状态码/响应体/挂起行为）与断连幂等。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
        time::{Duration, Instant},
    },
    veil::{
        config::Config,
        router::build_router,
        service::matrix::ResolveOutcome,
        state::{AppState, SqliteOutcome},
    },
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

const ADMIN_TOKEN: &str = "observability-admin-token-0123456789";
const WHITELIST: &str = "@admin:example.com";

fn base_env(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut env = HashMap::from([
        (
            "HOMESERVER".to_string(),
            "https://matrix.example.com".to_string(),
        ),
        ("ROOM_ID".to_string(), "!r:example.com".to_string()),
        ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
        (
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            ADMIN_TOKEN.to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
        ("GET_BINARY_HASH".to_string(), "gethash1".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    env
}

/// 建 state 与 router 并回传 state 句柄（pending/审批表经句柄可查，供 e2e 断言）。
/// `cfg_mut` 供测试注入缩短的审批超时（默认装配为 `300`s，禁止真等）。
fn test_app(extra: &[(&str, &str)], cfg_mut: impl FnOnce(&mut Config)) -> (axum::Router, AppState) {
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let mut cfg = Config::load_from(&base_env(extra)).unwrap();
    cfg_mut(&mut cfg);
    let state = AppState::new(
        cfg,
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-cred-block-{n}.sqlite")),
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    (build_router(state.clone()), state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

fn cred_body(hash: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "auth": {"caller_hash": hash, "caller_path": path},
        "entry": "网易", "field": "授权码"
    })
}

/// 1.3：默认 `202 + E_PENDING`——未决审批下立即返回、同请求不挂起、pending 建单可查。
#[tokio::test]
async fn default_202_pending_returns_immediately_with_ticket() {
    let (app, state) = test_app(&[("AUTO_APPROVE", "none")], |_| {});
    let (base, handle) = serve(app).await;
    // 客户端硬超时 2s：若网关同请求挂起等待审批，请求将超时报错而非 202。
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let start = Instant::now();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-t13-1", "/srv/t13.sh"))
        .send()
        .await
        .expect("默认模式不得挂起（须立即 202）");
    let elapsed = start.elapsed();
    assert_eq!(resp.status().as_u16(), 202);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_PENDING", "实际: {body}");
    assert!(
        elapsed < Duration::from_secs(1),
        "同请求不得阻塞等审批，墙钟须秒级内返回，实际 {elapsed:?}"
    );
    // pending 建单可查：服务层 pending 表 + 审批网关待决表各一条（键为 caller_path:caller_hash）。
    assert_eq!(state.pending.len(), 1);
    assert!(
        state.pending.get("/srv/t13.sh:h-t13-1").is_some(),
        "pending 建单须可按调用方键查询"
    );
    assert_eq!(
        state.approval.pending_len().await,
        1,
        "审批网关须待决恰一单"
    );
    handle.abort();
}

/// 等阻塞模式建单（审批事件 id），超时即失败。
async fn wait_pending_event(state: &AppState) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(id) = state.approval.pending_event_ids().await.into_iter().next() {
            return id;
        }
        assert!(Instant::now() < deadline, "阻塞模式须先建单");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn blocking_env() -> [(&'static str, &'static str); 3] {
    [
        ("AUTO_APPROVE", "none"),
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", WHITELIST),
    ]
}

/// 1.4（批准路径）：阻塞模式批准后同请求返回 `__VG_CRED_` 凭据（无 `202`）。
#[tokio::test]
async fn block_wait_approve_returns_credential_same_request() {
    let (app, state) = test_app(&blocking_env(), |_| {});
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let base_for_req = base.clone();
    let req = tokio::spawn(async move {
        client
            .post(format!("{base_for_req}/credential"))
            .header("X-Get-Binary-Hash", "gethash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&cred_body("h-t14-a", "/srv/t14a.sh"))
            .send()
            .await
    });
    // 请求挂起期间由审批侧批准（HTTP 线已发出且服务端已建单）。
    let event_id = wait_pending_event(&state).await;
    assert_eq!(
        state.approval.resolve(&event_id, WHITELIST, true).await,
        ResolveOutcome::Applied(true)
    );
    let resp = tokio::time::timeout(Duration::from_secs(5), req)
        .await
        .expect("批准后同请求须返回，不得悬挂")
        .expect("任务不崩")
        .expect("HTTP 请求不失败");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "阻塞模式批准须同请求返回凭据（无 202）"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let value = body["credential"]["value"].as_str().unwrap_or("");
    assert!(value.starts_with("__VG_CRED_"), "须返回凭据占位: {body}");
    handle.abort();
}

/// 1.4（超时路径）：测试内缩短审批超时（1s，不真等 `300`s），
/// 超时按拒绝口径返回且清理待决单（无悬挂任务残留）。
#[tokio::test]
async fn block_wait_timeout_rejects_without_hanging() {
    let (app, state) = test_app(&blocking_env(), |cfg| {
        cfg.credential_approval_timeout_secs = 1;
    });
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let start = Instant::now();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-t14-t", "/srv/t14t.sh"))
        .send()
        .await
        .expect("超时路径须有响应，不得悬挂");
    let elapsed = start.elapsed();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "超时按拒绝口径（design D1；Python `_credential.py:433`）"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_AUTH", "实际: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("超时"),
        "须指明超时按拒绝: {body}"
    );
    assert!(
        elapsed >= Duration::from_millis(900),
        "须经注入的 1s 超时等待，实际 {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "不得真等 300s，实际 {elapsed:?}"
    );
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "超时须清理待决单，无悬挂任务残留"
    );
    handle.abort();
}

/// 5.3：客户端早断连幂等——请求 future 提前 drop 后，
/// 待决单可清理、批准不 panic、重复触发幂等（补凭据侧对应覆盖）。
#[tokio::test]
async fn early_disconnect_pending_cleanup_and_idempotent_resolve() {
    let (app, state) = test_app(&blocking_env(), |cfg| {
        cfg.credential_approval_timeout_secs = 5;
    });
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let base_for_req = base.clone();
    let req = tokio::spawn(async move {
        client
            .post(format!("{base_for_req}/credential"))
            .header("X-Get-Binary-Hash", "gethash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&cred_body("h-t53", "/srv/t53.sh"))
            .send()
            .await
    });
    let event_id = wait_pending_event(&state).await;
    // 客户端提前断连：请求 future 被 drop（连接关闭）。
    req.abort();
    assert!(req.await.unwrap_err().is_cancelled());
    // 断连后审批侧批准不 panic，重复触发幂等不重复落定。
    assert_eq!(
        state.approval.resolve(&event_id, WHITELIST, true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        state.approval.resolve(&event_id, WHITELIST, true).await,
        ResolveOutcome::Duplicate
    );
    // 已决单可清理；清理后重复触发仍幂等（无精确匹配，不 panic）。
    assert!(state.approval.forget_decided().await >= 1);
    assert_eq!(
        state.approval.pending_len().await,
        0,
        "断连后不得残留待决单"
    );
    assert_eq!(
        state.approval.resolve(&event_id, WHITELIST, true).await,
        ResolveOutcome::Ignored("event id 无精确匹配")
    );
    // 服务未被断连拖垮：健康检查仍 200（无资源耗尽挂死）。
    let health = reqwest::get(format!("{base}/health")).await.unwrap();
    assert_eq!(health.status().as_u16(), 200);
    handle.abort();
}
