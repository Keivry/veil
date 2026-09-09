//! 审批三语义 e2e + 单测（B8）：AUTO_APPROVE 三态、非法值拒启动、大小写变体、
//! 非 full 入口 approve 降级阻断、篡改转 pending 202。每个用例独立建 app。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{config::Config, router::build_router, state::SqliteOutcome},
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

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
            "observability-admin-token-0123456789".to_string(),
        ),
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
        ("GET_BINARY_HASH".to_string(), "gethash1".to_string()),
    ]);
    for (k, v) in extra {
        env.insert((*k).to_string(), (*v).to_string());
    }
    env
}

fn test_app(extra: &[(&str, &str)]) -> axum::Router {
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let state = veil::state::AppState::new(
        Config::load_from(&base_env(extra)).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-approval-{n}.sqlite")),
            memory_only: true,
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
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

fn cred_body(hash: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "auth": {"caller_hash": hash, "caller_path": path},
        "entry": "网易", "field": "授权码"
    })
}

// B8.1：AUTO_APPROVE=true 未注册调用方放行 200。
#[tokio::test]
async fn b8_auto_approve_true_allows_unenrolled() {
    let (base, handle) = serve(test_app(&[("AUTO_APPROVE", "true")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-b8-true-1", "/srv/b8true.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    handle.abort();
}

// B8.1：AUTO_APPROVE=false 未注册调用方拒绝 403。
#[tokio::test]
async fn b8_auto_approve_false_denies_unenrolled() {
    let (base, handle) = serve(test_app(&[("AUTO_APPROVE", "false")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-b8-false-1", "/srv/b8false.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    handle.abort();
}

// B8.1：AUTO_APPROVE=none 未注册调用方转 Matrix 审批 202。
#[tokio::test]
async fn b8_auto_approve_none_pends_unenrolled() {
    let (base, handle) = serve(test_app(&[("AUTO_APPROVE", "none")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-b8-none-1", "/srv/b8none.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    handle.abort();
}

// B8.1：非法值拒启动（不断言放行）；大小写变体与 AuditMode 大小写敏感对照。
#[test]
fn b8_auto_approve_invalid_rejects_startup_and_case_variants() {
    let mut bad = base_env(&[("AUTO_APPROVE", "bogus")]);
    assert!(Config::load_from(&bad).is_err(), "非法值须拒启动");
    bad = base_env(&[("AUTO_APPROVE", "TRUEE")]);
    assert!(Config::load_from(&bad).is_err(), "近似非法值须拒启动");
    for (raw, allow) in [
        ("True", true),
        ("TRUE", true),
        ("False", false),
        ("FALSE", false),
        ("None", false),
        ("NONE", false),
    ] {
        let env = base_env(&[("AUTO_APPROVE", raw)]);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.auto_approve == veil::config::AutoApprove::Allow,
            allow,
            "{raw}"
        );
    }
    // 对照：AuditMode 大小写敏感，大写须拒启动。
    let env = base_env(&[("AUDIT_MODE", "BLOCK")]);
    assert!(Config::load_from(&env).is_err(), "AuditMode 大写须拒启动");
    let env = base_env(&[("AUDIT_MODE", "block")]);
    assert!(Config::load_from(&env).is_ok());
}

// B8.2：非 full 入口下 approve_hash_change 降级阻断（403）且不执行变更。
#[tokio::test]
async fn b8_non_full_entry_approve_blocked_without_mutation() {
    for mode in ["credential-only", "llm-only"] {
        let (base, handle) = serve(test_app(&[
            ("VEIL_ENTRY_MODE", mode),
            ("AUTO_APPROVE", "false"),
        ]))
        .await;
        let client = reqwest::Client::new();
        let reg = client
            .post(format!("{base}/register-caller"))
            .json(&serde_json::json!({
                "caller_path": "/srv/b8deg.sh",
                "caller_hash": "h-b8-deg-A",
                "name": "b8deg-job",
                "entry": "网易",
                "field": "授权码"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(reg.status().as_u16(), 200, "{mode}");
        let approve = client
            .post(format!("{base}/approve-hash-change"))
            .json(&serde_json::json!({
                "caller_path": "/srv/b8deg.sh",
                "new_hash": "h-b8-deg-B"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(approve.status().as_u16(), 403, "{mode} 下须降级阻断");
        // 未执行变更（credential-only 下验证：同一 vault_ops 入口门覆盖全部非 full 模式）：
        // 新哈希仍走篡改分支转审批 202，而非匹配后拒绝 403。
        if mode == "credential-only" {
            let use_b = client
                .post(format!("{base}/credential"))
                .header("X-Get-Binary-Hash", "gethash1")
                .header("X-Get-Binary-Secret", "s3cr3t")
                .json(&cred_body("h-b8-deg-B", "/srv/b8deg.sh"))
                .send()
                .await
                .unwrap();
            assert_eq!(use_b.status().as_u16(), 202, "{mode} 下变更须未生效");
        }
        handle.abort();
    }
}

// B8.2：已注册篡改哈希返回 202 建单 pending。
#[tokio::test]
async fn b8_enrolled_tamper_turns_to_pending_202() {
    let (base, handle) = serve(test_app(&[("AUTO_APPROVE", "none")])).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .json(&serde_json::json!({
            "caller_path": "/srv/b8tamper.sh",
            "caller_hash": "hash-aaa-b8",
            "name": "b8tamper-job",
            "entry": "网易",
            "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 200);
    let cred = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("hash-bbb-tampered", "/srv/b8tamper.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(cred.status().as_u16(), 202);
    handle.abort();
}

// B8.2 边缘：未注册未知哈希在 none 下同样 pending（202），不直接拒绝。
#[tokio::test]
async fn b8_unenrolled_unknown_hash_pends_not_rejected() {
    let (base, handle) = serve(test_app(&[("AUTO_APPROVE", "none")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-b8-unknown-tamper", "/srv/b8unknown.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202);
    handle.abort();
}
