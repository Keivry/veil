//! T-M4 vault 稳定 e2e（`veil-review-followup-test-gap` T3.2）：
//! 凭据表 LRU 逐出 + 容量分表 5000/1000 回归。HTTP 层走注册取用全链路，
//! 逐出语义经同二进制 `CredentialVault` 大容量断言（与单测同口径）。

use {
    std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, atomic::AtomicU64},
    },
    veil::{
        config::Config,
        router::build_router,
        service::{credential::AppStateParts, credential_vault::MAX_TOKEN_ENTRIES},
        state::SqliteOutcome,
    },
};

static APP_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_app() -> (axum::Router, veil::state::AppState) {
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
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
        ("GET_BINARY_HASH".to_string(), "gethash1".to_string()),
    ]);
    let n = APP_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let state = veil::state::AppState::new(
        Config::load_from(&env).unwrap(),
        SqliteOutcome {
            sqlite_ok: true,
            sqlite_error: None,
            db_path: PathBuf::from(format!("/tmp/veil-e2e-vault-{n}.sqlite")),
            memory_only: true,
        },
    )
    .with_keepass(Arc::new(veil::keepass::MockKeePass::unlocked()));
    let router = build_router(state.clone());
    (router, state)
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn t3_2_vault_backed_credential_flow_e2e() {
    // vault 承载的注册取用全链路：注册 200 → 取用 200。
    let (app, _state) = test_app();
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .json(&serde_json::json!({
            "caller_path": "/srv/vault-flow.sh",
            "caller_hash": "h-vault-flow-1",
            "name": "vault-flow-job",
            "entry": "网易", "field": "授权码"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 200);
    let cred_body = serde_json::json!({
        "auth": {"caller_hash": "h-vault-flow-1", "caller_path": "/srv/vault-flow.sh"},
        "entry": "网易", "field": "授权码"
    });
    let pre = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body)
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status().as_u16(), 403, "审批启用前须拒绝");
    let approve = client
        .post(format!("{base}/approve-hash-change"))
        .json(&serde_json::json!({
            "caller_path": "/srv/vault-flow.sh",
            "new_hash": "h-vault-flow-1"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status().as_u16(), 200);
    let cred = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body)
        .send()
        .await
        .unwrap();
    assert_eq!(cred.status().as_u16(), 200);
    handle.abort();
}

#[tokio::test]
async fn t3_2_vault_lru_eviction_and_capacity_split() {
    // 容量分表锁定：凭据 5000 / PII 请求响应单表 1000。
    assert_eq!(MAX_TOKEN_ENTRIES, 5000, "凭据表容量分表锁定");
    assert_eq!(
        veil::service::pii::PII_MAX_ENTRIES,
        1000,
        "PII 单表容量分表锁定"
    );
    // LRU 逐出：同二进制 vault 批量注册至溢出，最久未用优先淘汰、热点保留。
    let (_app, state) = test_app();
    let vault = state.vault().clone();
    let val = |i: usize| format!("t3-vault-value-{i:06}-padding-ok");
    let mut first_tokens = Vec::new();
    for i in 0..MAX_TOKEN_ENTRIES {
        first_tokens.push(vault.register(&val(i)).unwrap());
    }
    assert_eq!(vault.len(), MAX_TOKEN_ENTRIES);
    // 触达最早条目提升为热点，再溢出 5 条。
    assert_eq!(vault.register(&val(0)).unwrap(), first_tokens[0]);
    for i in 0..5 {
        vault.register(&val(MAX_TOKEN_ENTRIES + i)).unwrap();
    }
    assert_eq!(vault.len(), MAX_TOKEN_ENTRIES, "溢出后条数恒封顶");
    // 热点保留：val(0) 复用返回同一 token。
    assert_eq!(
        vault.register(&val(0)).unwrap(),
        first_tokens[0],
        "热点须驻留"
    );
    // 冷淘汰：val(1..5) 已逐出，重注册得新 token。
    for (i, first) in first_tokens.iter().enumerate().skip(1).take(4) {
        let again = vault.register(&val(i)).unwrap();
        assert_ne!(again, *first, "冷条目 val({i}) 须已被 LRU 逐出");
    }
}
