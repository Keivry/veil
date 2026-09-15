//! T-M4 vault 稳定 e2e（`veil-review-followup-test-gap` T3.2）：
//! 凭据表 LRU 逐出 + 容量分表 5000/1000 回归。HTTP 层走注册取用全链路，
//! 逐出语义经同二进制 `CredentialVault` 大容量断言（与单测同口径）。

use {
    common::{serve, test_app},
    veil::service::{credential::AppStateParts, credential_vault::MAX_TOKEN_ENTRIES},
};

mod common;

#[tokio::test]
async fn t3_2_vault_backed_credential_flow_e2e() {
    // vault 承载的注册取用全链路：注册 202 → 审批启用 → 取用 200。
    let (app, state) = test_app(common::TestOpts::default());
    let (base, handle) = serve(app).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/vault-flow.sh",
            "caller_hash": "h-vault-flow-1",
            "name": "vault-flow-job",
            "entry": "网易", "field": "授权码",
            "auth": {"caller_hash": "h-vault-flow-1", "caller_path": "/srv/vault-flow.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202, "C1：注册默认转审批");
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
    // CRD-4：注册审批 ✅ 启用条目（哈希变更落定不再激活既有条目）。
    let event_id = wait_new_event_id(&state).await;
    state
        .approval
        .resolve(&event_id, "@admin:example.com", true)
        .await;
    wait_until_enabled(&state, "/srv/vault-flow.sh").await;
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
    let (_app, state) = test_app(common::TestOpts::default());
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

async fn wait_new_event_id(state: &veil::state::AppState) -> String {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(id) = state.approval.pending_event_ids().await.into_iter().next() {
            return id;
        }
        assert!(tokio::time::Instant::now() < deadline, "审批建单超时");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn wait_until_enabled(state: &veil::state::AppState, path: &str) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if state
            .registry
            .read()
            .await
            .lookup_by_path(path)
            .is_some_and(|e| e.enabled)
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "注册审批启用超时: {path}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
