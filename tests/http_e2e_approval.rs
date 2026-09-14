//! 审批三语义 e2e + 单测（B8）：AUTO_APPROVE 三态、非法值拒启动、大小写变体、
//! 非 full 入口 approve 降级阻断、篡改转 pending 202。每个用例独立建 app。

use {
    common::{base_env_with, serve, test_app_router},
    veil::config::Config,
};

mod common;

fn cred_body(hash: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "auth": {"caller_hash": hash, "caller_path": path},
        "entry": "网易", "field": "授权码"
    })
}

// AUTH-4/B8.1：AUTO_APPROVE=true 也未注册者不放行——默认转审批 202。
#[tokio::test]
async fn b8_auto_approve_true_unenrolled_still_pends() {
    let (base, handle) = serve(test_app_router(&[("AUTO_APPROVE", "true")])).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/credential"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&cred_body("h-b8-true-1", "/srv/b8true.sh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 202, "未注册不得因全局默认放行");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "E_PENDING");
    handle.abort();
}

// B8.1：AUTO_APPROVE=false 未注册调用方拒绝 403。
#[tokio::test]
async fn b8_auto_approve_false_denies_unenrolled() {
    let (base, handle) = serve(test_app_router(&[("AUTO_APPROVE", "false")])).await;
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
    let (base, handle) = serve(test_app_router(&[("AUTO_APPROVE", "none")])).await;
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
    let mut bad = base_env_with(&[("AUTO_APPROVE", "bogus")]);
    assert!(Config::load_from(&bad).is_err(), "非法值须拒启动");
    bad = base_env_with(&[("AUTO_APPROVE", "TRUEE")]);
    assert!(Config::load_from(&bad).is_err(), "近似非法值须拒启动");
    for (raw, allow) in [
        ("True", true),
        ("TRUE", true),
        ("False", false),
        ("FALSE", false),
        ("None", false),
        ("NONE", false),
    ] {
        let env = base_env_with(&[("AUTO_APPROVE", raw)]);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.auto_approve == veil::config::AutoApprove::Allow,
            allow,
            "{raw}"
        );
    }
    // 对照：AuditMode 大小写敏感，大写须拒启动。
    let env = base_env_with(&[("AUDIT_MODE", "BLOCK")]);
    assert!(Config::load_from(&env).is_err(), "AuditMode 大写须拒启动");
    let env = base_env_with(&[("AUDIT_MODE", "block")]);
    assert!(Config::load_from(&env).is_ok());
}

// B8.2：非 full 入口下 approve_hash_change 降级阻断（403）且不执行变更。
#[tokio::test]
async fn b8_non_full_entry_approve_blocked_without_mutation() {
    for mode in ["credential-only", "llm-only"] {
        let (base, handle) = serve(test_app_router(&[
            ("VEIL_ENTRY_MODE", mode),
            ("AUTO_APPROVE", "false"),
        ]))
        .await;
        let client = reqwest::Client::new();
        let reg = client
            .post(format!("{base}/register-caller"))
            .header("X-Get-Binary-Hash", "gethash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&serde_json::json!({
                "caller_path": "/srv/b8deg.sh",
                "caller_hash": "h-b8-deg-A",
                "name": "b8deg-job",
                "entry": "网易",
                "field": "授权码",
                "auth": {"caller_hash": "h-b8-deg-A", "caller_path": "/srv/b8deg.sh"}
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(reg.status().as_u16(), 202, "{mode}");
        let approve = client
            .post(format!("{base}/approve-hash-change"))
            .header("X-Get-Binary-Hash", "gethash1")
            .header("X-Get-Binary-Secret", "s3cr3t")
            .json(&serde_json::json!({
                "caller_path": "/srv/b8deg.sh",
                "new_hash": "h-b8-deg-B",
                "auth": {"caller_hash": "h-b8-deg-A", "caller_path": "/srv/b8deg.sh"}
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
    let (base, handle) = serve(test_app_router(&[("AUTO_APPROVE", "none")])).await;
    let client = reqwest::Client::new();
    let reg = client
        .post(format!("{base}/register-caller"))
        .header("X-Get-Binary-Hash", "gethash1")
        .header("X-Get-Binary-Secret", "s3cr3t")
        .json(&serde_json::json!({
            "caller_path": "/srv/b8tamper.sh",
            "caller_hash": "hash-aaa-b8",
            "name": "b8tamper-job",
            "entry": "网易",
            "field": "授权码",
            "auth": {"caller_hash": "hash-aaa-b8", "caller_path": "/srv/b8tamper.sh"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reg.status().as_u16(), 202);
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
    let (base, handle) = serve(test_app_router(&[("AUTO_APPROVE", "none")])).await;
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
