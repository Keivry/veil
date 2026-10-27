use {
    super::*,
    crate::{
        error::VeilError,
        service::credential::{
            AuthBlock,
            CredentialBody,
            CredentialHeaders,
            register_caller,
            revoke_caller,
            test_support::*,
        },
    },
    axum::response::IntoResponse as _,
};

#[tokio::test]
async fn unenrolled_defaults_to_pending() {
    // 未注册调用方默认转审批（202 + E_PENDING），不返回凭据。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("callerhash1", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(err.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1, "未注册须建审批单");
}

#[tokio::test]
async fn enrolled_explicit_allow_still_passes() {
    // 已注册且显式放行（allow_mode=Allow）行为不变，直接返回凭据。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    crate::service::credential::vault_ops::register_caller_extended(
        &state,
        &crate::registry::RegisterParams {
            caller_path: "/s/allow.sh".to_string(),
            caller_hash: "allowhash".to_string(),
            entries: entries_for("网易", &["授权码"]),
            allow_mode: Some(AutoApprove::Allow),
            ..Default::default()
        },
        "allow-src",
    )
    .await
    .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/allow.sh", true)
        .unwrap();
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("allowhash", "/s/allow.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn missing_any_factor_returns_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("gethash", None),
        &body("callerhash1", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    let err2 = handle_credential(
        &state,
        &headers("", Some("s3cr3t")),
        &body("callerhash1", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err2.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn forged_secret_rejected_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("gethash", Some("wrong")),
        &body("callerhash1", "/s/a.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn body_secret_compat_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/b.sh", "callerhash2").await;
    let out = handle_credential(
        &state,
        &headers("gethash", None),
        &body("callerhash2", "/s/b.sh", Some("s3cr3t")),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn spoofed_get_own_hash_rejected_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let mut raw = body("gethash", "/s/a.sh", None);
    raw.token = Some(false);
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &raw)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approval_three_messages_each_asserted() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    // 已注册：重复注册冲突文案。
    register_caller(&state, "/s/dup.sh", "h-dup", "src-dup")
        .await
        .unwrap();
    let dup = register_caller(&state, "/s/dup.sh", "h-dup2", "src-dup")
        .await
        .unwrap_err();
    assert!(
        dup.to_string().contains("调用方已注册"),
        "已注册文案: {dup}"
    );
    // 未注册：吊销缺条目文案。
    let missing = revoke_caller(&state, "/s/never.sh").await.unwrap_err();
    assert!(
        missing.to_string().contains("调用方不存在"),
        "未注册文案: {missing}"
    );
    // 终端直调：原文请求拒绝文案。
    let mut raw = body("gethash", "/s/a.sh", None);
    raw.token = Some(false);
    let direct = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &raw)
        .await
        .unwrap_err();
    match direct {
        VeilError::Auth { message } => assert!(
            message.contains("不允许终端直接调用"),
            "终端直调文案: {message}"
        ),
        other => panic!("须为鉴权拒绝，实得: {other:?}"),
    }
}

#[tokio::test]
async fn go_body_alias_without_headers_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/go.sh", "gohash1").await;
    let body = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: Some("gohash1".to_string()),
            caller_path: Some("/s/go.sh".to_string()),
            veilctl_binary_hash: Some("gethash".to_string()),
            veilctl_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &body)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn go_body_alias_wrong_secret_still_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let body = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: Some("gohash2".to_string()),
            caller_path: Some("/s/go2.sh".to_string()),
            veilctl_binary_hash: Some("gethash".to_string()),
            veilctl_secret: Some("wrong".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let err = handle_credential(&state, &CredentialHeaders::new(None, None), &body)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn three_factor_body_auth_fallback() {
    // 头缺失时回退读取 `body.auth.veilctl_binary_hash`/`veilctl_secret`
    //（Go 存量 `CredentialBody` 形态），按三因子语义放行；
    // 仅缺 caller 字段时返回 403「body.auth.caller_hash/caller_path 必填」。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/go-fallback.sh", "gohash-fallback").await;
    let go_body = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: Some("gohash-fallback".to_string()),
            caller_path: Some("/s/go-fallback.sh".to_string()),
            veilctl_binary_hash: Some("gethash".to_string()),
            veilctl_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &go_body)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
    let no_caller = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: None,
            caller_path: None,
            veilctl_binary_hash: Some("gethash".to_string()),
            veilctl_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let err = handle_credential(&state, &CredentialHeaders::new(None, None), &no_caller)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    match err {
        VeilError::Auth { message } => assert!(
            message.contains("body.auth.caller_hash/caller_path 必填"),
            "缺 caller 因子文案: {message}"
        ),
        other => panic!("须为鉴权拒绝: {other:?}"),
    }
}

#[tokio::test]
async fn missing_entry_returns_400_with_hint() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let mut missing = body("entryless", "/s/none.sh", None);
    missing.entry = None;
    missing.field = None;
    missing.fields = None;
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &missing)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert!(err.to_string().contains("entry"));
}

#[tokio::test]
async fn missing_field_returns_whole_entry() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/nof.sh", "nofield").await;
    let mut full = body("nofield", "/s/nof.sh", None);
    full.field = None;
    full.fields = None;
    let out = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &full)
        .await
        .unwrap();
    assert_eq!(out.get("title").and_then(|v| v.as_str()), Some("网易"));
    assert!(
        out.get("password")
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.starts_with("__CRED_"))
    );
    assert!(out.get("custom_properties").is_some());
}

#[tokio::test]
async fn plural_fields_form_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/p.sh", "plural1").await;
    let mut plural = body("plural1", "/s/p.sh", None);
    plural.field = None;
    plural.fields = Some(serde_json::json!(["授权码"]));
    let out = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &plural)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn false_token_returns_raw_value() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/raw.sh", "raw1").await;
    enroll_allow(&state, "/s/raw2.sh", "raw2").await;
    let mut raw = body("raw1", "/s/raw.sh", None);
    raw.token = Some(false);
    let out = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &raw)
        .await
        .unwrap();
    assert_eq!(credential_value(&out), "__MOCK_CRED_网易-授权码__");
    let mut full_body = body("raw2", "/s/raw2.sh", None);
    full_body.token = Some(false);
    full_body.field = None;
    full_body.fields = None;
    let full = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &full_body)
        .await
        .unwrap();
    assert_eq!(
        full.get("password").and_then(|v| v.as_str()),
        Some("__MOCK_CRED_网易__")
    );
}

#[tokio::test]
async fn missing_attribute_returns_404_named() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    // 空字段列表 = 条目内任意字段放行，使请求抵达 KeePass 查询以断言 404。
    enrolled_with_entries(&state, "/s/na.sh", "noattr", entries_for("网易", &[])).await;
    let mut missing = body("noattr", "/s/na.sh", None);
    missing.field = Some("不存在的字段".to_string());
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &missing)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
    assert!(err.to_string().contains("不存在的字段"));
}

#[tokio::test]
async fn out_of_scope_entry_rejected_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/acl.sh",
        "aclhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let mut over = body("aclhash", "/s/acl.sh", None);
    over.entry = Some("未知条目".to_string());
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &over)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert!(format!("{err:?}").contains("越权"));
}

#[tokio::test]
async fn out_of_scope_field_rejected_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/aclf.sh",
        "aclfhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let mut over = body("aclfhash", "/s/aclf.sh", None);
    over.field = Some("未授权字段".to_string());
    let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &over)
        .await
        .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn in_scope_allows_200() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/ok.sh",
        "okhash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("okhash", "/s/ok.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn go_registered_script_match_allows_200() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/job.sh",
        "scripthash",
        entries_for("网易", &["授权码"]),
    )
    .await;
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("scripthash", "/s/job.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn pure_body_without_headers_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/pure.sh", "purehash").await;
    let pure = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: Some("purehash".to_string()),
            caller_path: Some("/s/pure.sh".to_string()),
            veilctl_binary_hash: Some("gethash".to_string()),
            veilctl_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &pure)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn header_hash_mismatch_rejected_403() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("forged-hash", Some("s3cr3t")),
        &body("forged-hash", "/s/f.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_hash_caller_fetch_allows() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/term.sh", "gethash").await;
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("gethash", "/s/term.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&out).starts_with("__CRED_"));
}

#[tokio::test]
async fn same_secret_cross_requests_same_token() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enroll_allow(&state, "/s/cross1.sh", "cross1").await;
    enroll_allow(&state, "/s/cross2.sh", "cross2").await;
    let first = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("cross1", "/s/cross1.sh", None),
    )
    .await
    .unwrap();
    let second = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("cross2", "/s/cross2.sh", None),
    )
    .await
    .unwrap();
    assert!(credential_value(&first).starts_with("__CRED_"));
    assert_eq!(credential_value(&first), credential_value(&second));
}

#[tokio::test]
async fn pending_entry_always_requires_approval_in_credential_only_mode() {
    // 审批豁免已删除：`credential-only` 下 `Pending` 条目仍须建票（202 + E_PENDING），
    // 不得直接放行返回凭据。
    let env = cred_env(&[("VEIL_ENTRY_MODE", "credential-only")]);
    let state = cred_state(&env);
    assert_eq!(
        state.config().entry_mode,
        crate::config::EntryMode::CredentialOnly
    );
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("credonly1", "/s/credonly.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(err.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1, "credential-only 下仍须建审批单");
}

#[tokio::test]
async fn pending_entry_always_requires_approval_in_full_mode() {
    let env = cred_env(&[("VEIL_ENTRY_MODE", "full")]);
    let state = cred_state(&env);
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("fullmode1", "/s/fullmode.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(state.pending.len(), 1);
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// 把条目置为「已到期」：`authorized_at = now - ttl - 1`。
async fn expire_entry(state: &impl AppStateParts, path: &str, ttl: u64) {
    let at = now_secs().saturating_sub(ttl).saturating_sub(1);
    set_authorization(state, path, Some(at), Some(ttl)).await;
}

/// 直接改写条目的授权窗口（测试注入口；注册表无公开 setter）。
async fn set_authorization(
    state: &impl AppStateParts,
    path: &str,
    at: Option<u64>,
    ttl: Option<u64>,
) {
    let mut registry = state.registry().write().await;
    registry.set_authorization_window(path, at, ttl).unwrap();
}

#[tokio::test]
async fn expired_allow_entry_turns_into_pending_ticket() {
    // 到期覆盖：`allow_mode = allow` 的条目到期后必须建票（202/E_PENDING），不再直接返回凭据。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/exp-allow.sh",
        "h-exp-allow",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/exp-allow.sh", Some(crate::config::AutoApprove::Allow))
        .unwrap();
    expire_entry(&state, "/s/exp-allow.sh", 3_600).await;

    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h-exp-allow", "/s/exp-allow.sh", Some("网易")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(err.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1, "到期须建审批票");
    let reason = state
        .pending
        .get("/s/exp-allow.sh:h-exp-allow")
        .expect("到期须建 pending 记录")
        .reason;
    assert_eq!(
        reason, "authorization_expired",
        "原因标签须区别于 auto_approve_none"
    );
}

#[tokio::test]
async fn unexpired_allow_entry_still_returns_credential() {
    // 对照：窗口未到期时不建票，直接返回凭据。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/live-allow.sh",
        "h-live-allow",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/live-allow.sh", Some(crate::config::AutoApprove::Allow))
        .unwrap();
    set_authorization(&state, "/s/live-allow.sh", Some(now_secs()), Some(3_600)).await;
    let value = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h-live-allow", "/s/live-allow.sh", Some("网易")),
    )
    .await
    .expect("未到期须直接放行");
    assert!(
        credential_value(&value).starts_with("__CRED_"),
        "未到期须返回 token 化凭据: {value}"
    );
    assert_eq!(state.pending.len(), 0, "未到期不得建票");
}

#[tokio::test]
async fn expired_entry_with_global_deny_still_creates_ticket() {
    // 到期是「重新询问」而非「拒绝」：全局 deny 也不得让到期条目直接 403。
    let env = cred_env(&[("AUTO_APPROVE", "false")]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/exp-deny.sh",
        "h-exp-deny",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/exp-deny.sh", Some(crate::config::AutoApprove::Deny))
        .unwrap();
    expire_entry(&state, "/s/exp-deny.sh", 3_600).await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h-exp-deny", "/s/exp-deny.sh", Some("网易")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(err.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1);
}

#[tokio::test]
async fn entry_without_ttl_never_expires() {
    // `authorized_ttl_secs = None` 即无期限：久远的 `authorized_at` 也不触发建票。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/no-ttl.sh",
        "h-no-ttl",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/no-ttl.sh", Some(crate::config::AutoApprove::Allow))
        .unwrap();
    set_authorization(&state, "/s/no-ttl.sh", Some(1), None).await;
    let value = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h-no-ttl", "/s/no-ttl.sh", Some("网易")),
    )
    .await
    .expect("无期限条目须直接放行");
    assert!(
        credential_value(&value).starts_with("__CRED_"),
        "无期限条目须返回 token 化凭据: {value}"
    );
    assert_eq!(state.pending.len(), 0);
}

#[tokio::test]
async fn expired_entry_in_credential_only_mode_still_creates_ticket() {
    // 到期与 entry_mode 无交互：credential-only 下到期条目仍建票。
    let env = cred_env(&[("VEIL_ENTRY_MODE", "credential-only")]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/exp-co.sh",
        "h-exp-co",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/exp-co.sh", Some(crate::config::AutoApprove::Allow))
        .unwrap();
    expire_entry(&state, "/s/exp-co.sh", 3_600).await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("h-exp-co", "/s/exp-co.sh", Some("网易")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(err.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1);
}

#[tokio::test]
async fn expired_entry_without_acl_still_forbidden_no_ticket() {
    // 到期判定在 ACL 之后：越权请求仍 403，不因到期而建票（否则成越权探测放大器）。
    let env = cred_env(&[]);
    let state = cred_state(&env);
    enrolled_with_entries(
        &state,
        "/s/exp-acl.sh",
        "h-exp-acl",
        entries_for("网易", &["授权码"]),
    )
    .await;
    state
        .registry
        .write()
        .await
        .set_allow_mode("/s/exp-acl.sh", Some(crate::config::AutoApprove::Allow))
        .unwrap();
    expire_entry(&state, "/s/exp-acl.sh", 3_600).await;
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &unauthorized_body("h-exp-acl", "/s/exp-acl.sh"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(state.pending.len(), 0, "越权不得建票");
}

/// 请求一个条目 ACL 未授予的 selector（越权探测用）。
fn unauthorized_body(hash: &str, path: &str) -> CredentialBody {
    let mut b = body(hash, path, Some("s3cr3t"));
    b.entry = Some("未授权条目".to_string());
    b.field = Some("任意字段".to_string());
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approving_expired_ticket_renews_authorization_window() {
    // 到期 → 建票 → `✅` 落定后须续期：`authorized_at` 刷新、原 TTL 保留，
    // 且下一次取用直接返回凭据（不再建票）。这是 spec「到期后重新批准即续期」
    // 的端到端锁定——此前只有注册审批写入窗口，凭据票批准后续不上。
    let env = cred_env(&[
        ("CREDENTIAL_BLOCK_WAIT", "1"),
        ("APPROVAL_WHITELIST", "@admin:example.com"),
    ]);
    let state = cred_state(&env);
    let path = "/s/exp-renew.sh";
    let hash = "h-exp-renew";
    enrolled_with_entries(&state, path, hash, entries_for("网易", &["授权码"])).await;
    state
        .registry
        .write()
        .await
        .set_allow_mode(path, Some(crate::config::AutoApprove::Allow))
        .unwrap();
    expire_entry(&state, path, 3_600).await;

    let before = now_secs();
    let worker = state.clone();
    let handle = tokio::spawn(async move {
        handle_credential(
            &worker,
            &headers("gethash", Some("s3cr3t")),
            &body(hash, path, Some("网易")),
        )
        .await
    });
    let event_id = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let ids = state.approval.pending_event_ids().await;
            if let Some(id) = ids.first() {
                break id.clone();
            }
            assert!(std::time::Instant::now() < deadline, "到期票未建单");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    };
    let input = crate::service::matrix::ReactionInput {
        target_event_id: event_id,
        key: "✅".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 1,
    };
    state
        .approval
        .on_reaction(&input, "@bot:example.com", "!r:example.com", 0)
        .await;
    let out = handle.await.unwrap().expect("批准后须返回凭据");
    assert!(credential_value(&out).starts_with("__CRED_"));

    let (at, ttl) = {
        let reg = state.registry.read().await;
        let entry = reg.lookup_by_path(path).unwrap();
        (entry.authorized_at, entry.authorized_ttl_secs)
    };
    let at = at.expect("批准须刷新 authorized_at");
    assert!(at >= before, "续期须写批准时刻: {at} >= {before}");
    assert_eq!(ttl, Some(3_600), "续期须保留原 TTL");

    // 窗口已续期：下一次取用直接放行，不再建票。
    // 限流窗口 2s 且上一步已取用一次，故等过窗口再验证放行语义。
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, Some("网易")),
    )
    .await
    .expect("续期后须直接放行");
    assert!(credential_value(&out).starts_with("__CRED_"));
}

/// 审批幂等重试豁免（D4）：在途票存在时，同一 `pending_key` 的立即重试跳过 2s
/// 限流，复用既有票返回 `202 + E_PENDING`，不得退化成 429。
#[tokio::test]
async fn in_flight_approval_retry_skips_rate_limit() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let first = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("retryhash", "/s/retry.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(first.status_code(), axum::http::StatusCode::ACCEPTED);
    assert_eq!(first.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1, "首次请求须建单");

    let retry = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body("retryhash", "/s/retry.sh", None),
    )
    .await
    .unwrap_err();
    assert_eq!(
        retry.status_code(),
        axum::http::StatusCode::ACCEPTED,
        "在途重试须复用既有票，不得 429"
    );
    assert_eq!(retry.code(), "E_PENDING");
    assert_eq!(state.pending.len(), 1, "重试不得重复建单");
}

/// 对照：不进入审批通道（`allow_mode=allow`）的请求不产生决策表条目，
/// 立即连发第二次仍按 2s 窗口限流（429 + `retry-after`）。
#[tokio::test]
async fn allow_path_without_decision_entry_still_rate_limited() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let path = "/s/no-entry.sh";
    let hash = "h-no-entry";
    enroll_allow(&state, path, hash).await;
    handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .unwrap();
    let key = format!("{path}:{hash}");
    assert!(
        !crate::service::credential::decision::credential_decision_exists(&state, &key),
        "放行路径不得留下决策表条目"
    );

    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    let response = err.into_response();
    assert!(response.headers().contains_key("retry-after"));
}

/// `enters_approval` 守卫：即便决策表已有同 `pending_key` 条目，`Allow` 调用方
/// 也不得借豁免绕过限流——第二次立即请求仍 429。
#[tokio::test]
async fn allow_caller_with_decision_entry_still_rate_limited() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let path = "/s/allow-entry.sh";
    let hash = "h-allow-entry";
    enrolled_with_entries(&state, path, hash, entries_for("网易", &["授权码"])).await;
    state
        .registry
        .write()
        .await
        .set_allow_mode(path, Some(AutoApprove::Allow))
        .unwrap();
    let key = format!("{path}:{hash}");
    state.decisions().lock().unwrap().begin(&key);
    assert!(crate::service::credential::decision::credential_decision_exists(&state, &key));

    handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .expect("放行调用方首次取用须成功");
    let err = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.status_code(),
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "Allow 调用方不享受审批重试豁免"
    );
}

/// 未消费的 `Decided(Approved)` 重试：跳过 2s 限流并继续走批准动作取到凭据。
#[tokio::test]
async fn unconsumed_approved_retry_skips_rate_limit() {
    let env = cred_env(&[]);
    let state = cred_state(&env);
    let path = "/s/decided-ok.sh";
    let hash = "h-decided-ok";
    enrolled_with_entries(&state, path, hash, entries_for("网易", &["授权码"])).await;
    state
        .registry
        .write()
        .await
        .set_allow_mode(path, Some(AutoApprove::Pending))
        .unwrap();
    let key = format!("{path}:{hash}");

    let first = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .unwrap_err();
    assert_eq!(first.code(), "E_PENDING");
    state.decisions().lock().unwrap().resolve(&key, Some(true));

    let out = handle_credential(
        &state,
        &headers("gethash", Some("s3cr3t")),
        &body(hash, path, None),
    )
    .await
    .expect("已批准未消费的重试须跳过限流并取到凭据");
    assert!(credential_value(&out).starts_with("__CRED_"));
}
