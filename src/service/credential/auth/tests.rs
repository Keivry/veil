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
};

#[tokio::test]
async fn unenrolled_defaults_to_pending() {
    // AUTH-4：未注册调用方默认转审批（202 + E_PENDING），不返回凭据。
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
    // AUTH-4：已注册且显式放行（allow_mode=Allow）行为不变，直接返回凭据。
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &body)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("wrong".to_string()),
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
    // GO/D8：头缺失时回退读取 `body.auth.get_binary_hash`/`get_binary_secret`
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
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &go_body)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
    let no_caller = CredentialBody {
        secret: None,
        auth: Some(AuthBlock {
            caller_hash: None,
            caller_path: None,
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("s3cr3t".to_string()),
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
            .is_some_and(|v| v.starts_with("__VG_CRED_"))
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("s3cr3t".to_string()),
        }),
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        token: None,
    };
    let out = handle_credential(&state, &CredentialHeaders::new(None, None), &pure)
        .await
        .unwrap();
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
    assert!(credential_value(&out).starts_with("__VG_CRED_"));
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
    assert!(credential_value(&first).starts_with("__VG_CRED_"));
    assert_eq!(credential_value(&first), credential_value(&second));
}
