//! 三因子鉴权入口：密钥/哈希/调用者身份核验与取用决策。
//!
//! H3.1 owner 声明：底层比较原语（`ct_eq/secret_eq`）owner 为 `crate::auth`
//! 工具实体，本文件只做网关核验编排与取用决策，不得自造比较实现。

use {
    super::{
        AppStateParts,
        CredentialBody,
        CredentialHeaders,
        approval::{approval_dual_mode, notify_hash_change},
        ratelimit::check_rate,
        vault_ops::query_keepass,
    },
    crate::{
        auth::{ct_eq, secret_eq},
        config::{AutoApprove, CREDENTIAL_RATE_WINDOW_SECS, EntryMode},
        error::{Result, VeilError},
    },
};

fn effective_secret(headers: &CredentialHeaders, body: &CredentialBody) -> Option<String> {
    headers
        .binary_secret
        .clone()
        .filter(|v| !v.is_empty())
        .or_else(|| body.secret.clone().filter(|v| !v.is_empty()))
        .or_else(|| {
            body.auth
                .as_ref()
                .and_then(|a| a.get_binary_secret.clone())
                .filter(|v| !v.is_empty())
        })
}

fn effective_binary_hash(headers: &CredentialHeaders, body: &CredentialBody) -> String {
    let header_hash = headers.binary_hash.clone().unwrap_or_default();
    if !header_hash.is_empty() {
        return header_hash;
    }
    body.auth
        .as_ref()
        .and_then(|a| a.get_binary_hash.clone())
        .unwrap_or_default()
}

fn entry_selector(body: &CredentialBody) -> (Option<String>, Option<String>) {
    let entry = body
        .entry
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let field = body
        .field
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| match body.fields.as_ref() {
            Some(serde_json::Value::String(s)) => {
                let trimmed = s.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            Some(serde_json::Value::Array(items)) => items.iter().find_map(|v| {
                v.as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            }),
            _ => None,
        });
    (entry, field)
}

pub async fn handle_credential(
    state: &impl AppStateParts,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<serde_json::Value> {
    if state.config().entry_mode == EntryMode::LlmOnly {
        return Err(VeilError::Auth {
            message: "llm-only 纯代理入口，凭据接口不可用".to_string(),
        });
    }
    let auth = body.auth.clone().unwrap_or_default();
    let caller_hash = auth.caller_hash.unwrap_or_default();
    let caller_path = auth.caller_path.unwrap_or_default();
    if caller_hash.is_empty() || caller_path.is_empty() {
        return Err(VeilError::Auth {
            message: "三因子缺失：body.auth.caller_hash/caller_path 必填".to_string(),
        });
    }
    let use_token = body.token.unwrap_or(true);
    let header_hash = effective_binary_hash(headers, body);
    let server_get_hash = state
        .config()
        .get_binary_hash
        .as_deref()
        .filter(|v| !v.is_empty());
    if let Some(expected_get) = server_get_hash {
        if !ct_eq(&header_hash, expected_get) {
            return Err(VeilError::Auth {
                message: "三因子缺失或不一致：get_binary_hash 不匹配".to_string(),
            });
        }
        if !use_token && ct_eq(&caller_hash, expected_get) {
            return Err(VeilError::Auth {
                message: "原始凭据请求被拒绝（token=false/--raw）：不允许终端直接调用".to_string(),
            });
        }
    }
    if let Some(expected_secret) = state.config().credential_secret.as_deref()
        && !expected_secret.is_empty()
    {
        match effective_secret(headers, body) {
            Some(got) if secret_eq(&got, expected_secret) => {}
            _ => {
                return Err(VeilError::Auth {
                    message: "三因子缺失或不一致：Secret 校验失败".to_string(),
                });
            }
        }
    }
    let (entry, field) = entry_selector(body);
    let entry = entry.ok_or_else(|| VeilError::BadRequest {
        message: "取用选择器缺失：entry 必填（POST /credential 须携带 entry，如 {\"entry\":\"网易\",\"field\":\"授权码\"}；缺 field 取整条目）"
            .to_string(),
    })?;

    let pending_key = format!("{caller_path}:{caller_hash}");
    let mut hash_grace = false;
    let decision = {
        let registry = state.registry().read().await;
        if let Some(caller) = registry.lookup_by_path(&caller_path) {
            // 双模顺序（credential-approval-dual-mode）：先比 hash，
            // 失配后再查吊销可达性——已吊销→403，其余转审批（默认 202 抛单）。
            // 新注册（enabled=false 未启用）失配时同样转审批，不在此直接 403。
            if ct_eq(&caller_hash, &caller.expected_hash) {
                if caller.revoked || !caller.enabled {
                    return Err(VeilError::Auth {
                        message: format!("调用方已禁用（{}），拒绝", caller.status_emoji()),
                    });
                }
                if !caller.check_entry_allowed(&entry, field.as_deref()) {
                    return Err(VeilError::Auth {
                        message: format!("越权：调用方 {caller_path} 未授权访问 {entry}，拒绝"),
                    });
                }
                Some(caller.effective_allow_mode(state.config().auto_approve))
            } else if caller.matches_old_hash(&caller_hash) {
                if caller.revoked || !caller.enabled {
                    return Err(VeilError::Auth {
                        message: format!("调用方已禁用（{}），拒绝", caller.status_emoji()),
                    });
                }
                if !caller.check_entry_allowed(&entry, field.as_deref()) {
                    return Err(VeilError::Auth {
                        message: format!("越权：调用方 {caller_path} 未授权访问 {entry}，拒绝"),
                    });
                }
                hash_grace = true;
                Some(caller.effective_allow_mode(state.config().auto_approve))
            } else {
                if caller.revoked {
                    return Err(VeilError::Auth {
                        message: format!("调用方已吊销（{}），拒绝", caller.status_emoji()),
                    });
                }
                None
            }
        } else if let Some(caller) = registry.lookup_by_hash(&caller_hash) {
            if caller.revoked || !caller.enabled {
                return Err(VeilError::Auth {
                    message: format!("调用方已禁用（{}），拒绝", caller.status_emoji()),
                });
            }
            if !caller.check_entry_allowed(&entry, field.as_deref()) {
                return Err(VeilError::Auth {
                    message: format!("越权：调用方 {caller_path} 未授权访问 {entry}，拒绝"),
                });
            }
            Some(caller.effective_allow_mode(state.config().auto_approve))
        } else {
            Some(state.config().auto_approve)
        }
    };
    if hash_grace {
        notify_hash_change(state, &pending_key, "old_hash宽限内放行");
    }

    check_rate(
        state.credential_hits(),
        &pending_key,
        CREDENTIAL_RATE_WINDOW_SECS,
    )
    .await?;

    let effective = match decision {
        None => {
            return approval_dual_mode(
                state,
                &pending_key,
                "hash_mismatch",
                &entry,
                field.as_deref(),
                use_token,
            )
            .await;
        }
        Some(AutoApprove::Deny) => {
            return Err(VeilError::Auth {
                message: "自动放行=False，拒绝".to_string(),
            });
        }
        Some(AutoApprove::Pending) if state.config().entry_mode != EntryMode::CredentialOnly => {
            return approval_dual_mode(
                state,
                &pending_key,
                "auto_approve_none",
                &entry,
                field.as_deref(),
                use_token,
            )
            .await;
        }
        Some(_) => AutoApprove::Allow,
    };
    let _ = effective;

    query_keepass(state, &entry, field.as_deref(), use_token).await
}

#[cfg(test)]
mod tests {
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
    async fn three_factors_consistent_unenrolled_passes() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let out = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("callerhash1", "/s/a.sh", None),
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
}
