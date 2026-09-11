//! KeePass 查询 + 注册表运维：凭据取值脱敏、注册/吊销/哈希变更。
//!
//! H3.1 owner 声明：查询与运维归本文件；token 映射实体归
//! `service::credential_vault`（取值经其 token 化）；两处互不垫片。

use {
    super::{
        super::matrix,
        AppStateParts,
        RegistrationView,
        approval::{notify_hash_change, record_pending},
        ratelimit::check_rate,
        registration_view,
    },
    crate::{
        auth::{ct_eq, is_private_ip, secret_eq},
        config::{EntryMode, REGISTER_RATE_WINDOW_SECS},
        error::{Result, VeilError},
        registry::RegisterParams,
        service::credential_vault,
    },
};

fn tokenize_field(
    vault: &credential_vault::CredentialVault,
    value: &str,
    use_token: bool,
) -> String {
    if !use_token || value.is_empty() {
        return value.to_string();
    }
    vault.register(value).unwrap_or_else(|_| value.to_string())
}

pub async fn query_keepass(
    state: &impl AppStateParts,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    let snapshot = match state.keepass().fetch_entry(entry.to_string()).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            if matches!(
                e,
                VeilError::KeePass { .. } | VeilError::Storage { .. } | VeilError::Internal(_)
            ) {
                notify_keepass_failure(state, entry, &e.to_string());
            }
            return Err(e);
        }
    };
    let vault = state.vault().as_ref();
    match field {
        None => {
            let mut custom_properties = serde_json::Map::new();
            for prop in &snapshot.custom {
                let value = if prop.protected {
                    tokenize_field(vault, &prop.value, use_token)
                } else {
                    prop.value.clone()
                };
                custom_properties.insert(prop.name.clone(), serde_json::Value::String(value));
            }
            Ok(serde_json::json!({
                "title": snapshot.title,
                "username": snapshot.username,
                "password": tokenize_field(vault, &snapshot.password, use_token),
                "url": snapshot.url,
                "custom_properties": custom_properties,
            }))
        }
        Some(name) => {
            let lowered = name.to_lowercase();
            let (value, protect) = match lowered.as_str() {
                "title" => (snapshot.title.clone(), false),
                "username" | "user name" => (snapshot.username.clone(), false),
                "password" => (snapshot.password.clone(), true),
                "url" => (snapshot.url.clone(), false),
                _ => match snapshot.custom.iter().find(|c| c.name == name) {
                    Some(prop) => (prop.value.clone(), prop.protected),
                    None => {
                        return Err(VeilError::NotFound {
                            message: format!("属性未找到: {entry}/{name}"),
                        });
                    }
                },
            };
            let value = if protect {
                tokenize_field(vault, &value, use_token)
            } else {
                value
            };
            Ok(serde_json::json!({ "value": value }))
        }
    }
}

fn notify_keepass_failure(state: &impl AppStateParts, entry: &str, detail: &str) {
    let bot = matrix::MatrixBot::with_client(
        state.config().homeserver.clone(),
        state.config().room_id.clone(),
        state.config().matrix_access_token.clone(),
        state.http_client().as_ref().clone(),
    );
    let summary = format!("KeePass 查询失败 :: {entry} :: {detail}");
    let text = bot.format_approval(matrix::MatrixBranch::Credential, Some(false), &summary);
    tokio::spawn(async move {
        let _ = bot.send_text(&text).await;
    });
}

pub async fn list_registrations(
    state: &impl AppStateParts,
    admin_token: Option<&str>,
    secret: Option<&str>,
) -> Result<Vec<RegistrationView>> {
    let admin_ok = match (
        admin_token,
        state.config().observability_admin_token.as_str(),
    ) {
        (Some(got), expected) if !got.is_empty() => ct_eq(got, expected),
        _ => false,
    };
    let secret_ok = match (secret, state.config().credential_secret.as_deref()) {
        (Some(got), Some(expected)) if !got.is_empty() && !expected.is_empty() => {
            secret_eq(got, expected)
        }
        _ => false,
    };
    if !admin_ok && !secret_ok {
        return Err(VeilError::Unauthorized {
            message: "注册查询需鉴权".to_string(),
        });
    }
    let registry = state.registry().read().await;
    Ok(registry.snapshot().iter().map(registration_view).collect())
}

pub async fn register_caller(
    state: &impl AppStateParts,
    caller_path: &str,
    caller_hash: &str,
    source: &str,
) -> Result<RegistrationView> {
    register_caller_extended(
        state,
        &RegisterParams {
            caller_path: caller_path.to_string(),
            caller_hash: caller_hash.to_string(),
            ..RegisterParams::default()
        },
        source,
    )
    .await
}

pub async fn register_caller_extended(
    state: &impl AppStateParts,
    params: &RegisterParams,
    source: &str,
) -> Result<RegistrationView> {
    if params.caller_path.trim().is_empty() || params.caller_hash.trim().is_empty() {
        return Err(VeilError::BadRequest {
            message: "caller_path 与 caller_hash 均必填".to_string(),
        });
    }
    {
        let registry = state.registry().read().await;
        if registry.lookup_by_path(params.caller_path.trim()).is_some()
            || registry.lookup_by_hash(params.caller_hash.trim()).is_some()
        {
            return Err(VeilError::Conflict {
                message: format!("调用方已注册: {}", params.caller_path.trim()),
            });
        }
    }
    let rate_key = if source.is_empty() {
        "register:unknown".to_string()
    } else {
        format!("register:{source}")
    };
    check_rate(state.register_hits(), &rate_key, REGISTER_RATE_WINDOW_SECS).await?;
    let view = {
        let mut registry = state.registry().write().await;
        let entry = registry.register_extended(params)?;
        let view = registration_view(entry);
        registry.save_to(state.registry_path()).ok();
        view
    };
    Ok(view)
}

pub async fn revoke_caller(state: &impl AppStateParts, key: &str) -> Result<RegistrationView> {
    let view = {
        let mut registry = state.registry().write().await;
        let entry = registry.revoke(key)?;
        let view = registration_view(entry);
        registry.save_to(state.registry_path()).ok();
        view
    };
    Ok(view)
}

pub async fn emergency_revoke(
    state: &impl AppStateParts,
    key: &str,
    admin_token: Option<&str>,
    peer_ip: Option<&str>,
    file_present: bool,
) -> Result<RegistrationView> {
    let admin_ok = match (
        admin_token,
        state.config().observability_admin_token.as_str(),
    ) {
        (Some(got), expected) if !got.is_empty() => ct_eq(got, expected),
        _ => false,
    };
    let net_ok = peer_ip.is_some_and(is_private_ip);
    if admin_ok || file_present || net_ok {
        return revoke_caller(state, key).await;
    }
    Err(record_pending(state, key, "emergency_revoke转常规审批").await)
}

pub async fn approve_hash_change(
    state: &impl AppStateParts,
    caller_path: &str,
    new_hash: &str,
) -> Result<RegistrationView> {
    if state.config().entry_mode != EntryMode::Full {
        tracing::warn!(
            "轻量入口（{:?}）配 approve：已降级为阻断，不执行哈希变更",
            state.config().entry_mode
        );
        return Err(VeilError::Auth {
            message: "轻量入口 approve 已降级为阻断".to_string(),
        });
    }
    if caller_path.is_empty() || new_hash.is_empty() {
        return Err(VeilError::BadRequest {
            message: "caller_path 与 new_hash 均必填".to_string(),
        });
    }
    let view = {
        let mut registry = state.registry().write().await;
        let entry = registry.approve_hash_change(caller_path, new_hash)?;
        let view = registration_view(entry);
        registry.save_to(state.registry_path()).ok();
        view
    };
    notify_hash_change(
        state,
        caller_path,
        "approve_hash_change 已生效，旧哈希进入3600s宽限",
    );
    Ok(view)
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            config::Config,
            service::credential::{handle_credential, test_support::*},
            state::{AppState, SqliteOutcome},
        },
        std::{path::PathBuf, sync::Arc},
    };

    #[tokio::test]
    async fn real_backend_missing_entry_returns_404() {
        use zeroize::Zeroizing;
        let dir = std::env::temp_dir().join(format!(
            "veil-service-keepass-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("svc.kdbx");
        crate::keepass::build_test_kdbx(&db_path, b"svc-pw", &[("网易", "u", "s", "", vec![])]);
        let provider: crate::keepass::PasswordProvider =
            std::sync::Arc::new(|| Ok(Zeroizing::new(b"svc-pw".to_vec())));
        let env = cred_env(&[]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            crate::state::SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: dir.join("x.sqlite"),
            },
        )
        .with_keepass(Arc::new(crate::keepass::RealKeePass::new(
            db_path, None, provider,
        )));
        let mut missing = body("svc1", "/s/svc.sh", None);
        missing.entry = Some("不存在".to_string());
        let err = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &missing)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::NOT_FOUND);
        assert!(err.to_string().contains("不存在"));
        let mut ok_body = body("svc2", "/s/svc2.sh", None);
        ok_body.field = None;
        ok_body.fields = None;
        let ok = handle_credential(&state, &headers("gethash", Some("s3cr3t")), &ok_body)
            .await
            .unwrap();
        assert_eq!(ok.get("title").and_then(|v| v.as_str()), Some("网易"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn locked_returns_503() {
        let env = cred_env(&[]);
        let locked = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
            },
        );
        let err = handle_credential(
            &locked,
            &headers("gethash", Some("s3cr3t")),
            &body("k1", "/s/k.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
