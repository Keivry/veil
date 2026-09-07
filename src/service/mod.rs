use {
    crate::{
        approval::{ApprovalGateway as _, NoopApproval, PendingRecord},
        auth::{ct_eq, is_private_ip},
        config::{AutoApprove, CREDENTIAL_RATE_WINDOW_SECS, REGISTER_RATE_WINDOW_SECS},
        error::{Result, VeilError},
        registry::CallerEntry,
        state::AppState,
    },
    serde::{Deserialize, Serialize},
    std::{collections::HashMap, time::Instant},
};

pub mod admin;
pub mod audit;
pub mod audit_hold;
pub mod block_inject;
/// §3 脱敏子模块（单向依赖：只读 `state` 经调用方注入，不触网络与路由）。
pub mod credential_vault;
pub mod json_walk;
pub mod llm_gateway;
pub mod matrix;
pub mod metrics;
pub mod pii;
pub mod redaction;
pub mod sse;
pub mod tpm;

#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub sqlite_ok: bool,
    pub sqlite_error: Option<String>,
}

pub fn health_status(state: &AppState) -> HealthStatus {
    use std::sync::atomic::Ordering;
    let sqlite_error = match state.sqlite_error.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => None,
    };
    HealthStatus {
        sqlite_ok: state.sqlite_ok.load(Ordering::SeqCst),
        sqlite_error,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthBlock {
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
}

#[derive(Debug, Clone, Default)]
pub struct CredentialHeaders {
    pub binary_hash: Option<String>,
    pub binary_secret: Option<String>,
}

impl CredentialHeaders {
    pub fn new(binary_hash: Option<String>, binary_secret: Option<String>) -> Self {
        Self {
            binary_hash,
            binary_secret,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationView {
    pub caller_path: String,
    pub enabled: bool,
    pub revoked: bool,
    pub status: String,
}

fn check_rate(
    hits: &std::sync::Mutex<HashMap<String, Instant>>,
    key: &str,
    window_secs: u64,
) -> Result<()> {
    let mut guard = hits.lock().map_err(|_| VeilError::Storage {
        message: "限流表锁定失败".to_string(),
    })?;
    let now = Instant::now();
    if let Some(last) = guard.get(key)
        && now.duration_since(*last).as_secs() < window_secs
    {
        let remain = window_secs.saturating_sub(now.duration_since(*last).as_secs());
        return Err(VeilError::RateLimited {
            retry_after_secs: remain.max(1),
        });
    }
    guard.insert(key.to_string(), now);
    Ok(())
}

fn effective_secret(headers: &CredentialHeaders, body: &CredentialBody) -> Option<String> {
    headers
        .binary_secret
        .clone()
        .filter(|v| !v.is_empty())
        .or_else(|| body.secret.clone().filter(|v| !v.is_empty()))
}

fn record_pending(state: &AppState, key: &str, reason: &str) -> VeilError {
    let record = PendingRecord::new(key, reason);
    let gateway = NoopApproval;
    let _ = gateway.request_approval(&record);
    state.pending.insert(record);
    VeilError::PendingApproval {
        message: format!("已转 Matrix 人工审批: {reason}"),
    }
}

pub async fn handle_credential(
    state: &AppState,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<String> {
    if state.config.entry_mode == crate::config::EntryMode::LlmOnly {
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
    if let Some(expected_get) = state.config.get_binary_hash.as_deref()
        && !expected_get.is_empty()
        && ct_eq(&caller_hash, expected_get)
    {
        return Err(VeilError::Auth {
            message: "调用方冒用 get 自身哈希直调，拒绝".to_string(),
        });
    }
    if let Some(expected_secret) = state.config.credential_secret.as_deref()
        && !expected_secret.is_empty()
    {
        match effective_secret(headers, body) {
            Some(got) if ct_eq(&got, expected_secret) => {}
            _ => {
                return Err(VeilError::Auth {
                    message: "三因子缺失或不一致：Secret 校验失败".to_string(),
                });
            }
        }
    }
    let header_hash = headers.binary_hash.clone().unwrap_or_default();
    if header_hash.is_empty() {
        return Err(VeilError::Auth {
            message: "三因子缺失：X-Get-Binary-Hash 必填".to_string(),
        });
    }

    let pending_key = format!("{caller_path}:{caller_hash}");
    let decision = {
        let registry = state.registry.read().await;
        if !ct_eq(&header_hash, &caller_hash) {
            None
        } else if let Some(entry) = registry.lookup_by_path(&caller_path) {
            if !ct_eq(&header_hash, &entry.expected_hash) {
                None
            } else if entry.revoked || !entry.enabled {
                return Err(VeilError::Auth {
                    message: format!("调用方已禁用（{}），拒绝", entry.status_emoji()),
                });
            } else {
                Some(entry.auto_approve.unwrap_or(state.config.auto_approve))
            }
        } else if registry.lookup_by_hash(&header_hash).is_some() {
            None
        } else {
            Some(state.config.auto_approve)
        }
    };

    let effective = match decision {
        None => {
            return Err(record_pending(state, &pending_key, "hash_mismatch"));
        }
        Some(AutoApprove::Deny) => {
            return Err(VeilError::Auth {
                message: "自动放行=False，拒绝".to_string(),
            });
        }
        Some(AutoApprove::Pending)
            if state.config.entry_mode != crate::config::EntryMode::CredentialOnly =>
        {
            return Err(record_pending(state, &pending_key, "auto_approve_none"));
        }
        Some(_) => AutoApprove::Allow,
    };
    let _ = effective;

    check_rate(
        &state.credential_hits,
        &pending_key,
        CREDENTIAL_RATE_WINDOW_SECS,
    )?;

    state.keepass.fetch_credential(&caller_path)
}

pub async fn list_registrations(
    state: &AppState,
    admin_token: Option<&str>,
    secret: Option<&str>,
) -> Result<Vec<RegistrationView>> {
    let admin_ok = match (admin_token, state.config.observability_admin_token.as_str()) {
        (Some(got), expected) if !got.is_empty() => ct_eq(got, expected),
        _ => false,
    };
    let secret_ok = match (secret, state.config.credential_secret.as_deref()) {
        (Some(got), Some(expected)) if !got.is_empty() && !expected.is_empty() => {
            ct_eq(got, expected)
        }
        _ => false,
    };
    if !admin_ok && !secret_ok {
        return Err(VeilError::Unauthorized {
            message: "注册查询需鉴权".to_string(),
        });
    }
    let registry = state.registry.read().await;
    Ok(registry
        .snapshot()
        .iter()
        .map(|e: &CallerEntry| RegistrationView {
            caller_path: e.caller_path.clone(),
            enabled: e.enabled,
            revoked: e.revoked,
            status: e.status_emoji().to_string(),
        })
        .collect())
}

pub async fn register_caller(
    state: &AppState,
    caller_path: &str,
    caller_hash: &str,
    source: &str,
) -> Result<RegistrationView> {
    if caller_path.is_empty() || caller_hash.is_empty() {
        return Err(VeilError::BadRequest {
            message: "caller_path 与 caller_hash 均必填".to_string(),
        });
    }
    {
        let registry = state.registry.read().await;
        if registry.lookup_by_path(caller_path).is_some()
            || registry.lookup_by_hash(caller_hash).is_some()
        {
            return Err(VeilError::Conflict {
                message: format!("调用方已注册: {caller_path}"),
            });
        }
    }
    let rate_key = if source.is_empty() {
        "register:unknown".to_string()
    } else {
        format!("register:{source}")
    };
    check_rate(&state.register_hits, &rate_key, REGISTER_RATE_WINDOW_SECS)?;
    let view = {
        let mut registry = state.registry.write().await;
        let entry = registry.register(caller_path, caller_hash)?;
        let view = RegistrationView {
            caller_path: entry.caller_path.clone(),
            enabled: entry.enabled,
            revoked: entry.revoked,
            status: entry.status_emoji().to_string(),
        };
        registry.save_to(&state.registry_path).ok();
        view
    };
    Ok(view)
}

pub async fn revoke_caller(state: &AppState, key: &str) -> Result<RegistrationView> {
    let view = {
        let mut registry = state.registry.write().await;
        let entry = registry.revoke(key)?;
        let view = RegistrationView {
            caller_path: entry.caller_path.clone(),
            enabled: entry.enabled,
            revoked: entry.revoked,
            status: entry.status_emoji().to_string(),
        };
        registry.save_to(&state.registry_path).ok();
        view
    };
    Ok(view)
}

pub async fn emergency_revoke(
    state: &AppState,
    key: &str,
    admin_token: Option<&str>,
    source: Option<&str>,
    file_present: bool,
) -> Result<RegistrationView> {
    let admin_ok = match (admin_token, state.config.observability_admin_token.as_str()) {
        (Some(got), expected) if !got.is_empty() => ct_eq(got, expected),
        _ => false,
    };
    let net_ok = source.is_some_and(is_private_ip);
    if admin_ok || file_present || net_ok {
        return revoke_caller(state, key).await;
    }
    Err(record_pending(state, key, "emergency_revoke转常规审批"))
}

pub async fn approve_hash_change(
    state: &AppState,
    caller_path: &str,
    new_hash: &str,
) -> Result<RegistrationView> {
    if state.config.entry_mode != crate::config::EntryMode::Full {
        tracing::warn!(
            "轻量入口（{:?}）配 approve：已降级为阻断，不执行哈希变更",
            state.config.entry_mode
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
        let mut registry = state.registry.write().await;
        let entry = registry.approve_hash_change(caller_path, new_hash)?;
        let view = RegistrationView {
            caller_path: entry.caller_path.clone(),
            enabled: entry.enabled,
            revoked: entry.revoked,
            status: entry.status_emoji().to_string(),
        };
        registry.save_to(&state.registry_path).ok();
        view
    };
    Ok(view)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Config, state::SqliteOutcome},
        axum::response::IntoResponse as _,
        std::{collections::HashMap, path::PathBuf, sync::Arc},
    };

    fn test_state(sqlite_ok: bool) -> AppState {
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
        ]);
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok,
                sqlite_error: if sqlite_ok {
                    None
                } else {
                    Some("ENOSPC".to_string())
                },
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: !sqlite_ok,
            },
        )
    }

    #[test]
    fn 健康状态透出降级标志() {
        assert!(health_status(&test_state(true)).sqlite_ok);
        let degraded = health_status(&test_state(false));
        assert!(!degraded.sqlite_ok);
        assert_eq!(degraded.sqlite_error.as_deref(), Some("ENOSPC"));
    }

    fn cred_env(extra: &[(&str, &str)]) -> HashMap<String, String> {
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
            ("GET_BINARY_HASH".to_string(), "gethash".to_string()),
        ]);
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        env
    }

    fn cred_state(env: &HashMap<String, String>) -> AppState {
        let state = AppState::new(
            Config::load_from(env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        );
        state.with_keepass(Arc::new(crate::keepass::MockKeePass::unlocked()))
    }

    fn body(hash: &str, path: &str, secret: Option<&str>) -> CredentialBody {
        CredentialBody {
            secret: secret.map(|s| s.to_string()),
            auth: Some(AuthBlock {
                caller_hash: Some(hash.to_string()),
                caller_path: Some(path.to_string()),
            }),
        }
    }

    fn headers(hash: &str, secret: Option<&str>) -> CredentialHeaders {
        CredentialHeaders::new(Some(hash.to_string()), secret.map(|s| s.to_string()))
    }

    #[tokio::test]
    async fn 三因子一致未enrolled放行() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let out = handle_credential(
            &state,
            &headers("callerhash1", Some("s3cr3t")),
            &body("callerhash1", "/s/a.sh", None),
        )
        .await
        .unwrap();
        assert!(out.contains("/s/a.sh"));
    }

    #[tokio::test]
    async fn 三因子缺一即403() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let err = handle_credential(
            &state,
            &headers("callerhash1", None),
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
    async fn 伪造secret被拒403() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let err = handle_credential(
            &state,
            &headers("callerhash1", Some("wrong")),
            &body("callerhash1", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn body_secret兼容放行() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let out = handle_credential(
            &state,
            &headers("callerhash2", None),
            &body("callerhash2", "/s/b.sh", Some("s3cr3t")),
        )
        .await
        .unwrap();
        assert!(out.contains("/s/b.sh"));
    }

    #[tokio::test]
    async fn 冒用get自身哈希拒403() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("gethash", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn 已enrolled哈希篡改转审批202() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "goodhash", "test-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("badhash", Some("s3cr3t")),
            &body("badhash", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
    }

    #[tokio::test]
    async fn 自动放行_false拒403() {
        let env = cred_env(&[("AUTO_APPROVE", "false")]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "goodhash", "test-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("goodhash", Some("s3cr3t")),
            &body("goodhash", "/s/a.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn 自动放行_none转202() {
        let env = cred_env(&[("AUTO_APPROVE", "none")]);
        let state = cred_state(&env);
        let err = handle_credential(
            &state,
            &headers("fresh", Some("s3cr3t")),
            &body("fresh", "/s/fresh.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn 凭据限流2秒429带_retry_after() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        handle_credential(
            &state,
            &headers("rlhash", Some("s3cr3t")),
            &body("rlhash", "/s/rl.sh", None),
        )
        .await
        .unwrap();
        let err = handle_credential(
            &state,
            &headers("rlhash", Some("s3cr3t")),
            &body("rlhash", "/s/rl.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        let response = err.into_response();
        assert!(response.headers().contains_key("retry-after"));
    }

    #[tokio::test]
    async fn 注册限流1秒() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/r1.sh", "h1", "src1")
            .await
            .unwrap();
        let dup = register_caller(&state, "/s/r1.sh", "h1", "src1")
            .await
            .unwrap_err();
        assert_eq!(dup.status_code(), axum::http::StatusCode::CONFLICT);
        let limited = register_caller(&state, "/s/r2.sh", "h2", "src1")
            .await
            .unwrap_err();
        assert_eq!(
            limited.status_code(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn 未解锁返回503() {
        let env = cred_env(&[]);
        let locked = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        );
        let err = handle_credential(
            &locked,
            &headers("k1", Some("s3cr3t")),
            &body("k1", "/s/k.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn 轻量入口approve降级阻断() {
        let env = cred_env(&[("VEIL_ENTRY_MODE", "credential-only")]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "h1", "test-src")
            .await
            .unwrap();
        let err = approve_hash_change(&state, "/s/a.sh", "h2")
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn 紧急吊销三免审与转审批() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/a.sh", "h1", "src-a")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/a.sh", true)
            .unwrap();
        let view = emergency_revoke(
            &state,
            "/s/a.sh",
            Some("observability-admin-token-0123456789"),
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(view.status, "❎");
        register_caller(&state, "/s/b.sh", "h2", "src-b")
            .await
            .unwrap();
        let err = emergency_revoke(&state, "/s/b.sh", None, Some("203.0.113.9"), false)
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
    }
}
