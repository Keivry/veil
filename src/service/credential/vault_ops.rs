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

/// B1/D1：写锁已释放后经阻塞池落盘；失败显式 warn（best-effort，不回滚内存）。
async fn persist_registry_bytes(path: &std::path::Path, bytes: Result<Vec<u8>>) {
    match bytes {
        Ok(bytes) => {
            let path = path.to_path_buf();
            match tokio::task::spawn_blocking(move || crate::registry::write_atomic(&path, &bytes))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("注册表落盘失败（内存已更新但未持久化）: {e}");
                }
                Err(e) => {
                    tracing::warn!("注册表落盘任务异常（内存已更新但未持久化）: {e}");
                }
            }
        }
        Err(e) => {
            tracing::warn!("注册表完整性/序列化失败，已中止落盘（内存已更新）: {e}");
        }
    }
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
    // B5/D5：脚本哈希读取在取全序点/写锁前于阻塞池完成，锁内零文件 I/O。
    let script_sha256 = crate::registry::bind_script_sha256_async(
        params.caller_path.trim().to_string(),
        params.caller_hash.trim().to_string(),
    )
    .await;
    // B1/D1：全序点 → 写锁内改内存并取 bytes → 释放写锁 → spawn_blocking 落盘。
    let save_guard = state.registry_save_lock().lock().await;
    let (view, bytes) = {
        let mut registry = state.registry().write().await;
        let entry = registry.register_extended_with_script_sha256(params, script_sha256)?;
        let view = registration_view(entry);
        (view, registry.to_file_bytes())
    };
    persist_registry_bytes(state.registry_path(), bytes).await;
    drop(save_guard);
    Ok(view)
}

pub async fn revoke_caller(state: &impl AppStateParts, key: &str) -> Result<RegistrationView> {
    let save_guard = state.registry_save_lock().lock().await;
    let (view, bytes) = {
        let mut registry = state.registry().write().await;
        let entry = registry.revoke(key)?;
        let view = registration_view(entry);
        (view, registry.to_file_bytes())
    };
    persist_registry_bytes(state.registry_path(), bytes).await;
    drop(save_guard);
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
    // B5/D5：脚本哈希读取在取全序点/写锁前于阻塞池完成，锁内零文件 I/O。
    let script_sha256 = crate::registry::bind_script_sha256_async(
        caller_path.trim().to_string(),
        new_hash.trim().to_string(),
    )
    .await;
    let save_guard = state.registry_save_lock().lock().await;
    let (view, bytes) = {
        let mut registry = state.registry().write().await;
        let entry = registry.approve_hash_change_with_script_sha256(
            caller_path,
            new_hash,
            script_sha256,
        )?;
        let view = registration_view(entry);
        (view, registry.to_file_bytes())
    };
    persist_registry_bytes(state.registry_path(), bytes).await;
    drop(save_guard);
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
        super::register_caller_extended,
        crate::{
            config::Config,
            registry::RegisterParams,
            service::credential::{AppStateParts, handle_credential, test_support::*},
            state::{AppState, SqliteOutcome},
        },
        std::{path::PathBuf, sync::Arc},
    };

    fn unique_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "veil-vault-ops-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn state_with_registry_path(path: &std::path::Path) -> AppState {
        let path_str = path.to_string_lossy().into_owned();
        cred_state(&cred_env(&[("CALLER_REGISTRY_PATH", path_str.as_str())]))
    }

    fn params(path: &str, hash: &str) -> RegisterParams {
        RegisterParams {
            caller_path: path.to_string(),
            caller_hash: hash.to_string(),
            ..RegisterParams::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_save_not_blocking_reads() {
        use std::sync::atomic::Ordering;
        let dir = unique_dir("slow-save");
        let path = dir.join("caller_registry.json");
        let state = state_with_registry_path(&path);
        crate::registry::SAVE_TEST_DELAY_MS.store(500, Ordering::SeqCst);
        let starts_before = crate::registry::SAVE_TEST_WRITE_STARTS.load(Ordering::SeqCst);
        let s = state.clone();
        let handle = tokio::spawn(async move {
            register_caller_extended(&s, &params("/s/slow.sh", "slow-h1"), "slow-save-test").await
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while crate::registry::SAVE_TEST_WRITE_STARTS.load(Ordering::SeqCst) == starts_before {
            assert!(std::time::Instant::now() < deadline, "落盘未在超时内开始");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let t0 = std::time::Instant::now();
        let guard = state.registry().read().await;
        let waited = t0.elapsed();
        drop(guard);
        crate::registry::SAVE_TEST_DELAY_MS.store(0, Ordering::SeqCst);
        assert!(
            waited < std::time::Duration::from_millis(250),
            "读路径等待 {waited:?}，疑似被落盘/写锁阻塞"
        );
        handle.await.unwrap().unwrap();
        let loaded = crate::registry::CallerRegistry::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1, "落盘完成后文件须可加载");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn save_order_preserved() {
        let dir = unique_dir("save-order");
        let path = dir.join("caller_registry.json");
        let state = state_with_registry_path(&path);
        let mut set = tokio::task::JoinSet::new();
        for i in 0..8 {
            let s = state.clone();
            set.spawn(async move {
                register_caller_extended(
                    &s,
                    &params(&format!("/s/order-{i}.sh"), &format!("order-h{i}")),
                    &format!("order-test-{i}"),
                )
                .await
            });
        }
        while let Some(r) = set.join_next().await {
            r.expect("任务不得 panic").expect("注册须成功");
        }
        let loaded = crate::registry::CallerRegistry::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 8, "全序点须保证终态落盘含全部并发写");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn register_offlock_hash() {
        use std::sync::atomic::Ordering;
        let dir = unique_dir("offlock");
        let script = dir.join("job.sh");
        std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        let registry_path = dir.join("caller_registry.json");
        let state = state_with_registry_path(&registry_path);
        crate::registry::BIND_READ_DELAY_MS.store(500, Ordering::SeqCst);
        crate::registry::BIND_READ_ENTERED.store(false, Ordering::SeqCst);
        let s = state.clone();
        let script_path = script.to_string_lossy().into_owned();
        let script_path_for_task = script_path.clone();
        let handle = tokio::spawn(async move {
            register_caller_extended(
                &s,
                &params(&script_path_for_task, "offlock-h"),
                "offlock-test",
            )
            .await
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !crate::registry::BIND_READ_ENTERED.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "脚本读取未在超时内开始"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let t0 = std::time::Instant::now();
        let guard = state.registry().write().await;
        let waited = t0.elapsed();
        drop(guard);
        crate::registry::BIND_READ_DELAY_MS.store(0, Ordering::SeqCst);
        assert!(
            waited < std::time::Duration::from_millis(250),
            "写锁被读盘阻塞 {waited:?}，读取须在锁外"
        );
        handle.await.unwrap().unwrap();
        let loaded = crate::registry::CallerRegistry::load_from(&registry_path).unwrap();
        let entry = loaded.lookup_by_path(&script_path).expect("注册条目须在");
        assert_eq!(
            entry.script_sha256,
            crate::registry::script_sha256_of_bytes(b"#!/bin/sh\necho hi\n"),
            "锁外完成后写入的 script_sha256 须为真实文件哈希"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn save_failure_observable() {
        let dir = unique_dir("save-fail");
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let path = blocker.join("caller_registry.json");
        let state = state_with_registry_path(&path);
        let view = register_caller_extended(&state, &params("/s/fail.sh", "fail-h1"), "fail-test")
            .await
            .expect("落盘失败不得使注册接口失败（best-effort）");
        assert_eq!(view.caller_path, "/s/fail.sh");
        assert!(
            state
                .registry()
                .read()
                .await
                .lookup_by_path("/s/fail.sh")
                .is_some(),
            "内存态须保留"
        );
        assert!(!path.exists(), "失败不得产生落盘文件");
        std::fs::remove_dir_all(&dir).ok();
    }

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
