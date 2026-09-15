//! KeePass 查询 + 注册表运维：凭据取值脱敏、注册/吊销/哈希变更。
//!
//! H3.1 owner 声明：查询与运维归本文件；token 映射实体归
//! `service::credential_vault`（取值经其 token 化）；两处互不垫片。
//!
//! H7/D7 锁序不变量：写路径统一序 **`registry_save_lock → registry().write()`**，
//! 任何写锁必须在 `registry_save_lock` 全序点之后获取；流内 keepalive gate 不得
//! 逆序获取 hold 锁（见 `service::audit::hold::RequestKeepalive`）。审查清单真源见
//! design D7，源码扫描守护见 `service::declaration_lock::lock_order_invariants`。

use {
    super::{
        super::matrix,
        AppStateParts,
        RegistrationView,
        approval::{
            AutoPolicy,
            BeginOutcome,
            ClosureLane,
            CredentialDecision,
            approval_decision_closure,
            begin_decision,
            cancel_decision,
            clear_terminal_pending,
            consume_decision_key,
            notify_hash_change,
            record_credential_decision,
            submit_pending_with_branch,
        },
        ratelimit::check_rate,
        registration_view,
    },
    crate::{
        auth::{is_private_ip, secret_eq},
        config::{EntryMode, REGISTER_RATE_WINDOW_SECS},
        error::{Result, VeilError},
        registry::{HashChangeOutcome, RegisterParams},
        service::credential_vault,
    },
    std::time::Duration,
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
    let spool = state.notify();
    let summary = format!("KeePass 查询失败 :: {entry} :: {detail}");
    let text = spool.format_approval(matrix::MatrixBranch::Credential, Some(false), &summary);
    spool.notify_text(text);
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
        (Some(got), expected) if !got.is_empty() => secret_eq(got, expected),
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
        let name = params.name.trim();
        let name_conflict =
            !name.is_empty() && registry.lookup_by_name(name).is_some_and(|e| !e.revoked);
        // 注册判重口径（`F17`，`veil-oracle-followup-fix`）：全局 hash 去重已移除
        // （内容相同双脚本可各自注册）；判重仍按 `caller_path` 与未吊销 `name`。
        if registry.lookup_by_path(params.caller_path.trim()).is_some() || name_conflict {
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
    // H7/D7 锁序：`registry_save_lock` 必须先于 `registry().write()` 获取。
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

fn approval_timeout(state: &impl AppStateParts) -> Duration {
    Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64)
}

/// C1/D1 三态落定：`🔓 (true, true)` 保持 `disabled`；`✅ (true, false)` 启用；
/// `❎ (false, _)` 与 `None`（超时）置 `revoked=true`。落定后原子落盘。
async fn apply_register_approval(
    state: &impl AppStateParts,
    caller_path: &str,
    decision: Option<(bool, bool)>,
) {
    let save_guard = state.registry_save_lock().lock().await;
    let bytes = {
        let mut registry = state.registry().write().await;
        match decision {
            Some((true, true)) => {}
            Some((true, false)) => {
                if let Err(e) = registry.set_enabled(caller_path, true) {
                    tracing::warn!("注册审批启用失败 {caller_path}: {e}");
                }
            }
            _ => {
                if let Err(e) = registry.revoke(caller_path) {
                    tracing::warn!("注册审批吊销失败 {caller_path}: {e}");
                }
            }
        }
        registry.to_file_bytes()
    };
    persist_registry_bytes(state.registry_path(), bytes).await;
    drop(save_guard);
}

/// `AUTH-6` 原子回滚：删除指定条目的内存态并落盘，使 `caller_path` 立即可重试。
async fn rollback_registered_entry(state: &impl AppStateParts, caller_path: &str) {
    let save_guard = state.registry_save_lock().lock().await;
    let bytes = {
        let mut registry = state.registry().write().await;
        if registry.remove_entry(caller_path).is_some() {
            Some(registry.to_file_bytes())
        } else {
            None
        }
    };
    match bytes {
        Some(Ok(bytes)) => persist_registry_bytes(state.registry_path(), Ok(bytes)).await,
        Some(Err(e)) => tracing::warn!("注册回滚序列化失败（内存已回滚）: {e}"),
        None => {}
    }
    drop(save_guard);
}

/// `CRD-6`：终态重试回读注册视图（已批准条目）。
async fn read_registration_view(
    state: &impl AppStateParts,
    caller_path: &str,
) -> Result<RegistrationView> {
    let registry = state.registry().read().await;
    let entry = registry
        .lookup_by_path(caller_path)
        .ok_or_else(|| VeilError::Storage {
            message: "注册审批后回读失败".to_string(),
        })?;
    Ok(registration_view(entry))
}

/// C1/D1：注册审批链。先落盘中立条目（`disabled`），再建 `Register` 审批单，
/// 复用双模：默认 `202` 抛单（后台等待落定回写），`CREDENTIAL_BLOCK_WAIT=1`
/// 阻塞至 `300s`。三态落定见 [`apply_register_approval`]。
/// `AUTH-6`：建单/发送失败时回滚已落条目，不遗留不可决孤儿。
/// `CRD-6`：同一未决 `caller_path` 重试经决策表幂等复用（`202 + E_PENDING`，不重复建单、
/// 不误 `409`）；终态后重试返回终态结果（`✅` 放行、`❎`/超时 `403`）。
pub async fn register_caller_with_approval(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    params: &RegisterParams,
    source: &str,
) -> Result<RegistrationView> {
    let pending_key = format!("register:{}", params.caller_path.trim());
    match begin_decision(state, &pending_key) {
        Some(BeginOutcome::Busy) => {
            return Err(VeilError::PendingApproval {
                message: format!("注册已转 Matrix 人工审批: {}", params.caller_path.trim()),
            });
        }
        Some(BeginOutcome::Decided(CredentialDecision::Approved)) => {
            return read_registration_view(state, params.caller_path.trim()).await;
        }
        Some(BeginOutcome::Decided(CredentialDecision::Denied)) => {
            return Err(VeilError::Auth {
                message: "注册审批被拒绝".to_string(),
            });
        }
        Some(BeginOutcome::Decided(CredentialDecision::TimedOut)) => {
            return Err(VeilError::Auth {
                message: "注册审批超时，已按吊销处理".to_string(),
            });
        }
        Some(BeginOutcome::Reserved) | None => {}
    }
    let view = match register_caller_extended(state, params, source).await {
        Ok(view) => view,
        Err(err) => {
            cancel_decision(state, &pending_key);
            return Err(err);
        }
    };
    let caller_path = view.caller_path.clone();
    let reg_id = if view.script_hash.is_empty() {
        caller_path.clone()
    } else {
        view.script_hash.clone()
    };
    let reason = format!("register审批 :: {reg_id} :: {caller_path}");
    let event_id = match submit_pending_with_branch(
        state,
        &caller_path,
        &reason,
        matrix::MatrixBranch::Register,
        "",
        None,
    )
    .await
    {
        Ok(event_id) => event_id,
        Err(err) => {
            rollback_registered_entry(state, &caller_path).await;
            cancel_decision(state, &pending_key);
            return Err(err);
        }
    };
    if !state.config().credential_block_wait {
        let owned = (*state).clone();
        let path_for_task = caller_path.clone();
        let key_for_task = pending_key.clone();
        tokio::task::spawn(async move {
            let timeout = approval_timeout(&owned);
            let decision = owned.approval().ask(&event_id, timeout).await;
            let auto = owned
                .approval()
                .applied_auto(&event_id)
                .await
                .unwrap_or(false);
            apply_register_approval(&owned, &path_for_task, decision.map(|ok| (ok, auto))).await;
            record_credential_decision(&owned, &key_for_task, decision);
            clear_terminal_pending(&owned, &path_for_task, &event_id).await;
        });
        return Err(VeilError::PendingApproval {
            message: format!("注册已转 Matrix 人工审批: {caller_path}"),
        });
    }
    let decision = state
        .approval()
        .ask(&event_id, approval_timeout(state))
        .await;
    let auto = state
        .approval()
        .applied_auto(&event_id)
        .await
        .unwrap_or(false);
    apply_register_approval(state, &caller_path, decision.map(|ok| (ok, auto))).await;
    clear_terminal_pending(state, &caller_path, &event_id).await;
    consume_decision_key(state, &pending_key);
    match decision {
        Some(true) => read_registration_view(state, &caller_path).await,
        Some(false) => Err(VeilError::Auth {
            message: "注册审批被拒绝".to_string(),
        }),
        None => Err(VeilError::Auth {
            message: "注册审批超时，已按吊销处理".to_string(),
        }),
    }
}

/// C2/D2：常规吊销审批链。仅 `✅ (true, false)` 执行吊销；`❎`（含 `🔓`）与
/// 超时保持条目原状（不做破坏性动作）。默认 `202` 抛单，阻塞模式同
/// `CREDENTIAL_BLOCK_WAIT` 口径。
/// `CRD-6`：同一未决吊销请求重试经决策表幂等复用（`202 + E_PENDING`，不重复建单）；
/// 终态后重试返回终态（批准后条目保持 `revoked=true`/`enabled=false`，拒绝/超时 `403`）。
pub async fn revoke_caller_with_approval(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
) -> Result<RegistrationView> {
    let caller_path = {
        let registry = state.registry().read().await;
        registry
            .lookup_by_path(key)
            .or_else(|| registry.lookup_by_hash(key))
            .or_else(|| registry.lookup_by_name(key))
            .map(|entry| entry.caller_path.clone())
            .ok_or_else(|| VeilError::BadRequest {
                message: format!("调用方不存在: {key}"),
            })?
    };
    let pending_key = format!("revoke:{caller_path}");
    match begin_decision(state, &pending_key) {
        Some(BeginOutcome::Busy) => {
            return Err(VeilError::PendingApproval {
                message: format!("吊销已转 Matrix 人工审批: {caller_path}"),
            });
        }
        Some(BeginOutcome::Decided(CredentialDecision::Approved)) => {
            return revoke_caller(state, &caller_path).await;
        }
        Some(BeginOutcome::Decided(CredentialDecision::Denied)) => {
            return Err(VeilError::Auth {
                message: "吊销审批被拒绝".to_string(),
            });
        }
        Some(BeginOutcome::Decided(CredentialDecision::TimedOut)) => {
            return Err(VeilError::Auth {
                message: "吊销审批超时，按拒绝处理".to_string(),
            });
        }
        Some(BeginOutcome::Reserved) | None => {}
    }
    let reason = format!("revoke审批 :: {caller_path}");
    let event_id = match submit_pending_with_branch(
        state,
        &caller_path,
        &reason,
        matrix::MatrixBranch::Register,
        "",
        None,
    )
    .await
    {
        Ok(event_id) => event_id,
        Err(err) => {
            cancel_decision(state, &pending_key);
            return Err(err);
        }
    };
    if !state.config().credential_block_wait {
        let owned = (*state).clone();
        let path_for_task = caller_path.clone();
        let key_for_task = pending_key.clone();
        tokio::task::spawn(async move {
            let timeout = approval_timeout(&owned);
            let decision = owned.approval().ask(&event_id, timeout).await;
            let auto = owned
                .approval()
                .applied_auto(&event_id)
                .await
                .unwrap_or(false);
            // `T1`/D1：`🔓`（`Some(true) && auto`）按拒绝落定，不执行吊销。
            let effective = if decision == Some(true) && auto {
                Some(false)
            } else {
                decision
            };
            if effective == Some(true)
                && let Err(e) = revoke_caller(&owned, &path_for_task).await
            {
                tracing::warn!("吊销审批落定失败 {path_for_task}: {e}");
            }
            record_credential_decision(&owned, &key_for_task, effective);
            clear_terminal_pending(&owned, &path_for_task, &event_id).await;
        });
        return Err(VeilError::PendingApproval {
            message: format!("吊销已转 Matrix 人工审批: {caller_path}"),
        });
    }
    let decision = state
        .approval()
        .ask(&event_id, approval_timeout(state))
        .await;
    let auto = state
        .approval()
        .applied_auto(&event_id)
        .await
        .unwrap_or(false);
    clear_terminal_pending(state, &caller_path, &event_id).await;
    consume_decision_key(state, &pending_key);
    if decision == Some(true) && !auto {
        return revoke_caller(state, &caller_path).await;
    }
    Err(VeilError::Auth {
        message: "吊销未获确认，条目保持原状".to_string(),
    })
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

/// `CRD-13`：内网判定在 `auth::is_private_ip` 之上补 IPv4-mapped IPv6 形
/// （如 `::ffff:127.0.0.1`，等价 `127.0.0.0/8`），避免映射环回绕过内网豁免。
fn is_private_peer(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(v6) = h.parse::<std::net::Ipv6Addr>()
        && let Some(v4) = v6.to_ipv4_mapped()
        && is_private_ip(&v4.to_string())
    {
        return true;
    }
    is_private_ip(host)
}

pub async fn emergency_revoke(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    admin_token: Option<&str>,
    peer_ip: Option<&str>,
) -> Result<RegistrationView> {
    let admin_ok = match (
        admin_token,
        state.config().observability_admin_token.as_str(),
    ) {
        (Some(got), expected) if !got.is_empty() => secret_eq(got, expected),
        _ => false,
    };
    let net_ok = peer_ip.is_some_and(is_private_peer);
    if admin_ok || net_ok {
        return revoke_caller(state, key).await;
    }
    // `S1`/D1：转常规审批不再裸建单，改走同一决策闭环（批准动作 = 吊销注册）。
    // 决策键由吊销定位键派生，同一请求重试命中同一票；未决不重复建单。
    let pending_key = format!("revoke:{key}");
    approval_decision_closure(
        state,
        &pending_key,
        "emergency_revoke转常规审批",
        "",
        None,
        ClosureLane {
            label: "吊销",
            auto_policy: AutoPolicy::Reject,
            branch: matrix::MatrixBranch::Register,
        },
        || revoke_caller(state, key),
    )
    .await
}

pub async fn approve_hash_change(
    state: &impl AppStateParts,
    key: &str,
    new_hash: &str,
    outcome: HashChangeOutcome,
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
    if key.is_empty() || new_hash.is_empty() {
        return Err(VeilError::BadRequest {
            message: "reg_id/caller_path 与 new_hash 均必填".to_string(),
        });
    }
    // `C3`/D3：落定入口以 `reg_id`（或回退 `caller_path`）定位条目，支持
    // path/hash 两种键；解析在取写锁前完成。
    let caller_path = {
        let registry = state.registry().read().await;
        registry
            .resolve_path(key)
            .ok_or_else(|| VeilError::BadRequest {
                message: format!("调用方不存在: {key}"),
            })?
    };
    // B5/D5：脚本哈希读取在取全序点/写锁前于阻塞池完成，锁内零文件 I/O。
    let script_sha256 =
        crate::registry::bind_script_sha256_async(caller_path.clone(), new_hash.trim().to_string())
            .await;
    let save_guard = state.registry_save_lock().lock().await;
    let (view, bytes) = {
        let mut registry = state.registry().write().await;
        let entry = registry.approve_hash_change_with_script_sha256(
            &caller_path,
            new_hash,
            script_sha256,
            outcome,
        )?;
        let view = registration_view(entry);
        (view, registry.to_file_bytes())
    };
    persist_registry_bytes(state.registry_path(), bytes).await;
    drop(save_guard);
    notify_hash_change(
        state,
        &caller_path,
        "approve_hash_change 已生效，旧哈希进入3600s宽限",
    );
    Ok(view)
}

#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod retry_tests;
#[cfg(test)]
mod rollback_tests;
#[cfg(test)]
mod tests;
