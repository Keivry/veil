//! 三因子鉴权入口：密钥/哈希/调用者身份核验与取用决策。
//!
//! H3.1 owner 声明：底层比较原语（`ct_eq/secret_eq`）owner 为 `crate::auth`
//! 工具实体，本文件只做网关核验编排与取用决策，不得自造比较实现。

use {
    super::{
        AppStateParts,
        CredentialBody,
        CredentialHeaders,
        approval::{approval_dual_mode, notify_hash_grace_once},
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

/// 三因子核验守卫（`AUTH-1`/`AUTH-3`）：与 `/credential` 同源，供
/// `/approve-hash-change`、`/register-caller`、`/revoke` 三处写端点复用。
///
/// 校验：`X-Get-Binary-Hash`（或 `body.auth.get_binary_hash` 回退）、部署密钥
/// （`X-Get-Binary-Secret` / `body.secret` / `body.auth.get_binary_secret`）、调用者身份
/// （`body.auth.caller_hash` 与 `caller_path` 双必填）。任一因子缺失或不一致返回 403
/// （`E_AUTH`）；守卫在业务动作前执行，失败即无副作用。
pub async fn verify_three_factor(
    state: &impl AppStateParts,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<()> {
    let auth = body.auth.clone().unwrap_or_default();
    let caller_hash = auth.caller_hash.unwrap_or_default();
    let caller_path = auth.caller_path.unwrap_or_default();
    if caller_hash.is_empty() || caller_path.is_empty() {
        return Err(VeilError::Auth {
            message: "三因子缺失：body.auth.caller_hash/caller_path 必填".to_string(),
        });
    }
    let header_hash = effective_binary_hash(headers, body);
    let server_get_hash = state
        .config()
        .get_binary_hash
        .as_deref()
        .filter(|v| !v.is_empty());
    if let Some(expected_get) = server_get_hash
        && !ct_eq(&header_hash, expected_get)
    {
        return Err(VeilError::Auth {
            message: "三因子缺失或不一致：get_binary_hash 不匹配".to_string(),
        });
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
    Ok(())
}

/// 写端点部署密钥强制守卫（`AUTH-11`，fail-closed）：`/approve-hash-change`、
/// `/register-caller`、`/revoke` 三处写端点 SHALL 在部署未配置部署密钥
/// （`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 均空）时直接返回 403（`E_AUTH`）
/// 且在业务动作前失败（无副作用）；已配置时行为与 [`verify_three_factor`] 完全一致。
///
/// `/credential` 读路径保持 Python 兼容语义（未配置即跳过 Secret 因子），
/// 有意不经过本守卫——写操作收敛为 fail-closed，读操作维持既有口径。
pub async fn verify_three_factor_write(
    state: &impl AppStateParts,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<()> {
    let secret_configured = state
        .config()
        .credential_secret
        .as_deref()
        .is_some_and(|v| !v.is_empty());
    if !secret_configured {
        return Err(VeilError::Auth {
            message: "写端点要求配置部署密钥（GET_BINARY_SECRET/CREDENTIAL_SECRET），未配置拒绝"
                .to_string(),
        });
    }
    verify_three_factor(state, headers, body).await
}

pub async fn handle_credential(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
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
    let use_token = body.token.unwrap_or(true);
    verify_three_factor(state, headers, body).await?;
    // 终端直调拒绝：`token=false` 且调用者冒用 get 自身哈希（`--raw` 仅限脚本内调用）。
    let server_get_hash = state
        .config()
        .get_binary_hash
        .as_deref()
        .filter(|v| !v.is_empty());
    if let Some(expected_get) = server_get_hash
        && !use_token
        && ct_eq(&caller_hash, expected_get)
    {
        return Err(VeilError::Auth {
            message: "原始凭据请求被拒绝（token=false/--raw）：不允许终端直接调用".to_string(),
        });
    }
    let (entry, field) = entry_selector(body);
    let entry = entry.ok_or_else(|| VeilError::BadRequest {
        message: "取用选择器缺失：entry 必填（POST /credential 须携带 entry，如 {\"entry\":\"网易\",\"field\":\"授权码\"}；缺 field 取整条目）"
            .to_string(),
    })?;

    let pending_key = format!("{caller_path}:{caller_hash}");
    let mut hash_grace = false;
    let mut grace_notify: Option<(String, String, u64)> = None;
    // AUTH-4：调用者身份未匹配任何注册条目时置位；自动放行仅对已注册条目生效。
    let mut unenrolled = false;
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
                grace_notify = caller
                    .old_hash
                    .clone()
                    .zip(caller.old_hash_expires_at)
                    .map(|(old, exp)| (caller.caller_path.clone(), old, exp));
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
            unenrolled = true;
            Some(state.config().auto_approve)
        }
    };
    if hash_grace && let Some((entry, old_hash, exp)) = grace_notify {
        notify_hash_grace_once(state, &entry, &old_hash, exp);
    }

    check_rate(
        state.credential_hits(),
        &pending_key,
        CREDENTIAL_RATE_WINDOW_SECS,
    )
    .await?;

    // AUTH-4：未注册调用方默认转审批（显式 `Deny` 才拒绝），不因全局默认放行取值直接放行。
    if unenrolled {
        return match state.config().auto_approve {
            AutoApprove::Deny => Err(VeilError::Auth {
                message: "未注册调用方且自动放行=False，拒绝".to_string(),
            }),
            _ => {
                approval_dual_mode(
                    state,
                    &pending_key,
                    "unenrolled_default_pending",
                    &entry,
                    field.as_deref(),
                    use_token,
                )
                .await
            }
        };
    }

    match decision {
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
        Some(_) => {}
    }

    query_keepass(state, &entry, field.as_deref(), use_token).await
}

#[cfg(test)]
mod tests;
