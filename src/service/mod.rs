use {
    crate::{
        approval::{ApprovalGateway as _, NoopApproval, PendingRecord},
        auth::{ct_eq, is_private_ip, secret_eq},
        config::{AutoApprove, CREDENTIAL_RATE_WINDOW_SECS, REGISTER_RATE_WINDOW_SECS},
        error::{Result, VeilError},
        registry::CallerEntry,
        state::AppState,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        time::{Duration, Instant},
    },
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
    /// Go 互操作别名：`body.auth.get_binary_hash` 等价 `X-Get-Binary-Hash` 头。
    #[serde(default)]
    pub get_binary_hash: Option<String>,
    /// Go 互操作别名：`body.auth.get_binary_secret` 等价 `X-Get-Binary-Secret` 头（及
    /// `body.secret`）。
    #[serde(default)]
    pub get_binary_secret: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
    /// 取用选择器：条目名（Go `get credential <entry> <field>` 的 entry）。
    #[serde(default)]
    pub entry: Option<String>,
    /// 取用选择器：字段名单数形态。
    #[serde(default)]
    pub field: Option<String>,
    /// 取用选择器：字段名复数形态（接受字符串或字符串数组，兼容 Go 侧形态）。
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
    /// 脱敏开关：`None` 默认 true；`password` 与受保护自定义属性按 `use_token` 脱敏。
    #[serde(default)]
    pub token: Option<bool>,
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
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub allow_mode: Option<AutoApprove>,
}

fn registration_view(entry: &CallerEntry) -> RegistrationView {
    RegistrationView {
        caller_path: entry.caller_path.clone(),
        enabled: entry.enabled,
        revoked: entry.revoked,
        status: entry.status_emoji().to_string(),
        name: entry.name.clone(),
        description: entry.description.clone(),
        allow_mode: entry.allow_mode.or(entry.auto_approve),
    }
}

/// 限流表（有界 + 双触发清扫，对齐原仓语义）：请求路径内联清扫，不新增后台任务。
/// - 计数触发：条目超 `SWEEP_LEN` 时清过期键；
/// - 时间触发：距上次清扫超 `SWEEP_SECS` 时清过期键；
/// - 硬上限：超 `MAX_ENTRIES` 时挤出任意非当前键（永不影响本次判定）。
#[derive(Debug)]
pub struct RateTable {
    hits: HashMap<String, Instant>,
    last_sweep: Instant,
}

impl RateTable {
    pub const MAX_ENTRIES: usize = 4096;
    pub const SWEEP_LEN: usize = 1000;
    pub const SWEEP_SECS: u64 = 60;

    pub fn new() -> Self {
        Self { hits: HashMap::new(), last_sweep: Instant::now() }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.hits.len() }
}

impl Default for RateTable {
    fn default() -> Self { Self::new() }
}

fn check_rate(
    hits: &std::sync::Mutex<RateTable>,
    key: &str,
    window_secs: u64,
) -> Result<()> {
    let mut guard = hits.lock().map_err(|_| VeilError::Storage {
        message: "限流表锁定失败".to_string(),
    })?;
    let now = Instant::now();
    if guard.hits.len() > RateTable::SWEEP_LEN
        || now.duration_since(guard.last_sweep).as_secs() >= RateTable::SWEEP_SECS
    {
        guard
            .hits
            .retain(|_, t| now.duration_since(*t).as_secs() < window_secs);
        guard.last_sweep = now;
    }
    if let Some(last) = guard.hits.get(key)
        && now.duration_since(*last).as_secs() < window_secs
    {
        let remain = window_secs.saturating_sub(now.duration_since(*last).as_secs());
        return Err(VeilError::RateLimited {
            retry_after_secs: remain.max(1),
        });
    }
    guard.hits.insert(key.to_string(), now);
    if guard.hits.len() > RateTable::MAX_ENTRIES
        && let Some(victim) = guard.hits.keys().find(|k| k.as_str() != key).cloned()
    {
        guard.hits.remove(&victim);
    }
    Ok(())
}

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

fn approval_event_id(key: &str, reason: &str) -> String {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash as _, Hasher as _},
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = DefaultHasher::new();
    (key, reason, nanos).hash(&mut hasher);
    format!("$veil-{nanos}-{:08x}", hasher.finish() & 0xffff_ffff)
}

async fn submit_pending(state: &AppState, key: &str, reason: &str) -> String {
    let record = PendingRecord::new(key, reason);
    let gateway = NoopApproval;
    let _ = gateway.request_approval(&record);
    state.pending.insert(record);
    let event_id = approval_event_id(key, reason);
    let branch = matrix::MatrixBranch::from_reason(reason);
    state.approval.submit_branch(&event_id, branch).await;
    let bot = matrix::MatrixBot::with_client(
        state.config.homeserver.clone(),
        state.config.room_id.clone(),
        state.config.matrix_access_token.clone(),
        (*state.http_client).clone(),
    );
    let summary = format!("{reason} :: {key}");
    let text = bot.format_approval(branch, None, &summary);
    tracing::info!("审批已发送: event {event_id} 原因 {reason}");
    tokio::spawn(async move {
        if let Err(err) = bot.send_text(&text).await {
            tracing::warn!("审批消息发送失败: {err:#}");
        }
    });
    event_id
}

async fn record_pending(state: &AppState, key: &str, reason: &str) -> VeilError {
    submit_pending(state, key, reason).await;
    VeilError::PendingApproval {
        message: format!("已转 Matrix 人工审批: {reason}"),
    }
}

async fn approval_dual_mode(
    state: &AppState,
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    if !state.config.credential_block_wait {
        return Err(record_pending(state, key, reason).await);
    }
    let event_id = submit_pending(state, key, reason).await;
    let timeout = Duration::from_secs(
        state.config.credential_approval_timeout_secs.max(1) as u64,
    );
    match state.approval.ask(&event_id, timeout).await {
        Some(true) => query_keepass(state, entry, field, use_token).await,
        Some(false) => Err(VeilError::Auth {
            message: "凭据审批被拒绝".to_string(),
        }),
        None => Err(VeilError::Auth {
            message: "凭据审批超时，按拒绝处理".to_string(),
        }),
    }
}

fn notify_hash_change(state: &AppState, key: &str, detail: &str) {
    let bot = matrix::MatrixBot::with_client(
        state.config.homeserver.clone(),
        state.config.room_id.clone(),
        state.config.matrix_access_token.clone(),
        (*state.http_client).clone(),
    );
    let summary = format!("哈希变更 :: {key} :: {detail}");
    let text = bot.format_approval(matrix::MatrixBranch::Credential, None, &summary);
    tokio::spawn(async move {
        let _ = bot.send_text(&text).await;
    });
    tracing::warn!("调用方哈希变更通知: {summary}");
}

/// 凭据审批问询（300s 超时口径）：超时/发送失败返回 None，调用方按 rejected 处理。
pub async fn await_credential_approval(state: &AppState, event_id: &str) -> Option<bool> {
    let timeout = state.approval.credential_timeout();
    state.approval.ask(event_id, timeout).await
}

/// 审计审批问询（`AUDIT_TIMEOUT` 口径，默认 90s）：超时返回 None，调用方按 rejected 处理。
pub async fn await_audit_approval(state: &AppState, event_id: &str) -> Option<bool> {
    state.approval.ask_audit(event_id).await
}

pub async fn handle_credential(
    state: &AppState,
    headers: &CredentialHeaders,
    body: &CredentialBody,
) -> Result<serde_json::Value> {
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
    let use_token = body.token.unwrap_or(true);
    let header_hash = effective_binary_hash(headers, body);
    let server_get_hash = state
        .config
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
    if let Some(expected_secret) = state.config.credential_secret.as_deref()
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
        let registry = state.registry.read().await;
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
                Some(caller.effective_allow_mode(state.config.auto_approve))
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
                Some(caller.effective_allow_mode(state.config.auto_approve))
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
            Some(caller.effective_allow_mode(state.config.auto_approve))
        } else {
            Some(state.config.auto_approve)
        }
    };
    if hash_grace {
        notify_hash_change(state, &pending_key, "old_hash宽限内放行");
    }

    check_rate(
        &state.credential_hits,
        &pending_key,
        CREDENTIAL_RATE_WINDOW_SECS,
    )?;

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
        Some(AutoApprove::Pending)
            if state.config.entry_mode != crate::config::EntryMode::CredentialOnly =>
        {
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
    state: &AppState,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    let snapshot = match state.keepass.fetch_entry(entry.to_string()).await {
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
    let vault = state.vault.as_ref();
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

fn notify_keepass_failure(state: &AppState, entry: &str, detail: &str) {
    let bot = matrix::MatrixBot::with_client(
        state.config.homeserver.clone(),
        state.config.room_id.clone(),
        state.config.matrix_access_token.clone(),
        (*state.http_client).clone(),
    );
    let summary = format!("KeePass 查询失败 :: {entry} :: {detail}");
    let text = bot.format_approval(matrix::MatrixBranch::Credential, Some(false), &summary);
    tokio::spawn(async move {
        let _ = bot.send_text(&text).await;
    });
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
            secret_eq(got, expected)
        }
        _ => false,
    };
    if !admin_ok && !secret_ok {
        return Err(VeilError::Unauthorized {
            message: "注册查询需鉴权".to_string(),
        });
    }
    let registry = state.registry.read().await;
    Ok(registry.snapshot().iter().map(registration_view).collect())
}

pub async fn register_caller(
    state: &AppState,
    caller_path: &str,
    caller_hash: &str,
    source: &str,
) -> Result<RegistrationView> {
    register_caller_extended(
        state,
        &crate::registry::RegisterParams {
            caller_path: caller_path.to_string(),
            caller_hash: caller_hash.to_string(),
            ..crate::registry::RegisterParams::default()
        },
        source,
    )
    .await
}

pub async fn register_caller_extended(
    state: &AppState,
    params: &crate::registry::RegisterParams,
    source: &str,
) -> Result<RegistrationView> {
    if params.caller_path.trim().is_empty() || params.caller_hash.trim().is_empty() {
        return Err(VeilError::BadRequest {
            message: "caller_path 与 caller_hash 均必填".to_string(),
        });
    }
    {
        let registry = state.registry.read().await;
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
    check_rate(&state.register_hits, &rate_key, REGISTER_RATE_WINDOW_SECS)?;
    let view = {
        let mut registry = state.registry.write().await;
        let entry = registry.register_extended(params)?;
        let view = registration_view(entry);
        registry.save_to(&state.registry_path).ok();
        view
    };
    Ok(view)
}

pub async fn revoke_caller(state: &AppState, key: &str) -> Result<RegistrationView> {
    let view = {
        let mut registry = state.registry.write().await;
        let entry = registry.revoke(key)?;
        let view = registration_view(entry);
        registry.save_to(&state.registry_path).ok();
        view
    };
    Ok(view)
}

pub async fn emergency_revoke(
    state: &AppState,
    key: &str,
    admin_token: Option<&str>,
    peer_ip: Option<&str>,
    file_present: bool,
) -> Result<RegistrationView> {
    let admin_ok = match (admin_token, state.config.observability_admin_token.as_str()) {
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
        let view = registration_view(entry);
        registry.save_to(&state.registry_path).ok();
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
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            entry: Some("网易".to_string()),
            field: Some("授权码".to_string()),
            fields: None,
            token: None,
        }
    }

    fn credential_value(out: &serde_json::Value) -> &str {
        out.get("value").and_then(|v| v.as_str()).unwrap_or("")
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
            &headers("gethash", Some("s3cr3t")),
            &body("callerhash1", "/s/a.sh", None),
        )
        .await
        .unwrap();
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }

    #[tokio::test]
    async fn 三因子缺一即403() {
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
    async fn 伪造secret被拒403() {
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
    async fn body_secret兼容放行() {
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
    async fn 冒用get自身哈希拒403() {
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
    async fn go体别名无头放行() {
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
    async fn go体别名密钥错仍403() {
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
    async fn 缺entry报400带指引() {
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
    async fn 缺field取整条目() {
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
    async fn fields复数形态放行() {
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
    async fn token假值返回原文() {
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
    async fn 缺属性报404具名() {
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
    async fn 真实后端缺条目经服务报404() {
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
                memory_only: false,
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
            &headers("gethash", Some("s3cr3t")),
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
            &headers("gethash", Some("s3cr3t")),
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
            &headers("gethash", Some("s3cr3t")),
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
            &headers("gethash", Some("s3cr3t")),
            &body("rlhash", "/s/rl.sh", None),
        )
        .await
        .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
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

    #[test]
    fn 限流表双触发清扫只删过期键() {
        use std::sync::Mutex;
        let table = Mutex::new(RateTable::new());
        // 计数触发：超 1000 条后下一次检查清扫；窗口 0 使旧键全部过期。
        for i in 0..(RateTable::SWEEP_LEN + 5) {
            check_rate(&table, &format!("cold-{i}"), 0).unwrap();
        }
        let guard = table.lock().unwrap();
        assert!(
            guard.len() <= RateTable::SWEEP_LEN + 6,
            "过期键须被清扫，长跑不膨胀: {}",
            guard.len()
        );
        drop(guard);
        // 活跃键判定不受清扫影响：同键在窗口内仍限流。
        check_rate(&table, "hot-key", 3600).unwrap();
        let err = check_rate(&table, "hot-key", 3600).unwrap_err();
        assert_eq!(
            err.status_code(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn 限流表硬上限挤出不影响本次判定() {
        use std::sync::Mutex;
        let table = Mutex::new(RateTable::new());
        for i in 0..(RateTable::MAX_ENTRIES + 10) {
            check_rate(&table, &format!("k-{i}"), u64::MAX).unwrap();
        }
        let guard = table.lock().unwrap();
        assert_eq!(guard.len(), RateTable::MAX_ENTRIES, "硬上限须钳制");
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

    #[tokio::test]
    async fn 审批建单落矩阵网关且问询口径分表() {
        use std::time::Duration;
        let env = cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]);
        let state = cred_state(&env);
        assert_eq!(state.approval.pending_len().await, 0);
        register_caller(&state, "/s/w.sh", "goodhash", "wire-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/w.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/w.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.approval.pending_len().await, 1);
        assert_eq!(
            state.approval.credential_timeout(),
            Duration::from_secs(300)
        );
        assert_eq!(state.approval.audit_timeout(), Duration::from_secs(90));
        state.approval.submit("$wire-ev").await;
        state
            .approval
            .resolve("$wire-ev", "@admin:example.com", true)
            .await;
        let _ = state.approval.submit("$wire-ev2").await;
        assert_eq!(
            await_credential_approval(&state, "$wire-ev").await,
            Some(true)
        );
        assert_eq!(
            state
                .approval
                .ask("$wire-ev2", Duration::from_millis(50))
                .await,
            None
        );
        assert_eq!(state.approval.pending_len().await, 2);
    }

    #[tokio::test]
    async fn 审计问询走_audit_timeout口径() {
        let mut env = cred_env(&[]);
        env.insert("AUDIT_TIMEOUT".to_string(), "1".to_string());
        let state = cred_state(&env);
        assert_eq!(
            state.approval.audit_timeout(),
            std::time::Duration::from_secs(1)
        );
        state.approval.submit("$audit-ev").await;
        assert_eq!(
            await_audit_approval(&state, "$audit-ev-missing").await,
            None
        );
        assert_eq!(state.approval.pending_len().await, 1);
    }

    #[tokio::test]
    async fn 发送失败仍回202建单() {
        let env = cred_env(&[
            ("APPROVAL_WHITELIST", "@admin:example.com"),
            ("HOMESERVER", "http://127.0.0.1:9"),
        ]);
        let state = cred_state(&env);
        register_caller(&state, "/s/down.sh", "goodhash", "wire-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/down.sh", true)
            .unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/down.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
        assert_eq!(state.approval.pending_len().await, 1);
    }

    use std::collections::BTreeMap as TestMap;

    fn entries_for(entry: &str, fields: &[&str]) -> TestMap<String, Vec<String>> {
        TestMap::from([(
            entry.to_string(),
            fields.iter().map(|s| (*s).to_string()).collect(),
        )])
    }

    async fn enrolled_with_entries(
        state: &AppState,
        path: &str,
        hash: &str,
        entries: TestMap<String, Vec<String>>,
    ) {
        register_caller_extended(
            state,
            &crate::registry::RegisterParams {
                caller_path: path.to_string(),
                caller_hash: hash.to_string(),
                name: "test".to_string(),
                description: String::new(),
                entries,
                allow_mode: None,
            },
            &format!("acl-test-{path}"),
        )
        .await
        .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled(path, true)
            .unwrap();
    }

    #[tokio::test]
    async fn 越权条目拒绝403() {
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
    async fn 越权字段拒绝403() {
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
    async fn 授权范围内放行200() {
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
    async fn 哈希篡改转审批202并通知() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        enrolled_with_entries(
            &state,
            "/s/tamper.sh",
            "goodhash",
            entries_for("网易", &["授权码"]),
        )
        .await;
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/tamper.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::ACCEPTED);
        assert_eq!(state.pending.len(), 1);
    }

    #[tokio::test]
    async fn 旧哈希宽限内放行() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        enrolled_with_entries(
            &state,
            "/s/grace.sh",
            "h1",
            entries_for("网易", &["授权码"]),
        )
        .await;
        state
            .registry
            .write()
            .await
            .approve_hash_change("/s/grace.sh", "h2")
            .unwrap();
        let out = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("h1", "/s/grace.sh", None),
        )
        .await
        .unwrap();
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }

    #[tokio::test]
    async fn go正常脚本已注册匹配放行200() {
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
    async fn 纯body形态无头放行() {
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
    async fn 头哈希与服务端失配拒403() {
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
    async fn 终端token取用放行() {
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
    async fn 已吊销调用方哈希失配仍拒403() {
        let env = cred_env(&[]);
        let state = cred_state(&env);
        register_caller(&state, "/s/r.sh", "goodhash", "rev-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/r.sh", true)
            .unwrap();
        revoke_caller(&state, "/s/r.sh").await.unwrap();
        let err = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("badhash", "/s/r.sh", None),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::FORBIDDEN);
        assert!(state.pending.is_empty());
    }

    #[tokio::test]
    async fn 同秘密跨请求同token() {
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

    #[tokio::test]
    async fn 阻塞模批准同请求返回凭据() {
        let env = cred_env(&[
            ("CREDENTIAL_BLOCK_WAIT", "1"),
            ("APPROVAL_WHITELIST", "@admin:example.com"),
        ]);
        let state = cred_state(&env);
        register_caller(&state, "/s/b.sh", "goodhash", "blk-src")
            .await
            .unwrap();
        state
            .registry
            .write()
            .await
            .set_enabled("/s/b.sh", true)
            .unwrap();
        let worker = state.clone();
        let handle = tokio::spawn(async move {
            handle_credential(
                &worker,
                &headers("gethash", Some("s3cr3t")),
                &body("badhash", "/s/b.sh", None),
            )
            .await
        });
        let event_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let ids = state.approval.pending_event_ids().await;
                if let Some(id) = ids.into_iter().next() {
                    return id;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("阻塞模须先建单");
        state
            .approval
            .resolve(&event_id, "@admin:example.com", true)
            .await;
        let out = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("阻塞问询须在批准后返回")
            .expect("任务不崩")
            .expect("批准后同请求须返回凭据");
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }
}
