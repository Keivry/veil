//! 凭据面处理器：三因子鉴权 + 注册/吊销/哈希变更审批 + 紧急吊销。
//! 纯透传层，业务语义归 `service`（`handle_credential/register/revoke/approve`）；
//! 注册 DTO→域映射（条目/字段/放行模式）归 `service::credential::register_map`
//! （H4/D4），本层仅提取原始字段并委派，不承载业务解析。
//! 紧急吊销只认 TCP 远端 `ConnectInfo`，禁采信代理头。

use {
    crate::{
        error::{Result, VeilError},
        handler::peer_ip::PeerIp,
        service::{self, CredentialBody, CredentialHeaders},
        state::AppState,
    },
    axum::{Json, extract::State, http::HeaderMap},
    serde::Deserialize,
    serde_json::{Value, json},
};

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn credential_headers(headers: &HeaderMap) -> CredentialHeaders {
    CredentialHeaders::new(
        header_str(headers, "x-get-binary-hash"),
        header_str(headers, "x-get-binary-secret"),
    )
}

/// 写端点三因子守卫入口（`AUTH-1`/`AUTH-3`）：把头凭证与 DTO 的 `auth`/`secret`
/// 归拢为 [`CredentialBody`] 后委派 [`service::verify_three_factor_write`]；三处写端点
/// （`/approve-hash-change`、`/register-caller`、`/revoke`）与 `/credential` 同源，
/// 且额外要求部署密钥已配置（`AUTH-11`，fail-closed；读路径不受影响）。
async fn require_three_factor(
    state: &AppState,
    headers: &HeaderMap,
    auth: Option<&service::AuthBlock>,
    secret: Option<&str>,
) -> Result<()> {
    let body = CredentialBody {
        secret: secret.map(str::to_string),
        auth: auth.cloned(),
        ..CredentialBody::default()
    };
    service::verify_three_factor_write(state, &credential_headers(headers), &body).await
}

pub async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CredentialBody>,
) -> Result<Json<Value>> {
    let payload = service::handle_credential(&state, &credential_headers(&headers), &body).await?;
    Ok(Json(json!({ "ok": true, "credential": payload })))
}

pub async fn registrations_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let views = service::list_registrations(
        &state,
        header_str(&headers, "x-admin-token").as_deref(),
        header_str(&headers, "x-get-binary-secret").as_deref(),
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registrations": views })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterBody {
    #[serde(default, alias = "script_path", alias = "path")]
    pub caller_path: String,
    #[serde(default, alias = "script_hash", alias = "hash")]
    pub caller_hash: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default, alias = "desc")]
    pub description: String,
    #[serde(default)]
    pub entries: Option<serde_json::Value>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default, alias = "auto_approve", alias = "allowMode")]
    pub allow_mode: Option<String>,
    #[serde(default)]
    pub auto: Option<bool>,
    #[serde(default)]
    pub auth: Option<service::AuthBlock>,
    #[serde(default)]
    pub secret: Option<String>,
}

/// Go 加性兼容（`veil-hardening` 5.x 网关侧补齐）：推导非空 `reg_id`。
/// 服务层注册前置校验 `caller_path`/`caller_hash` 均非空，`RegistrationView`
/// 的 `script_hash`（`expected_hash` 回显）在成功路径恒非空且随注册表唯一，
/// 故以其为稳定标识；依次回退 `caller_path`/`name`，末尾常量仅为防御性兜底
/// （禁止空串语义，当前校验下不可达）。
fn registration_reg_id(view: &service::RegistrationView) -> String {
    if !view.script_hash.is_empty() {
        return view.script_hash.clone();
    }
    if !view.caller_path.is_empty() {
        return view.caller_path.clone();
    }
    if !view.name.is_empty() {
        return view.name.clone();
    }
    "reg_unknown".to_string()
}

pub async fn register_caller_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<Json<Value>> {
    require_three_factor(&state, &headers, body.auth.as_ref(), body.secret.as_deref()).await?;
    let source = body
        .source
        .clone()
        .or_else(|| header_str(&headers, "x-source").or_else(|| Some("unknown".to_string())));
    let params = crate::registry::RegisterParams {
        caller_path: if body.caller_path.trim().is_empty() {
            String::new()
        } else {
            body.caller_path.trim().to_string()
        },
        caller_hash: body.caller_hash.trim().to_string(),
        name: body.name.trim().to_string(),
        description: body.description.trim().to_string(),
        entries: service::register_map::parse_register_entries(
            body.entries.as_ref(),
            body.entry.as_deref(),
            body.field.as_deref(),
            body.fields.as_ref(),
        ),
        allow_mode: service::register_map::parse_register_allow_mode(
            body.allow_mode.as_deref(),
            body.auto,
        ),
    };
    let view = service::register_caller_with_approval(
        &state,
        &params,
        source.as_deref().unwrap_or("unknown"),
    )
    .await?;
    let reg_id = registration_reg_id(&view);
    // Go 加性超集：既有 `ok`/`registration` 不删，顶层同步 Go 形态字段
    //（`reg_id`/`name`/`script_path`/`script_hash`/`entries`/`allow_mode`）供直接解析。
    Ok(Json(json!({
        "ok": true,
        "reg_id": reg_id,
        "registration": view.clone(),
        "name": view.name,
        "script_path": view.script_path,
        "script_hash": view.script_hash,
        "entries": view.entries,
        "allow_mode": view.allow_mode,
    })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub auth: Option<service::AuthBlock>,
    #[serde(default)]
    pub secret: Option<String>,
}

fn revoke_key(body: &RevokeBody) -> Result<String> {
    body.key
        .clone()
        .or_else(|| body.caller_path.clone())
        .or_else(|| body.caller_hash.clone())
        .or_else(|| body.name.clone())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VeilError::BadRequest {
            message: "key/caller_path/caller_hash/name 四选一必填".to_string(),
        })
}

pub async fn revoke_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>> {
    require_three_factor(&state, &headers, body.auth.as_ref(), body.secret.as_deref()).await?;
    let view = service::revoke_caller_with_approval(&state, &revoke_key(&body)?).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmergencyRevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
}

pub async fn emergency_revoke_handler(
    State(state): State<AppState>,
    peer: PeerIp,
    headers: HeaderMap,
    Json(body): Json<EmergencyRevokeBody>,
) -> Result<Json<Value>> {
    let key = revoke_key(&RevokeBody {
        key: body.key.clone(),
        caller_path: body.caller_path.clone(),
        caller_hash: body.caller_hash.clone(),
        name: None,
        auth: None,
        secret: None,
    })?;
    let admin_token = body
        .admin_token
        .clone()
        .or_else(|| header_str(&headers, "x-admin-token"));
    // 安全契约（security-compat-fix）：紧急吊销只认 TCP 远端 `ConnectInfo`，
    // MUST NOT 回退 `X-Forwarded-For` 等代理头（伪造头可绕过内网豁免）。
    let peer_ip = peer.0.map(|ip| ip.to_string());
    let view =
        service::emergency_revoke(&state, &key, admin_token.as_deref(), peer_ip.as_deref()).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveHashChangeBody {
    #[serde(default)]
    pub caller_path: String,
    #[serde(default)]
    pub reg_id: String,
    #[serde(default)]
    pub reaction: Option<String>,
    #[serde(default)]
    pub new_hash: String,
    #[serde(default)]
    pub auth: Option<service::AuthBlock>,
    #[serde(default)]
    pub secret: Option<String>,
}

pub async fn approve_hash_change_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ApproveHashChangeBody>,
) -> Result<Json<Value>> {
    require_three_factor(&state, &headers, body.auth.as_ref(), body.secret.as_deref()).await?;
    // C3/D3：`reg_id` 优先，缺省回退 `caller_path`；`reaction` 缺省按保持自动，
    // 未知非空值返回 400（对标 Python 显式校验）。
    let key = if body.reg_id.trim().is_empty() {
        body.caller_path.trim()
    } else {
        body.reg_id.trim()
    };
    let outcome = crate::registry::HashChangeOutcome::from_reaction(body.reaction.as_deref())
        .ok_or_else(|| VeilError::BadRequest {
            message: "reaction 必须为 🔓/✅/❎".to_string(),
        })?;
    let view = service::approve_hash_change(&state, key, &body.new_hash, outcome).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[cfg(test)]
mod tests;
