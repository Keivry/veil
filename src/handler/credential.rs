//! 凭据面处理器：三因子鉴权 + 注册/吊销/哈希变更审批 + 紧急吊销。
//! 纯透传层，业务语义归 `service`（`handle_credential/register/revoke/approve`）。
//! 紧急吊销只认 TCP 远端 `ConnectInfo`，禁采信代理头。

use {
    crate::{
        error::{Result, VeilError},
        service::{self, CredentialBody, CredentialHeaders},
        state::AppState,
    },
    axum::{
        Json,
        extract::{ConnectInfo, State},
        http::HeaderMap,
    },
    serde::Deserialize,
    serde_json::{Value, json},
    std::net::SocketAddr,
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
}

fn parse_register_entries(body: &RegisterBody) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(v) = body.entries.as_ref() {
        match v {
            serde_json::Value::Object(map) => {
                for (k, fv) in map {
                    let key = k.trim();
                    if key.is_empty() {
                        continue;
                    }
                    let fields = match fv {
                        serde_json::Value::String(s) => {
                            let s = s.trim();
                            if s.is_empty() {
                                vec![]
                            } else {
                                vec![s.to_string()]
                            }
                        }
                        serde_json::Value::Array(items) => items
                            .iter()
                            .filter_map(|i| i.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                        _ => vec![],
                    };
                    out.insert(key.to_string(), fields);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    match item {
                        serde_json::Value::String(s) => {
                            let s = s.trim();
                            if !s.is_empty() {
                                out.entry(s.to_string()).or_default();
                            }
                        }
                        serde_json::Value::Object(map) => {
                            for (k, fv) in map {
                                let key = k.trim();
                                if key.is_empty() {
                                    continue;
                                }
                                let fields = match fv {
                                    serde_json::Value::String(s) => {
                                        let s = s.trim();
                                        if s.is_empty() {
                                            vec![]
                                        } else {
                                            vec![s.to_string()]
                                        }
                                    }
                                    serde_json::Value::Array(a) => a
                                        .iter()
                                        .filter_map(|i| i.as_str())
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(str::to_string)
                                        .collect(),
                                    _ => vec![],
                                };
                                out.insert(key.to_string(), fields);
                            }
                        }
                        _ => {}
                    }
                }
            }
            serde_json::Value::String(s) => {
                let s = s.trim();
                if !s.is_empty() {
                    out.entry(s.to_string()).or_default();
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        let single_entry = body
            .entry
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(e) = single_entry {
            let mut fields: Vec<String> = vec![];
            if let Some(f) = body
                .field
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                fields.push(f.to_string());
            }
            if let Some(fv) = body.fields.as_ref() {
                match fv {
                    serde_json::Value::String(s) => {
                        let s = s.trim();
                        if !s.is_empty() && !fields.contains(&s.to_string()) {
                            fields.push(s.to_string());
                        }
                    }
                    serde_json::Value::Array(items) => {
                        for i in items {
                            if let Some(s) = i.as_str().map(str::trim).filter(|s| !s.is_empty())
                                && !fields.contains(&s.to_string())
                            {
                                fields.push(s.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            out.insert(e.to_string(), fields);
        }
    }
    out
}

fn parse_register_allow_mode(body: &RegisterBody) -> Option<crate::config::AutoApprove> {
    use std::str::FromStr as _;
    if let Some(raw) = body
        .allow_mode
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Ok(mode) = crate::config::AutoApprove::from_str(raw)
    {
        return Some(mode);
    }
    body.auto.map(|a| {
        if a {
            crate::config::AutoApprove::Allow
        } else {
            crate::config::AutoApprove::Deny
        }
    })
}

pub async fn register_caller_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<Json<Value>> {
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
        entries: parse_register_entries(&body),
        allow_mode: parse_register_allow_mode(&body),
    };
    let view =
        service::register_caller_extended(&state, &params, source.as_deref().unwrap_or("unknown"))
            .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
}

fn revoke_key(body: &RevokeBody) -> Result<String> {
    body.key
        .clone()
        .or_else(|| body.caller_path.clone())
        .or_else(|| body.caller_hash.clone())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VeilError::BadRequest {
            message: "key/caller_path/caller_hash 三选一必填".to_string(),
        })
}

pub async fn revoke_handler(
    State(state): State<AppState>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>> {
    let view = service::revoke_caller(&state, &revoke_key(&body)?).await?;
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
    #[serde(default)]
    pub file_present: bool,
}

pub struct PeerIp(pub Option<String>);

impl<S> axum::extract::FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        Ok(Self(ip))
    }
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
    })?;
    let admin_token = body
        .admin_token
        .clone()
        .or_else(|| header_str(&headers, "x-admin-token"));
    // 安全契约（security-compat-fix）：紧急吊销只认 TCP 远端 `ConnectInfo`，
    // MUST NOT 回退 `X-Forwarded-For` 等代理头（伪造头可绕过内网豁免）。
    let peer_ip = peer.0;
    let view = service::emergency_revoke(
        &state,
        &key,
        admin_token.as_deref(),
        peer_ip.as_deref(),
        body.file_present,
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveHashChangeBody {
    #[serde(default)]
    pub caller_path: String,
    #[serde(default)]
    pub new_hash: String,
}

pub async fn approve_hash_change_handler(
    State(state): State<AppState>,
    Json(body): Json<ApproveHashChangeBody>,
) -> Result<Json<Value>> {
    let view = service::approve_hash_change(&state, &body.caller_path, &body.new_hash).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            config::Config,
            service,
            state::{AppState, SqliteOutcome},
        },
        axum::{
            Json,
            extract::State,
            http::{HeaderMap, StatusCode},
        },
        std::{collections::HashMap, path::PathBuf},
    };

    fn revoke_test_state() -> AppState {
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
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        )
    }

    fn revoke_body(key: &str) -> Json<EmergencyRevokeBody> {
        Json(EmergencyRevokeBody {
            key: Some(key.to_string()),
            caller_path: None,
            caller_hash: None,
            admin_token: None,
            file_present: false,
        })
    }

    #[tokio::test]
    async fn forged_proxy_headers_do_not_bypass_revoke_check() {
        // 内网豁免只认 TCP 远端：公网对端携带伪造内网 XFF 仍转审批，不直接吊销。
        let state = revoke_test_state();
        service::register_caller(&state, "/s/xff.sh", "h-xff", "src-xff")
            .await
            .unwrap();
        let mut forged = HeaderMap::new();
        forged.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let err = emergency_revoke_handler(
            State(state.clone()),
            PeerIp(Some("203.0.113.9".to_string())),
            forged,
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::ACCEPTED);
        // 回环 TCP 对端无头时豁免路径仍可用。
        let ok = emergency_revoke_handler(
            State(state),
            PeerIp(Some("127.0.0.1".to_string())),
            HeaderMap::new(),
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap();
        assert_eq!(ok.0["ok"], true);
    }
}
