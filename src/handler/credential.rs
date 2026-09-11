//! 凭据面处理器：三因子鉴权 + 注册/吊销/哈希变更审批 + 紧急吊销。
//! 纯透传层，业务语义归 `service`（`handle_credential/register/revoke/approve`）。
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
    let peer_ip = peer.0.map(|ip| ip.to_string());
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
    async fn register_response_carries_nonempty_reg_id_and_legacy_fields() {
        // GO：`/register-caller` 加性超集——新增非空 `reg_id`（脚本哈希回显），
        // 既有 `ok`/`registration`/`name`/`script_path`/`script_hash`/`entries`/`allow_mode` 不删。
        let state = revoke_test_state();
        let body = Json(RegisterBody {
            caller_path: "/srv/reg-id.sh".to_string(),
            caller_hash: "h-reg-id-1".to_string(),
            source: Some("go-client".to_string()),
            name: "reg-id-job".to_string(),
            description: String::new(),
            entries: Some(json!({"网易": ["授权码"]})),
            entry: None,
            fields: None,
            field: None,
            allow_mode: Some("true".to_string()),
            auto: None,
        });
        let Json(resp) = register_caller_handler(State(state), HeaderMap::new(), body)
            .await
            .unwrap();
        let reg_id = resp["reg_id"].as_str().unwrap_or("");
        assert!(!reg_id.is_empty(), "reg_id 须非空: {resp}");
        assert_eq!(reg_id, "h-reg-id-1", "reg_id 须稳定可取（脚本哈希回显）");
        assert_eq!(resp["ok"], true);
        let registration = &resp["registration"];
        assert_eq!(registration["caller_path"], "/srv/reg-id.sh");
        assert_eq!(resp["name"], "reg-id-job");
        assert_eq!(resp["script_path"], "/srv/reg-id.sh");
        assert_eq!(resp["script_hash"], "h-reg-id-1");
        assert_eq!(resp["entries"]["网易"][0], "授权码");
        assert_eq!(resp["allow_mode"], "true");
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
            PeerIp(Some("203.0.113.9".parse().unwrap())),
            forged,
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::ACCEPTED);
        // 回环 TCP 对端无头时豁免路径仍可用。
        let ok = emergency_revoke_handler(
            State(state),
            PeerIp(Some("127.0.0.1".parse().unwrap())),
            HeaderMap::new(),
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap();
        assert_eq!(ok.0["ok"], true);
    }
}
