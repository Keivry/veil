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
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>> {
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
        name: None,
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
    pub reg_id: String,
    #[serde(default)]
    pub reaction: Option<String>,
    #[serde(default)]
    pub new_hash: String,
}

pub async fn approve_hash_change_handler(
    State(state): State<AppState>,
    Json(body): Json<ApproveHashChangeBody>,
) -> Result<Json<Value>> {
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
            ("CREDENTIAL_BLOCK_WAIT".to_string(), "1".to_string()),
            (
                "APPROVAL_WHITELIST".to_string(),
                "@admin:example.com".to_string(),
            ),
        ]);
        service::credential::test_support::inject_sink(
            AppState::new(
                Config::load_from(&env).unwrap(),
                SqliteOutcome {
                    sqlite_ok: true,
                    sqlite_error: None,
                    db_path: PathBuf::from("/tmp/x.sqlite"),
                },
            ),
            service::credential::test_support::InjectSink::success(),
        )
    }

    async fn wait_event_id(state: &AppState) -> String {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let ids = state.approval.pending_event_ids().await;
                if let Some(id) = ids.into_iter().next() {
                    return id;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("审批建单超时")
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
    async fn register_caller_handler_response_carries_nonempty_reg_id_and_legacy_fields() {
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
        let worker = state.clone();
        let request = tokio::spawn(async move {
            register_caller_handler(State(worker), HeaderMap::new(), body).await
        });
        let event_id = wait_event_id(&state).await;
        state
            .approval
            .resolve(&event_id, "@admin:example.com", true)
            .await;
        let Json(resp) = request.await.unwrap().unwrap();
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

    #[tokio::test]
    async fn emergency_revoke_network_ranges() {
        // C13/D13：保留现有内网网段 + file_present 放行，只认 TCP 远端。
        let state = revoke_test_state();
        service::register_caller(&state, "/s/net.sh", "h-net", "src-net")
            .await
            .unwrap();
        let private = [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.20.0.1",
            "192.168.0.5",
            "169.254.10.20",
            "100.64.0.1",
            "fd00::1",
            "fe80::1",
        ];
        assert!(
            crate::auth::is_private_ip("localhost"),
            "localhost 须判内网"
        );
        for ip in private {
            assert!(crate::auth::is_private_ip(ip), "{ip} 须判内网");
            let peer: std::net::IpAddr = ip.parse().unwrap();
            let Json(resp) = emergency_revoke_handler(
                State(state.clone()),
                PeerIp(Some(peer)),
                HeaderMap::new(),
                revoke_body("/s/net.sh"),
            )
            .await
            .unwrap();
            assert_eq!(resp["ok"], true, "{ip} 须直接吊销（内网豁免）");
        }
        // 公网来源转常规审批（202），不直接吊销。
        let public: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let err = emergency_revoke_handler(
            State(state.clone()),
            PeerIp(Some(public)),
            HeaderMap::new(),
            revoke_body("/s/net.sh"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::ACCEPTED, "公网须转审批");
        // 伪造内网 X-Forwarded-For 不改变 TCP 远端判定，仍转审批。
        let mut forged = HeaderMap::new();
        forged.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let err = emergency_revoke_handler(
            State(state),
            PeerIp(Some(public)),
            forged,
            revoke_body("/s/net.sh"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::ACCEPTED, "XFF 伪造无效");
    }

    #[tokio::test]
    async fn approve_hash_change_handler_contract() {
        // C3/D3：缺 `reg_id`/`reaction` 按 `caller_path` + 保持自动落定并返回成功。
        let state = revoke_test_state();
        service::register_caller(&state, "/s/contract.sh", "c-old", "src-contract")
            .await
            .unwrap();
        let Json(resp) = approve_hash_change_handler(
            State(state.clone()),
            Json(ApproveHashChangeBody {
                caller_path: "/s/contract.sh".to_string(),
                reg_id: String::new(),
                reaction: None,
                new_hash: "c-new".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp["ok"], true);
        {
            let registry = state.registry.read().await;
            let e = registry.lookup_by_path("/s/contract.sh").unwrap();
            assert_eq!(e.expected_hash, "c-new");
            assert!(e.enabled && !e.revoked, "缺省 reaction 按保持自动并激活");
            assert_eq!(e.allow_mode, None, "缺省 reaction 不得改动 allow_mode");
        }
        // `reg_id`（哈希）可定位：显式 `✅` 降级人工。
        let Json(resp2) = approve_hash_change_handler(
            State(state.clone()),
            Json(ApproveHashChangeBody {
                caller_path: String::new(),
                reg_id: "c-new".to_string(),
                reaction: Some("✅".to_string()),
                new_hash: "c-next".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp2["ok"], true);
        {
            let registry = state.registry.read().await;
            let e = registry.lookup_by_path("/s/contract.sh").unwrap();
            assert_eq!(e.expected_hash, "c-next");
            assert_eq!(
                e.allow_mode,
                Some(crate::config::AutoApprove::Pending),
                "✅ 须降级人工"
            );
        }
        // 未知 reaction 仍 400（不弱化显式校验）。
        let err = approve_hash_change_handler(
            State(state),
            Json(ApproveHashChangeBody {
                caller_path: "/s/contract.sh".to_string(),
                reg_id: String::new(),
                reaction: Some("👍".to_string()),
                new_hash: "c-x".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }
}
