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
        ("GET_BINARY_SECRET".to_string(), "s3cr3t".to_string()),
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
        auth: Some(service::AuthBlock {
            caller_hash: Some("h-reg-id-1".to_string()),
            caller_path: Some("/srv/reg-id.sh".to_string()),
            get_binary_hash: None,
            get_binary_secret: None,
        }),
        secret: Some("s3cr3t".to_string()),
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
    // C13/D13：保留现有内网网段放行（`file_present` 自证通道已移除），只认 TCP 远端。
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
    // CRD-4：落定不激活既有条目（仅更新哈希与宽限）。
    let state = revoke_test_state();
    service::register_caller(&state, "/s/contract.sh", "c-old", "src-contract")
        .await
        .unwrap();
    let Json(resp) = approve_hash_change_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(ApproveHashChangeBody {
            caller_path: "/s/contract.sh".to_string(),
            reg_id: String::new(),
            reaction: None,
            new_hash: "c-new".to_string(),
            auth: Some(service::AuthBlock {
                caller_hash: Some("c-old".to_string()),
                caller_path: Some("/s/contract.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: Some("s3cr3t".to_string()),
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["ok"], true);
    {
        let registry = state.registry.read().await;
        let e = registry.lookup_by_path("/s/contract.sh").unwrap();
        assert_eq!(e.expected_hash, "c-new");
        assert!(
            !e.enabled && !e.revoked,
            "CRD-4：缺省 reaction 仅更新哈希，不激活既有条目"
        );
        assert_eq!(e.allow_mode, None, "缺省 reaction 不得改动 allow_mode");
    }
    // `reg_id`（哈希）可定位：显式 `✅` 降级人工。
    let Json(resp2) = approve_hash_change_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(ApproveHashChangeBody {
            caller_path: String::new(),
            reg_id: "c-new".to_string(),
            reaction: Some("✅".to_string()),
            new_hash: "c-next".to_string(),
            auth: Some(service::AuthBlock {
                caller_hash: Some("c-old".to_string()),
                caller_path: Some("/s/contract.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: Some("s3cr3t".to_string()),
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
        HeaderMap::new(),
        Json(ApproveHashChangeBody {
            caller_path: "/s/contract.sh".to_string(),
            reg_id: String::new(),
            reaction: Some("👍".to_string()),
            new_hash: "c-x".to_string(),
            auth: Some(service::AuthBlock {
                caller_hash: Some("c-old".to_string()),
                caller_path: Some("/s/contract.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: Some("s3cr3t".to_string()),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
}

fn three_factor_state() -> AppState {
    service::credential::test_support::cred_state(&service::credential::test_support::cred_env(&[]))
}

fn list_items(item: &Value, path: &str) -> Value {
    item["registrations"]
        .as_array()
        .and_then(|items| items.iter().find(|i| i["caller_path"] == path))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `CRD-3`：`GET /registrations` 每条目含 Go 契约 `type` 字段（非空、稳定 `caller`）。
#[tokio::test]
async fn registrations_response_has_type() {
    let state = three_factor_state();
    service::register_caller(&state, "/s/list-type.sh", "list-type-h", "src-list")
        .await
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-get-binary-secret", "s3cr3t".parse().unwrap());
    let Json(body) = registrations_handler(State(state.clone()), headers)
        .await
        .unwrap();
    let item = list_items(&body, "/s/list-type.sh");
    assert_eq!(item["type"], "caller", "响应须含 Go 契约 type: {body}");
    assert!(
        item["type"].as_str().is_some_and(|t| !t.is_empty()),
        "type 须非空: {item}"
    );
}

/// `CRD-3`：`allow_mode` 输出词汇为 `auto`/`manual`；输入三态兼容保持。
#[tokio::test]
async fn registrations_allow_mode_vocabulary() {
    use crate::{config::AutoApprove, registry::RegisterParams};
    let state = three_factor_state();
    {
        let mut registry = state.registry.write().await;
        for (path, hash, mode) in [
            ("/s/am-auto.sh", "am-auto-h", Some(AutoApprove::Allow)),
            ("/s/am-manual.sh", "am-manual-h", Some(AutoApprove::Pending)),
            ("/s/am-none.sh", "am-none-h", None),
        ] {
            registry
                .register_extended(&RegisterParams {
                    caller_path: path.to_string(),
                    caller_hash: hash.to_string(),
                    name: hash.to_string(),
                    allow_mode: mode,
                    ..RegisterParams::default()
                })
                .unwrap();
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert("x-get-binary-secret", "s3cr3t".parse().unwrap());
    let Json(body) = registrations_handler(State(state.clone()), headers)
        .await
        .unwrap();
    assert_eq!(list_items(&body, "/s/am-auto.sh")["allow_mode"], "auto");
    assert_eq!(list_items(&body, "/s/am-manual.sh")["allow_mode"], "manual");
    assert_eq!(
        list_items(&body, "/s/am-none.sh")["allow_mode"],
        "manual",
        "缺省词汇按 manual 呈现"
    );
    // 输入三态兼容保持（`auto`→放行、`manual`→审批、未知回退 auto 布尔）。
    assert_eq!(
        service::register_map::parse_register_allow_mode(Some("auto"), None),
        Some(AutoApprove::Allow)
    );
    assert_eq!(
        service::register_map::parse_register_allow_mode(Some("manual"), None),
        Some(AutoApprove::Pending)
    );
    assert_eq!(
        service::register_map::parse_register_allow_mode(Some("bogus"), Some(true)),
        Some(AutoApprove::Allow)
    );
}

#[tokio::test]
async fn approve_hash_change_requires_three_factor() {
    let state = three_factor_state();
    service::register_caller(&state, "/s/auth-approve.sh", "auth-approve-old", "auth-src")
        .await
        .unwrap();
    let err = approve_hash_change_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(ApproveHashChangeBody {
            caller_path: "/s/auth-approve.sh".to_string(),
            reg_id: String::new(),
            reaction: None,
            new_hash: "auth-approve-new".to_string(),
            auth: None,
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "E_AUTH");
    let registry = state.registry.read().await;
    assert_eq!(
        registry
            .lookup_by_path("/s/auth-approve.sh")
            .unwrap()
            .expected_hash,
        "auth-approve-old",
        "未鉴权不得改写 expected_hash"
    );
}

#[tokio::test]
async fn register_caller_requires_three_factor() {
    let state = three_factor_state();
    let err = register_caller_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(RegisterBody {
            caller_path: "/s/auth-reg.sh".to_string(),
            caller_hash: "auth-reg-h".to_string(),
            source: None,
            name: "auth-reg".to_string(),
            description: String::new(),
            entries: None,
            entry: None,
            fields: None,
            field: None,
            allow_mode: None,
            auto: None,
            auth: None,
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/auth-reg.sh")
            .is_none(),
        "未鉴权不得落注册条目"
    );
    assert_eq!(state.pending.len(), 0, "未鉴权不得建审批单");
}

#[tokio::test]
async fn revoke_requires_three_factor() {
    let state = three_factor_state();
    service::register_caller(&state, "/s/auth-rev.sh", "auth-rev-h", "auth-src")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/auth-rev.sh", true)
        .unwrap();
    let err = revoke_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(RevokeBody {
            key: Some("/s/auth-rev.sh".to_string()),
            caller_path: None,
            caller_hash: None,
            name: None,
            auth: None,
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path("/s/auth-rev.sh").unwrap();
    assert!(entry.enabled && !entry.revoked, "未鉴权不得触发吊销");
}

fn no_deployment_secret_state() -> AppState {
    service::credential::test_support::cred_state(&service::credential::test_support::cred_env(&[
        ("GET_BINARY_SECRET", ""),
        ("GET_BINARY_HASH", ""),
    ]))
}

#[tokio::test]
async fn write_endpoints_require_deployment_secret() {
    // AUTH-11：未配置部署密钥（compat 默认）时三写端点 fail-closed（403 + E_AUTH），
    // 且动作前失败——注册表/pending 均无副作用。`/credential` 读路径不受影响。
    let state = no_deployment_secret_state();

    service::register_caller(&state, "/s/fc-approve.sh", "fc-approve-old", "fc-src")
        .await
        .unwrap();
    let err = approve_hash_change_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(ApproveHashChangeBody {
            caller_path: "/s/fc-approve.sh".to_string(),
            reg_id: String::new(),
            reaction: None,
            new_hash: "fc-approve-new".to_string(),
            auth: Some(service::AuthBlock {
                caller_hash: Some("fc-approve-old".to_string()),
                caller_path: Some("/s/fc-approve.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "E_AUTH");
    assert_eq!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/fc-approve.sh")
            .unwrap()
            .expected_hash,
        "fc-approve-old",
        "无部署密钥时不得改写 expected_hash"
    );

    let err = register_caller_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(RegisterBody {
            caller_path: "/s/fc-reg.sh".to_string(),
            caller_hash: "fc-reg-h".to_string(),
            source: None,
            name: "fc-reg".to_string(),
            description: String::new(),
            entries: None,
            entry: None,
            fields: None,
            field: None,
            allow_mode: None,
            auto: None,
            auth: Some(service::AuthBlock {
                caller_hash: Some("fc-reg-h".to_string()),
                caller_path: Some("/s/fc-reg.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "E_AUTH");
    assert!(
        state
            .registry
            .read()
            .await
            .lookup_by_path("/s/fc-reg.sh")
            .is_none(),
        "无部署密钥时不得落注册条目"
    );

    service::register_caller(&state, "/s/fc-rev.sh", "fc-rev-h", "fc-src-rev")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/fc-rev.sh", true)
        .unwrap();
    let err = revoke_handler(
        State(state.clone()),
        HeaderMap::new(),
        Json(RevokeBody {
            key: Some("/s/fc-rev.sh".to_string()),
            caller_path: None,
            caller_hash: None,
            name: None,
            auth: Some(service::AuthBlock {
                caller_hash: Some("fc-rev-h".to_string()),
                caller_path: Some("/s/fc-rev.sh".to_string()),
                get_binary_hash: None,
                get_binary_secret: None,
            }),
            secret: None,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(err.code(), "E_AUTH");
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path("/s/fc-rev.sh").unwrap();
        assert!(entry.enabled && !entry.revoked, "无部署密钥时不得触发吊销");
    }
    assert_eq!(state.pending.len(), 0, "无部署密钥时不得建审批单");
}

#[tokio::test]
async fn register_handler_auto_mode_effective() {
    // AUTH-10：Go 形态（`allow_mode:"auto"` + `auto:true`）落定为自动放行。
    let state = three_factor_state();
    let body = Json(RegisterBody {
        caller_path: "/s/auto-mode.sh".to_string(),
        caller_hash: "auto-h".to_string(),
        source: Some("go-client".to_string()),
        name: "auto-job".to_string(),
        description: String::new(),
        entries: None,
        entry: Some("网易".to_string()),
        field: Some("授权码".to_string()),
        fields: None,
        allow_mode: Some("auto".to_string()),
        auto: Some(true),
        auth: Some(service::AuthBlock {
            caller_hash: Some("auto-h".to_string()),
            caller_path: Some("/s/auto-mode.sh".to_string()),
            get_binary_hash: Some("gethash".to_string()),
            get_binary_secret: Some("s3cr3t".to_string()),
        }),
        secret: None,
    });
    let err = register_caller_handler(State(state.clone()), HeaderMap::new(), body)
        .await
        .unwrap_err();
    assert_eq!(
        err.status_code(),
        StatusCode::ACCEPTED,
        "默认模式注册转审批 202"
    );
    let registry = state.registry.read().await;
    let entry = registry
        .lookup_by_path("/s/auto-mode.sh")
        .expect("条目须已落盘");
    assert_eq!(
        entry.allow_mode,
        Some(crate::config::AutoApprove::Allow),
        "auto 须落为自动放行模式"
    );
}

#[tokio::test]
async fn emergency_revoke_forged_file_present_rejected() {
    // AUTH-2：`file_present` 自证通道已移除——公网来源即使携带
    // `{"file_present":true}` 也转常规审批（202），条目不被吊销。
    let state = three_factor_state();
    service::register_caller(&state, "/s/forged.sh", "h-forged", "src-forged")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/forged.sh", true)
        .unwrap();
    let body: EmergencyRevokeBody = serde_json::from_value(json!({
        "key": "/s/forged.sh",
        "file_present": true,
    }))
    .expect("未知字段 file_present 须被忽略而非拒解析");
    let err = emergency_revoke_handler(
        State(state.clone()),
        PeerIp(Some("203.0.113.9".parse().unwrap())),
        HeaderMap::new(),
        Json(body),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.status_code(),
        StatusCode::ACCEPTED,
        "伪造 file_present 须转审批"
    );
    let registry = state.registry.read().await;
    let entry = registry.lookup_by_path("/s/forged.sh").unwrap();
    assert!(entry.enabled && !entry.revoked, "条目不得被吊销");
}

#[tokio::test]
async fn emergency_revoke_admin_token_only() {
    // AUTH-2：管理 token 单独构成放行依据，直接吊销且不建审批单。
    let state = three_factor_state();
    service::register_caller(&state, "/s/admin-only.sh", "h-admin-only", "src-admin")
        .await
        .unwrap();
    state
        .registry
        .write()
        .await
        .set_enabled("/s/admin-only.sh", true)
        .unwrap();
    let Json(resp) = emergency_revoke_handler(
        State(state.clone()),
        PeerIp(Some("203.0.113.9".parse().unwrap())),
        HeaderMap::new(),
        Json(EmergencyRevokeBody {
            key: Some("/s/admin-only.sh".to_string()),
            caller_path: None,
            caller_hash: None,
            admin_token: Some("observability-admin-token-0123456789".to_string()),
        }),
    )
    .await
    .unwrap();
    assert_eq!(resp["ok"], true);
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path("/s/admin-only.sh").unwrap();
        assert!(entry.revoked && !entry.enabled, "管理 token 须直接吊销");
    }
    assert_eq!(state.pending.len(), 0, "直接吊销不建内存审批单");
    assert_eq!(state.approval.pending_len().await, 0, "不建 Matrix 审批单");
}
