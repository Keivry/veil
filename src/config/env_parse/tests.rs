//! `load_from` 行为保持单测（按域拆分后自 `env_parse.rs` 拆出；断言零修改）。

use {super::*, test_support::base_env};

#[test]
fn empty_targets_extension_matches_public_load_from() {
    let env = base_env();
    let baseline = Config::load_from(&env).unwrap();
    assert!(baseline.llm_targets.is_empty(), "未声明覆盖须为空表");
    assert_eq!(
        Config::load_from_with_targets(&env, crate::config::LlmTargets::new()).unwrap(),
        baseline,
        "扩展入口传空覆盖表须与既有 load_from 逐字段相等"
    );
}

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "env_parse.rs",
        include_str!("../env_parse.rs"),
    );
}

#[test]
fn optional_auth_keys_no_longer_reject_and_gate_features() {
    // 全量配置：三要素齐、管理 token 在 → 两功能均启用。
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(cfg.matrix_enabled(), "三要素齐备须启用 Matrix");
    assert!(cfg.admin_surface_enabled(), "admin token 在须启用管理面");
    assert!(cfg.missing_matrix_keys().is_empty());

    // 全缺：不拒启动；两功能关闭，四字段为空串。
    let mut env = base_env();
    for key in [
        "HOMESERVER",
        "ROOM_ID",
        "MATRIX_ACCESS_TOKEN",
        "OBSERVABILITY_ADMIN_TOKEN",
    ] {
        env.remove(key);
    }
    let cfg = Config::load_from(&env).expect("四键全缺不得拒启动");
    assert!(!cfg.matrix_enabled());
    assert!(!cfg.admin_surface_enabled());
    assert_eq!(
        cfg.missing_matrix_keys(),
        vec!["HOMESERVER", "ROOM_ID", "MATRIX_ACCESS_TOKEN"]
    );
    assert!(cfg.homeserver.is_empty());
    assert!(cfg.room_id.is_empty());
    assert!(cfg.matrix_access_token.is_empty());
    assert!(cfg.observability_admin_token.is_empty());

    // 三要素逐个缺失：仅关闭 Matrix，管理面不受影响（admin token 仍在）。
    for key in ["HOMESERVER", "ROOM_ID", "MATRIX_ACCESS_TOKEN"] {
        let mut env = base_env();
        env.remove(key);
        let cfg = Config::load_from(&env).unwrap_or_else(|e| panic!("缺 {key} 不得拒启动: {e}"));
        assert!(!cfg.matrix_enabled(), "缺 {key} 须关闭 Matrix");
        assert!(cfg.admin_surface_enabled(), "缺 {key} 不影响管理面");
        assert_eq!(cfg.missing_matrix_keys(), vec![key]);
    }

    // 仅缺 admin token：仅关闭管理面，Matrix 不受影响。
    let mut env = base_env();
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    let cfg = Config::load_from(&env).expect("缺 admin token 不得拒启动");
    assert!(cfg.matrix_enabled());
    assert!(!cfg.admin_surface_enabled());
}

#[test]
fn blank_optional_keys_load_with_feature_off() {
    let mut env = base_env();
    env.insert("ROOM_ID".to_string(), "   ".to_string());
    let cfg = Config::load_from(&env).expect("空白 ROOM_ID 不得拒启动");
    assert!(!cfg.matrix_enabled(), "空白 ROOM_ID 须关闭 Matrix");
    assert_eq!(cfg.missing_matrix_keys(), vec!["ROOM_ID"]);
}

#[test]
fn admin_token_must_not_reuse_service_token() {
    let mut env = base_env();
    env.insert(
        "OBSERVABILITY_ADMIN_TOKEN".to_string(),
        "syt_matrix_token_xxx".to_string(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("OBSERVABILITY_ADMIN_TOKEN"));
}

#[test]
fn approve_without_whitelist_rejects_startup() {
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "approve".to_string());
    let err = Config::load_from(&env).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("APPROVAL_WHITELIST") && msg.contains("approve"));
}

#[test]
fn approve_with_whitelist_allows() {
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "approve".to_string());
    env.insert(
        "APPROVAL_WHITELIST".to_string(),
        "@admin:example.com, @ops:example.com".to_string(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.approval_whitelist.len(), 2);
}

#[test]
fn empty_whitelist_warns_when_matrix_enabled() {
    let cfg = Config::load_from(&base_env()).unwrap();
    let msg = cfg
        .empty_whitelist_warning()
        .expect("Matrix 启用 + 空白名单须返回告警文本");
    assert!(msg.contains("任意成员"), "告警须说明空白名单的后果: {msg}");
    assert!(
        msg.contains("[audit].approval_whitelist"),
        "告警须指名真实配置键: {msg}"
    );
}

#[test]
fn non_empty_whitelist_suppresses_warning() {
    let mut env = base_env();
    env.insert(
        "APPROVAL_WHITELIST".to_string(),
        "@admin:example.com".to_string(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.approval_whitelist.len(), 1);
    assert!(
        cfg.empty_whitelist_warning().is_none(),
        "非空白名单不得告警"
    );
}

#[test]
fn empty_whitelist_without_matrix_is_silent() {
    let mut env = base_env();
    env.remove("HOMESERVER");
    let cfg = Config::load_from(&env).unwrap();
    assert!(!cfg.matrix_enabled());
    assert!(
        cfg.empty_whitelist_warning().is_none(),
        "Matrix 面未启用时空白名单无意义，不得告警"
    );
}

#[test]
fn http_client_defaults_and_overrides_ok() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert_eq!(cfg.http_timeout_secs, HTTP_TIMEOUT_SECS_DEFAULT);
    assert_eq!(
        cfg.http_pool_max_idle_per_host,
        HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT
    );
    assert_eq!(
        cfg.http_pool_idle_timeout_secs,
        HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT
    );
    let mut env = base_env();
    env.insert("HTTP_TIMEOUT_SECS".to_string(), "10".to_string());
    env.insert("HTTP_POOL_MAX_IDLE_PER_HOST".to_string(), "8".to_string());
    env.insert("HTTP_POOL_IDLE_TIMEOUT_SECS".to_string(), "60".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.http_timeout_secs, 10);
    assert_eq!(cfg.http_pool_max_idle_per_host, 8);
    assert_eq!(cfg.http_pool_idle_timeout_secs, 60);
    // 转发路径逐字段独立：仅覆盖一变量时其余保持默认（不串扰）。
    let mut env = base_env();
    env.insert("HTTP_TIMEOUT_SECS".to_string(), "7".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.http_timeout_secs, 7);
    assert_eq!(
        cfg.http_pool_max_idle_per_host,
        HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT
    );
    assert_eq!(
        cfg.http_pool_idle_timeout_secs,
        HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT
    );
}

#[test]
fn http_client_invalid_rejects_startup() {
    for (var, raw) in [
        ("HTTP_TIMEOUT_SECS", "0"),
        ("HTTP_TIMEOUT_SECS", "abc"),
        ("HTTP_POOL_MAX_IDLE_PER_HOST", "0"),
        ("HTTP_POOL_IDLE_TIMEOUT_SECS", "-5"),
    ] {
        let mut env = base_env();
        env.insert(var.to_string(), raw.to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "输入 {var}={raw} 报错须指明变量名"
        );
    }
}

#[test]
fn redaction_alias_and_semantic_toggles() {
    // 默认：脱敏开、宽松关、强化关。
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(cfg.redaction_enabled);
    assert!(!cfg.pii_fuzzy_restore);
    assert!(!cfg.pii_detection_hardening);
    // 兼容别名单独置位等价开启。
    let mut env = base_env();
    env.insert("PII_REDACTION_ENABLED".to_string(), "1".to_string());
    assert!(Config::load_from(&env).unwrap().redaction_enabled);
    // 别名显式关闭同样生效。
    let mut env = base_env();
    env.insert("PII_REDACTION_ENABLED".to_string(), "0".to_string());
    assert!(!Config::load_from(&env).unwrap().redaction_enabled);
    // 主变量优先于别名。
    let mut env = base_env();
    env.insert("REDACTION_ENABLED".to_string(), "0".to_string());
    env.insert("PII_REDACTION_ENABLED".to_string(), "1".to_string());
    assert!(!Config::load_from(&env).unwrap().redaction_enabled);
    // 语义覆盖。
    let mut env = base_env();
    env.insert("PII_FUZZY_RESTORE".to_string(), "yes".to_string());
    env.insert("PII_DETECTION_HARDENING".to_string(), "on".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.pii_fuzzy_restore);
    assert!(cfg.pii_detection_hardening);
}

#[test]
fn sampling_toggles_defaults_and_overrides() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(!cfg.pii_value_sample_enabled);
    assert!(cfg.pii_value_sample_persist);
    assert!(cfg.pii_value_sample_hmac_key.is_none());
    let mut env = base_env();
    env.insert("PII_VALUE_SAMPLE_ENABLED".to_string(), "1".to_string());
    env.insert("PII_VALUE_SAMPLE_PERSIST".to_string(), "0".to_string());
    env.insert(
        "PII_VALUE_SAMPLE_HMAC_KEY".to_string(),
        "k-0123456789".to_string(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.pii_value_sample_enabled);
    assert!(!cfg.pii_value_sample_persist);
    assert_eq!(
        cfg.pii_value_sample_hmac_key.as_deref(),
        Some("k-0123456789")
    );
}

#[test]
fn lib_dirs_default_derived_and_explicit_override() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert_eq!(cfg.db_dir, PathBuf::from("/data/db"));
    assert_eq!(cfg.tpm_dir, PathBuf::from("/data/tpm"));
    assert_eq!(cfg.keepass_backend, KeepassBackendKind::Real);
    let mut env = base_env();
    env.insert("DB_DIR".to_string(), "/srv/kdbx".to_string());
    env.insert("TPM_DIR".to_string(), "/srv/tpm".to_string());
    env.insert("VEIL_KEEPASS_BACKEND".to_string(), "mock".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.db_dir, PathBuf::from("/srv/kdbx"));
    assert_eq!(cfg.tpm_dir, PathBuf::from("/srv/tpm"));
    assert_eq!(cfg.keepass_backend, KeepassBackendKind::Mock);
    let mut env = base_env();
    env.insert("VEIL_KEEPASS_BACKEND".to_string(), "bogus".to_string());
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("VEIL_KEEPASS_BACKEND"));
}

fn upstream_env() -> HashMap<String, String> {
    let mut env = base_env();
    env.insert(
        "LLM_UPSTREAM".to_string(),
        "http://缺省上游:11434".to_string(),
    );
    env.insert(
        "LLM_8878".to_string(),
        "http://八七七八上游:11434".to_string(),
    );
    env.insert(
        "LLM_8879".to_string(),
        "http://八七七九上游:11434".to_string(),
    );
    env
}

#[test]
fn ingress_port_hits_matching_upstream() {
    use crate::service::llm_gateway::resolve_upstream;
    let cfg = Config::load_from(&upstream_env()).unwrap();
    assert_eq!(
        resolve_upstream(&cfg, Some(8878)).as_deref(),
        Some("http://八七七八上游:11434")
    );
    assert_eq!(
        resolve_upstream(&cfg, Some(8879)).as_deref(),
        Some("http://八七七九上游:11434")
    );
}

#[test]
fn unmatched_port_and_empty_context_fall_back_to_default() {
    use crate::service::llm_gateway::resolve_upstream;
    let cfg = Config::load_from(&upstream_env()).unwrap();
    for port in [None, Some(8877), Some(9999)] {
        assert_eq!(
            resolve_upstream(&cfg, port).as_deref(),
            Some("http://缺省上游:11434"),
            "端口 {port:?} 须回落缺省而非猜测"
        );
    }
}

#[test]
fn without_default_falls_back_to_any_port_upstream() {
    use crate::service::llm_gateway::resolve_upstream;
    let mut env = upstream_env();
    env.remove("LLM_UPSTREAM");
    let cfg = Config::load_from(&env).unwrap();
    let got = resolve_upstream(&cfg, Some(9999)).expect("须有回落");
    assert!(
        got == "http://八七七八上游:11434" || got == "http://八七七九上游:11434",
        "回落须为已知端口上游之一，实际: {got}"
    );
    assert!(resolve_upstream(&cfg, None).is_some());
}

#[test]
fn approval_block_wait_default_off() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(!cfg.credential_block_wait);
    for raw in ["1", "true", "yes", "on"] {
        let mut env = base_env();
        env.insert("CREDENTIAL_BLOCK_WAIT".to_string(), raw.to_string());
        assert!(
            Config::load_from(&env).unwrap().credential_block_wait,
            "{raw}"
        );
    }
    for raw in ["0", "false", "", "off"] {
        let mut env = base_env();
        if raw.is_empty() {
            env.remove("CREDENTIAL_BLOCK_WAIT");
        } else {
            env.insert("CREDENTIAL_BLOCK_WAIT".to_string(), raw.to_string());
        }
        assert!(
            !Config::load_from(&env).unwrap().credential_block_wait,
            "{raw}"
        );
    }
}

#[test]
fn hardening_toggle_matrix() {
    // 默认关/真值开/非真值关三态；非真值不拒启动为 Rust 现行行为（已登记）。
    assert!(
        !Config::load_from(&base_env())
            .unwrap()
            .pii_detection_hardening
    );
    for raw in ["1", "true", "yes", "on", " ON "] {
        let mut env = base_env();
        env.insert("PII_DETECTION_HARDENING".to_string(), raw.to_string());
        assert!(
            Config::load_from(&env).unwrap().pii_detection_hardening,
            "真值 {raw:?} 须开启"
        );
    }
    for raw in ["0", "false", "no", "off", "2", "bogus"] {
        let mut env = base_env();
        env.insert("PII_DETECTION_HARDENING".to_string(), raw.to_string());
        let cfg = Config::load_from(&env).expect("非真值不得拒启动（Rust 现行口径）");
        assert!(!cfg.pii_detection_hardening, "非真值 {raw:?} 须关闭");
    }
}

/// `AUDIT_ENABLED` 已并入遗留清单：置位不再是 env 显式、不再回退 `block`（仅告警）。
#[test]
fn legacy_audit_enabled_no_longer_changes_mode() {
    for raw in ["true", "1", "yes", "on"] {
        let mut env = base_env();
        env.insert("AUDIT_ENABLED".to_string(), raw.to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.audit_mode,
            AuditMode::Off,
            "AUDIT_ENABLED={raw} 不得再改变生效模式"
        );
        assert!(!cfg.audit_mode_explicit, "AUDIT_ENABLED 不得置显式位");
    }
    // 显式 `AUDIT_MODE` 仍照常生效（与遗留名无耦合）。
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "block".to_string());
    env.insert("AUDIT_ENABLED".to_string(), "1".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.audit_mode, AuditMode::Block);
    assert!(cfg.audit_mode_explicit);
}

/// `CREDENTIAL_ADMIN_TOKEN` 交叉校验已废除：与 `OBSERVABILITY_ADMIN_TOKEN` 相同不再拒启动。
#[test]
fn credential_admin_token_cross_check_removed() {
    let mut env = base_env();
    let token = env
        .get("OBSERVABILITY_ADMIN_TOKEN")
        .expect("基准须含管理 token")
        .clone();
    env.insert("CREDENTIAL_ADMIN_TOKEN".to_string(), token.clone());
    let cfg = Config::load_from(&env).expect("交叉校验已废除，不得拒启动");
    assert_eq!(cfg.observability_admin_token, token);
}

#[test]
fn disable_and_missing_token_toggle_admin_surface() {
    // 缺 token（未禁用）：不拒启动，管理面关闭。
    let mut env = base_env();
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    let cfg = Config::load_from(&env).expect("缺 token 不得拒启动");
    assert!(!cfg.observability_disabled);
    assert!(!cfg.admin_surface_enabled());
    assert!(cfg.observability_admin_token.is_empty());

    // DISABLE=1 且缺 token：不拒启动，observability_disabled 置位。
    let mut env = base_env();
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    env.insert("OBSERVABILITY_DISABLE".to_string(), "1".to_string());
    let cfg = Config::load_from(&env).expect("DISABLE=1 缺 token 不得拒启动");
    assert!(cfg.observability_disabled);
    assert!(!cfg.admin_surface_enabled());

    // 非 =1（未设/其它值）且缺 token：仍不拒启动（可选语义），管理面关闭。
    for value in ["", "0", "true", "yes", "2"] {
        let mut env = base_env();
        env.remove("OBSERVABILITY_ADMIN_TOKEN");
        if !value.is_empty() {
            env.insert("OBSERVABILITY_DISABLE".to_string(), value.to_string());
        }
        let cfg = Config::load_from(&env)
            .unwrap_or_else(|e| panic!("值 {value:?} 缺 token 不得拒启动: {e}"));
        assert!(!cfg.observability_disabled, "值 {value:?} 不得置禁用");
        assert!(!cfg.admin_surface_enabled());
    }
}

#[test]
fn entry_mode_notice_only_for_non_full_modes() {
    assert!(
        entry_mode_notice(EntryMode::Full).is_none(),
        "full 无启动提示"
    );
    let credential_only = entry_mode_notice(EntryMode::CredentialOnly).expect("须有提示");
    assert!(
        credential_only.contains("已等价于 full"),
        "{credential_only}"
    );
    assert!(
        credential_only.contains("审批豁免已删除"),
        "{credential_only}"
    );
    assert!(
        credential_only.contains("allow_mode = allow"),
        "须给出改用条目 ACL 的指引: {credential_only}"
    );
    let llm_only = entry_mode_notice(EntryMode::LlmOnly).expect("须有提示");
    assert!(llm_only.contains("凭据面"), "{llm_only}");
    assert!(llm_only.contains("不可用"), "{llm_only}");
}

#[test]
fn authorization_ttl_defaults_to_none_and_zero_normalizes() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert_eq!(cfg.authorization_ttl, None, "缺省须为无期限");

    let mut env = base_env();
    env.insert("AUTHORIZATION_TTL_SECS".to_string(), "0".to_string());
    assert_eq!(
        Config::load_from(&env).unwrap().authorization_ttl,
        None,
        "0 须归一为无期限"
    );

    let mut env = base_env();
    env.insert("AUTHORIZATION_TTL_SECS".to_string(), "3600".to_string());
    assert_eq!(
        Config::load_from(&env).unwrap().authorization_ttl,
        Some(3_600)
    );
}

#[test]
fn authorization_ttl_invalid_value_rejects_startup() {
    for raw in ["-1", "abc", "1.5", ""] {
        let mut env = base_env();
        env.insert("AUTHORIZATION_TTL_SECS".to_string(), raw.to_string());
        let result = Config::load_from(&env);
        if raw.is_empty() {
            assert_eq!(
                result.expect("空串等同于未设置").authorization_ttl,
                None,
                "空串须按缺省处理"
            );
            continue;
        }
        let err = result.expect_err(&format!("{raw:?} 须拒启动"));
        let text = err.to_string();
        assert!(
            text.contains("AUTHORIZATION_TTL_SECS"),
            "错误须含变量名: {text}"
        );
    }
}

#[test]
fn authorization_ttl_loaded_from_config_file() {
    let dir = std::env::temp_dir().join(format!(
        "veil-auth-ttl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("veil.toml");
    std::fs::write(
        &path,
        "[storage]\ndata_dir = \"/tmp/veil-ttl\"\nauthorization_ttl_secs = 7200\n",
    )
    .unwrap();
    let mut env = base_env();
    env.insert(
        "VEIL_CONFIG_FILE".to_string(),
        path.to_string_lossy().into_owned(),
    );
    let cfg = Config::from_env_map(env).expect("文件层须可加载该键（`load_from` 不含文件层）");
    assert_eq!(cfg.authorization_ttl, Some(7_200));
    std::fs::remove_dir_all(&dir).ok();
}
