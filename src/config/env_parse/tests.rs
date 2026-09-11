//! `load_from` 行为保持单测（A2 拆分后自 `env_parse.rs` 拆出；断言零修改）。

use {super::*, test_support::base_env};

#[test]
fn missing_required_each_rejects_startup_naming_var() {
    for var in [
        "HOMESERVER",
        "ROOM_ID",
        "MATRIX_ACCESS_TOKEN",
        "OBSERVABILITY_ADMIN_TOKEN",
    ] {
        let mut env = base_env();
        env.remove(var);
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(var), "报错须指明变量名 {var}，实际: {msg}");
    }
}

#[test]
fn blank_required_also_rejects_startup() {
    let mut env = base_env();
    env.insert("ROOM_ID".to_string(), "   ".to_string());
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("ROOM_ID"));
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
fn redaction_alias_and_three_semantic_toggles() {
    // 默认：脱敏开、响应侧开、宽松关、强化关。
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(cfg.redaction_enabled);
    assert!(cfg.pii_response_side);
    assert!(!cfg.pii_fuzzy_restore);
    assert!(!cfg.pii_detection_hardening);
    // 原仓别名单独置位等价开启。
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
    // 三语义覆盖。
    let mut env = base_env();
    env.insert("PII_RESPONSE_SIDE".to_string(), "0".to_string());
    env.insert("PII_FUZZY_RESTORE".to_string(), "yes".to_string());
    env.insert("PII_DETECTION_HARDENING".to_string(), "on".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert!(!cfg.pii_response_side);
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
