//! 文件层合并优先级与集成用例（自 `tests.rs` 拆出保持红线内）。
//!
//! 覆盖 env 显式恒胜、别名胜文件、空白 env 回落、审计 mode 层级、
//! 端口表逐键合并与「未声明 targets 即零变化」基线。

use super::*;

#[test]
fn merge_env_canonical_wins_over_file_and_warns() {
    let file = TempFile::new(
        "canonical-wins.toml",
        "[audit]\nmode = \"block\"\n[pii_scope]\nttl_secs = 99\n",
    );
    let mut env = with_config_file(&file);
    env.insert("AUDIT_MODE".to_string(), "off".to_string());
    env.insert("PII_SCOPE_TTL_SECS".to_string(), "3600".to_string());
    let messages = capture_apply(&mut env);
    assert_eq!(env.get("AUDIT_MODE").map(String::as_str), Some("off"));
    assert_eq!(
        env.get("PII_SCOPE_TTL_SECS").map(String::as_str),
        Some("3600")
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("audit.mode") && m.contains("AUDIT_MODE")),
        "冲突须记指名概念的 warn: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("pii_scope.ttl_secs")),
        "冲突须记指名概念的 warn: {messages:?}"
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.audit_mode, AuditMode::Off);
    assert_eq!(cfg.pii_scope_ttl_secs, 3600);
}

#[test]
fn merge_blank_env_falls_back_to_file() {
    let file = TempFile::new(
        "blank-env.toml",
        "[pii_scope]\nttl_secs = 99\n[redaction]\nenabled = false\n",
    );
    let mut env = with_config_file(&file);
    env.insert("PII_SCOPE_TTL_SECS".to_string(), "   ".to_string());
    env.insert("REDACTION_ENABLED".to_string(), "\t".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.pii_scope_ttl_secs, 99);
    assert!(!cfg.redaction_enabled);
    assert_eq!(
        env.get("PII_SCOPE_TTL_SECS").map(String::as_str),
        Some("99"),
        "空白 env 视同未设置，文件值写入"
    );
}

#[test]
fn merge_env_aliases_win_over_file_canonical_keys() {
    let file = TempFile::new("alias-enabled.toml", "[redaction]\nenabled = true\n");
    let mut env = with_config_file(&file);
    env.insert("PII_REDACTION_ENABLED".to_string(), "0".to_string());
    let cfg = apply_and_load(&mut env);
    assert!(!cfg.redaction_enabled, "env 别名关闭须恒胜文件开启");
    assert!(
        !env.contains_key("REDACTION_ENABLED"),
        "冲突时不得写入规范名"
    );

    let rules = TempFile::new(
        "alias-rules.json",
        r#"[{"name":"ext-id","pattern":"EXT-\\d{6}"}]"#,
    );
    let file = TempFile::new(
        "alias-rules.toml",
        "[redaction]\ncustom_rules_file = \"/nonexistent/file-would-win.json\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert(
        "PII_RULES_FILE".to_string(),
        rules.path().to_string_lossy().into_owned(),
    );
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.path()));
    assert!(!env.contains_key("PII_CUSTOM_RULES_FILE"));

    let file = TempFile::secret(
        "alias-secret.toml",
        "[storage]\nveilctl_secret = \"file-secret\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert(
        "CREDENTIAL_SECRET".to_string(),
        "env-alias-secret".to_string(),
    );
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.veilctl_secret.as_deref(), Some("file-secret"));
    assert!(env.contains_key("VEILCTL_SECRET"));
}

#[test]
fn merge_ignores_legacy_audit_enabled_file_mode_wins() {
    for raw in ["true", " ON ", "1", "yes"] {
        let file = TempFile::new("audit-enabled.toml", "[audit]\nmode = \"off\"\n");
        let mut env = with_config_file(&file);
        env.insert("AUDIT_ENABLED".to_string(), raw.to_string());
        let messages = capture_apply(&mut env);
        assert_eq!(
            env.get("AUDIT_MODE").map(String::as_str),
            Some("off"),
            "AUDIT_ENABLED 不再是 env 显式，文件 mode 须写入"
        );
        assert!(
            !messages.iter().any(|m| m.contains("AUDIT_ENABLED")),
            "AUDIT_ENABLED 不应再触发审计冲突 warn: {messages:?}"
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.audit_mode,
            AuditMode::Off,
            "AUDIT_ENABLED 真值 {raw:?} 不得再回退 block"
        );
        assert!(cfg.audit_mode_explicit, "文件写入 AUDIT_MODE 后视同显式");
    }
}

#[test]
fn audit_file_mode_wins_policy_file_mode() {
    let policy_off = TempFile::new("policy-off.yaml", "mode: off\n");
    let policy_block = TempFile::new("policy-block.yaml", "mode: block\n");
    let config_file = TempFile::new("audit-file-block.toml", "[audit]\nmode = \"block\"\n");

    let mut env = with_config_file(&config_file);
    let mut cfg = apply_and_load(&mut env);
    assert!(cfg.audit_mode_explicit, "文件 mode 视同显式");
    let policy = AuditPolicy::load_from_file(Some(policy_off.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(
        cfg.audit_mode,
        AuditMode::Block,
        "配置文件 mode 须优先于策略文件 mode"
    );

    let mut env = with_config_file(&config_file);
    env.insert("AUDIT_MODE".to_string(), "off".to_string());
    let mut cfg = apply_and_load(&mut env);
    let policy = AuditPolicy::load_from_file(Some(policy_block.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(cfg.audit_mode, AuditMode::Off, "env 显式须恒胜");
}

#[test]
fn legacy_audit_enabled_ignored_policy_mode_applies() {
    let policy_off = TempFile::new("policy-off-2.yaml", "mode: off\n");
    let config_file = TempFile::new("audit-enabled-policy.toml", "[audit]\nmode = \"off\"\n");
    let mut env = with_config_file(&config_file);
    env.insert("AUDIT_ENABLED".to_string(), "true".to_string());
    let mut cfg = apply_and_load(&mut env);
    let policy = AuditPolicy::load_from_file(Some(policy_off.path())).expect("策略文件可解析");
    policy.apply_effective_mode(&mut cfg);
    assert_eq!(
        cfg.audit_mode,
        AuditMode::Off,
        "AUDIT_ENABLED 已废弃，须以文件 mode 为准"
    );
}

#[test]
fn llm_upstream_ports_merge_by_port() {
    let file = TempFile::new(
        "llm-ports.toml",
        "[llm.upstreams]\n\"8879\" = \"http://file-8879:1\"\n\"8890\" = \"http://file-8890:1\"\n",
    );
    let mut env = with_config_file(&file);
    env.insert("LLM_8878".to_string(), "http://env-8878:1".to_string());
    env.insert("LLM_8890".to_string(), "http://env-8890:1".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8878).map(String::as_str),
        Some("http://env-8878:1")
    );
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://file-8879:1")
    );
    assert_eq!(
        cfg.llm_upstreams.get(&8890).map(String::as_str),
        Some("http://env-8890:1"),
        "同端口 env 恒胜"
    );
    assert_eq!(cfg.llm_upstreams.len(), 3);

    let file_only = TempFile::new(
        "llm-file-only.toml",
        "[llm.upstreams]\n8879 = \"http://file:1\"\n",
    );
    let mut env = with_config_file(&file_only);
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://file:1")
    );

    let empty = TempFile::new("llm-empty.toml", "");
    let mut env = with_config_file(&empty);
    env.insert("LLM_8879".to_string(), "http://env:1".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(
        cfg.llm_upstreams.get(&8879).map(String::as_str),
        Some("http://env:1")
    );
    assert_eq!(cfg.llm_upstreams.len(), 1);

    let none = TempFile::new("llm-none.toml", "");
    let mut env = with_config_file(&none);
    let cfg = apply_and_load(&mut env);
    assert!(cfg.llm_upstreams.is_empty(), "两处皆缺不得新增端口");
}

#[test]
fn llm_invalid_port_via_file_rejects_startup() {
    let file = TempFile::new(
        "llm-bad-port.toml",
        "[llm.upstreams]\n\"abc\" = \"http://x:1\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(BOOTSTRAP_VAR) && msg.contains("abc"),
        "实际: {msg}"
    );
}

#[test]
fn file_without_targets_stays_env_only_baseline() {
    // task 5.2：文件含默认值键（非 targets）时零变化——返回空覆盖表、cfg 与
    // env-only 基线逐字段相等，且不新增与 [llm.targets] 相关的告警。
    let file = TempFile::new(
        "no-targets.toml",
        "[audit]\nhold_max_bytes = 1048576\n[llm]\ntimeout_secs = 30\n",
    );
    let mut env = with_config_file(&file);
    let capture = CaptureMessages::default();
    let outcome = crate::test_support::with_capture_subscriber(capture.clone(), || {
        apply_config_file(&mut env).expect("文件层应用须成功")
    });
    let messages = capture.take();
    assert!(outcome.llm_targets.is_empty(), "未声明覆盖须返回空表");
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("llm.targets")),
        "未声明 [llm.targets] 不得新增相关告警: {messages:?}"
    );
    let cfg =
        Config::load_from_with_targets(&env, outcome.llm_targets).expect("合并后配置须可加载");
    assert_eq!(
        cfg,
        Config::load_from(&base_env()).unwrap(),
        "设文件但未声明 [llm.targets] 须与 env-only 基线逐字段相等"
    );
}

#[test]
fn integration_absent_file_layer_is_baseline() {
    let mut env = base_env();
    apply_only(&mut env);
    assert_eq!(env, base_env());
    assert_eq!(
        Config::load_from(&env).unwrap(),
        Config::load_from(&base_env()).unwrap(),
        "未设引导变量须与基线逐字段相等"
    );
}

#[test]
fn integration_file_only_and_env_precedence() {
    let file = TempFile::new(
        "integration.toml",
        "[server]\nsurface_mode = \"llm_only\"\n\
         [credential]\ndefault_decision = \"deny\"\n\
         [redaction]\nfuzzy_restore = true\nenabled = false\n\
         [llm]\ndefault_upstream = \"http://file-upstream:11434\"\ntimeout_secs = 12\n",
    );

    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.surface_mode, EntryMode::LlmOnly);
    assert_eq!(cfg.auto_approve, AutoApprove::Deny);
    assert!(cfg.pii_fuzzy_restore);
    assert!(!cfg.redaction_enabled);
    assert_eq!(
        cfg.llm_default_upstream.as_deref(),
        Some("http://file-upstream:11434")
    );
    assert_eq!(cfg.http_timeout_secs, 12);

    let mut env = with_config_file(&file);
    env.insert("VEIL_ENTRY_MODE".to_string(), "full".to_string());
    env.insert("AUTO_APPROVE".to_string(), "pending".to_string());
    env.insert("HTTP_TIMEOUT_SECS".to_string(), "45".to_string());
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.surface_mode, EntryMode::Full);
    assert_eq!(cfg.auto_approve, AutoApprove::Pending);
    assert_eq!(cfg.http_timeout_secs, 45);
    assert!(cfg.pii_fuzzy_restore, "未冲突键仍取文件值");
}

#[test]
fn file_value_bounds_reuse_env_validation() {
    for (content, var) in [
        ("[audit]\ntimeout_secs = 120\n", "AUDIT_TIMEOUT_SECS"),
        ("[llm]\nnonstream_max_bytes = 0\n", "NONSTREAM_MAX_BYTES"),
        ("[llm]\ntimeout_secs = 0\n", "HTTP_TIMEOUT_SECS"),
    ] {
        let file = TempFile::new("bounds.toml", content);
        let mut env = with_config_file(&file);
        apply_only(&mut env);
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "文件值越界须沿用既有 env 校验并指名 {var}: {err}"
        );
    }

    let file = TempFile::new("approve-empty.toml", "[audit]\nmode = \"approve\"\n");
    let mut env = with_config_file(&file);
    apply_only(&mut env);
    let err = Config::load_from(&env).unwrap_err();
    assert!(
        err.to_string().contains("APPROVAL_WHITELIST"),
        "approve 空白名单门禁须沿用: {err}"
    );
}
