use {
    super::*,
    crate::config::env_parse::{AuditMode, Config, test_support::base_env},
};

#[test]
fn audit_timeout_zero_negative_and_forbidden_zone_rejects_startup() {
    for raw in ["0", "-5", "110", "120", "130"] {
        let mut env = base_env();
        env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("AUDIT_TIMEOUT"),
            "报错须指明变量名，输入 {raw} 实际: {msg}"
        );
    }
}

#[test]
fn audit_timeout_valid_values_allow_with_range_hint() {
    for (raw, want) in [("90", 90), ("1", 1), ("109", 109), ("131", 131)] {
        let mut env = base_env();
        env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.audit_timeout_secs, want);
    }
    let mut env = base_env();
    env.insert("AUDIT_TIMEOUT".to_string(), "120".to_string());
    let msg = Config::load_from(&env).unwrap_err().to_string();
    assert!(msg.contains("110-130") && msg.contains("≥1"));
}

#[test]
fn nonstream_max_bytes_default_override_and_invalid_reject() {
    // 三例：缺省 8388608、覆盖生效、非法（非整数或 <1）拒启动（fail-closed）。
    let cfg = Config::load_from(&base_env()).unwrap();
    assert_eq!(cfg.nonstream_max_bytes, 8 * 1024 * 1024);
    let mut env = base_env();
    env.insert("NONSTREAM_MAX_BYTES".to_string(), "1024".to_string());
    assert_eq!(Config::load_from(&env).unwrap().nonstream_max_bytes, 1024);
    for raw in ["0", "-1", "abc", "1.5"] {
        let mut env = base_env();
        env.insert("NONSTREAM_MAX_BYTES".to_string(), raw.to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains("NONSTREAM_MAX_BYTES"),
            "输入 {raw} 报错须指明变量名"
        );
    }
}

#[test]
fn invalid_whitelist_member_rejects_startup() {
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "approve".to_string());
    env.insert(
        "APPROVAL_WHITELIST".to_string(),
        "\"@keivry@matrix.example\"".to_string(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("APPROVAL_WHITELIST"));
}

#[test]
fn invalid_audit_mode_rejects_startup_with_valid_values() {
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "allow".to_string());
    let msg = Config::load_from(&env).unwrap_err().to_string();
    assert!(msg.contains("AUDIT_MODE") && msg.contains("off/block/approve"));
}

/// `AUDIT_ENABLED` 回退已终止：真值不再是 env 显式、不再映射 `block`；
/// 显式 `AUDIT_MODE` 仍优先。
#[test]
fn audit_enabled_fallback_removed() {
    let mode_of = |audit_mode: Option<&str>, audit_enabled: Option<&str>| {
        let mut env = base_env();
        env.insert(
            "APPROVAL_WHITELIST".to_string(),
            "@admin:example.com".to_string(),
        );
        match audit_mode {
            Some(v) => env.insert("AUDIT_MODE".to_string(), v.to_string()),
            None => env.remove("AUDIT_MODE"),
        };
        match audit_enabled {
            Some(v) => env.insert("AUDIT_ENABLED".to_string(), v.to_string()),
            None => env.remove("AUDIT_ENABLED"),
        };
        Config::load_from(&env).unwrap()
    };
    // 仅 AUDIT_ENABLED 置位（含空白 AUDIT_MODE）→ 不生效，且不置显式位。
    for raw in ["1", "true", "yes", "on"] {
        let cfg = mode_of(None, Some(raw));
        assert_eq!(
            cfg.audit_mode,
            AuditMode::Off,
            "AUDIT_ENABLED={raw} 不得生效"
        );
        assert!(!cfg.audit_mode_explicit, "AUDIT_ENABLED 不得置显式位");
        let blank = mode_of(Some("   "), Some(raw));
        assert_eq!(blank.audit_mode, AuditMode::Off, "空白 AUDIT_MODE 不得回退");
    }
    // 显式非空 AUDIT_MODE 仍照常生效，与 AUDIT_ENABLED 无耦合。
    assert_eq!(mode_of(Some("off"), Some("1")).audit_mode, AuditMode::Off);
    assert_eq!(
        mode_of(Some("block"), Some("0")).audit_mode,
        AuditMode::Block
    );
    assert_eq!(
        mode_of(Some("approve"), Some("1")).audit_mode,
        AuditMode::Approve
    );
    assert_eq!(mode_of(None, None).audit_mode, AuditMode::Off);
}

/// `AUDIT_ENABLED` 真值表一律不生效（不再映射 `block`、不置显式位）。
#[test]
fn audit_enabled_truthy_table_no_effect() {
    let cfg_of = |audit_enabled: &str| {
        let mut env = base_env();
        env.insert("AUDIT_ENABLED".to_string(), audit_enabled.to_string());
        Config::load_from(&env).unwrap()
    };
    for raw in [
        "1", "true", "TRUE", "yes", "YES", "on", " On ", "\ttrue\n", "0", "false", "no", "off",
        "bogus", "", "   ",
    ] {
        let cfg = cfg_of(raw);
        assert_eq!(
            cfg.audit_mode,
            AuditMode::Off,
            "AUDIT_ENABLED={raw:?} 须一律不生效"
        );
        assert!(
            !cfg.audit_mode_explicit,
            "AUDIT_ENABLED={raw:?} 不得置显式位"
        );
    }
    // 显式空白 AUDIT_MODE 亦不再回退。
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "   ".to_string());
    env.insert("AUDIT_ENABLED".to_string(), "yes".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.audit_mode, AuditMode::Off);
    assert!(!cfg.audit_mode_explicit);
}

/// 非法 `AUDIT_TIMEOUT`（0/负/110-130）与 `AUDIT_HOLD_MAX_BYTES`（0/非整数）
/// 一律拒启动，不静默回落默认值。
#[test]
fn audit_invalid_env_rejects() {
    for raw in ["0", "-1", "110", "120", "130", "abc", "1.5"] {
        let mut env = base_env();
        env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains("AUDIT_TIMEOUT"),
            "AUDIT_TIMEOUT={raw:?} 须拒启动并指明变量"
        );
    }
    for raw in ["0", "-1", "abc", "1.5"] {
        let mut env = base_env();
        env.insert("AUDIT_HOLD_MAX_BYTES".to_string(), raw.to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains("AUDIT_HOLD_MAX_BYTES"),
            "AUDIT_HOLD_MAX_BYTES={raw:?} 须拒启动并指明变量"
        );
    }
    // 合法边界仍放行（1 与 109/131 避开禁区）。
    let mut env = base_env();
    env.insert("AUDIT_TIMEOUT".to_string(), "109".to_string());
    env.insert("AUDIT_HOLD_MAX_BYTES".to_string(), "1".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.audit_timeout_secs, 109);
    assert_eq!(cfg.audit_hold_max_bytes, 1);
}

#[test]
fn placeholder_toggle_defaults_on_and_off_short_circuits() {
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(cfg.placeholder_prompt_enabled);
    assert!(cfg.placeholder_prompt_text.is_empty());
    for raw in ["0", "false", "no", "  No  "] {
        let mut env = base_env();
        env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
        env.insert(
            "PII_PLACEHOLDER_PROMPT_TEXT".to_string(),
            "__PII_1_ab12cd34__".repeat(100),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert!(!cfg.placeholder_prompt_enabled, "{raw}");
        assert!(cfg.placeholder_prompt_text.is_empty());
    }
    for raw in ["1", "true", "yes", ""] {
        let mut env = base_env();
        if raw.is_empty() {
            env.remove("PII_PLACEHOLDER_PROMPT");
        } else {
            env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
        }
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.placeholder_prompt_enabled, "{raw}");
    }
}

#[test]
fn placeholder_text_cap_and_shape_fallback() {
    let mut env = base_env();
    env.insert(
        "PII_PLACEHOLDER_PROMPT_TEXT".to_string(),
        "Keep verbatim".to_string(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        effective_placeholder_prompt(&cfg.placeholder_prompt_text),
        "Keep verbatim"
    );
    for bad in [
        "Keep __PII_1_ab12cd34__ verbatim",
        "Keep __PII_1_AB12CD34__ verbatim",
        "Keep __CRED_42__ verbatim",
    ] {
        let mut env = base_env();
        env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), bad.to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.placeholder_prompt_text.is_empty(), "{bad}");
        assert!(effective_placeholder_prompt(&cfg.placeholder_prompt_text).contains("__PII_*__"));
    }
    let long = "x".repeat(PLACEHOLDER_PROMPT_MAX_LEN + 100);
    let mut env = base_env();
    env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), long);
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        cfg.placeholder_prompt_text.len(),
        PLACEHOLDER_PROMPT_MAX_LEN
    );
    let mut env = base_env();
    env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), "   ".to_string());
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.placeholder_prompt_text.is_empty());
}

#[test]
fn placeholder_off_disables_reusing_falsy() {
    for raw in ["off", "OFF", "  off  "] {
        let mut env = base_env();
        env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert!(!cfg.placeholder_prompt_enabled, "{raw}");
    }
}

#[test]
fn legacy_var_names_not_read() {
    let mut env = base_env();
    env.insert(
        "CREDENTIAL_MASTER_PASSWORD".to_string(),
        "旧主密码".to_string(),
    );
    env.insert("CREDENTIAL_PORT".to_string(), "9999".to_string());
    // 检出谓词：两遗留变量非空即命中，空值不命中。
    assert_eq!(
        legacy_ignored_detected(&env),
        vec!["CREDENTIAL_MASTER_PASSWORD", "CREDENTIAL_PORT"]
    );
    let mut empty_hit = base_env();
    empty_hit.insert("CREDENTIAL_PORT".to_string(), "   ".to_string());
    assert!(legacy_ignored_detected(&empty_hit).is_empty());
    // 行为仍为不读取：启动仅 warn，不断链、不生效。
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.credential_secret.is_none());
    assert!(!cfg.llm_upstreams.contains_key(&9999));
    assert!(crate::service::llm_gateway::resolve_upstream(&cfg, Some(9999)).is_none());
}

#[test]
fn legacy_warn_covers_env_loopback_and_api_port() {
    let mut env = base_env();
    for var in ["ENV", "ALLOW_LOOPBACK_NO_TOKEN", "CREDENTIAL_API_PORT"] {
        env.insert(var.to_string(), "set".to_string());
    }
    let detected = legacy_ignored_detected(&env);
    for var in ["ENV", "ALLOW_LOOPBACK_NO_TOKEN", "CREDENTIAL_API_PORT"] {
        assert!(detected.contains(&var), "{var} 非空须命中");
    }
    let blank = HashMap::from([
        ("ENV".to_string(), "  ".to_string()),
        ("ALLOW_LOOPBACK_NO_TOKEN".to_string(), String::new()),
        ("CREDENTIAL_API_PORT".to_string(), "\t".to_string()),
    ]);
    assert!(legacy_ignored_detected(&blank).is_empty(), "空值不得命中");
    let mut loaded = base_env();
    loaded.insert("ENV".to_string(), "dev".to_string());
    loaded.insert("ALLOW_LOOPBACK_NO_TOKEN".to_string(), "1".to_string());
    loaded.insert("CREDENTIAL_API_PORT".to_string(), "9999".to_string());
    let cfg = Config::load_from(&loaded).unwrap();
    assert_eq!(cfg.audit_mode, AuditMode::Off);
    assert_eq!(cfg.entry_mode, crate::config::EntryMode::Full);
    assert!(!cfg.credential_block_wait);
    assert!(!cfg.llm_upstreams.contains_key(&9999));
}

#[test]
fn legacy_ignored_vars_set_locked() {
    let names: std::collections::BTreeSet<&str> =
        LEGACY_IGNORED_VARS.iter().map(|(name, _)| *name).collect();
    let want = std::collections::BTreeSet::from([
        "CREDENTIAL_MASTER_PASSWORD",
        "CREDENTIAL_PORT",
        "ENV",
        "ALLOW_LOOPBACK_NO_TOKEN",
        "CREDENTIAL_API_PORT",
        "CREDENTIAL_ADMIN_TOKEN",
        "AUDIT_ENABLED",
    ]);
    assert_eq!(names, want, "清单须恰为七项，增删须同步本测试");
    assert_eq!(LEGACY_IGNORED_VARS.len(), 7, "不得重复项扩容");
    for (name, hint) in LEGACY_IGNORED_VARS {
        assert!(!hint.trim().is_empty(), "{name} hint 不得为空");
    }
}

/// 新纳入的两项（`CREDENTIAL_ADMIN_TOKEN`/`AUDIT_ENABLED`）非空置位即被检出。
#[test]
fn legacy_new_names_detected() {
    for var in ["CREDENTIAL_ADMIN_TOKEN", "AUDIT_ENABLED"] {
        let mut env = base_env();
        env.insert(var.to_string(), "set".to_string());
        assert!(
            legacy_ignored_detected(&env).contains(&var),
            "{var} 非空须命中"
        );
        let blank = HashMap::from([(var.to_string(), "   ".to_string())]);
        assert!(
            legacy_ignored_detected(&blank).is_empty(),
            "{var} 空白不得命中"
        );
    }
}

#[test]
fn legacy_vars_reference_lockstep() {
    const ENGINEERING_REFERENCE: &str = include_str!("../../../docs/engineering-reference.md");
    let section = ENGINEERING_REFERENCE
        .split("### 7.4 遗留变量兼容表")
        .nth(1)
        .expect("工程参考须含 §7.4 遗留变量兼容表");
    let mut names: Vec<String> = Vec::new();
    for line in section.lines().skip(1) {
        if line.starts_with("### ") {
            break;
        }
        let Some(row) = line.strip_prefix('|') else {
            continue;
        };
        let cell = row.split('|').next().unwrap_or("").trim();
        let name = cell.trim_matches('`').trim();
        if name.is_empty() || name == "遗留变量" || name.chars().all(|c| c == ':' || c == '-') {
            continue;
        }
        names.push(name.to_string());
    }
    let reference_set: std::collections::BTreeSet<String> = names.iter().cloned().collect();
    let list_set: std::collections::BTreeSet<String> = LEGACY_IGNORED_VARS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    assert_eq!(
        reference_set, list_set,
        "工程参考 §7.4 与 LEGACY_IGNORED_VARS 名称集合须相等"
    );
    assert_eq!(
        names.len(),
        reference_set.len(),
        "工程参考 §7.4 不得重复变量行"
    );
}

/// `@` 前缀后再含 `@` 的 MXID 一律拒绝（配置侧与 Matrix 链路侧同结论）。
#[test]
fn mxid_reject_multiple_at() {
    assert!(!is_valid_mxid("@a@b:c"));
    let get = |_: &str| Some("@a@b:c".to_string());
    assert!(parse_whitelist(&get).is_err());
    assert!(crate::service::matrix::validate_whitelist_mxids(&["@a@b:c".to_string()]).is_err());
}

/// 常规合法形态通过，缺段/多段/空白/多点 `@` 拒绝。
#[test]
fn mxid_valid_forms() {
    for s in [
        "@admin:example.com",
        "@keivry:matrix.example.org",
        "@a.b-c_d:x.y",
    ] {
        assert!(is_valid_mxid(s), "合法 MXID 须通过: {s}");
    }
    for s in [
        "@a@b:c",
        "admin:example.com",
        "@a:",
        "@:b",
        "@a b:c",
        "@a:b:c",
    ] {
        assert!(!is_valid_mxid(s), "非法 MXID 须拒绝: {s}");
    }
}

/// 配置加载期真源与 `branch.rs::validate_whitelist_mxids` 表驱动同结论。
#[test]
fn whitelist_validator_parity() {
    for s in [
        "@admin:example.com",
        "@a@b:c",
        "admin:example.com",
        "@a:",
        "@:b",
        "@a b:c",
        "@keivry@matrix.example",
    ] {
        let get = |_: &str| Some(s.to_string());
        let via_config = parse_whitelist(&get);
        let via_branch = crate::service::matrix::validate_whitelist_mxids(&[s.to_string()]);
        assert_eq!(
            via_config.is_ok(),
            via_branch.is_ok(),
            "校验真源与 Matrix 门禁须同结论: {s:?}"
        );
    }
}

/// 字节级匹配——中文等多字节文案不 panic，且不误判为 token 形态。
#[test]
fn placeholder_shape_multibyte_no_panic() {
    assert!(!has_placeholder_token_shape("请勿回显占位符说明文本"));
    assert!(!has_placeholder_token_shape("中文__PII_"));
    assert!(!has_placeholder_token_shape("中文 __PII_x__ 结尾"));
    assert!(!has_placeholder_token_shape(&"占".repeat(2000)));
    assert!(has_placeholder_token_shape("中文 __PII_1_ab12cd34__ 结尾"));
    assert!(has_placeholder_token_shape("中文 __CRED_42__ 结尾"));
    assert!(has_placeholder_token_shape(&format!(
        "{}__PII_1_ab12cd34__",
        "占".repeat(2000)
    )));
}
