//! `[session]` 文件层用例：FileOnly 值经 `FileLayerOutcome.session` 直达 `Config`、
//! 旧会话键预扫描错误文本、迁移建议数组边界、启动期校验的 fail-closed。

use {super::*, crate::config::SessionHeaders};

/// `[session]` 声明时 `FileLayerOutcome.session` 须有值，且最终 `Config` 等于文件值。
#[test]
fn session_section_flows_through_outcome_into_config() {
    let file = TempFile::new(
        "session.toml",
        "[session]\nheaders = [\"x-client-session\", \"x-client-tenant\"]\nalias_max_entries = 2048\n",
    );
    let mut env = with_config_file(&file);
    let outcome = apply_config_file(&mut env).expect("文件层须应用成功");
    let declared = outcome
        .session
        .as_ref()
        .expect("声明 [session] 后产物须有值");
    assert_eq!(
        declared.headers.as_deref(),
        Some(
            [
                "x-client-session".to_string(),
                "x-client-tenant".to_string()
            ]
            .as_slice()
        )
    );
    assert_eq!(declared.alias_max_entries, Some(2048));

    let cfg = Config::load_from_with_file(&env, outcome).expect("合并后配置须可加载");
    assert_eq!(
        cfg.session_headers.as_slice(),
        [
            "x-client-session".to_string(),
            "x-client-tenant".to_string()
        ]
    );
    assert_eq!(cfg.session_alias_max_entries, 2048);
    assert_eq!(cfg.session_headers.primary(), "x-client-session");

    // 文件专属：值不进 env map，逐键合并跳过。
    assert!(
        !env.contains_key("PII_SCOPE_KEY_HEADER") && !env.contains_key("SESSION_HEADERS"),
        "FileOnly 键不得被写进 env map: {env:?}"
    );
}

/// `session.*` 是「文件专属标量键」，不是结构键根：不得进 `FILE_ONLY_KEYS`
/// （否则整根跳过会让值被丢弃），且 `env_explicit_names` 必须为空。
#[test]
fn session_mappings_are_file_only_scalars_not_structure_roots() {
    assert!(
        !FILE_ONLY_KEYS.contains(&"session"),
        "session 不得登记为文件专属结构键根"
    );
    for key in ["session.headers", "session.alias_max_entries"] {
        let mapping = mapping_for(key).unwrap_or_else(|| panic!("{key} 须在封闭映射表中"));
        assert!(
            matches!(mapping.target, MappingTarget::FileOnly),
            "{key} 的映射目标须为 FileOnly"
        );
        assert!(
            mapping.env_explicit_names.is_empty(),
            "{key} 不得声明 env 显式名"
        );
    }
    assert_eq!(MAPPINGS.len(), 48, "封闭映射表须仍恰 48 行");
    assert!(
        !MAPPINGS.iter().any(|m| m.key.starts_with("pii_scope.")
            && m.key != "pii_scope.mode"
            && m.key != "pii_scope.ttl_secs"
            && m.key != "pii_scope.max_conversations"),
        "pii_scope 只应保留 mode/ttl_secs/max_conversations 三条映射"
    );
}

#[test]
fn absent_session_section_keeps_defaults() {
    let file = TempFile::new("no-session.toml", "[audit]\nmode = \"off\"\n");
    let mut env = with_config_file(&file);
    let outcome = apply_config_file(&mut env).expect("文件层须应用成功");
    assert!(
        outcome.session.is_none(),
        "未声明 [session] 时产物须为 None"
    );
    let cfg = Config::load_from_with_file(&env, outcome).expect("配置须可加载");
    assert_eq!(cfg.session_headers, SessionHeaders::default_chain());
    assert_eq!(
        cfg.session_alias_max_entries,
        crate::config::env_parse::session::SESSION_ALIAS_MAX_ENTRIES_DEFAULT
    );
}

#[test]
fn header_chain_validation_fails_closed_at_startup() {
    for (content, needle) in [
        ("[session]\nheaders = []\n", "[session].headers"),
        (
            "[session]\nheaders = [\"bad header\"]\n",
            "[session].headers",
        ),
        (
            "[session]\nheaders = [\"X-Session\", \"x-session\"]\n",
            "重复",
        ),
        ("[session]\nheaders = [\"cookie\"]\n", "cookie"),
        (
            "[session]\nheaders = [\"transfer-encoding\"]\n",
            "transfer-encoding",
        ),
        ("[session]\nheaders = \"x-a\"\n", "headers"),
        ("[session]\nalias_max_entries = 0\n", "alias_max_entries"),
        ("[session]\nalias_max_entries = -1\n", "alias_max_entries"),
    ] {
        let file = TempFile::new("session-invalid.toml", content);
        let mut env = with_config_file(&file);
        // 类型错误在 TOML 反序列化阶段失败、语义错误在 `[session]` 加载期失败，
        // 两者都属 fail-closed；统一按「任一阶段报错且指名该键」断言。
        let message = match apply_config_file(&mut env) {
            Err(err) => err.to_string(),
            Ok(outcome) => Config::load_from_with_file(&env, outcome)
                .expect_err(&format!("{content} 须拒启动"))
                .to_string(),
        };
        assert!(
            message.contains(needle),
            "{content} 的错误须指名 {needle}: {message}"
        );
    }
}

/// 旧键 `pii_scope.key_header`：错误须指名旧键、替代键与**完整**建议数组。
#[test]
fn legacy_key_header_prescan_names_replacement_and_array() {
    let file = TempFile::new(
        "legacy-key-header.toml",
        "[pii_scope]\nmode = \"conversation\"\nkey_header = \"x-client-session\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧键须拒启动");
    let message = err.to_string();
    for needle in [
        "pii_scope.key_header",
        "[session].headers",
        "headers = [\"x-client-session\", \"x-opencode-session\", \"x-opencode-session-id\"]",
    ] {
        assert!(message.contains(needle), "错误须含 {needle}: {message}");
    }
    assert!(message.contains(BOOTSTRAP_VAR), "须指名引导变量: {message}");
}

/// 旧键 `pii_scope.prev_id_max_entries`：错误须指名旧键与替代键，并写明条目计口径。
#[test]
fn legacy_prev_id_prescan_names_replacement_and_semantics() {
    let file = TempFile::new(
        "legacy-prev-id.toml",
        "[pii_scope]\nprev_id_max_entries = 64\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧键须拒启动");
    let message = err.to_string();
    for needle in [
        "pii_scope.prev_id_max_entries",
        "[session].alias_max_entries",
        "alias_max_entries = 64",
        "按别名条目计",
    ] {
        assert!(message.contains(needle), "错误须含 {needle}: {message}");
    }
}

/// 迁移建议数组的五类边界（空 / 自定义 / 等于回退头 / 三个不可信名 / cookie）。
#[test]
fn legacy_key_header_migration_boundaries() {
    let build = |value: &str| {
        let file = TempFile::new(
            "legacy-boundary.toml",
            &format!("[pii_scope]\nkey_header = {value}\n"),
        );
        let mut env = with_config_file(&file);
        apply_config_file(&mut env)
            .expect_err("旧键须拒启动")
            .to_string()
    };

    let empty = build("\"\"");
    assert!(
        empty.contains(
            "headers = [\"x-veil-conversation-id\", \"x-opencode-session\", \"x-opencode-session-id\"]"
        ),
        "空旧值须给默认完整数组: {empty}"
    );

    let fallback = build("\"x-opencode-session\"");
    assert!(
        fallback.contains("headers = [\"x-opencode-session\", \"x-opencode-session-id\"]"),
        "等于回退头须去重: {fallback}"
    );

    for untrusted in [
        "\"x-opencode-parent-session-id\"",
        "\"x-session-affinity\"",
        "\"x-session-id\"",
        "\"cookie\"",
    ] {
        let message = build(untrusted);
        assert!(
            message.contains("无法等价迁移"),
            "{untrusted} 须明确告知无法等价迁移: {message}"
        );
    }
}

/// 未声明旧键的文件不产生预扫描误报（预扫描只命中 `[pii_scope]` 下这两个键）。
#[test]
fn prescan_is_silent_without_legacy_keys() {
    let file = TempFile::new(
        "no-legacy.toml",
        "[pii_scope]\nmode = \"request\"\nttl_secs = 60\n[session]\nheaders = [\"x-client-session\"]\n",
    );
    let mut env = with_config_file(&file);
    apply_config_file(&mut env).expect("无旧键须正常应用");
    assert_eq!(
        env.get("PII_SCOPE_TTL_SECS").map(String::as_str),
        Some("60")
    );
}

/// 语法错误不由预扫描拦下（错误归属仍为 TOML 解析单点）。
#[test]
fn prescan_defers_syntax_errors_to_toml_parser() {
    let file = TempFile::new("broken-toml.toml", "[pii_scope\nkey_header = \"x\"\n");
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("语法错误须拒启动");
    assert!(
        err.to_string().contains("TOML 解析失败"),
        "语法错误须由 TOML 解析报出: {err}"
    );
}
