use super::{super::is_dangerous, *};

#[test]
fn invalid_policy_file_fails_at_startup() {
    let config_err = |text: &str| -> String {
        match AuditPolicy::parse_minimal_yaml(text) {
            Err(crate::error::VeilError::Config { message, .. }) => message,
            other => panic!("须为 Config 错误，实际 {other:?}"),
        }
    };
    // 六类非法输入全部返回 `VeilError::Config` 并带行号/键名。
    assert!(config_err("mode: allow\n").contains("mode"));
    assert!(config_err("- 孤儿项\n").contains("不在任何段下"));
    assert!(config_err("未知键: 1\n").contains("未知键"));
    assert!(config_err("这是一行无法解析的文本\n").contains("无法解析"));
    assert!(config_err("allow: not-a-list\n").contains("列表段"));
    let unreadable = AuditPolicy::load_startup(Some(std::path::Path::new(
        "/nonexistent-veil-policy/policy.yaml",
    )))
    .expect_err("不可读策略文件须拒启动");
    assert!(
        matches!(unreadable, crate::error::VeilError::Config { .. }),
        "不可读须为 Config 错误"
    );
    let ok =
        AuditPolicy::parse_minimal_yaml("mode: block\nextra_block_substrings:\n  - rm -rf /\n")
            .unwrap();
    assert_eq!(ok.extra_block_substrings, vec!["rm -rf /"]);
    assert_eq!(ok.mode, Some(AuditMode::Block), "合法 mode 须写入策略字段");
    assert!(
        AuditPolicy::load_startup(None).is_ok(),
        "未配置策略文件须以默认策略启动"
    );
}

#[test]
fn corrupted_policy_file_rejects_startup_naming_var() {
    let path = std::env::temp_dir().join(format!(
        "veil-policy-corrupt-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(&path, "mode: bogus\n").unwrap();
    let err = AuditPolicy::load_startup(Some(&path)).expect_err("损坏策略须拒启动");
    std::fs::remove_file(&path).ok();
    assert!(
        err.to_string().contains("AUDIT_POLICY_FILE"),
        "错误文本须含变量名（启动 stderr 可见）: {err}"
    );
    assert!(
        matches!(err, crate::error::VeilError::Config { .. }),
        "损坏策略须为 Config 错误"
    );
    assert!(
        AuditPolicy::load_startup(None)
            .unwrap()
            .extra_dangerous
            .is_empty(),
        "未设置 AUDIT_POLICY_FILE 须以默认策略启动（不回归）"
    );
}

#[test]
fn policy_mode_effective() {
    use crate::config::env_parse::test_support::base_env;
    // 优先级纯函数四象限。
    assert_eq!(
        resolve_effective_mode(Some(AuditMode::Off), Some(AuditMode::Block)),
        AuditMode::Off,
        "env 显式优先于文件"
    );
    assert_eq!(
        resolve_effective_mode(Some(AuditMode::Approve), None),
        AuditMode::Approve
    );
    assert_eq!(
        resolve_effective_mode(None, Some(AuditMode::Block)),
        AuditMode::Block
    );
    assert_eq!(resolve_effective_mode(None, None), AuditMode::Off);

    // 文件 mode: block + env 未设 → 生效模式 Block 并注入运行时配置。
    let policy = AuditPolicy::parse_minimal_yaml("mode: block\n").unwrap();
    let mut config = Config::load_from(&base_env()).unwrap();
    assert!(!config.audit_mode_explicit, "基准 env 未设 AUDIT_MODE");
    policy.apply_effective_mode(&mut config);
    assert_eq!(config.audit_mode, AuditMode::Block, "文件 mode 须实际生效");

    // 显式 `AUDIT_MODE=off` 覆盖文件 `mode: block`（冲突以 env 为准）。
    let mut env = base_env();
    env.insert("AUDIT_MODE".into(), "off".into());
    let mut config = Config::load_from(&env).unwrap();
    assert!(config.audit_mode_explicit);
    policy.apply_effective_mode(&mut config);
    assert_eq!(config.audit_mode, AuditMode::Off, "env 显式覆盖文件 mode");

    // `AUDIT_ENABLED` 已废弃：不再置 `audit_mode_explicit`、不再回退 `block`；
    // 文件 `mode: off` 直接生效（生效来源只剩文件与策略文件）。
    let off = AuditPolicy::parse_minimal_yaml("mode: off\n").unwrap();
    let mut env = base_env();
    env.insert("AUDIT_ENABLED".into(), "1".into());
    let mut config = Config::load_from(&env).unwrap();
    assert!(
        !config.audit_mode_explicit,
        "AUDIT_ENABLED 不得再置 audit_mode_explicit"
    );
    assert_eq!(
        config.audit_mode,
        AuditMode::Off,
        "AUDIT_ENABLED 不得再回退 block"
    );
    off.apply_effective_mode(&mut config);
    assert_eq!(
        config.audit_mode,
        AuditMode::Off,
        "文件 mode: off 须生效（无 env 显式层）"
    );
}

#[test]
fn file_mode_approve_empty_whitelist_rejects() {
    use crate::config::{env_parse::test_support::base_env, validate_approve_whitelist};
    // `AUDIT_MODE` 未设 + 文件 `mode: approve` + 空白名单 → 生效模式 approve 须拒启动。
    let policy = AuditPolicy::parse_minimal_yaml("mode: approve\n").unwrap();
    let mut config = Config::load_from(&base_env()).unwrap();
    assert!(config.approval_whitelist.is_empty());
    policy.apply_effective_mode(&mut config);
    assert_eq!(config.audit_mode, AuditMode::Approve);
    let err =
        validate_approve_whitelist(config.audit_mode, &config.approval_whitelist).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("APPROVAL_WHITELIST"), "{msg}");
    assert!(msg.contains("approve"), "{msg}");
}

#[test]
fn file_mode_approve_with_whitelist_starts() {
    use crate::config::{env_parse::test_support::base_env, validate_approve_whitelist};
    // `AUDIT_MODE` 未设 + 文件 `mode: approve` + 非空白名单 → approve 生效且可启动。
    let policy = AuditPolicy::parse_minimal_yaml("mode: approve\n").unwrap();
    let mut env = base_env();
    env.insert(
        "APPROVAL_WHITELIST".to_string(),
        "@admin:example.com".to_string(),
    );
    let mut config = Config::load_from(&env).unwrap();
    policy.apply_effective_mode(&mut config);
    assert_eq!(config.audit_mode, AuditMode::Approve);
    assert!(
        validate_approve_whitelist(config.audit_mode, &config.approval_whitelist).is_ok(),
        "非空白名单须放行启动"
    );
}

#[test]
fn approve_empty_whitelist_env_gate() {
    use crate::config::env_parse::test_support::base_env;
    // env 路径既有门禁不回归：`AUDIT_MODE=approve` + 空名单由 `Config::load_from` 直接拒。
    let mut env = base_env();
    env.insert("AUDIT_MODE".to_string(), "approve".to_string());
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("APPROVAL_WHITELIST"), "{err}");
}

#[test]
fn audit_policy_object_form() {
    let flow = AuditPolicy::parse_minimal_yaml(
        "dangerous:\n  - {pattern: base64 -d, reason: 解码外传, network: true}\n",
    )
    .unwrap();
    assert_eq!(flow.extra_dangerous.len(), 1);
    assert_eq!(flow.extra_dangerous[0].pattern, "base64 -d");
    assert_eq!(flow.extra_dangerous[0].reason, "解码外传");
    assert!(flow.extra_dangerous[0].network);

    let block = AuditPolicy::parse_minimal_yaml(
        "dangerous:\n  - pattern: telnet\n    reason: 网络传输\n    network: true\n",
    )
    .unwrap();
    assert_eq!(block.extra_dangerous[0].pattern, "telnet");
    assert_eq!(block.extra_dangerous[0].reason, "网络传输");
    assert!(block.extra_dangerous[0].network);

    let dflt = AuditPolicy::parse_minimal_yaml("dangerous:\n  - pattern: curl\n    reason: 拉取\n")
        .unwrap();
    assert!(!dflt.extra_dangerous[0].network, "network 缺省 false");

    let json = AuditPolicy::parse_minimal_yaml(
        "dangerous:\n  - {\"pattern\": \"openssl\", \"reason\": \"解密\", \"network\": true}\n",
    )
    .unwrap();
    assert_eq!(json.extra_dangerous[0].pattern, "openssl");
    assert_eq!(json.extra_dangerous[0].reason, "解密");
    assert!(json.extra_dangerous[0].network);

    let mixed = AuditPolicy::parse_minimal_yaml(
        "dangerous:\n  - rm -rf / => 危险删除\n  - {pattern: mkfs, reason: 格式化, network: false}\n",
    )
    .unwrap();
    assert_eq!(mixed.extra_dangerous.len(), 2, "字符串形与对象形须并存");
    assert_eq!(mixed.extra_dangerous[0].pattern, "rm -rf /");
    assert_eq!(mixed.extra_dangerous[0].reason, "危险删除");

    let mut p = AuditPolicy::default_policy();
    p.extra_dangerous.push(DangerRule {
        pattern: "exfil-probe".to_string(),
        reason: "网络外传".to_string(),
        network: true,
    });
    p.internal_suffixes = vec!["corp.example".to_string()];
    assert!(
        is_dangerous("exec", "exfil-probe http://evil.example/x", &p).is_some(),
        "network=true 外部 host 须命中"
    );
    assert!(
        is_dangerous("exec", "exfil-probe http://svc.corp.example/x", &p).is_none(),
        "network=true 内网 host 须豁免"
    );
}

#[test]
fn audit_policy_legacy_file() {
    let path = std::env::temp_dir().join(format!(
        "veil-policy-legacy-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    let text = "\
allow:
  - read_file
deny:
  - evil_tool
internal_suffixes:
  - .corp
dangerous:
  - {pattern: rm -rf, reason: 危险删除, network: false}
  - {pattern: curl, reason: 网络外传, network: true}
";
    std::fs::write(&path, text).unwrap();
    let loaded = AuditPolicy::load_from_file(Some(&path));
    std::fs::remove_file(&path).ok();
    let p = loaded.unwrap();
    assert_eq!(p.allow, vec!["read_file"]);
    assert_eq!(p.deny, vec!["evil_tool"]);
    assert_eq!(p.internal_suffixes, vec![".corp"]);
    assert_eq!(p.extra_dangerous.len(), 2);
    assert_eq!(p.extra_dangerous[0].pattern, "rm -rf");
    assert_eq!(p.extra_dangerous[0].reason, "危险删除");
    assert!(!p.extra_dangerous[0].network);
    assert_eq!(p.extra_dangerous[1].pattern, "curl");
    assert!(p.extra_dangerous[1].network);
    assert!(is_dangerous("exec", "rm -rf /tmp", &p).is_some());
}

#[test]
fn policy_all_shapes_compat_loading() {
    let text = "allow:\n  - read_file\ndeny:\n  - evil\ninternal_suffixes:\n  - .corp\ndangerous:\n  - rm -rf / => 危险删除\n";
    let p = AuditPolicy::parse_minimal_yaml(text).unwrap();
    assert_eq!(p.allow, vec!["read_file"]);
    assert_eq!(p.deny, vec!["evil"]);
    assert_eq!(p.internal_suffixes, vec![".corp"]);
    assert_eq!(p.extra_dangerous.len(), 1);
    assert_eq!(p.extra_dangerous[0].reason, "危险删除");
    assert!(is_dangerous("exec", "rm -rf /tmp", &p).is_some());
}

#[test]
fn policy_top_level_json() {
    let text = r#"{"mode":"block","allow":["read_file"],"deny":["evil"],"internal_suffixes":[".Corp"],"extra_block_substrings":["RM -RF"],"dangerous":[{"pattern":"curl","reason":"网络外传","network":true}]}"#;
    let p = AuditPolicy::parse_json_policy(text).unwrap();
    assert_eq!(p.mode, Some(AuditMode::Block));
    assert_eq!(p.allow, vec!["read_file"]);
    assert_eq!(p.deny, vec!["evil"]);
    assert_eq!(p.internal_suffixes, vec![".corp"], "后缀须小写归一");
    assert_eq!(p.extra_block_substrings, vec!["rm -rf"], "子串须小写归一");
    assert_eq!(p.extra_dangerous.len(), 1);
    assert!(p.extra_dangerous[0].network);
    assert!(is_dangerous("exec", "curl http://evil.example/x", &p).is_some());

    // `load_from_file` 经 JSON 分支加载顶层对象。
    let path = std::env::temp_dir().join(format!(
        "veil-policy-json-{}-{}.json",
        std::process::id(),
        line!()
    ));
    std::fs::write(&path, text).unwrap();
    let loaded = AuditPolicy::load_from_file(Some(&path)).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(loaded.mode, Some(AuditMode::Block));
    assert_eq!(loaded.extra_dangerous.len(), 1);
}

#[test]
fn policy_json_dangerous_object() {
    // 对象形 `dangerous` 可加载、`network` 缺省 false；字符串形与 `[network]` 兼容。
    let p = AuditPolicy::parse_json_policy(
        r#"{"dangerous":[{"pattern":"telnet","reason":"网络传输"},{"pattern":"rm -rf","reason":"删除","network":false},"base64 -d => 解码 [network]"]}"#,
    )
    .unwrap();
    assert_eq!(p.extra_dangerous.len(), 3);
    assert_eq!(p.extra_dangerous[0].pattern, "telnet");
    assert!(!p.extra_dangerous[0].network, "network 缺省 false");
    assert_eq!(p.extra_dangerous[1].reason, "删除");
    assert_eq!(p.extra_dangerous[2].pattern, "base64 -d");
    assert!(p.extra_dangerous[2].network);
    // fail-closed：损坏 JSON / 未知键 / 类型不符均拒启动。
    assert!(AuditPolicy::parse_json_policy("{ not json").is_err());
    assert!(AuditPolicy::parse_json_policy(r#"{"unknown":1}"#).is_err());
    assert!(AuditPolicy::parse_json_policy(r#"{"allow":"x"}"#).is_err());
    assert!(AuditPolicy::parse_json_policy(r#"{"mode":"allow"}"#).is_err());
    assert!(AuditPolicy::parse_json_policy(r#"[1,2]"#).is_err());
}
