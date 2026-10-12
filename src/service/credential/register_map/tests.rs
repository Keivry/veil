use {super::*, crate::config::AutoApprove, serde_json::json, std::collections::BTreeMap};

fn expected(entry: &str, fields: &[&str]) -> BTreeMap<String, Vec<String>> {
    BTreeMap::from([(
        entry.to_string(),
        fields.iter().map(|s| (*s).to_string()).collect(),
    )])
}

#[test]
fn parse_register_params_trim() {
    // 字段 trim 与构造下沉后语义不变——四字段 trim、空白
    // `caller_path` 归一空串、`entries`/`allow_mode` 复用同批解析。
    let p = parse_register_params(RegisterInputs {
        caller_path: "  /srv/job.sh  ",
        caller_hash: " hash1 ",
        name: " 网易 ",
        description: " desc ",
        entries: None,
        entry: Some(" 网易 "),
        field: Some(" 授权码 "),
        fields: Some(&json!(["密码", " 授权码 "])),
        allow_mode: Some(" auto "),
        auto: Some(false),
    });
    assert_eq!(p.caller_path, "/srv/job.sh");
    assert_eq!(p.caller_hash, "hash1");
    assert_eq!(p.name, "网易");
    assert_eq!(p.description, "desc");
    assert_eq!(p.entries, expected("网易", &["授权码", "密码"]));
    assert_eq!(
        p.allow_mode,
        Some(AutoApprove::Allow),
        "auto 须优先布尔回退"
    );

    let p2 = parse_register_params(RegisterInputs {
        caller_path: "   ",
        caller_hash: "",
        name: "",
        description: "",
        entries: Some(&json!({" 腾讯 ": " 微信 "})),
        entry: None,
        field: None,
        fields: None,
        allow_mode: Some("bogus"),
        auto: Some(true),
    });
    assert_eq!(p2.caller_path, "", "空白 caller_path 归一空串");
    assert_eq!(p2.entries, expected("腾讯", &["微信"]));
    assert_eq!(
        p2.allow_mode,
        Some(AutoApprove::Allow),
        "非法 allow_mode 回退 auto"
    );
}

#[test]
fn register_map_pure() {
    // 对象形（值字符串/数组/非法）。
    assert_eq!(
        parse_register_entries(Some(&json!({"网易": "授权码"})), None, None, None),
        expected("网易", &["授权码"])
    );
    assert_eq!(
        parse_register_entries(Some(&json!({"网易": ["授权码", "密码"]})), None, None, None),
        expected("网易", &["授权码", "密码"])
    );
    assert_eq!(
        parse_register_entries(Some(&json!({"网易": 42})), None, None, None),
        expected("网易", &[])
    );
    // 数组形：字符串项 + 对象项混合；纯字符串项字段为空。
    assert_eq!(
        parse_register_entries(
            Some(&json!(["网易", {"腾讯": ["a", "b"]}])),
            None,
            None,
            None
        ),
        BTreeMap::from([
            ("网易".to_string(), vec![]),
            ("腾讯".to_string(), vec!["a".to_string(), "b".to_string()]),
        ])
    );
    // 字符串形。
    assert_eq!(
        parse_register_entries(Some(&json!("网易")), None, None, None),
        expected("网易", &[])
    );
    // 空白键/空白字段剔除。
    assert_eq!(
        parse_register_entries(Some(&json!({"  ": "x", "k": "  "})), None, None, None),
        expected("k", &[])
    );
    assert_eq!(
        parse_register_entries(None, Some("网易"), Some("授权码"), Some(&json!("密码"))),
        expected("网易", &["授权码", "密码"])
    );
}

#[test]
fn register_map_single_entry_and_fields_fallback() {
    // entries 为空 → 回退 entry + field + fields（字符串/数组去重）。
    assert_eq!(
        parse_register_entries(None, Some("网易"), Some("授权码"), Some(&json!("密码"))),
        expected("网易", &["授权码", "密码"])
    );
    assert_eq!(
        parse_register_entries(
            None,
            Some(" 网易 "),
            None,
            Some(&json!(["授权码", "授权码", " 密码 ", 1]))
        ),
        expected("网易", &["授权码", "密码"])
    );
    // entries 非空时不回退。
    assert_eq!(
        parse_register_entries(
            Some(&json!({"a": "b"})),
            Some("网易"),
            Some("授权码"),
            Some(&json!("密码"))
        ),
        expected("a", &["b"])
    );
    // entry 空白/缺失 → 空映射。
    assert_eq!(
        parse_register_entries(None, Some("   "), Some("授权码"), None),
        BTreeMap::new()
    );
    assert_eq!(
        parse_register_entries(None, None, None, None),
        BTreeMap::new()
    );
}

#[test]
fn register_map_allow_mode_invalid_falls_back_to_auto() {
    assert_eq!(
        parse_register_allow_mode(Some("none"), None),
        Some(AutoApprove::Pending)
    );
    assert_eq!(
        parse_register_allow_mode(Some(" TRUE "), None),
        Some(AutoApprove::Allow)
    );
    // 非法/空白回退 auto。
    assert_eq!(
        parse_register_allow_mode(Some("bogus"), Some(false)),
        Some(AutoApprove::Deny)
    );
    assert_eq!(
        parse_register_allow_mode(Some("  "), Some(true)),
        Some(AutoApprove::Allow)
    );
    assert_eq!(parse_register_allow_mode(None, None), None);
    assert_eq!(parse_register_allow_mode(Some("bogus"), None), None);
}

#[test]
fn register_allow_mode_accepts_auto_and_manual() {
    // `auto`→放行、`manual`→审批，大小写不敏感且优先于布尔回退。
    assert_eq!(
        parse_register_allow_mode(Some("auto"), None),
        Some(AutoApprove::Allow)
    );
    assert_eq!(
        parse_register_allow_mode(Some(" AUTO "), None),
        Some(AutoApprove::Allow)
    );
    assert_eq!(
        parse_register_allow_mode(Some("manual"), None),
        Some(AutoApprove::Pending)
    );
    assert_eq!(
        parse_register_allow_mode(Some("Manual"), None),
        Some(AutoApprove::Pending)
    );
    assert_eq!(
        parse_register_allow_mode(Some("auto"), Some(false)),
        Some(AutoApprove::Allow),
        "auto 须优先于布尔回退"
    );
}
