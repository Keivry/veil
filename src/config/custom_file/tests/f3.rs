//! F3 `PII_DICT_FILE` 别名单测（自 `custom_file.rs` 拆分保红线）：
//! 别名采用与列序优先级、主名/别名等价加载（解析/命中/脱敏一致）、缺失拒启动。

use {
    super::{Config, base_env, custom_tmp_file, parse_custom_text},
    std::collections::HashMap,
};

#[test]
fn pii_dict_file_alias_adopted_with_python_precedence() {
    // F3：`PII_DICT_FILE` 别名进字典槽（主名列首 > PII_DICT_FILE > Python 历史名）。
    let main = custom_tmp_file("dict-alias-main.json", r#"["主名"]"#);
    let alias = custom_tmp_file("dict-alias-py.json", r#"["别名"]"#);
    let hist = custom_tmp_file("dict-alias-hist.json", r#"["历史名"]"#);
    // 别名单独设置即被采用为字典路径。
    let mut env = base_env();
    env.insert(
        "PII_DICT_FILE".to_string(),
        alias.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(alias.as_path()));
    // Rust 主名列首优先。
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        main.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(main.as_path()));
    // `PII_DICT_FILE` 优先于 Python 历史名（相对优先级与 `_pii.py:569` 一致）。
    let mut env = base_env();
    env.insert(
        "PII_DICT_FILE".to_string(),
        alias.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_SENSITIVE_DICT_FILE".to_string(),
        hist.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        cfg.pii_custom_dict_file.as_deref(),
        Some(alias.as_path()),
        "PII_DICT_FILE 须优先于 PII_SENSITIVE_DICT_FILE"
    );
    // 别名缺失文件 fail-closed 且报错指明变量名。
    let mut env = base_env();
    env.insert(
        "PII_DICT_FILE".to_string(),
        "/nonexistent/veil-pii-dict-缺失.json".to_string(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("PII_DICT_FILE"), "实际: {err}");
    for p in [main, alias, hist] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn pii_dict_file_alias_equivalent_hits_and_redaction() {
    // F3 等价性：同一字典内容分别经主名与 `PII_DICT_FILE` 启动 → 解析条目一致、
    // 字典命中一致、脱敏输出（token 归一后）一致。
    let content = "张三\n李四\n";
    let main = custom_tmp_file("dict-eq-main.txt", content);
    let alias = custom_tmp_file("dict-eq-alias.txt", content);
    let entries_of = |var: &str, path: &std::path::Path| {
        let text = std::fs::read_to_string(path).unwrap();
        let value = parse_custom_text(var, path, &text).expect("TXT 名单须可解析");
        value
            .as_array()
            .expect("字典须为数组")
            .iter()
            .map(|v| (v.as_str().unwrap().to_string(), "name".to_string()))
            .collect::<Vec<_>>()
    };
    let main_entries = entries_of("PII_CUSTOM_DICT_FILE", &main);
    let alias_entries = entries_of("PII_DICT_FILE", &alias);
    assert_eq!(main_entries, alias_entries, "同内容解析条目须一致");
    let hits_of = |entries: &[(String, String)]| {
        use crate::service::pii::detector::test_support::{detector, empty_cred};
        let d = detector();
        d.load_dict(entries);
        let hits = d.scan_dict_sync("联系 张三 或 李四", &empty_cred());
        let mut named: Vec<String> = hits.iter().map(|h| h.1.clone()).collect();
        named.sort();
        named
    };
    assert_eq!(
        hits_of(&main_entries),
        hits_of(&alias_entries),
        "字典命中集合须一致"
    );
    let redact_of = |entries: &[(String, String)]| {
        use crate::service::pii::{PiiDetector, PiiScope};
        let d = PiiDetector::new();
        d.load_dict(entries);
        let scope = PiiScope::new();
        let out = crate::service::redaction::redact_leaf(
            &scope,
            &d,
            &crate::service::credential_vault::P2tSnapshot::empty(),
            &HashMap::new(),
            "联系 张三 或 李四".to_string(),
        );
        let re = regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("token 形态正则");
        re.replace_all(&out, "__PII_TOKEN__").into_owned()
    };
    let main_redacted = redact_of(&main_entries);
    let alias_redacted = redact_of(&alias_entries);
    assert_eq!(main_redacted, alias_redacted, "脱敏结果（归一后）须一致");
    assert!(
        !main_redacted.contains("张三") && !main_redacted.contains("李四"),
        "字典命中须被脱敏: {main_redacted}"
    );
    // Config 侧两名字均被采用（fail-closed 加载口径一致）。
    for (var, path) in [("PII_CUSTOM_DICT_FILE", &main), ("PII_DICT_FILE", &alias)] {
        let mut env = base_env();
        env.insert(var.to_string(), path.to_string_lossy().into_owned());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.pii_custom_dict_file.as_deref(),
            Some(path.as_path()),
            "{var}"
        );
    }
    for p in [main, alias] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn custom_inline_alias_fail_closed_and_overlay() {
    // P8/D9：无 `_FILE` 后缀短名槽（内联登记）与文件变量同加载器，非法值一律 fail-closed
    // 且报错含变量名。
    for var in ["PII_CUSTOM_RULES", "PII_CUSTOM_PATTERNS", "PII_CUSTOM_DICT"] {
        let mut env = base_env();
        env.insert(var.to_string(), "{不是 json".to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains(var), "变量 {var} 报错须指明变量名");
    }
    for var in ["PII_CUSTOM_RULES", "PII_CUSTOM_PATTERNS", "PII_CUSTOM_DICT"] {
        let mut env = base_env();
        env.insert(
            var.to_string(),
            "/nonexistent/veil-inline-缺失.json".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains(var), "变量 {var} 缺失须报错含名");
    }
    // 短名槽 + 分离文件槽叠加生效（跨槽）。
    let rules = custom_tmp_file("inline-rules.json", r#"[{"name":"x1","pattern":"X1\\d+"}]"#);
    let dict = custom_tmp_file("inline-dict.json", r#"["张三"]"#);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES".to_string(),
        rules.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
    for p in [rules, dict] {
        std::fs::remove_file(p).ok();
    }
}
