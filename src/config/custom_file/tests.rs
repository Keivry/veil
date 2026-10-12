use {
    super::*,
    crate::config::env_parse::{Config, test_support::base_env},
    std::collections::HashMap,
};

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "custom_file.rs",
        include_str!("../custom_file.rs"),
    );
}

fn custom_tmp_file(name: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("veil-config-test-{}-{name}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn custom_file_missing_rejects_startup_naming_var() {
    for var in [
        "PII_CUSTOM_RULES_FILE",
        "PII_CUSTOM_PATTERNS_FILE",
        "PII_CUSTOM_DICT_FILE",
        "PII_CUSTOM_RULES",
        "PII_CUSTOM_DICT",
    ] {
        let mut env = base_env();
        env.insert(
            var.to_string(),
            "/nonexistent/veil-custom-缺失.json".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains(var), "变量 {var} 报错须指明变量名");
    }
}

#[test]
fn custom_file_parse_failure_and_bad_shape_rejects_startup() {
    // 非法 JSON。
    let bad = custom_tmp_file("bad.json", "{不是 json");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_PATTERNS_FILE".to_string(),
        bad.to_string_lossy().into_owned(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("PII_CUSTOM_PATTERNS_FILE"));
    // 缺 pattern 字段。
    let malformed = custom_tmp_file("malformed.json", r#"[{"name":"x"}]"#);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        malformed.to_string_lossy().into_owned(),
    );
    let err = Config::load_from(&env).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("PII_CUSTOM_RULES_FILE"), "实际: {msg}");
    // 顶层非数组/映射。
    let scalar = custom_tmp_file("scalar.json", "42");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        scalar.to_string_lossy().into_owned(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("PII_CUSTOM_DICT_FILE"));
    for p in [bad, malformed, scalar] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn custom_file_valid_shape_allows() {
    let rules = custom_tmp_file(
        "rules.json",
        r#"[{"name":"ext-id","pattern":"EXT-\\d{6}"}]"#,
    );
    let patterns = custom_tmp_file("patterns.json", r#"{"p1":"bar\\d+"}"#);
    let dict = custom_tmp_file("dict.json", r#"[{"name":"张三丰","type":"name"}]"#);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        rules.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_PATTERNS".to_string(),
        patterns.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
    assert_eq!(
        cfg.pii_custom_patterns_file.as_deref(),
        Some(patterns.as_path())
    );
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
    // 未配置时为 None。
    let cfg = Config::load_from(&base_env()).unwrap();
    assert!(cfg.pii_custom_rules_file.is_none());
    for p in [rules, patterns, dict] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn yaml_merged_files_load_ok() {
    let rules = custom_tmp_file(
        "compat-rules.yaml",
        "# 自定义规则\n- name: ext-id\n  pattern: EXT-\\d{6}\n- name: emp_no\n  pattern: (?P<emp_no>(?<![\\d])工号\\d{6}(?![\\d]))\n",
    );
    let patterns = custom_tmp_file(
        "compat-patterns.yaml",
        "p1: bar\\d+\n# 注释行\np2: foo\\d+\n",
    );
    let dict = custom_tmp_file("compat-dict.yaml", "- 张三丰\n- 李四\n");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        rules.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_PATTERNS_FILE".to_string(),
        patterns.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
    assert_eq!(
        cfg.pii_custom_patterns_file.as_deref(),
        Some(patterns.as_path())
    );
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
    for p in [rules, patterns, dict] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn txt_allowlist_loads_ok_ignoring_comments() {
    let dict = custom_tmp_file(
        "compat-dict.txt",
        "# 敏感名单\n张三丰\n\n李四 # 行尾注释\n# 全行注释\n王五\n",
    );
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
    std::fs::remove_file(dict).ok();
}

#[test]
fn four_aliases_each_take_effect() {
    let rules = custom_tmp_file("alias-a.json", r#"[{"name":"x1","pattern":"X1\\d+"}]"#);
    let patterns = custom_tmp_file("alias-b.json", r#"{"p1":"P1\\d+"}"#);
    let dict = custom_tmp_file("alias-c.json", r#"["张三"]"#);
    let dict2 = custom_tmp_file("alias-d.json", r#"["李四"]"#);
    for (var, path, check) in [
        ("PII_RULES_FILE", &rules, "rules"),
        ("PII_CUSTOM_PATTERN_FILE", &patterns, "patterns"),
        ("PII_SENSITIVE_DICT_FILE", &dict, "dict"),
        ("PII_SENSITIVE_NAMES_FILE", &dict2, "dict"),
    ] {
        let mut env = base_env();
        env.insert(var.to_string(), path.to_string_lossy().into_owned());
        let cfg = Config::load_from(&env).unwrap();
        match check {
            "rules" => assert_eq!(
                cfg.pii_custom_rules_file.as_deref(),
                Some(path.as_path()),
                "{var}"
            ),
            "patterns" => assert_eq!(
                cfg.pii_custom_patterns_file.as_deref(),
                Some(path.as_path()),
                "{var}"
            ),
            _ => assert_eq!(
                cfg.pii_custom_dict_file.as_deref(),
                Some(path.as_path()),
                "{var}"
            ),
        }
    }
    for p in [rules, patterns, dict, dict2] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn three_vars_overlay_primary_file_wins_coexist() {
    let merged = custom_tmp_file(
        "overlay-merged.json",
        r#"[{"name":"m1","pattern":"M1\\d+"}]"#,
    );
    let alias = custom_tmp_file(
        "overlay-alias.json",
        r#"[{"name":"a1","pattern":"A1\\d+"}]"#,
    );
    let short = custom_tmp_file(
        "overlay-short.json",
        r#"[{"name":"s1","pattern":"S1\\d+"}]"#,
    );
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        merged.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_RULES_FILE".to_string(),
        alias.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_RULES".to_string(),
        short.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(merged.as_path()));
    let patterns = custom_tmp_file("overlay-p.json", r#"{"pp":"PP\\d+"}"#);
    let dict = custom_tmp_file("overlay-d.json", r#"["赵六"]"#);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        merged.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_PATTERNS_FILE".to_string(),
        patterns.to_string_lossy().into_owned(),
    );
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        dict.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert!(cfg.pii_custom_rules_file.is_some());
    assert!(cfg.pii_custom_patterns_file.is_some());
    assert!(cfg.pii_custom_dict_file.is_some());
    let mut env = base_env();
    env.insert(
        "PII_SENSITIVE_DICT_FILE".to_string(),
        "/nonexistent/veil-别名缺失.json".to_string(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("PII_SENSITIVE_DICT_FILE"));
    for p in [merged, alias, short, patterns, dict] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn empty_file_zero_hits_warns_and_allows() {
    let empty = custom_tmp_file("compat-empty.json", "   \n");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        empty.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(empty.as_path()));
    let comments_only = custom_tmp_file("compat-comments.txt", "# 只有注释\n# 无名单\n");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_DICT_FILE".to_string(),
        comments_only.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        cfg.pii_custom_dict_file.as_deref(),
        Some(comments_only.as_path())
    );
    std::fs::remove_file(empty).ok();
    std::fs::remove_file(comments_only).ok();
}

#[test]
fn yaml_bad_shape_rejects_startup() {
    let bad = custom_tmp_file("compat-bad.yaml", ":\n: :\n- \n???\n");
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        bad.to_string_lossy().into_owned(),
    );
    let err = Config::load_from(&env).unwrap_err();
    assert!(err.to_string().contains("PII_CUSTOM_RULES_FILE"));
    std::fs::remove_file(bad).ok();
}

#[test]
fn example_yaml_loads_on_startup() {
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        "examples/pii-custom.yaml".to_string(),
    );
    let cfg = Config::load_from(&env).unwrap();
    assert_eq!(
        cfg.pii_custom_rules_file.as_deref(),
        Some(std::path::Path::new("examples/pii-custom.yaml"))
    );
}

#[test]
fn multi_db_sorted_last_with_matching_key_preferred() {
    let dir = std::env::temp_dir().join(format!(
        "veil-resolve-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.kdbx"), b"a").unwrap();
    std::fs::write(dir.join("z.kdbx"), b"z").unwrap();
    std::fs::write(dir.join("z.key"), b"key").unwrap();
    let found = resolve_kdbx(&dir).expect("须选中末位库");
    assert_eq!(found.db_path, dir.join("z.kdbx"));
    assert_eq!(found.keyfile_path, Some(dir.join("z.key")));
    std::fs::remove_file(dir.join("z.key")).unwrap();
    let found = resolve_kdbx(&dir).expect("无 keyfile 仍选中库");
    assert_eq!(found.db_path, dir.join("z.kdbx"));
    assert_eq!(found.keyfile_path, None);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn kdbx_key_pairing() {
    // 多库取排序末位，仅同名 `.key` 配对，不取首个 `.key`。
    let dir = std::env::temp_dir().join(format!(
        "veil-resolve-pair-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.kdbx"), b"a").unwrap();
    std::fs::write(dir.join("a.key"), b"first-key").unwrap();
    std::fs::write(dir.join("z.kdbx"), b"z").unwrap();
    let found = resolve_kdbx(&dir).expect("须选中末位库");
    assert_eq!(found.db_path, dir.join("z.kdbx"), "须取排序末位 .kdbx");
    assert_eq!(
        found.keyfile_path, None,
        "末位库无同名 key 时不得取首个 .key"
    );
    std::fs::write(dir.join("z.key"), b"z-key").unwrap();
    let found = resolve_kdbx(&dir).expect("须选中末位库");
    assert_eq!(
        found.keyfile_path,
        Some(dir.join("z.key")),
        "仅同名 .key 配对"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_db_returns_none() {
    let dir = std::env::temp_dir().join(format!(
        "veil-resolve-empty-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.txt"), b"x").unwrap();
    assert!(resolve_kdbx(&dir).is_none());
    assert!(resolve_kdbx(&dir.join("不存在的子目录")).is_none());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pii_dict_file_alias_adopted_with_main_name_precedence() {
    // `PII_DICT_FILE` 别名进字典槽（主名列首 > PII_DICT_FILE > 历史别名）。
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
    // `PII_DICT_FILE` 优先于其它历史别名。
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
    // 等价性：同一字典内容分别经主名与 `PII_DICT_FILE` 启动 → 解析条目一致、
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
        let out = crate::service::redaction::leaf::redact_leaf(
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
    // 无 `_FILE` 后缀短名槽（内联登记）与文件变量同加载器，非法值一律 fail-closed
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

/// 构造内容为合法 JSON 数组、总字节恰为 `total` 的文件（尾部空白容纳长度）。
fn sized_json_file(name: &str, total: usize) -> std::path::PathBuf {
    let head = r#"[{"name":"x","pattern":"A"}]"#;
    assert!(head.len() <= total);
    let mut content = String::with_capacity(total);
    content.push_str(head);
    content.push_str(&" ".repeat(total - head.len()));
    custom_tmp_file(name, &content)
}

#[test]
fn custom_file_size_cap() {
    let path = sized_json_file("cap-over.json", (CUSTOM_FILE_MAX_BYTES + 1) as usize);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        path.to_string_lossy().into_owned(),
    );
    let err = Config::load_from(&env).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("PII_CUSTOM_RULES_FILE"),
        "报错须含变量名: {msg}"
    );
    assert!(
        msg.contains(&(CUSTOM_FILE_MAX_BYTES + 1).to_string()),
        "报错须含实际字节数: {msg}"
    );

    let boundary = sized_json_file("cap-boundary.json", CUSTOM_FILE_MAX_BYTES as usize);
    let mut env = base_env();
    env.insert(
        "PII_CUSTOM_RULES_FILE".to_string(),
        boundary.to_string_lossy().into_owned(),
    );
    let cfg = Config::load_from(&env).expect("恰 1MB 须放行且进入既有形态校验");
    assert_eq!(
        cfg.pii_custom_rules_file.as_deref(),
        Some(boundary.as_path())
    );

    std::fs::remove_file(path).ok();
    std::fs::remove_file(boundary).ok();
}

#[test]
fn custom_file_size_cap_all_slots() {
    for (var, slot) in [
        ("PII_CUSTOM_RULES_FILE", "rules"),
        ("PII_CUSTOM_PATTERNS_FILE", "patterns"),
        ("PII_CUSTOM_DICT_FILE", "dict"),
    ] {
        let path = sized_json_file(
            &format!("cap-slot-{slot}.json"),
            (CUSTOM_FILE_MAX_BYTES + 1) as usize,
        );
        let mut env = base_env();
        env.insert(var.to_string(), path.to_string_lossy().into_owned());
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "槽 {var} 超限须具名拒绝: {err}"
        );
        std::fs::remove_file(path).ok();
    }
}

#[test]
fn yaml_unquote_equivalence() {
    // 合并前的 `unquote`/`strip_yaml_quotes` 两份实现逐字节相同；此处以参考实现对照
    // 锁定单一实现等价：成对引号剥离 + trim，不成对/空白/转义序列原样保留。
    fn reference(s: &str) -> String {
        let s = s.trim();
        if s.len() >= 2
            && ((s.starts_with('"') && s.ends_with('"'))
                || (s.starts_with('\'') && s.ends_with('\'')))
        {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    }
    let cases: &[(&str, &str)] = &[
        ("\"quoted\"", "quoted"),
        ("'single'", "single"),
        ("  \"padded\"  ", "padded"),
        ("  'padded'  ", "padded"),
        ("unquoted", "unquoted"),
        ("  unquoted  ", "unquoted"),
        ("\"", "\""),
        ("''", ""),
        ("", ""),
        ("   ", ""),
        ("\"mismatch'", "\"mismatch'"),
        ("'mismatch\"", "'mismatch\""),
        ("\"a\\\"b\"", "a\\\"b"),
        ("'it''s'", "it''s"),
        ("\"\"", ""),
        ("x\"y\"", "x\"y\""),
    ];
    for (input, expected) in cases {
        assert_eq!(
            strip_yaml_quotes(input),
            reference(input),
            "strip_yaml_quotes({input:?}) 与参考实现不等价"
        );
        assert_eq!(
            strip_yaml_quotes(input),
            *expected,
            "strip_yaml_quotes({input:?}) 行为漂移"
        );
    }
}
