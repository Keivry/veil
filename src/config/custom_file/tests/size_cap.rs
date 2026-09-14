//! `POL-3`/D3 自定义 PII 文件 1MB 上限单测（独立子模块保 `custom_file.rs` 800 行红线）：
//! 超限拒绝并报变量名/字节数、恰 1MB 放行、三槽一致。

use {
    super::{Config, base_env, custom_tmp_file},
    crate::config::custom_file::CUSTOM_FILE_MAX_BYTES,
};

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
