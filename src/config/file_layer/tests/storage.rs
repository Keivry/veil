//! `[storage]` 请求日志两键（`request_log_enabled` / `request_log_retention_days`）
//! 的文件层单测：默认值、显式取值、`0` = 不清理，以及「无 env 对应源」的键归属。

use super::*;

fn apply_with_file(env: &mut HashMap<String, String>) -> Config {
    let outcome = apply_config_file(env).expect("文件层应用须成功");
    Config::load_from_with_file(env, outcome).expect("合并后配置须可加载")
}

#[test]
fn request_log_keys_default_when_section_absent() {
    let file = TempFile::new(
        "no-storage.toml",
        "[limits]\naudit_hold_max_bytes = 1048576\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert!(cfg.request_log_enabled, "缺省须启用请求日志");
    assert_eq!(cfg.request_log_retention_days, 7, "缺省保留 7 天");
}

#[test]
fn request_log_keys_default_when_section_present_without_them() {
    let file = TempFile::new(
        "storage-no-log-keys.toml",
        "[storage]\ndata_dir = \"/srv/veil\"\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert!(cfg.request_log_enabled);
    assert_eq!(cfg.request_log_retention_days, 7);
}

#[test]
fn request_log_keys_take_explicit_file_values() {
    let file = TempFile::new(
        "storage-log-keys.toml",
        "[storage]\nrequest_log_enabled = false\nrequest_log_retention_days = 30\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert!(!cfg.request_log_enabled);
    assert_eq!(cfg.request_log_retention_days, 30);
}

#[test]
fn request_log_retention_zero_means_no_purge() {
    let file = TempFile::new(
        "storage-log-zero.toml",
        "[storage]\nrequest_log_retention_days = 0\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert_eq!(
        cfg.request_log_retention_days, 0,
        "0 须原样保留（表示不清理），不得归一为默认值"
    );
}

#[test]
fn request_log_keys_have_no_env_surface() {
    for key in [
        "storage.request_log_enabled",
        "storage.request_log_retention_days",
    ] {
        let mapping = MAPPINGS
            .iter()
            .find(|m| m.key == key)
            .unwrap_or_else(|| panic!("{key} 须在封闭映射表中"));
        assert!(
            matches!(mapping.target, MappingTarget::FileOnly),
            "{key} 须为文件专属（无 env 对应源）"
        );
        assert!(
            mapping.env_explicit_names.is_empty(),
            "{key} 不得登记 env 显式名"
        );
    }
}

#[test]
fn request_log_keys_outcome_matches_config() {
    let file = TempFile::new(
        "storage-log-outcome.toml",
        "[storage]\nrequest_log_enabled = false\nrequest_log_retention_days = 3\n",
    );
    let mut env = with_config_file(&file);
    let outcome = apply_config_file(&mut env).expect("文件层应用须成功");
    assert!(!outcome.request_log.enabled);
    assert_eq!(outcome.request_log.retention_days, 3);
    let cfg = Config::load_from_with_file(&env, outcome).expect("合并后配置须可加载");
    assert!(!cfg.request_log_enabled);
    assert_eq!(cfg.request_log_retention_days, 3);
}

#[test]
fn request_log_key_type_errors_rejected() {
    for (text, key) in [
        (
            "[storage]\nrequest_log_enabled = \"no\"\n",
            "request_log_enabled",
        ),
        (
            "[storage]\nrequest_log_retention_days = -1\n",
            "request_log_retention_days",
        ),
        (
            "[storage]\nrequest_log_retention_days = 1.5\n",
            "request_log_retention_days",
        ),
    ] {
        let err = parse(text).expect_err(&format!("类型错误 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}
