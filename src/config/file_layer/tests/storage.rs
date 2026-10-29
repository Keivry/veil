//! `[request_log]` 与 `[storage]` 两节的文件层单测：默认值、显式取值、
//! `0` = 不清理，「无 env 对应源」的键归属，以及 `[credential.authorization]`
//! 的 `0` = 无期限语义（tasks 2.2 / 6.2）。

use super::*;

fn apply_with_file(env: &mut HashMap<String, String>) -> Config {
    let outcome = apply_config_file(env).expect("文件层应用须成功");
    Config::load_from_with_file(env, outcome).expect("合并后配置须可加载")
}

#[test]
fn request_log_keys_default_when_section_absent() {
    let file = TempFile::new("no-request-log.toml", "[audit]\nhold_max_bytes = 1048576\n");
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
        "request-log-keys.toml",
        "[request_log]\nenabled = false\nretention_days = 30\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert!(!cfg.request_log_enabled);
    assert_eq!(cfg.request_log_retention_days, 30);
}

/// `retention_days = 0` 合法且原样保留（表示不清理），不得归一为默认值。
#[test]
fn request_log_retention_zero_means_no_purge() {
    let file = TempFile::new(
        "request-log-zero.toml",
        "[request_log]\nretention_days = 0\n",
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
    for key in ["request_log.enabled", "request_log.retention_days"] {
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

/// `[storage]` 只留路径与部署密钥六键。
#[test]
fn storage_section_limited_to_paths_and_secrets() {
    let storage_keys: Vec<&str> = MAPPINGS
        .iter()
        .map(|m| m.key)
        .filter(|key| key.starts_with("storage."))
        .collect();
    assert_eq!(
        storage_keys,
        vec![
            "storage.data_dir",
            "storage.db_dir",
            "storage.tpm_dir",
            "storage.caller_registry_path",
            "storage.veilctl_secret",
            "storage.veilctl_binary_hash",
        ],
        "[storage] 须只留路径与部署密钥"
    );
    for removed in [
        "storage.entry_mode",
        "storage.auto_approve",
        "storage.credential_block_wait",
        "storage.authorization_ttl_secs",
        "storage.request_log_enabled",
        "storage.request_log_retention_days",
    ] {
        assert!(
            !MAPPINGS.iter().any(|m| m.key == removed),
            "{removed} 已迁出 [storage]"
        );
    }
}

#[test]
fn request_log_keys_outcome_matches_config() {
    let file = TempFile::new(
        "request-log-outcome.toml",
        "[request_log]\nenabled = false\nretention_days = 3\n",
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
        ("[request_log]\nenabled = \"no\"\n", "enabled"),
        ("[request_log]\nretention_days = -1\n", "retention_days"),
        ("[request_log]\nretention_days = 1.5\n", "retention_days"),
    ] {
        let err = parse(text).expect_err(&format!("类型错误 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

/// `credential.default_decision` 的内建默认是 `Allow`（**不是** `pending`）：
/// design 1.4 的「默认 pending」是文档错误，见 R2。示例文件显式写 `pending`，
/// 那是示例值，不是内建默认。
#[test]
fn credential_default_decision_builtin_default_is_allow() {
    let baseline = Config::load_from(&base_env()).expect("基准须合法");
    assert_eq!(
        baseline.auto_approve,
        AutoApprove::Allow,
        "未声明 default_decision 时内建默认须为 allow"
    );

    // 分节存在但未声明该键：仍取内建默认。
    let file = TempFile::new(
        "credential-no-decision.toml",
        "[credential]\nvault_backend = \"real\"\n",
    );
    let mut env = with_config_file(&file);
    assert_eq!(apply_with_file(&mut env).auto_approve, AutoApprove::Allow);

    // 显式 pending 才生效（示例文件即此写法）。
    let file = TempFile::new(
        "credential-pending.toml",
        "[credential]\ndefault_decision = \"pending\"\n",
    );
    let mut env = with_config_file(&file);
    assert_eq!(apply_with_file(&mut env).auto_approve, AutoApprove::Pending);
}

/// `credential.authorization.ttl_secs = 0` 合法且归一为 `None`（无期限）。
#[test]
fn credential_authorization_ttl_zero_is_none() {
    let file = TempFile::new(
        "authorization-ttl-zero.toml",
        "[credential.authorization]\nttl_secs = 0\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert_eq!(
        cfg.authorization_ttl, None,
        "0 须归一为无期限（None），不得拒启动"
    );

    let file = TempFile::new(
        "authorization-ttl-nonzero.toml",
        "[credential.authorization]\nttl_secs = 3600\n",
    );
    let mut env = with_config_file(&file);
    let cfg = apply_with_file(&mut env);
    assert_eq!(cfg.authorization_ttl, Some(3_600));
}
