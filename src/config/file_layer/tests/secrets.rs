//! 文件层密钥权限门禁（`chmod 600` 要求；自 `tests.rs` 拆出保持红线内）。

use super::*;

#[cfg(unix)]
#[test]
fn secret_keys_with_wide_permissions_rejected() {
    let cases = [
        (
            "[matrix]\naccess_token = \"syt-token\"\n",
            "matrix.access_token",
        ),
        (
            "[admin]\ntoken = \"0123456789abcdef0123456789abcdef\"\n",
            "admin.token",
        ),
        (
            "[storage]\nveilctl_secret = \"deploy-secret\"\n",
            "storage.veilctl_secret",
        ),
        (
            "[storage]\nveilctl_binary_hash = \"abcdef0123456789\"\n",
            "storage.veilctl_binary_hash",
        ),
        (
            "[redaction]\nvalue_sample_hmac_key = \"hmac-key\"\n",
            "redaction.value_sample_hmac_key",
        ),
    ];
    for (index, (content, key)) in cases.iter().enumerate() {
        let file = TempFile::with_mode(&format!("secret-wide-{index}.toml"), content, 0o644);
        let mut env = with_config_file(&file);
        let err = apply_config_file(&mut env).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("chmod 600") && msg.contains("644"),
            "密钥键 {key} 宽权限须拒启动并给指引: {msg}"
        );
    }
}

/// 旧的 `[auth].matrix_access_token`：0.2.0 起在解析阶段即被拒，根本到不了密钥门禁
/// （无别名可作为绕过路径）。
#[cfg(unix)]
#[test]
fn legacy_secret_key_rejected_before_permission_gate() {
    let file = TempFile::with_mode(
        "secret-legacy-wide.toml",
        "[auth]\nmatrix_access_token = \"syt-token\"\n",
        0o644,
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧密钥键须拒启动");
    let message = err.to_string();
    assert!(
        message.contains("auth"),
        "错误须指名被删除的分节 auth: {message}"
    );
    assert!(
        !message.contains("chmod 600"),
        "旧键在解析阶段即拒，不应进入权限门禁: {message}"
    );
}

#[cfg(unix)]
#[test]
fn secret_key_with_narrow_permissions_passes() {
    let file = TempFile::with_mode(
        "secret-narrow.toml",
        "[storage]\nveilctl_secret = \"deploy-secret\"\n",
        0o600,
    );
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert_eq!(cfg.veilctl_secret.as_deref(), Some("deploy-secret"));
    assert_eq!(
        env.get("VEILCTL_SECRET").map(String::as_str),
        Some("deploy-secret")
    );
}

#[cfg(unix)]
#[test]
fn non_secret_wide_permissions_pass() {
    let file = TempFile::with_mode("non-secret.toml", "[redaction]\nenabled = false\n", 0o644);
    let mut env = with_config_file(&file);
    let cfg = apply_and_load(&mut env);
    assert!(!cfg.redaction_enabled, "无密钥不得施加权限门禁");
}

#[cfg(unix)]
#[test]
fn secret_env_override_does_not_exempt_gate() {
    let file = TempFile::with_mode(
        "secret-env-override.toml",
        "[storage]\nveilctl_secret = \"file-secret\"\n",
        0o644,
    );
    let mut env = with_config_file(&file);
    env.insert("VEILCTL_SECRET".to_string(), "env-secret".to_string());
    let err = apply_config_file(&mut env).unwrap_err();
    assert!(
        err.to_string().contains("chmod 600"),
        "env 覆盖不豁免门禁（密钥已落盘）: {err}"
    );
}
