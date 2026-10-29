//! `[limits]` 审计 hold 预算两键（`audit_hold_max_bytes` / `audit_hold_max_frames`）
//! 的文件层单测：TOML 类型拒收与越界值沿用 env 校验（`0` 一律拒启动）。

use super::*;

#[test]
fn limits_audit_hold_type_errors_rejected() {
    // 浮点类型在 toml 解析阶段即被拒（两键同口径），错误信息须指名键路径。
    for (text, key) in [
        (
            "[limits]\naudit_hold_max_bytes = 1.5\n",
            "audit_hold_max_bytes",
        ),
        (
            "[limits]\naudit_hold_max_frames = 1.5\n",
            "audit_hold_max_frames",
        ),
    ] {
        let err = parse(text).expect_err(&format!("类型错误 {key} 须被拒"));
        assert!(err.to_string().contains(key), "错误信息须指名 {key}: {err}");
    }
}

#[test]
fn limits_audit_hold_bounds_reuse_env_validation() {
    // 文件层 `0` 不得静默回落默认值：沿用 env 侧 `parse_positive` 校验并拒启动。
    for (content, var) in [
        (
            "[limits]\naudit_hold_max_bytes = 0\n",
            "AUDIT_HOLD_MAX_BYTES",
        ),
        (
            "[limits]\naudit_hold_max_frames = 0\n",
            "AUDIT_HOLD_MAX_FRAMES",
        ),
    ] {
        let file = TempFile::new("limits-bounds.toml", content);
        let mut env = with_config_file(&file);
        apply_only(&mut env);
        let err = Config::load_from(&env).unwrap_err();
        assert!(
            err.to_string().contains(var),
            "文件值越界须沿用既有 env 校验并指名 {var}: {err}"
        );
    }
}
