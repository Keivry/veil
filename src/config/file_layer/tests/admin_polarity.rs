//! `[admin].enabled` 主情形矩阵 + 旧分节拒绝。
//!
//! 四种文件情形（缺省启用、显式开启、显式关闭、空 token 关闭）必须各为独立用例：
//! 情形 1 与 2 的开关值相同但成因不同（缺省 vs 显式正向键），情形 1 与 4 的开关值
//! 相同但成因不同（token 非空 vs token 为空），合并后无法分辨是哪条路径坏了。旧
//! `[auth]` 分节自 0.2.0 起按未知分节拒启动，不再参与任何极性归一。

use super::*;

/// 应用一份 TOML 并取生效 `Config`（样例声明 `admin.token` 密钥类键，故按 0600 落盘）。
fn load(content: &str) -> Config {
    let file = TempFile::secret("admin-polarity.toml", content);
    let mut env = with_config_file(&file);
    apply_and_load(&mut env)
}

/// 情形 1：开关缺省 + token 非空 → 两者皆 `true`（缺省必须启用）。
#[test]
fn default_enables_admin_surface() {
    let cfg = load("[admin]\ntoken = \"admin-token-0123456789abcdef\"\n");
    assert!(cfg.admin_enabled, "缺省 admin.enabled 须为 true");
    assert!(
        cfg.admin_surface_enabled(),
        "token 非空且缺省启用时管理面须可用"
    );
}

/// 情形 2：显式 `enabled = true` + token 非空 → 两者皆 `true`
/// （正向键必须被真正读到：极性换算若把 `true` 映射成关闭，本用例即红）。
#[test]
fn explicit_true_with_token_enables_admin_surface() {
    let file = TempFile::secret(
        "admin-explicit-true.toml",
        "[admin]\nenabled = true\ntoken = \"admin-token-0123456789abcdef\"\n",
    );
    // 撤掉 env 注入的 token，令文件里的 `[admin].token` 成为生效来源。
    let mut env = with_config_file(&file);
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    let cfg = apply_and_load(&mut env);
    assert!(cfg.admin_enabled, "显式 admin.enabled = true 须保持开启");
    assert!(
        cfg.admin_surface_enabled(),
        "显式开启且 token 非空时管理面须可用"
    );

    // 反向对照：同一份文件把 token 置空串，管理面须转不可用。证明上一条断言由
    // 「开关 + token 非空」共同决定而非恒真；带 `[admin]` 分节与显式空串，区别于
    // 情形 4（完全无 `[admin]` 分节）。
    let empty_token = TempFile::secret(
        "admin-explicit-true-empty-token.toml",
        "[admin]\nenabled = true\ntoken = \"\"\n",
    );
    let mut env = with_config_file(&empty_token);
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    let cfg = apply_and_load(&mut env);
    assert!(
        cfg.admin_enabled,
        "开关仍为 true（显式 true 不因 token 为空而翻转）"
    );
    assert!(
        !cfg.admin_surface_enabled(),
        "token 置空后管理面须不可用（token 门禁独立生效）"
    );
}

/// 情形 3：`[admin] enabled = false` → 两者皆 `false`（新键负向）。
#[test]
fn explicit_false_disables_admin_surface() {
    let cfg = load("[admin]\nenabled = false\ntoken = \"admin-token-0123456789abcdef\"\n");
    assert!(!cfg.admin_enabled, "admin.enabled = false 须关闭开关");
    assert!(
        !cfg.admin_surface_enabled(),
        "开关关闭时管理面须不可用（即便 token 非空）"
    );
}

/// 情形 4：开关缺省 + token 为空 → 管理面不可用（token 门禁独立生效）。
#[test]
fn default_with_empty_token_disables_admin_surface() {
    let mut env = base_env();
    env.remove("OBSERVABILITY_ADMIN_TOKEN");
    let cfg = Config::load_from(&env).expect("缺 token 不得拒启动");
    assert!(cfg.admin_enabled, "缺省开关仍为 true");
    assert!(!cfg.admin_surface_enabled(), "token 为空时管理面须不可用");
    assert!(cfg.observability_admin_token.is_empty());
}

/// 边界 1：`[admin].enabled` 与已删除的 `[auth]` 分节并存 → 拒启动并指名 `auth`
/// （旧分节不再是「另一条归一来源」，本身就是未知键）。
#[test]
fn admin_enabled_with_legacy_auth_section_rejected() {
    let file = TempFile::secret(
        "admin-conflict.toml",
        "[admin]\nenabled = true\ntoken = \"admin-token-0123456789abcdef\"\n\
         [auth]\nobservability_disable = false\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧 [auth] 分节须拒启动");
    let message = err.to_string();
    assert!(
        message.contains("auth"),
        "错误须指名被删除的分节 auth: {message}"
    );
    assert!(
        !message.contains("admin.enabled"),
        "旧分节不得被静默归一: {message}"
    );
}

/// 旧键 `[auth] observability_disable = true`：0.2.0 起按未知分节拒启动，不再归一。
#[test]
fn legacy_observability_disable_rejected_naming_section() {
    let file = TempFile::secret(
        "admin-legacy-disable.toml",
        "[auth]\nobservability_disable = true\n\
         [admin]\ntoken = \"admin-token-0123456789abcdef\"\n",
    );
    let mut env = with_config_file(&file);
    let err = apply_config_file(&mut env).expect_err("旧键须拒启动");
    let message = err.to_string();
    assert!(
        message.contains("auth"),
        "错误须指名被删除的分节 auth: {message}"
    );
    assert!(
        !message.contains("admin.enabled"),
        "旧键不得被静默归一到 admin.enabled: {message}"
    );
}

/// 注入通道的 `ADMIN_ENABLED` 仍生效（env 显式恒胜）；不因旧键移除而失去能力。
#[test]
fn admin_enabled_env_injection_still_works() {
    let mut env = base_env();
    env.insert("ADMIN_ENABLED".to_string(), "0".to_string());
    let cfg = Config::load_from(&env).expect("注入通道须可加载");
    assert!(!cfg.admin_enabled, "ADMIN_ENABLED=0 须关闭开关");
    assert!(!cfg.admin_surface_enabled(), "开关关闭时管理面须不可用");

    let mut env = base_env();
    env.insert("ADMIN_ENABLED".to_string(), "1".to_string());
    let cfg = Config::load_from(&env).expect("注入通道须可加载");
    assert!(cfg.admin_enabled, "ADMIN_ENABLED=1 须打开开关");
    assert!(
        cfg.admin_surface_enabled(),
        "token 非空且开关打开时管理面可用"
    );
}
