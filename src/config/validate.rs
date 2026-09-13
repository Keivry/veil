//! 启动期校验器：布尔开关/正整数/审计超时/白名单/占位符文案/遗留变量检出。

use {
    super::env_parse::{
        AUDIT_TIMEOUT_DEFAULT,
        AUDIT_TIMEOUT_RACE_MAX,
        AUDIT_TIMEOUT_RACE_MIN,
        PLACEHOLDER_PROMPT_DEFAULT,
        PLACEHOLDER_PROMPT_MAX_LEN,
    },
    crate::error::{Result, VeilError},
    std::collections::HashMap,
};

/// 原仓遗留变量名：二进制不读取，检出时启动期 warn 指引改名。
/// 权威清单：README §7.4 须逐项锁步（集合相等由 `legacy_vars_readme_lockstep` 守卫）。
pub const LEGACY_IGNORED_VARS: [(&str, &str); 6] = [
    (
        "CREDENTIAL_MASTER_PASSWORD",
        "主密码口令改走 TPM 解封（startup_tpm_in）",
    ),
    (
        "CREDENTIAL_PORT",
        "宿主机端口改用 PORT_8877/8878/8879（仅改映射）",
    ),
    (
        "CREDENTIAL_PROXY_DEBUG_DIR",
        "请求落盘排障改用结构化日志 + AUDIT_POLICY_FILE 审计面",
    ),
    (
        "ENV",
        "dev 环境显式配置 OBSERVABILITY_ADMIN_TOKEN 并携带 X-Admin-Token（回环免 token 未迁移，见 README §6.6）",
    ),
    (
        "ALLOW_LOOPBACK_NO_TOKEN",
        "回环免 token 未迁移：dev 环境显式配置 OBSERVABILITY_ADMIN_TOKEN 并携带 X-Admin-Token（见 README §6.6）",
    ),
    (
        "CREDENTIAL_API_PORT",
        "入口统一走 VEIL_ENTRY_MODE + 单端口 8877（见 README §8.4）",
    ),
];

/// 检出环境中的遗留变量（非空即命中；只读判定，不改变任何行为）。
pub fn legacy_ignored_detected(env: &HashMap<String, String>) -> Vec<&'static str> {
    LEGACY_IGNORED_VARS
        .iter()
        .filter(|(name, _)| env.get(*name).is_some_and(|v| !v.trim().is_empty()))
        .map(|(name, _)| *name)
        .collect()
}

pub(crate) fn is_falsy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// 真值集合 `1/true/yes/on`（trim + 大小写不敏感），默认关闭开关与
/// `AUDIT_ENABLED` 遗留回退共用同一口径，防两处集合漂移。
pub(crate) fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// 默认开启的布尔开关：空缺为真，仅显式假值关闭。
pub(crate) fn parse_bool_on(get: &dyn Fn(&str) -> Option<String>, var: &str) -> bool {
    match get(var).filter(|v| !v.is_empty()) {
        Some(v) => !is_falsy(&v),
        None => true,
    }
}

/// 默认关闭的布尔开关：空缺为假，仅显式真值开启。
pub(crate) fn parse_bool_off(get: &dyn Fn(&str) -> Option<String>, var: &str) -> bool {
    match get(var).filter(|v| !v.is_empty()) {
        Some(v) => is_truthy(&v),
        None => false,
    }
}

pub(crate) fn parse_placeholder_prompt(get: &dyn Fn(&str) -> Option<String>) -> (bool, String) {
    let raw = get("PII_PLACEHOLDER_PROMPT").unwrap_or_default();
    let enabled = !is_falsy(&raw);
    if !enabled {
        return (false, String::new());
    }
    let text = get("PII_PLACEHOLDER_PROMPT_TEXT").unwrap_or_default();
    if text.trim().is_empty() {
        return (true, String::new());
    }
    if has_placeholder_token_shape(&text) {
        tracing::warn!("PII_PLACEHOLDER_PROMPT_TEXT 含合法形态占位符，回退内置默认文案");
        return (true, String::new());
    }
    if text.len() > PLACEHOLDER_PROMPT_MAX_LEN {
        tracing::warn!(
            "PII_PLACEHOLDER_PROMPT_TEXT 超长（{}>{}），截断到上限",
            text.len(),
            PLACEHOLDER_PROMPT_MAX_LEN
        );
        let mut end = PLACEHOLDER_PROMPT_MAX_LEN;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        return (true, text[..end].to_string());
    }
    (true, text)
}

fn has_placeholder_token_shape(text: &str) -> bool {
    fn is_hex8(b: &[u8]) -> bool { b.len() == 8 && b.iter().all(|c| c.is_ascii_hexdigit()) }
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if text[i..].starts_with("__PII_") {
            let rest = &text[i + 6..];
            if let Some(us) = rest.find('_')
                && rest[..us].bytes().all(|c| c.is_ascii_digit())
                && !rest[..us].is_empty()
            {
                let after = &rest[us + 1..];
                if after.len() >= 10
                    && is_hex8(&after.as_bytes()[..8])
                    && after[8..].starts_with("__")
                {
                    return true;
                }
            }
        }
        if text[i..].starts_with("__VG_CRED_") {
            let rest = &text[i + 10..];
            let digits: usize = rest.bytes().take_while(|c| c.is_ascii_digit()).count();
            if digits > 0 && rest[digits..].starts_with("__") {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// 当前生效的占位符说明文案：自定义非空用自定义，否则内置默认。
pub fn effective_placeholder_prompt(custom: &str) -> &str {
    if custom.trim().is_empty() {
        PLACEHOLDER_PROMPT_DEFAULT
    } else {
        custom.trim()
    }
}

pub(crate) fn config_error(var: &str, message: &str) -> VeilError {
    VeilError::Config {
        var: var.to_string(),
        message: message.to_string(),
    }
}

pub(crate) fn require_non_empty(get: &dyn Fn(&str) -> Option<String>, var: &str) -> Result<String> {
    match get(var) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(config_error(
            var,
            &format!("未设置必填环境变量 {var}，拒绝启动"),
        )),
    }
}

pub(crate) fn parse_positive(
    get: &dyn Fn(&str) -> Option<String>,
    var: &str,
    default: i64,
) -> Result<i64> {
    let raw = get(var)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string());
    match raw.parse::<i64>() {
        Ok(v) if v >= 1 => Ok(v),
        Ok(_) => Err(config_error(var, &format!("{var} 必须 ≥1 正整数: {raw:?}"))),
        Err(_) => Err(config_error(var, &format!("{var} 非法整数: {raw:?}"))),
    }
}

pub(crate) fn parse_positive_u64(
    get: &dyn Fn(&str) -> Option<String>,
    var: &str,
    default: u64,
) -> Result<u64> {
    let raw = get(var)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string());
    match raw.parse::<u64>() {
        Ok(v) if v >= 1 => Ok(v),
        Ok(_) => Err(config_error(var, &format!("{var} 必须 ≥1 正整数: {raw:?}"))),
        Err(_) => Err(config_error(var, &format!("{var} 非法整数: {raw:?}"))),
    }
}

pub(crate) fn parse_positive_usize(
    get: &dyn Fn(&str) -> Option<String>,
    var: &str,
    default: usize,
) -> Result<usize> {
    let raw = get(var)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string());
    match raw.parse::<usize>() {
        Ok(v) if v >= 1 => Ok(v),
        Ok(_) => Err(config_error(var, &format!("{var} 必须 ≥1 正整数: {raw:?}"))),
        Err(_) => Err(config_error(var, &format!("{var} 非法整数: {raw:?}"))),
    }
}

pub(crate) fn parse_audit_timeout(get: &dyn Fn(&str) -> Option<String>) -> Result<i64> {
    let raw = get("AUDIT_TIMEOUT")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| AUDIT_TIMEOUT_DEFAULT.to_string());
    let timeout: i64 = raw
        .parse()
        .map_err(|_| config_error("AUDIT_TIMEOUT", &format!("AUDIT_TIMEOUT 非法整数: {raw:?}")))?;
    if timeout < 1 {
        return Err(config_error(
            "AUDIT_TIMEOUT",
            &format!("AUDIT_TIMEOUT 必须 ≥1s: {raw:?}"),
        ));
    }
    if (AUDIT_TIMEOUT_RACE_MIN..=AUDIT_TIMEOUT_RACE_MAX).contains(&timeout) {
        return Err(config_error(
            "AUDIT_TIMEOUT",
            &format!(
                "AUDIT_TIMEOUT 不得落在 {AUDIT_TIMEOUT_RACE_MIN}-{AUDIT_TIMEOUT_RACE_MAX}s 竞态区间\
                （上游约 120s 断连窗口）: {raw:?}，合法区间为 ≥1 且避开 110-130",
            ),
        ));
    }
    Ok(timeout)
}

pub(crate) fn parse_whitelist(get: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>> {
    let raw = get("APPROVAL_WHITELIST").unwrap_or_default();
    let mut out = Vec::new();
    for member in raw.split(',') {
        let mut m = member.trim().to_string();
        if m.len() >= 2
            && ((m.starts_with('"') && m.ends_with('"'))
                || (m.starts_with('\'') && m.ends_with('\'')))
        {
            m = m[1..m.len() - 1].to_string();
        }
        if m.is_empty() {
            continue;
        }
        if !is_valid_mxid(&m) {
            return Err(config_error(
                "APPROVAL_WHITELIST",
                &format!("APPROVAL_WHITELIST 成员格式非法: {m:?}（须形如 @user:server）"),
            ));
        }
        out.push(m);
    }
    Ok(out)
}

fn is_valid_mxid(s: &str) -> bool {
    let rest = s.strip_prefix('@').unwrap_or("");
    // A12/D11：`@` 前缀之后（localpart + domain）不得再含 `@`
    // （等价 Python `s[1:].count('@') == 0`），否则 `@a@b:c` 被误放行。
    if rest.contains('@') {
        return false;
    }
    let mut parts = rest.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(user), Some(server), None) => {
            !user.is_empty() && !server.is_empty() && !s.chars().any(|c| c.is_whitespace())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::config::env_parse::{AuditMode, Config, test_support::base_env},
    };

    #[test]
    fn audit_timeout_zero_negative_and_forbidden_zone_rejects_startup() {
        for raw in ["0", "-5", "110", "120", "130"] {
            let mut env = base_env();
            env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("AUDIT_TIMEOUT"),
                "报错须指明变量名，输入 {raw} 实际: {msg}"
            );
        }
    }

    #[test]
    fn audit_timeout_valid_values_allow_with_range_hint() {
        for (raw, want) in [("90", 90), ("1", 1), ("109", 109), ("131", 131)] {
            let mut env = base_env();
            env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
            let cfg = Config::load_from(&env).unwrap();
            assert_eq!(cfg.audit_timeout_secs, want);
        }
        let mut env = base_env();
        env.insert("AUDIT_TIMEOUT".to_string(), "120".to_string());
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(msg.contains("110-130") && msg.contains("≥1"));
    }

    #[test]
    fn pii_hold_max_non_positive_rejects_startup() {
        for raw in ["0", "-1", "abc", "1.5"] {
            let mut env = base_env();
            env.insert("PII_HOLD_MAX".to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            assert!(
                err.to_string().contains("PII_HOLD_MAX"),
                "输入 {raw} 报错须指明变量名"
            );
        }
    }

    #[test]
    fn nonstream_max_bytes_default_override_and_invalid_reject() {
        // F2 三例：缺省 8388608、覆盖生效、非法（非整数或 <1）拒启动（fail-closed）。
        let cfg = Config::load_from(&base_env()).unwrap();
        assert_eq!(cfg.nonstream_max_bytes, 8 * 1024 * 1024);
        let mut env = base_env();
        env.insert("NONSTREAM_MAX_BYTES".to_string(), "1024".to_string());
        assert_eq!(Config::load_from(&env).unwrap().nonstream_max_bytes, 1024);
        for raw in ["0", "-1", "abc", "1.5"] {
            let mut env = base_env();
            env.insert("NONSTREAM_MAX_BYTES".to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            assert!(
                err.to_string().contains("NONSTREAM_MAX_BYTES"),
                "输入 {raw} 报错须指明变量名"
            );
        }
    }

    #[test]
    fn invalid_whitelist_member_rejects_startup() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "approve".to_string());
        env.insert(
            "APPROVAL_WHITELIST".to_string(),
            "\"@keivry@matrix.example\"".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("APPROVAL_WHITELIST"));
    }

    #[test]
    fn invalid_audit_mode_rejects_startup_with_valid_values() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "allow".to_string());
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(msg.contains("AUDIT_MODE") && msg.contains("off/block/approve"));
    }

    #[test]
    fn audit_enabled_fallback_at_config_load() {
        let fallback_block = |raw: &str| {
            let mut env = base_env();
            env.insert("AUDIT_ENABLED".to_string(), raw.to_string());
            Config::load_from(&env).unwrap().audit_mode
        };
        assert_eq!(fallback_block("1"), AuditMode::Block);
        assert_eq!(fallback_block("on"), AuditMode::Block);

        let mut blank_mode = base_env();
        blank_mode.insert("AUDIT_MODE".to_string(), "   ".to_string());
        blank_mode.insert("AUDIT_ENABLED".to_string(), "yes".to_string());
        assert_eq!(
            Config::load_from(&blank_mode).unwrap().audit_mode,
            AuditMode::Block
        );

        let mut explicit_off = base_env();
        explicit_off.insert("AUDIT_MODE".to_string(), "off".to_string());
        explicit_off.insert("AUDIT_ENABLED".to_string(), "1".to_string());
        assert_eq!(
            Config::load_from(&explicit_off).unwrap().audit_mode,
            AuditMode::Off
        );

        let mut explicit_approve = base_env();
        explicit_approve.insert("AUDIT_MODE".to_string(), "approve".to_string());
        explicit_approve.insert(
            "APPROVAL_WHITELIST".to_string(),
            "@admin:example.com".to_string(),
        );
        explicit_approve.insert("AUDIT_ENABLED".to_string(), "1".to_string());
        assert_eq!(
            Config::load_from(&explicit_approve).unwrap().audit_mode,
            AuditMode::Approve
        );

        let mut falsy = base_env();
        falsy.insert("AUDIT_ENABLED".to_string(), "0".to_string());
        assert_eq!(
            Config::load_from(&falsy).unwrap().audit_mode,
            AuditMode::Off
        );
    }

    /// A7/D6：真值集恒为 `1/true/yes/on`（trim + 大小写不敏感）；显式非空 `AUDIT_MODE`
    /// 优先，空白 `AUDIT_MODE` 走 `AUDIT_ENABLED` 回退映射 `block`。
    #[test]
    fn audit_enabled_truthy_table() {
        let mode_of = |audit_mode: Option<&str>, audit_enabled: Option<&str>| {
            let mut env = base_env();
            env.insert(
                "APPROVAL_WHITELIST".to_string(),
                "@admin:example.com".to_string(),
            );
            match audit_mode {
                Some(v) => env.insert("AUDIT_MODE".to_string(), v.to_string()),
                None => env.remove("AUDIT_MODE"),
            };
            match audit_enabled {
                Some(v) => env.insert("AUDIT_ENABLED".to_string(), v.to_string()),
                None => env.remove("AUDIT_ENABLED"),
            };
            Config::load_from(&env).unwrap().audit_mode
        };
        // 真值样本（含大小写与首尾空白变体）→ block。
        for raw in ["1", "true", "TRUE", "yes", "YES", "on", " On ", "\ttrue\n"] {
            assert_eq!(
                mode_of(None, Some(raw)),
                AuditMode::Block,
                "真值须启用审计: {raw:?}"
            );
            assert_eq!(
                mode_of(Some("   "), Some(raw)),
                AuditMode::Block,
                "空白 AUDIT_MODE 须走回退: {raw:?}"
            );
        }
        // 非真值/乱值 → 不启用（off）。
        for raw in ["0", "false", "no", "off", "bogus", "", "   "] {
            assert_eq!(
                mode_of(None, Some(raw)),
                AuditMode::Off,
                "非真值不得启用审计: {raw:?}"
            );
        }
        // 显式非空 AUDIT_MODE 优先（含显式 off），回退不生效。
        for explicit in ["off", "block", "approve"] {
            let enabled = matches!(explicit, "block" | "approve");
            let mode = mode_of(Some(explicit), Some(if enabled { "0" } else { "1" }));
            let want = match explicit {
                "off" => AuditMode::Off,
                "block" => AuditMode::Block,
                _ => AuditMode::Approve,
            };
            assert_eq!(mode, want, "显式 AUDIT_MODE={explicit} 须优先");
        }
        // 两者皆缺省 → off。
        assert_eq!(mode_of(None, None), AuditMode::Off);
    }

    /// A7/D6：非法 `AUDIT_TIMEOUT`（0/负/110-130）与 `AUDIT_HOLD_MAX_BYTES`（0/非整数）
    /// 一律拒启动，不静默回落默认值。
    #[test]
    fn audit_invalid_env_rejects() {
        for raw in ["0", "-1", "110", "120", "130", "abc", "1.5"] {
            let mut env = base_env();
            env.insert("AUDIT_TIMEOUT".to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            assert!(
                err.to_string().contains("AUDIT_TIMEOUT"),
                "AUDIT_TIMEOUT={raw:?} 须拒启动并指明变量"
            );
        }
        for raw in ["0", "-1", "abc", "1.5"] {
            let mut env = base_env();
            env.insert("AUDIT_HOLD_MAX_BYTES".to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            assert!(
                err.to_string().contains("AUDIT_HOLD_MAX_BYTES"),
                "AUDIT_HOLD_MAX_BYTES={raw:?} 须拒启动并指明变量"
            );
        }
        // 合法边界仍放行（1 与 109/131 避开禁区）。
        let mut env = base_env();
        env.insert("AUDIT_TIMEOUT".to_string(), "109".to_string());
        env.insert("AUDIT_HOLD_MAX_BYTES".to_string(), "1".to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.audit_timeout_secs, 109);
        assert_eq!(cfg.audit_hold_max_bytes, 1);
    }

    #[test]
    fn placeholder_toggle_defaults_on_and_off_short_circuits() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(cfg.placeholder_prompt_enabled);
        assert!(cfg.placeholder_prompt_text.is_empty());
        for raw in ["0", "false", "no", "  No  "] {
            let mut env = base_env();
            env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
            env.insert(
                "PII_PLACEHOLDER_PROMPT_TEXT".to_string(),
                "__PII_1_ab12cd34__".repeat(100),
            );
            let cfg = Config::load_from(&env).unwrap();
            assert!(!cfg.placeholder_prompt_enabled, "{raw}");
            assert!(cfg.placeholder_prompt_text.is_empty());
        }
        for raw in ["1", "true", "yes", ""] {
            let mut env = base_env();
            if raw.is_empty() {
                env.remove("PII_PLACEHOLDER_PROMPT");
            } else {
                env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
            }
            let cfg = Config::load_from(&env).unwrap();
            assert!(cfg.placeholder_prompt_enabled, "{raw}");
        }
    }

    #[test]
    fn placeholder_text_cap_and_shape_fallback() {
        let mut env = base_env();
        env.insert(
            "PII_PLACEHOLDER_PROMPT_TEXT".to_string(),
            "Keep verbatim".to_string(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            effective_placeholder_prompt(&cfg.placeholder_prompt_text),
            "Keep verbatim"
        );
        for bad in [
            "Keep __PII_1_ab12cd34__ verbatim",
            "Keep __PII_1_AB12CD34__ verbatim",
            "Keep __VG_CRED_42__ verbatim",
        ] {
            let mut env = base_env();
            env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), bad.to_string());
            let cfg = Config::load_from(&env).unwrap();
            assert!(cfg.placeholder_prompt_text.is_empty(), "{bad}");
            assert!(
                effective_placeholder_prompt(&cfg.placeholder_prompt_text).contains("__PII_*__")
            );
        }
        let long = "x".repeat(PLACEHOLDER_PROMPT_MAX_LEN + 100);
        let mut env = base_env();
        env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), long);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.placeholder_prompt_text.len(),
            PLACEHOLDER_PROMPT_MAX_LEN
        );
        let mut env = base_env();
        env.insert("PII_PLACEHOLDER_PROMPT_TEXT".to_string(), "   ".to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.placeholder_prompt_text.is_empty());
    }

    #[test]
    fn placeholder_off_disables_reusing_falsy() {
        for raw in ["off", "OFF", "  off  "] {
            let mut env = base_env();
            env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
            let cfg = Config::load_from(&env).unwrap();
            assert!(!cfg.placeholder_prompt_enabled, "{raw}");
        }
    }

    #[test]
    fn legacy_var_names_not_read() {
        let mut env = base_env();
        env.insert(
            "CREDENTIAL_MASTER_PASSWORD".to_string(),
            "旧主密码".to_string(),
        );
        env.insert("CREDENTIAL_PORT".to_string(), "9999".to_string());
        // 检出谓词：三遗留变量非空即命中（含 DEBUG_DIR），空值不命中。
        assert_eq!(
            legacy_ignored_detected(&env),
            vec!["CREDENTIAL_MASTER_PASSWORD", "CREDENTIAL_PORT"]
        );
        env.insert(
            "CREDENTIAL_PROXY_DEBUG_DIR".to_string(),
            "/tmp/debug".to_string(),
        );
        assert_eq!(legacy_ignored_detected(&env).len(), 3);
        let mut empty_hit = base_env();
        empty_hit.insert("CREDENTIAL_PORT".to_string(), "   ".to_string());
        assert!(legacy_ignored_detected(&empty_hit).is_empty());
        // 行为仍为不读取：启动仅 warn，不断链、不生效。
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.credential_secret.is_none());
        assert!(!cfg.llm_upstreams.contains_key(&9999));
        assert!(crate::service::llm_gateway::resolve_upstream(&cfg, Some(9999)).is_none());
    }

    #[test]
    fn legacy_warn_covers_env_loopback_and_api_port() {
        let mut env = base_env();
        for var in ["ENV", "ALLOW_LOOPBACK_NO_TOKEN", "CREDENTIAL_API_PORT"] {
            env.insert(var.to_string(), "set".to_string());
        }
        let detected = legacy_ignored_detected(&env);
        for var in ["ENV", "ALLOW_LOOPBACK_NO_TOKEN", "CREDENTIAL_API_PORT"] {
            assert!(detected.contains(&var), "{var} 非空须命中");
        }
        let blank = HashMap::from([
            ("ENV".to_string(), "  ".to_string()),
            ("ALLOW_LOOPBACK_NO_TOKEN".to_string(), String::new()),
            ("CREDENTIAL_API_PORT".to_string(), "\t".to_string()),
        ]);
        assert!(legacy_ignored_detected(&blank).is_empty(), "空值不得命中");
        let mut loaded = base_env();
        loaded.insert("ENV".to_string(), "dev".to_string());
        loaded.insert("ALLOW_LOOPBACK_NO_TOKEN".to_string(), "1".to_string());
        loaded.insert("CREDENTIAL_API_PORT".to_string(), "9999".to_string());
        let cfg = Config::load_from(&loaded).unwrap();
        assert_eq!(cfg.audit_mode, AuditMode::Off);
        assert_eq!(cfg.entry_mode, crate::config::EntryMode::Full);
        assert!(!cfg.credential_block_wait);
        assert!(!cfg.llm_upstreams.contains_key(&9999));
    }

    #[test]
    fn legacy_ignored_vars_set_locked() {
        let names: std::collections::BTreeSet<&str> =
            LEGACY_IGNORED_VARS.iter().map(|(name, _)| *name).collect();
        let want = std::collections::BTreeSet::from([
            "CREDENTIAL_MASTER_PASSWORD",
            "CREDENTIAL_PORT",
            "CREDENTIAL_PROXY_DEBUG_DIR",
            "ENV",
            "ALLOW_LOOPBACK_NO_TOKEN",
            "CREDENTIAL_API_PORT",
        ]);
        assert_eq!(
            names, want,
            "清单须恰为六项，增删须同步本测试与本 change spec"
        );
        assert_eq!(LEGACY_IGNORED_VARS.len(), 6, "不得重复项扩容");
        for (name, hint) in LEGACY_IGNORED_VARS {
            assert!(!hint.trim().is_empty(), "{name} hint 不得为空");
        }
    }

    #[test]
    fn legacy_vars_readme_lockstep() {
        const README: &str = include_str!("../../README.md");
        let section = README
            .split("### 7.4 遗留变量兼容表")
            .nth(1)
            .expect("README 须含 §7.4 遗留变量兼容表");
        let mut names: Vec<String> = Vec::new();
        for line in section.lines().skip(1) {
            if line.starts_with("### ") {
                break;
            }
            let Some(row) = line.strip_prefix('|') else {
                continue;
            };
            let cell = row.split('|').next().unwrap_or("").trim();
            let name = cell.trim_matches('`').trim();
            if name.is_empty() || name == "遗留变量" || name.chars().all(|c| c == ':' || c == '-')
            {
                continue;
            }
            names.push(name.to_string());
        }
        let readme_set: std::collections::BTreeSet<String> = names.iter().cloned().collect();
        let list_set: std::collections::BTreeSet<String> = LEGACY_IGNORED_VARS
            .iter()
            .map(|(name, _)| name.to_string())
            .collect();
        assert_eq!(
            readme_set, list_set,
            "README §7.4 与 LEGACY_IGNORED_VARS 名称集合须相等"
        );
        assert_eq!(names.len(), readme_set.len(), "README §7.4 不得重复变量行");
    }

    /// A12/D11：`@` 前缀后再含 `@` 的 MXID 一律拒绝（配置侧与 Matrix 链路侧同结论）。
    #[test]
    fn mxid_reject_multiple_at() {
        assert!(!is_valid_mxid("@a@b:c"));
        let get = |_: &str| Some("@a@b:c".to_string());
        assert!(parse_whitelist(&get).is_err());
        assert!(crate::service::matrix::validate_whitelist_mxids(&["@a@b:c".to_string()]).is_err());
    }

    /// A12/D11：常规合法形态通过，缺段/多段/空白/多点 `@` 拒绝。
    #[test]
    fn mxid_valid_forms() {
        for s in [
            "@admin:example.com",
            "@keivry:matrix.example.org",
            "@a.b-c_d:x.y",
        ] {
            assert!(is_valid_mxid(s), "合法 MXID 须通过: {s}");
        }
        for s in [
            "@a@b:c",
            "admin:example.com",
            "@a:",
            "@:b",
            "@a b:c",
            "@a:b:c",
        ] {
            assert!(!is_valid_mxid(s), "非法 MXID 须拒绝: {s}");
        }
    }

    /// A15/D14：配置加载期真源与 `branch.rs::validate_whitelist_mxids` 表驱动同结论。
    #[test]
    fn whitelist_validator_parity() {
        for s in [
            "@admin:example.com",
            "@a@b:c",
            "admin:example.com",
            "@a:",
            "@:b",
            "@a b:c",
            "@keivry@matrix.example",
        ] {
            let get = |_: &str| Some(s.to_string());
            let via_config = parse_whitelist(&get);
            let via_branch = crate::service::matrix::validate_whitelist_mxids(&[s.to_string()]);
            assert_eq!(
                via_config.is_ok(),
                via_branch.is_ok(),
                "校验真源与 Matrix 门禁须同结论: {s:?}"
            );
        }
    }
}
