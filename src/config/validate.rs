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
pub const LEGACY_IGNORED_VARS: [(&str, &str); 3] = [
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

fn is_truthy(v: &str) -> bool {
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
        crate::config::env_parse::{Config, test_support::base_env},
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
}
