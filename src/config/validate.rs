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

/// 遗留变量名：二进制不读取，检出时启动期 warn 指引改名。
/// 权威清单：工程参考 §7.4 须逐项锁步（集合相等由 `legacy_vars_reference_lockstep` 守卫）。
pub const LEGACY_IGNORED_VARS: [(&str, &str); 7] = [
    (
        "CREDENTIAL_MASTER_PASSWORD",
        "主密码口令改走 TPM 解封（startup_tpm_in）",
    ),
    (
        "CREDENTIAL_PORT",
        "宿主机端口改用 PORT_8877/8878/8879（仅改映射）",
    ),
    (
        "ENV",
        "dev 环境显式配置 OBSERVABILITY_ADMIN_TOKEN 并携带 X-Admin-Token（回环免 token 未迁移，见 工程参考 §6.6）",
    ),
    (
        "ALLOW_LOOPBACK_NO_TOKEN",
        "回环免 token 未迁移：dev 环境显式配置 OBSERVABILITY_ADMIN_TOKEN 并携带 X-Admin-Token（见 工程参考 §6.6）",
    ),
    (
        "CREDENTIAL_API_PORT",
        "入口统一走 VEIL_ENTRY_MODE + 主监听 8877 / 已声明上游端口各一条专用监听（见 工程参考 §8.4）",
    ),
    (
        "CREDENTIAL_ADMIN_TOKEN",
        "启动期交叉校验已废除、二进制不读取；该变量应删除，独立管理 token 由部署面保证（见 工程参考 §7.4）",
    ),
    (
        "AUDIT_ENABLED",
        "env 真值回退已终止、二进制不读取；审计模式改用 [audit].mode（见 工程参考 §7.4）",
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
        // 全程字节级匹配，绝不按字节下标切 `str`（中文等多字节字符不 panic）。
        if bytes[i..].starts_with(b"__PII_") {
            let rest = &bytes[i + 6..];
            if let Some(us) = rest.iter().position(|b| *b == b'_')
                && !rest[..us].is_empty()
                && rest[..us].iter().all(|c| c.is_ascii_digit())
            {
                let after = &rest[us + 1..];
                if after.len() >= 10 && is_hex8(&after[..8]) && after[8..].starts_with(b"__") {
                    return true;
                }
            }
        }
        if bytes[i..].starts_with(b"__CRED_") {
            let rest = &bytes[i + 7..];
            let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits > 0 && rest[digits..].starts_with(b"__") {
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

/// 审计审批超时解析（`AUDIT_TIMEOUT_SECS`，`u64`）：`0` 与非法整数拒启动，
/// `110-130` 竞态区间拒启动。
pub(crate) fn parse_audit_timeout(get: &dyn Fn(&str) -> Option<String>) -> Result<u64> {
    let raw = get("AUDIT_TIMEOUT_SECS")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| AUDIT_TIMEOUT_DEFAULT.to_string());
    let timeout_secs: u64 = raw.parse().map_err(|_| {
        config_error(
            "AUDIT_TIMEOUT_SECS",
            &format!("AUDIT_TIMEOUT_SECS 非法整数: {raw:?}"),
        )
    })?;
    if timeout_secs < 1 {
        return Err(config_error(
            "AUDIT_TIMEOUT_SECS",
            &format!("AUDIT_TIMEOUT_SECS 必须 ≥1s: {raw:?}"),
        ));
    }
    if (AUDIT_TIMEOUT_RACE_MIN..=AUDIT_TIMEOUT_RACE_MAX).contains(&timeout_secs) {
        return Err(config_error(
            "AUDIT_TIMEOUT_SECS",
            &format!(
                "AUDIT_TIMEOUT_SECS 不得落在 {AUDIT_TIMEOUT_RACE_MIN}-{AUDIT_TIMEOUT_RACE_MAX}s 竞态区间\
                （上游约 120s 断连窗口）: {raw:?}，合法区间为 ≥1 且避开 110-130",
            ),
        ));
    }
    Ok(timeout_secs)
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

/// MXID 校验唯一实现；`service::matrix::branch` 经重导出复用，
/// 禁止再复制第二份。
pub(crate) fn is_valid_mxid(s: &str) -> bool {
    let rest = s.strip_prefix('@').unwrap_or("");
    // `@` 前缀之后（localpart + domain）不得再含 `@`，否则 `@a@b:c` 被误放行。
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
mod tests;
