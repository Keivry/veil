//! fail-closed 配置加载：缺必填项或非法值直接拒绝启动。
//!
//! 校验顺序对标原仓 `proxy.py __init__`：先可观测 token，
//! 再 Matrix 三件套，最后 PII 与审计。

use {
    crate::error::{Result, VeilError},
    std::{collections::HashMap, path::PathBuf},
};

/// 审计审批默认超时（秒）。
pub const AUDIT_TIMEOUT_DEFAULT: i64 = 90;
/// `AUDIT_TIMEOUT` 禁区下限（含端点）：上游约 120s 断连窗口两侧各留约 10s 余量。
pub const AUDIT_TIMEOUT_RACE_MIN: i64 = 110;
/// `AUDIT_TIMEOUT` 禁区上限（含端点）。
pub const AUDIT_TIMEOUT_RACE_MAX: i64 = 130;
/// `PII_HOLD_MAX` 默认值。
pub const PII_HOLD_MAX_DEFAULT: i64 = 64;
/// `AUDIT_HOLD_MAX_BYTES` 默认值。
pub const AUDIT_HOLD_MAX_BYTES_DEFAULT: i64 = 1_048_576;
/// 管理 token 建议最小长度，不足仅告警不断链。
pub const ADMIN_TOKEN_MIN_LEN: usize = 32;
/// 上游转发 `reqwest::Client` 整体超时默认值（秒，保守值）。
pub const HTTP_TIMEOUT_SECS_DEFAULT: u64 = 30;
/// 上游转发连接池每主机空闲连接上限默认值（保守值）。
pub const HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT: usize = 16;
/// 上游转发连接池空闲连接保活默认值（秒，保守值）。
pub const HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT: u64 = 90;
/// `PII_PLACEHOLDER_PROMPT_TEXT` 自定义文案长度上限（字节，4KB，超限截断并告警）。
pub const PLACEHOLDER_PROMPT_MAX_LEN: usize = 4096;
/// 内置默认占位符说明文案（对标原仓 `PII_PLACEHOLDER_PROMPT_DEFAULT`）：
/// 静态文本，不含真实 PII 值；用 `*` 通配形态描述，不命中真实占位符形态。
pub const PLACEHOLDER_PROMPT_DEFAULT: &str = "说明：消息中形如 __PII_*__ 和 __VG_CRED_*__ 的标记是安全网关的敏感信息脱敏占位符，代表被替换的原始值（如手机号、IP 地址、银行卡号、密钥等）。重要：这些占位符出现的位置，其原始内容已被安全网关替换，你无法直接看到原文；因此不要把占位符当作真实数据（不要用它做样例、比对、推断原文，也不要假设原文就是占位符形态）。请原样保留这些占位符（包括 content 与 tool calls/function 参数中的）：不要修改格式、不要校验其合法性、不要推断或补全内容，也不要视为输入错误。它们不是格式问题，直接使用即可。若你需要查看被替换的原文进行分析，请改用不经由此网关的通道（如直接在受信任环境执行命令），不要尝试从占位符本身还原。";

/// 自动放行三态：`True` 放行 / `False` 拒绝 / `None` 转 Matrix 审批。
/// 本 spec 禁用 `allow`/`deny`/`approve` 虚构命名，统一用此三态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoApprove {
    #[default]
    Allow,
    Deny,
    Pending,
}

impl std::str::FromStr for AutoApprove {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Self::Allow),
            "false" | "0" | "no" => Ok(Self::Deny),
            "none" | "pending" | "matrix" => Ok(Self::Pending),
            other => Err(format!(
                "AUTO_APPROVE 非法: {other:?}（取值 true/false/none）"
            )),
        }
    }
}

/// 轻量入口语义开关：完整 vs credential-only 自动批准 vs llm-only 纯代理。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntryMode {
    #[default]
    Full,
    CredentialOnly,
    LlmOnly,
}

impl std::str::FromStr for EntryMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "credential-only" | "credential-proxy-only" => Ok(Self::CredentialOnly),
            "llm-only" | "llm-proxy-only" => Ok(Self::LlmOnly),
            other => Err(format!(
                "VEIL_ENTRY_MODE 非法: {other:?}（取值 full/credential-only/llm-only）"
            )),
        }
    }
}

/// 凭据审批超时（秒），与审计 `AUDIT_TIMEOUT` 分表，固定 300s。
pub const CREDENTIAL_APPROVAL_TIMEOUT_SECS: i64 = 300;
/// `POST /credential` 同一调用方限流窗口（秒）。
pub const CREDENTIAL_RATE_WINDOW_SECS: u64 = 2;
/// 注册类接口同一来源限流窗口（秒）。
pub const REGISTER_RATE_WINDOW_SECS: u64 = 1;

/// 审计三模式，默认关闭。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditMode {
    #[default]
    Off,
    Block,
    Approve,
}

impl std::str::FromStr for AuditMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "off" => Ok(Self::Off),
            "block" => Ok(Self::Block),
            "approve" => Ok(Self::Approve),
            other => Err(format!(
                "AUDIT_MODE 非法: {other:?}（取值 off/block/approve）"
            )),
        }
    }
}

/// 启动期生效的全部配置，构造失败即拒绝启动。
#[derive(Debug, Clone)]
pub struct Config {
    pub homeserver: String,
    pub room_id: String,
    pub matrix_access_token: String,
    pub observability_admin_token: String,
    pub audit_mode: AuditMode,
    pub audit_timeout_secs: i64,
    pub approval_whitelist: Vec<String>,
    pub pii_hold_max: i64,
    pub audit_hold_max_bytes: i64,
    pub data_dir: PathBuf,
    pub credential_secret: Option<String>,
    pub get_binary_hash: Option<String>,
    pub auto_approve: AutoApprove,
    pub entry_mode: EntryMode,
    pub registry_path: PathBuf,
    pub credential_approval_timeout_secs: i64,
    pub llm_upstreams: HashMap<u16, String>,
    pub llm_default_upstream: Option<String>,
    pub redaction_enabled: bool,
    pub placeholder_prompt_enabled: bool,
    pub placeholder_prompt_text: String,
    /// FIX-5 字节契约开关（`NORMALIZE_JSON_WHITESPACE`，仅 `"1"` 开启；
    /// 默认关闭时请求体除 token 子串替换外保持字节一致）。
    pub normalize_json_whitespace: bool,
    /// §6.1 审计策略文件路径（`AUDIT_POLICY_FILE`，缺省为内建默认策略）。
    pub audit_policy_file: Option<PathBuf>,
    pub http_timeout_secs: u64,
    pub http_pool_max_idle_per_host: usize,
    pub http_pool_idle_timeout_secs: u64,
}

impl Config {
    /// 从进程环境变量加载，缺必填或非法值返回 [`VeilError::Config`]。
    pub fn from_env() -> Result<Self> {
        let map: HashMap<String, String> = std::env::vars().collect();
        Self::load_from(&map)
    }

    /// 可注入的加载核心，单测用、心智负担低。
    pub fn load_from(env: &HashMap<String, String>) -> Result<Self> {
        let get = |name: &str| env.get(name).map(|v| v.trim().to_string());

        let observability_admin_token = require_non_empty(&get, "OBSERVABILITY_ADMIN_TOKEN")?;
        if let Some(cred) = get("CREDENTIAL_ADMIN_TOKEN")
            && !cred.is_empty()
            && cred == observability_admin_token
        {
            return Err(config_error(
                "OBSERVABILITY_ADMIN_TOKEN",
                "OBSERVABILITY_ADMIN_TOKEN 须独立，不得复用 CREDENTIAL_ADMIN_TOKEN",
            ));
        }

        let homeserver = require_non_empty(&get, "HOMESERVER")?;
        let room_id = require_non_empty(&get, "ROOM_ID")?;
        let matrix_access_token = require_non_empty(&get, "MATRIX_ACCESS_TOKEN")?;
        if observability_admin_token == matrix_access_token {
            return Err(config_error(
                "OBSERVABILITY_ADMIN_TOKEN",
                "OBSERVABILITY_ADMIN_TOKEN 须独立，不得复用 MATRIX_ACCESS_TOKEN",
            ));
        }
        if observability_admin_token.len() < ADMIN_TOKEN_MIN_LEN {
            tracing::warn!(
                "OBSERVABILITY_ADMIN_TOKEN 长度不足 {ADMIN_TOKEN_MIN_LEN}，建议使用更长随机值"
            );
        }

        let pii_hold_max = parse_positive(&get, "PII_HOLD_MAX", PII_HOLD_MAX_DEFAULT)?;
        let audit_hold_max_bytes =
            parse_positive(&get, "AUDIT_HOLD_MAX_BYTES", AUDIT_HOLD_MAX_BYTES_DEFAULT)?;

        let audit_mode: AuditMode = match get("AUDIT_MODE") {
            Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
                var: "AUDIT_MODE".to_string(),
                message,
            })?,
            _ => AuditMode::Off,
        };
        let audit_timeout_secs = parse_audit_timeout(&get)?;
        let approval_whitelist = parse_whitelist(&get)?;

        if audit_mode == AuditMode::Approve && approval_whitelist.is_empty() {
            return Err(config_error(
                "APPROVAL_WHITELIST",
                "AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST（审批人 Matrix user id），否则拒绝启动",
            ));
        }

        let data_dir = get("DATA_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| PathBuf::from("/data"), PathBuf::from);

        let credential_secret = get("GET_BINARY_SECRET")
            .filter(|v| !v.is_empty())
            .or_else(|| get("CREDENTIAL_SECRET").filter(|v| !v.is_empty()));
        let get_binary_hash = get("GET_BINARY_HASH").filter(|v| !v.is_empty());
        let auto_approve: AutoApprove = match get("AUTO_APPROVE") {
            Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
                var: "AUTO_APPROVE".to_string(),
                message,
            })?,
            _ => AutoApprove::Allow,
        };
        let entry_mode: EntryMode = match get("VEIL_ENTRY_MODE") {
            Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
                var: "VEIL_ENTRY_MODE".to_string(),
                message,
            })?,
            _ => EntryMode::Full,
        };
        let registry_path = get("CALLER_REGISTRY_PATH")
            .filter(|v| !v.is_empty())
            .map_or_else(|| data_dir.join("caller_registry.json"), PathBuf::from);

        let mut llm_upstreams = HashMap::new();
        for (k, v) in env.iter() {
            if v.trim().is_empty() {
                continue;
            }
            if let Some(port_str) = k.strip_prefix("LLM_")
                && let Ok(port) = port_str.parse::<u16>()
            {
                llm_upstreams.insert(port, v.trim().to_string());
            }
        }
        let llm_default_upstream = get("LLM_UPSTREAM").filter(|v| !v.is_empty());
        let redaction_enabled = match get("REDACTION_ENABLED") {
            Some(v) if !v.is_empty() => !matches!(
                v.trim().to_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ),
            _ => true,
        };
        let audit_policy_file = get("AUDIT_POLICY_FILE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let normalize_json_whitespace =
            matches!(get("NORMALIZE_JSON_WHITESPACE").as_deref(), Some("1"));
        let (placeholder_prompt_enabled, placeholder_prompt_text) = parse_placeholder_prompt(&get);
        let http_timeout_secs =
            parse_positive_u64(&get, "HTTP_TIMEOUT_SECS", HTTP_TIMEOUT_SECS_DEFAULT)?;
        let http_pool_max_idle_per_host = parse_positive_usize(
            &get,
            "HTTP_POOL_MAX_IDLE_PER_HOST",
            HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT,
        )?;
        let http_pool_idle_timeout_secs = parse_positive_u64(
            &get,
            "HTTP_POOL_IDLE_TIMEOUT_SECS",
            HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT,
        )?;

        Ok(Self {
            homeserver,
            room_id,
            matrix_access_token,
            observability_admin_token,
            audit_mode,
            audit_timeout_secs,
            approval_whitelist,
            pii_hold_max,
            audit_hold_max_bytes,
            data_dir,
            credential_secret,
            get_binary_hash,
            auto_approve,
            entry_mode,
            registry_path,
            credential_approval_timeout_secs: CREDENTIAL_APPROVAL_TIMEOUT_SECS,
            llm_upstreams,
            llm_default_upstream,
            redaction_enabled,
            normalize_json_whitespace,
            audit_policy_file,
            placeholder_prompt_enabled,
            placeholder_prompt_text,
            http_timeout_secs,
            http_pool_max_idle_per_host,
            http_pool_idle_timeout_secs,
        })
    }
}

fn parse_placeholder_prompt(get: &dyn Fn(&str) -> Option<String>) -> (bool, String) {
    let raw = get("PII_PLACEHOLDER_PROMPT").unwrap_or_default();
    let enabled = !matches!(raw.trim().to_lowercase().as_str(), "0" | "false" | "no");
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

fn config_error(var: &str, message: &str) -> VeilError {
    VeilError::Config {
        var: var.to_string(),
        message: message.to_string(),
    }
}

fn require_non_empty(get: &dyn Fn(&str) -> Option<String>, var: &str) -> Result<String> {
    match get(var) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(config_error(
            var,
            &format!("未设置必填环境变量 {var}，拒绝启动"),
        )),
    }
}

fn parse_positive(get: &dyn Fn(&str) -> Option<String>, var: &str, default: i64) -> Result<i64> {
    let raw = get(var)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string());
    match raw.parse::<i64>() {
        Ok(v) if v >= 1 => Ok(v),
        Ok(_) => Err(config_error(var, &format!("{var} 必须 ≥1 正整数: {raw:?}"))),
        Err(_) => Err(config_error(var, &format!("{var} 非法整数: {raw:?}"))),
    }
}

fn parse_positive_u64(
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

fn parse_positive_usize(
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

fn parse_audit_timeout(get: &dyn Fn(&str) -> Option<String>) -> Result<i64> {
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

fn parse_whitelist(get: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>> {
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
    use super::*;

    fn base_env() -> HashMap<String, String> {
        HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!room:example.com".to_string()),
            (
                "MATRIX_ACCESS_TOKEN".to_string(),
                "syt_matrix_token_xxx".to_string(),
            ),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "admin-observability-token-0123456789abcdef".to_string(),
            ),
        ])
    }

    #[test]
    fn 缺必填项逐个拒启动并指明变量名() {
        for var in [
            "HOMESERVER",
            "ROOM_ID",
            "MATRIX_ACCESS_TOKEN",
            "OBSERVABILITY_ADMIN_TOKEN",
        ] {
            let mut env = base_env();
            env.remove(var);
            let err = Config::load_from(&env).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains(var), "报错须指明变量名 {var}，实际: {msg}");
        }
    }

    #[test]
    fn 空值必填同样拒启动() {
        let mut env = base_env();
        env.insert("ROOM_ID".to_string(), "   ".to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("ROOM_ID"));
    }

    #[test]
    fn 管理token不得复用业务token() {
        let mut env = base_env();
        env.insert(
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "syt_matrix_token_xxx".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("OBSERVABILITY_ADMIN_TOKEN"));
    }

    #[test]
    fn audit_timeout零负与禁区拒启动() {
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
    fn audit_timeout合法值放行并指明区间() {
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
    fn pii_hold_max非正整数拒启动() {
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
    fn approve无白名单拒启动() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "approve".to_string());
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("APPROVAL_WHITELIST") && msg.contains("approve"));
    }

    #[test]
    fn approve有白名单放行() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "approve".to_string());
        env.insert(
            "APPROVAL_WHITELIST".to_string(),
            "@admin:example.com, @ops:example.com".to_string(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.approval_whitelist.len(), 2);
    }

    #[test]
    fn 非法白名单成员拒启动() {
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
    fn 非法审计模式拒启动并给出合法取值() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "allow".to_string());
        let msg = Config::load_from(&env).unwrap_err().to_string();
        assert!(msg.contains("AUDIT_MODE") && msg.contains("off/block/approve"));
    }

    #[test]
    fn 占位符开关默认开启关闭短路() {
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
    fn 占位符文案上限与形态回退() {
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
    fn http_client配置缺省与覆盖均正常() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert_eq!(cfg.http_timeout_secs, HTTP_TIMEOUT_SECS_DEFAULT);
        assert_eq!(
            cfg.http_pool_max_idle_per_host,
            HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT
        );
        assert_eq!(
            cfg.http_pool_idle_timeout_secs,
            HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT
        );
        let mut env = base_env();
        env.insert("HTTP_TIMEOUT_SECS".to_string(), "10".to_string());
        env.insert("HTTP_POOL_MAX_IDLE_PER_HOST".to_string(), "8".to_string());
        env.insert("HTTP_POOL_IDLE_TIMEOUT_SECS".to_string(), "60".to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.http_timeout_secs, 10);
        assert_eq!(cfg.http_pool_max_idle_per_host, 8);
        assert_eq!(cfg.http_pool_idle_timeout_secs, 60);
    }

    #[test]
    fn http_client配置非法拒启动() {
        for (var, raw) in [
            ("HTTP_TIMEOUT_SECS", "0"),
            ("HTTP_TIMEOUT_SECS", "abc"),
            ("HTTP_POOL_MAX_IDLE_PER_HOST", "0"),
            ("HTTP_POOL_IDLE_TIMEOUT_SECS", "-5"),
        ] {
            let mut env = base_env();
            env.insert(var.to_string(), raw.to_string());
            let err = Config::load_from(&env).unwrap_err();
            assert!(
                err.to_string().contains(var),
                "输入 {var}={raw} 报错须指明变量名"
            );
        }
    }
}
