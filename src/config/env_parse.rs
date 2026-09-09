//! 环境解析：常量/三枚举/`Config`/`load_from`/`resolve_kdbx`/入口选路。
//!
//! 跨子模块引用：自定义文件经 `super::custom_file`，校验器经
//! `super::validate`（同级 `use` 成环无碍，Rust 允许）。

use {
    super::{
        custom_file::load_custom_file,
        validate::{
            config_error,
            is_falsy,
            parse_audit_timeout,
            parse_bool_off,
            parse_bool_on,
            parse_placeholder_prompt,
            parse_positive,
            parse_positive_u64,
            parse_positive_usize,
            parse_whitelist,
            require_non_empty,
        },
    },
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
/// 通用网关 ingress JSON 上限 10MB（检查点：`handler::llm` 入口 `to_bytes`；
/// spec `admin-ratelimit-contract` + design D4：与 8MB 审计/扫描类上限分属不同检查点，
/// 差异为有意设计；超限返回 413）。
pub const GATEWAY_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
/// 审计/扫描类子限 ceiling 8MB（检查点归属声明：审计 hold 与扫描上限类）。
/// 现网可配子限（`AUDIT_HOLD_MAX_BYTES` 默认 1MB）均不得超过本 ceiling；
/// 本常量为回归锚点，不接任何请求入口，不改变现行子限行为。
/// 归属 `config.rs`（D1 常量下沉），`handler::llm` 原位 `pub use` 转发。
pub const AUDIT_SUBLIMIT_CEILING_BYTES: usize = 8 * 1024 * 1024;
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
    /// 响应侧新检出脱敏开关（`PII_RESPONSE_SIDE`，默认开启；
    /// 关闭时响应中新 PII 不再注册为占位符，原样透出）。
    pub pii_response_side: bool,
    /// 宽松还原开关（`PII_FUZZY_RESTORE`，默认关闭；
    /// 开启时残缺/宽松形态 token 按序号回查请求表还原）。
    pub pii_fuzzy_restore: bool,
    /// 检测强化开关（`PII_DETECTION_HARDENING`，默认关闭；
    /// 开启时内置命中做严格边界复核，丢弃 ASCII 粘连与前导零 IPv4）。
    pub pii_detection_hardening: bool,
    /// 自定义正则规则文件（`PII_CUSTOM_RULES_FILE` 或 `PII_CUSTOM_RULES`，JSON 数组）。
    pub pii_custom_rules_file: Option<PathBuf>,
    /// 自定义模式文件（`PII_CUSTOM_PATTERNS_FILE` 或 `PII_CUSTOM_PATTERNS`，数组或映射）。
    pub pii_custom_patterns_file: Option<PathBuf>,
    /// 自定义字典文件（`PII_CUSTOM_DICT_FILE` 或 `PII_CUSTOM_DICT`，数组或映射）。
    pub pii_custom_dict_file: Option<PathBuf>,
    /// 值级采样开关（`PII_VALUE_SAMPLE_ENABLED`，默认关闭，热重载不支持）。
    pub pii_value_sample_enabled: bool,
    /// 值级采样落盘开关（`PII_VALUE_SAMPLE_PERSIST`，默认开启）。
    pub pii_value_sample_persist: bool,
    /// 值级采样 HMAC 键（`PII_VALUE_SAMPLE_HMAC_KEY`，未设退化为 SHA256）。
    pub pii_value_sample_hmac_key: Option<String>,
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
    pub db_dir: PathBuf,
    pub tpm_dir: PathBuf,
    pub keepass_backend: KeepassBackendKind,
    /// 凭据审批双模开关（`CREDENTIAL_BLOCK_WAIT`，默认关闭）：
    /// `=1` 时 enrolled 篡改/未 enrolled 待审走 300s 阻塞等 reaction，
    /// 默认保持 202 抛单（建单 + best-effort 发送即返回）。
    /// 接线：`service::credential::approval_dual_mode` 唯一读取方（D1 已复核接线，保留）。
    pub credential_block_wait: bool,
}

/// KeePass 后端选型：默认 real，显式 `VEIL_KEEPASS_BACKEND=mock` 仅 CI 逃生。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeepassBackendKind {
    #[default]
    Real,
    Mock,
}

impl std::str::FromStr for KeepassBackendKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "real" => Ok(Self::Real),
            "mock" => Ok(Self::Mock),
            other => Err(format!(
                "VEIL_KEEPASS_BACKEND 非法: {other:?}（取值 real/mock）"
            )),
        }
    }
}

/// 遗留兼容声明：`CREDENTIAL_MASTER_PASSWORD`/`CREDENTIAL_PORT` 为原仓遗留变量名，
/// 本二进制不读取（`load_from` 只认下述新名）；主密码口令改走 TPM 解封
/// （`service::tpm::startup_tpm_in`），部署密钥改用 `GET_BINARY_SECRET`/
///
/// `CREDENTIAL_SECRET`，宿主机端口改用 `PORT_8877/8878/8879`（仅改映射不改容器内
/// 监听）。沿用旧名部署会静默不生效，迁移时必须改名（见 README 兼容表）。
impl Config {
    /// 从进程环境变量加载，缺必填或非法值返回 [`VeilError::Config`]。
    pub fn from_env() -> Result<Self> {
        let map: HashMap<String, String> = std::env::vars().collect();
        Self::load_from(&map)
    }

    /// 可注入的加载核心，单测用、心智负担低。
    pub fn load_from(env: &HashMap<String, String>) -> Result<Self> {
        let get = |name: &str| env.get(name).map(|v| v.trim().to_string());
        for name in super::validate::legacy_ignored_detected(env) {
            let hint = super::validate::LEGACY_IGNORED_VARS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)
                .unwrap_or("见 README §7.4");
            tracing::warn!("{name} 已置位但二进制不读取（沿用旧名静默不生效）：{hint}");
        }

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
        // 脱敏总开关：`REDACTION_ENABLED` 优先，`PII_REDACTION_ENABLED` 为原仓别名；
        // 两者皆空默认开启，显式假值（0/false/no/off）关闭。
        let redaction_enabled = match get("REDACTION_ENABLED").filter(|v| !v.is_empty()) {
            Some(v) => !is_falsy(&v),
            None => match get("PII_REDACTION_ENABLED").filter(|v| !v.is_empty()) {
                Some(v) => !is_falsy(&v),
                None => true,
            },
        };
        let pii_response_side = parse_bool_on(&get, "PII_RESPONSE_SIDE");
        let pii_fuzzy_restore = parse_bool_off(&get, "PII_FUZZY_RESTORE");
        let pii_detection_hardening = parse_bool_off(&get, "PII_DETECTION_HARDENING");
        let pii_custom_rules_file = load_custom_file(
            &get,
            &[
                "PII_CUSTOM_RULES_FILE",
                "PII_RULES_FILE",
                "PII_CUSTOM_RULES",
            ],
        )?;
        let pii_custom_patterns_file = load_custom_file(
            &get,
            &[
                "PII_CUSTOM_PATTERNS_FILE",
                "PII_CUSTOM_PATTERN_FILE",
                "PII_CUSTOM_PATTERNS",
            ],
        )?;
        let pii_custom_dict_file = load_custom_file(
            &get,
            &[
                "PII_CUSTOM_DICT_FILE",
                "PII_SENSITIVE_DICT_FILE",
                "PII_SENSITIVE_NAMES_FILE",
                "PII_CUSTOM_DICT",
            ],
        )?;
        let pii_value_sample_enabled = parse_bool_off(&get, "PII_VALUE_SAMPLE_ENABLED");
        let pii_value_sample_persist = parse_bool_on(&get, "PII_VALUE_SAMPLE_PERSIST");
        let pii_value_sample_hmac_key = get("PII_VALUE_SAMPLE_HMAC_KEY").filter(|v| !v.is_empty());
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
        let db_dir = get("DB_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| data_dir.join("db"), PathBuf::from);
        let tpm_dir = get("TPM_DIR")
            .filter(|v| !v.is_empty())
            .map_or_else(|| data_dir.join("tpm"), PathBuf::from);
        let keepass_backend: KeepassBackendKind = match get("VEIL_KEEPASS_BACKEND") {
            Some(v) if !v.is_empty() => v.parse().map_err(|message| VeilError::Config {
                var: "VEIL_KEEPASS_BACKEND".to_string(),
                message,
            })?,
            _ => KeepassBackendKind::Real,
        };
        let credential_block_wait = parse_bool_off(&get, "CREDENTIAL_BLOCK_WAIT");

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
            pii_response_side,
            pii_fuzzy_restore,
            pii_detection_hardening,
            pii_custom_rules_file,
            pii_custom_patterns_file,
            pii_custom_dict_file,
            pii_value_sample_enabled,
            pii_value_sample_persist,
            pii_value_sample_hmac_key,
            normalize_json_whitespace,
            audit_policy_file,
            placeholder_prompt_enabled,
            placeholder_prompt_text,
            http_timeout_secs,
            http_pool_max_idle_per_host,
            http_pool_idle_timeout_secs,
            db_dir,
            tpm_dir,
            keepass_backend,
            credential_block_wait,
        })
    }
}

/// 跨子模块测试共享：基准环境（其它子模块测试经
/// `crate::config::env_parse::test_support` 复用）。
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;

    pub(crate) fn base_env() -> HashMap<String, String> {
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
}

#[cfg(test)]
mod tests {
    use {super::*, test_support::base_env};

    #[test]
    fn missing_required_each_rejects_startup_naming_var() {
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
    fn blank_required_also_rejects_startup() {
        let mut env = base_env();
        env.insert("ROOM_ID".to_string(), "   ".to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("ROOM_ID"));
    }

    #[test]
    fn admin_token_must_not_reuse_service_token() {
        let mut env = base_env();
        env.insert(
            "OBSERVABILITY_ADMIN_TOKEN".to_string(),
            "syt_matrix_token_xxx".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("OBSERVABILITY_ADMIN_TOKEN"));
    }

    #[test]
    fn approve_without_whitelist_rejects_startup() {
        let mut env = base_env();
        env.insert("AUDIT_MODE".to_string(), "approve".to_string());
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("APPROVAL_WHITELIST") && msg.contains("approve"));
    }

    #[test]
    fn approve_with_whitelist_allows() {
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
    fn http_client_defaults_and_overrides_ok() {
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
    fn http_client_invalid_rejects_startup() {
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

    #[test]
    fn redaction_alias_and_three_semantic_toggles() {
        // 默认：脱敏开、响应侧开、宽松关、强化关。
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(cfg.redaction_enabled);
        assert!(cfg.pii_response_side);
        assert!(!cfg.pii_fuzzy_restore);
        assert!(!cfg.pii_detection_hardening);
        // 原仓别名单独置位等价开启。
        let mut env = base_env();
        env.insert("PII_REDACTION_ENABLED".to_string(), "1".to_string());
        assert!(Config::load_from(&env).unwrap().redaction_enabled);
        // 别名显式关闭同样生效。
        let mut env = base_env();
        env.insert("PII_REDACTION_ENABLED".to_string(), "0".to_string());
        assert!(!Config::load_from(&env).unwrap().redaction_enabled);
        // 主变量优先于别名。
        let mut env = base_env();
        env.insert("REDACTION_ENABLED".to_string(), "0".to_string());
        env.insert("PII_REDACTION_ENABLED".to_string(), "1".to_string());
        assert!(!Config::load_from(&env).unwrap().redaction_enabled);
        // 三语义覆盖。
        let mut env = base_env();
        env.insert("PII_RESPONSE_SIDE".to_string(), "0".to_string());
        env.insert("PII_FUZZY_RESTORE".to_string(), "yes".to_string());
        env.insert("PII_DETECTION_HARDENING".to_string(), "on".to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert!(!cfg.pii_response_side);
        assert!(cfg.pii_fuzzy_restore);
        assert!(cfg.pii_detection_hardening);
    }

    #[test]
    fn sampling_toggles_defaults_and_overrides() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(!cfg.pii_value_sample_enabled);
        assert!(cfg.pii_value_sample_persist);
        assert!(cfg.pii_value_sample_hmac_key.is_none());
        let mut env = base_env();
        env.insert("PII_VALUE_SAMPLE_ENABLED".to_string(), "1".to_string());
        env.insert("PII_VALUE_SAMPLE_PERSIST".to_string(), "0".to_string());
        env.insert(
            "PII_VALUE_SAMPLE_HMAC_KEY".to_string(),
            "k-0123456789".to_string(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.pii_value_sample_enabled);
        assert!(!cfg.pii_value_sample_persist);
        assert_eq!(
            cfg.pii_value_sample_hmac_key.as_deref(),
            Some("k-0123456789")
        );
    }

    #[test]
    fn lib_dirs_default_derived_and_explicit_override() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert_eq!(cfg.db_dir, PathBuf::from("/data/db"));
        assert_eq!(cfg.tpm_dir, PathBuf::from("/data/tpm"));
        assert_eq!(cfg.keepass_backend, KeepassBackendKind::Real);
        let mut env = base_env();
        env.insert("DB_DIR".to_string(), "/srv/kdbx".to_string());
        env.insert("TPM_DIR".to_string(), "/srv/tpm".to_string());
        env.insert("VEIL_KEEPASS_BACKEND".to_string(), "mock".to_string());
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.db_dir, PathBuf::from("/srv/kdbx"));
        assert_eq!(cfg.tpm_dir, PathBuf::from("/srv/tpm"));
        assert_eq!(cfg.keepass_backend, KeepassBackendKind::Mock);
        let mut env = base_env();
        env.insert("VEIL_KEEPASS_BACKEND".to_string(), "bogus".to_string());
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("VEIL_KEEPASS_BACKEND"));
    }

    fn upstream_env() -> HashMap<String, String> {
        let mut env = base_env();
        env.insert(
            "LLM_UPSTREAM".to_string(),
            "http://缺省上游:11434".to_string(),
        );
        env.insert(
            "LLM_8878".to_string(),
            "http://八七七八上游:11434".to_string(),
        );
        env.insert(
            "LLM_8879".to_string(),
            "http://八七七九上游:11434".to_string(),
        );
        env
    }

    #[test]
    fn ingress_port_hits_matching_upstream() {
        use crate::service::llm_gateway::resolve_upstream;
        let cfg = Config::load_from(&upstream_env()).unwrap();
        assert_eq!(
            resolve_upstream(&cfg, Some(8878)).as_deref(),
            Some("http://八七七八上游:11434")
        );
        assert_eq!(
            resolve_upstream(&cfg, Some(8879)).as_deref(),
            Some("http://八七七九上游:11434")
        );
    }

    #[test]
    fn unmatched_port_and_empty_context_fall_back_to_default() {
        use crate::service::llm_gateway::resolve_upstream;
        let cfg = Config::load_from(&upstream_env()).unwrap();
        for port in [None, Some(8877), Some(9999)] {
            assert_eq!(
                resolve_upstream(&cfg, port).as_deref(),
                Some("http://缺省上游:11434"),
                "端口 {port:?} 须回落缺省而非猜测"
            );
        }
    }

    #[test]
    fn without_default_falls_back_to_any_port_upstream() {
        use crate::service::llm_gateway::resolve_upstream;
        let mut env = upstream_env();
        env.remove("LLM_UPSTREAM");
        let cfg = Config::load_from(&env).unwrap();
        let got = resolve_upstream(&cfg, Some(9999)).expect("须有回落");
        assert!(
            got == "http://八七七八上游:11434" || got == "http://八七七九上游:11434",
            "回落须为已知端口上游之一，实际: {got}"
        );
        assert!(resolve_upstream(&cfg, None).is_some());
    }

    #[test]
    fn approval_block_wait_default_off() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(!cfg.credential_block_wait);
        for raw in ["1", "true", "yes", "on"] {
            let mut env = base_env();
            env.insert("CREDENTIAL_BLOCK_WAIT".to_string(), raw.to_string());
            assert!(
                Config::load_from(&env).unwrap().credential_block_wait,
                "{raw}"
            );
        }
        for raw in ["0", "false", "", "off"] {
            let mut env = base_env();
            if raw.is_empty() {
                env.remove("CREDENTIAL_BLOCK_WAIT");
            } else {
                env.insert("CREDENTIAL_BLOCK_WAIT".to_string(), raw.to_string());
            }
            assert!(
                !Config::load_from(&env).unwrap().credential_block_wait,
                "{raw}"
            );
        }
    }
}
