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
/// 通用网关 ingress JSON 上限 10MB（检查点：`handler::llm` 入口 `to_bytes`；
/// spec `admin-ratelimit-contract` + design D4：与 8MB 审计/扫描类上限分属不同检查点，
/// 差异为有意设计；超限返回 413）。
pub const GATEWAY_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
/// 审计/扫描类子限 ceiling 8MB（检查点归属声明：审计 hold 与扫描上限类）。
/// 现网可配子限（`AUDIT_HOLD_MAX_BYTES` 默认 1MB）均不得超过本 ceiling；
/// 本常量为回归锚点，不接任何请求入口，不改变现行子限行为。
/// 归属 `config.rs`（D1 常量下沉），`handler::llm` 原位 `pub use` 转发。
pub const AUDIT_SUBLIMIT_CEILING_BYTES: usize = 8 * 1024 * 1024;
/// 审计/扫描类子限 ceiling 8MB（检查点归属声明：审计 hold 与扫描上限类）。
/// 现网可配子限（`AUDIT_HOLD_MAX_BYTES` 默认 1MB）均不得超过本 ceiling；
/// 本常量为回归锚点，不接任何请求入口，不改变现行子限行为。
/// 原仓遗留变量名：二进制不读取，检出时启动期 warn 指引改名（见 [`legacy_ignored_detected`]）。
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
    pub credential_block_wait: bool,
    /// PII 全局持久开关（`PII_GLOBAL_PERSIST`，默认关闭）：
    /// 关闭时请求隔离（跨请求不互见），开启时同明文跨请求复用同一占位符。
    pub pii_global_persist: bool,
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

/// DB 选择结果：排序取末的 `.kdbx` + 同名 `.key`（存在才带）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKdbx {
    pub db_path: PathBuf,
    pub keyfile_path: Option<PathBuf>,
}

/// 扫描 `DB_DIR` 下 `*.kdbx`，排序取末位；同名 `.key` 优先；多库打 warn；无库返回 None。
pub fn resolve_kdbx(db_dir: &std::path::Path) -> Option<ResolvedKdbx> {
    let entries = std::fs::read_dir(db_dir).ok()?;
    let mut kdbx: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("kdbx"))
        })
        .collect();
    kdbx.sort();
    let db_path = kdbx.pop()?;
    if !kdbx.is_empty() {
        tracing::warn!(
            "DB_DIR 存在多个 .kdbx（{} 个），按排序取末位: {}",
            kdbx.len() + 1,
            db_path.display()
        );
    }
    let keyfile_path = db_path.with_extension("key").is_file().then(|| {
        let key = db_path.with_extension("key");
        tracing::debug!("使用同名 keyfile: {}", key.display());
        key
    });
    Some(ResolvedKdbx {
        db_path,
        keyfile_path,
    })
}

/// 入口端口上下文选路（§7.1 给 handler 集成方的接线位，不碰 `handler/llm/` 目录）。
///
/// 语义与 `service::llm_gateway::resolve_upstream` 同字，差异仅在输入形态：
/// 本函数接受可选的宿主机入口端口（compose 下 `PORT_887x` 映射的宿主机侧端口，
/// 如 8878），命中 `LLM_<port>` 则返回对应上游，否则回落 `LLM_UPSTREAM` 缺省；
/// 缺省未设时回落任一 `LLM_<port>`（`HashMap` 迭代序不稳定，生产如需确定性
/// 回落必须显式配置 `LLM_UPSTREAM`）。`None` 恒走缺省分支，不按端口猜测。
/// 当前 `handler::llm::gateway_serve` 仍以 `None` 调用（单端口运行时，二进制只监听
/// `127.0.0.1:8877`），多端口生效需集成方把入口端口透传进来；改动面留给集成方，
/// 本函数 + 单测先把“端口→上游”映射锁死。
///
/// 遗留兼容声明：`CREDENTIAL_MASTER_PASSWORD`/`CREDENTIAL_PORT` 为原仓遗留变量名，
/// 本二进制不读取（`load_from` 只认下述新名）；主密码口令改走 TPM 解封
/// （`service::tpm::startup_tpm_in`），部署密钥改用 `GET_BINARY_SECRET`/
///
/// `CREDENTIAL_SECRET`，宿主机端口改用 `PORT_8877/8878/8879`（仅改映射不改容器内
/// 监听）。沿用旧名部署会静默不生效，迁移时必须改名（见 README 兼容表）。
pub fn resolve_upstream_with_ingress(config: &Config, ingress_port: Option<u16>) -> Option<String> {
    if let Some(port) = ingress_port
        && let Some(u) = config.llm_upstreams.get(&port)
    {
        return Some(u.clone());
    }
    if let Some(u) = config.llm_default_upstream.clone() {
        return Some(u);
    }
    config.llm_upstreams.values().next().cloned()
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
        for name in legacy_ignored_detected(env) {
            let hint = LEGACY_IGNORED_VARS
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
        let pii_global_persist = parse_bool_off(&get, "PII_GLOBAL_PERSIST");

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
            pii_global_persist,
        })
    }
}

fn is_falsy(v: &str) -> bool {
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
fn parse_bool_on(get: &dyn Fn(&str) -> Option<String>, var: &str) -> bool {
    match get(var).filter(|v| !v.is_empty()) {
        Some(v) => !is_falsy(&v),
        None => true,
    }
}

/// 默认关闭的布尔开关：空缺为假，仅显式真值开启。
fn parse_bool_off(get: &dyn Fn(&str) -> Option<String>, var: &str) -> bool {
    match get(var).filter(|v| !v.is_empty()) {
        Some(v) => is_truthy(&v),
        None => false,
    }
}

/// 自定义 PII 文件 fail-closed 加载：`vars` 按优先级依次命中（主文件变量优先，
/// 别名文件变量次之，短变量最后），三槽（rules/patterns/dict）相互叠加、互不排斥；
/// 首个非空命中即为生效路径。已配置但缺文件/不可读/解析失败/形态非法一律拒绝启动，
/// 报错指明实际命中的变量名；空文件（零字节/仅空白）仅 warn 不拒启动（零命中语义）。
/// 格式：JSON 优先；`.yaml`/`.yml` 后缀或类 YAML 内容走极简 YAML 子集；
/// `.txt` 后缀或字典类纯名单内容走 TXT 名单（每行一名，`#` 注释忽略）。
fn load_custom_file(
    get: &dyn Fn(&str) -> Option<String>,
    vars: &[&str],
) -> Result<Option<PathBuf>> {
    let (var, raw) = vars
        .iter()
        .filter_map(|v| get(v).filter(|s| !s.is_empty()).map(|s| (*v, s)))
        .next()
        .map_or(
            (
                vars.first().copied().unwrap_or("PII_CUSTOM_RULES_FILE"),
                String::new(),
            ),
            |(v, s)| (v, s),
        );
    if raw.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(&raw);
    if !path.is_file() {
        return Err(config_error(
            var,
            &format!("{var} 指向的文件不存在或不可读: {raw:?}，拒绝启动"),
        ));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| {
        config_error(
            var,
            &format!("{var} 文件读取失败 {}: {e:?}，拒绝启动", path.display()),
        )
    })?;
    if text.trim().is_empty() {
        tracing::warn!(
            "{var} 文件 {} 为空，仅告警不拒启动（零命中语义）",
            path.display()
        );
        return Ok(Some(path));
    }
    let value = parse_custom_text(var, &path, &text)?;
    // TXT 空名单（全注释/空行）同样仅 warn。
    if value.as_array().is_some_and(|a| a.is_empty())
        && path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("txt"))
    {
        tracing::warn!(
            "{var} 文件 {} 名单为空，仅告警不拒启动（零命中语义）",
            path.display()
        );
        return Ok(Some(path));
    }
    validate_custom_shape(var, &path, &value)?;
    Ok(Some(path))
}

/// 自定义文件多格式解析：JSON → 极简 YAML 子集 → TXT 名单（字典）。
/// 非字典槽的 TXT 内容按字符串数组解析后由形态校验拒绝（fail-closed）。
fn parse_custom_text(var: &str, path: &std::path::Path, text: &str) -> Result<serde_json::Value> {
    let is_dict = var.contains("DICT") || var.contains("NAMES");
    let ext_yaml = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
    let ext_txt = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("txt"));
    if ext_txt {
        return Ok(parse_txt_list(text));
    }
    if ext_yaml {
        return parse_yaml_subset(text).map_err(|e| {
            config_error(
                var,
                &format!("{var} 文件 {} YAML 解析失败: {e}，拒绝启动", path.display()),
            )
        });
    }
    // 无后缀：JSON 优先，失败则嗅探 YAML/TXT。
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) => Ok(v),
        Err(json_err) => {
            let trimmed = text.trim_start();
            let looks_yaml = trimmed.starts_with('-')
                || trimmed.starts_with('{')
                || text.lines().any(|l| {
                    let t = l.trim();
                    !t.is_empty()
                        && !t.starts_with('#')
                        && !t.starts_with('{')
                        && !t.starts_with('[')
                        && t.contains(':')
                });
            if looks_yaml && let Ok(v) = parse_yaml_subset(text) {
                return Ok(v);
            }
            // 字典槽纯名单回退 TXT（无冒号/括号的 bare 行）。
            if is_dict && looks_txt_list(text) {
                return Ok(parse_txt_list(text));
            }
            Err(config_error(
                var,
                &format!(
                    "{var} 文件 JSON 解析失败 {}: {json_err}，拒绝启动",
                    path.display()
                ),
            ))
        }
    }
}

/// TXT 名单：每行一名，`#` 整行/行尾注释忽略，空行跳过。
fn parse_txt_list(text: &str) -> serde_json::Value {
    let mut out = Vec::new();
    for line in text.lines() {
        let no_comment = line.split('#').next().unwrap_or("").trim();
        if no_comment.is_empty() {
            continue;
        }
        out.push(serde_json::Value::String(no_comment.to_string()));
    }
    serde_json::Value::Array(out)
}

/// 是否像 TXT 纯名单（每有效行都不含 JSON/YAML 结构字符）。
fn looks_txt_list(text: &str) -> bool {
    let mut any = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        any = true;
        if t.contains(['{', '}', '[', ']', ':', '"', '\'']) || t.starts_with('-') {
            return false;
        }
    }
    any
}

fn strip_yaml_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// 极简 YAML 子集（无外部依赖，对标原仓解析语义的最小交集）：
/// 支持 `- name: foo` + `pattern: bar` 列表映射、`- somename` 字符串列表、
/// `key: value` 顶层映射；`#` 注释与空行忽略，超集 YAML 按解析失败 fail-closed。
fn parse_yaml_subset(text: &str) -> std::result::Result<serde_json::Value, String> {
    use serde_json::{Map, Value as V};
    let mut items: Vec<V> = Vec::new();
    let mut mapping = Map::new();
    let mut has_mapping_line = false;
    let mut has_list_line = false;
    let mut current: Option<Map<String, V>> = None;
    let flush = |current: &mut Option<Map<String, V>>, items: &mut Vec<V>| {
        if let Some(m) = current.take()
            && !m.is_empty()
        {
            items.push(V::Object(m));
        }
    };
    for (idx, raw_line) in text.lines().enumerate() {
        let no_comment = match raw_line.find('#') {
            Some(p) => &raw_line[..p],
            None => raw_line,
        };
        if no_comment.trim().is_empty() {
            continue;
        }
        let indent = no_comment.len() - no_comment.trim_start().len();
        let t = no_comment.trim();
        if let Some(dash_rest) = t.strip_prefix('-') {
            has_list_line = true;
            flush(&mut current, &mut items);
            let rest = dash_rest.trim();
            if rest.is_empty() {
                current = Some(Map::new());
                continue;
            }
            if let Some(colon) = rest.find(':') {
                let (k, v) = rest.split_at(colon);
                let v = v[1..].trim();
                if k.trim().is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                let mut m = Map::new();
                m.insert(k.trim().to_string(), V::String(strip_yaml_quotes(v)));
                current = Some(m);
            } else {
                items.push(V::String(strip_yaml_quotes(rest)));
                current = None;
            }
            continue;
        }
        if let Some(colon) = t.find(':') {
            let (k, v) = t.split_at(colon);
            let (k, v) = (k.trim(), v[1..].trim());
            if k.is_empty() || k.contains(' ') && indent == 0 && has_list_line {
                return Err(format!("第 {} 行形态非法: {t:?}", idx + 1));
            }
            if indent == 0 && current.is_none() && !has_list_line {
                // 顶层映射形态。
                has_mapping_line = true;
                mapping.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
            } else {
                // 列表项续行（`  pattern: ...`）。
                if k.is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                match current.as_mut() {
                    Some(m) => {
                        m.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
                    }
                    None => return Err(format!("第 {} 行缩进键无归属列表项: {t:?}", idx + 1)),
                }
            }
            continue;
        }
        return Err(format!("第 {} 行无法解析: {t:?}", idx + 1));
    }
    flush(&mut current, &mut items);
    if has_mapping_line && !has_list_line {
        return Ok(V::Object(mapping));
    }
    if !items.is_empty() {
        return Ok(V::Array(items));
    }
    if has_mapping_line {
        return Ok(V::Object(mapping));
    }
    Err("空 YAML 文档".to_string())
}

/// 自定义文件形态校验：规则/模式须为 `{name, pattern}` 数组（模式兼容 `{name: pattern}` 映射），
/// 字典须为 `{name[, type]}` 数组、`[string]` 数组或 `{name: type}` 映射；缺字段即拒启动。
fn validate_custom_shape(
    var: &str,
    path: &std::path::Path,
    value: &serde_json::Value,
) -> Result<()> {
    use serde_json::Value as V;
    let is_dict = var.contains("DICT") || var.contains("NAMES");
    match value {
        V::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let ok = match item {
                    V::Object(map) => {
                        let has_name = map
                            .get("name")
                            .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()));
                        if is_dict {
                            has_name
                                && map
                                    .get("type")
                                    .is_none_or(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                        } else {
                            has_name
                                && map
                                    .get("pattern")
                                    .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                        }
                    }
                    V::String(s) => is_dict && !s.is_empty(),
                    _ => false,
                };
                if !ok {
                    return Err(config_error(
                        var,
                        &format!(
                            "{var} 文件 {} 第 {i} 项形态非法（规则/模式须含 name+pattern，字典须含 name），拒绝启动",
                            path.display()
                        ),
                    ));
                }
            }
            Ok(())
        }
        V::Object(map) => {
            if is_dict {
                if map
                    .values()
                    .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                {
                    return Ok(());
                }
            } else if map
                .values()
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
            {
                return Ok(());
            }
            Err(config_error(
                var,
                &format!(
                    "{var} 文件 {} 映射值须为非空字符串，拒绝启动",
                    path.display()
                ),
            ))
        }
        _ => Err(config_error(
            var,
            &format!("{var} 文件 {} 顶层须为数组或映射，拒绝启动", path.display()),
        )),
    }
}

fn parse_placeholder_prompt(get: &dyn Fn(&str) -> Option<String>) -> (bool, String) {
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

    #[test]
    fn 脱敏别名与三语义开关() {
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

    fn custom_tmp_file(name: &str, content: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("veil-config-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn 自定义文件缺失拒启动并指明变量名() {
        for var in [
            "PII_CUSTOM_RULES_FILE",
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_DICT_FILE",
            "PII_CUSTOM_RULES",
            "PII_CUSTOM_DICT",
        ] {
            let mut env = base_env();
            env.insert(
                var.to_string(),
                "/nonexistent/veil-custom-缺失.json".to_string(),
            );
            let err = Config::load_from(&env).unwrap_err();
            assert!(err.to_string().contains(var), "变量 {var} 报错须指明变量名");
        }
    }

    #[test]
    fn 自定义文件解析失败与形态非法拒启动() {
        // 非法 JSON。
        let bad = custom_tmp_file("bad.json", "{不是 json");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            bad.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_PATTERNS_FILE"));
        // 缺 pattern 字段。
        let malformed = custom_tmp_file("malformed.json", r#"[{"name":"x"}]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            malformed.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("PII_CUSTOM_RULES_FILE"), "实际: {msg}");
        // 顶层非数组/映射。
        let scalar = custom_tmp_file("scalar.json", "42");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            scalar.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_DICT_FILE"));
        for p in [bad, malformed, scalar] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn 自定义文件合法形态放行() {
        let rules = custom_tmp_file(
            "rules.json",
            r#"[{"name":"ext-id","pattern":"EXT-\\d{6}"}]"#,
        );
        let patterns = custom_tmp_file("patterns.json", r#"{"p1":"bar\\d+"}"#);
        let dict = custom_tmp_file("dict.json", r#"[{"name":"张三丰","type":"name"}]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            rules.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
        assert_eq!(
            cfg.pii_custom_patterns_file.as_deref(),
            Some(patterns.as_path())
        );
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        // 未配置时为 None。
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(cfg.pii_custom_rules_file.is_none());
        for p in [rules, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn 采样开关默认值与覆盖() {
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
    fn 库目录默认派生与显式覆盖() {
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

    #[test]
    fn 多库取排序末位同名key优先() {
        let dir = std::env::temp_dir().join(format!(
            "veil-resolve-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.kdbx"), b"a").unwrap();
        std::fs::write(dir.join("z.kdbx"), b"z").unwrap();
        std::fs::write(dir.join("z.key"), b"key").unwrap();
        let found = resolve_kdbx(&dir).expect("须选中末位库");
        assert_eq!(found.db_path, dir.join("z.kdbx"));
        assert_eq!(found.keyfile_path, Some(dir.join("z.key")));
        std::fs::remove_file(dir.join("z.key")).unwrap();
        let found = resolve_kdbx(&dir).expect("无 keyfile 仍选中库");
        assert_eq!(found.db_path, dir.join("z.kdbx"));
        assert_eq!(found.keyfile_path, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn yaml合并文件加载成功() {
        let rules = custom_tmp_file(
            "compat-rules.yaml",
            "# 自定义规则\n- name: ext-id\n  pattern: EXT-\\d{6}\n- name: emp_no\n  pattern: (?P<emp_no>(?<![\\d])工号\\d{6}(?![\\d]))\n",
        );
        let patterns = custom_tmp_file(
            "compat-patterns.yaml",
            "p1: bar\\d+\n# 注释行\np2: foo\\d+\n",
        );
        let dict = custom_tmp_file("compat-dict.yaml", "- 张三丰\n- 李四\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            rules.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(rules.as_path()));
        assert_eq!(
            cfg.pii_custom_patterns_file.as_deref(),
            Some(patterns.as_path())
        );
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        for p in [rules, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn txt名单加载成功注释忽略() {
        let dict = custom_tmp_file(
            "compat-dict.txt",
            "# 敏感名单\n张三丰\n\n李四 # 行尾注释\n# 全行注释\n王五\n",
        );
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_dict_file.as_deref(), Some(dict.as_path()));
        std::fs::remove_file(dict).ok();
    }

    #[test]
    fn 四别名各自生效() {
        let rules = custom_tmp_file("alias-a.json", r#"[{"name":"x1","pattern":"X1\\d+"}]"#);
        let patterns = custom_tmp_file("alias-b.json", r#"{"p1":"P1\\d+"}"#);
        let dict = custom_tmp_file("alias-c.json", r#"["张三"]"#);
        let dict2 = custom_tmp_file("alias-d.json", r#"["李四"]"#);
        for (var, path, check) in [
            ("PII_RULES_FILE", &rules, "rules"),
            ("PII_CUSTOM_PATTERN_FILE", &patterns, "patterns"),
            ("PII_SENSITIVE_DICT_FILE", &dict, "dict"),
            ("PII_SENSITIVE_NAMES_FILE", &dict2, "dict"),
        ] {
            let mut env = base_env();
            env.insert(var.to_string(), path.to_string_lossy().into_owned());
            let cfg = Config::load_from(&env).unwrap();
            match check {
                "rules" => assert_eq!(
                    cfg.pii_custom_rules_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
                "patterns" => assert_eq!(
                    cfg.pii_custom_patterns_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
                _ => assert_eq!(
                    cfg.pii_custom_dict_file.as_deref(),
                    Some(path.as_path()),
                    "{var}"
                ),
            }
        }
        for p in [rules, patterns, dict, dict2] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn 三变量叠加主文件优先可共存() {
        let merged = custom_tmp_file(
            "overlay-merged.json",
            r#"[{"name":"m1","pattern":"M1\\d+"}]"#,
        );
        let alias = custom_tmp_file(
            "overlay-alias.json",
            r#"[{"name":"a1","pattern":"A1\\d+"}]"#,
        );
        let short = custom_tmp_file(
            "overlay-short.json",
            r#"[{"name":"s1","pattern":"S1\\d+"}]"#,
        );
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            merged.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_RULES_FILE".to_string(),
            alias.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_RULES".to_string(),
            short.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(merged.as_path()));
        let patterns = custom_tmp_file("overlay-p.json", r#"{"pp":"PP\\d+"}"#);
        let dict = custom_tmp_file("overlay-d.json", r#"["赵六"]"#);
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            merged.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_PATTERNS_FILE".to_string(),
            patterns.to_string_lossy().into_owned(),
        );
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            dict.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert!(cfg.pii_custom_rules_file.is_some());
        assert!(cfg.pii_custom_patterns_file.is_some());
        assert!(cfg.pii_custom_dict_file.is_some());
        let mut env = base_env();
        env.insert(
            "PII_SENSITIVE_DICT_FILE".to_string(),
            "/nonexistent/veil-别名缺失.json".to_string(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_SENSITIVE_DICT_FILE"));
        for p in [merged, alias, short, patterns, dict] {
            std::fs::remove_file(p).ok();
        }
    }

    #[test]
    fn 空文件零命中仅告警放行() {
        let empty = custom_tmp_file("compat-empty.json", "   \n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            empty.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(cfg.pii_custom_rules_file.as_deref(), Some(empty.as_path()));
        let comments_only = custom_tmp_file("compat-comments.txt", "# 只有注释\n# 无名单\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_DICT_FILE".to_string(),
            comments_only.to_string_lossy().into_owned(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.pii_custom_dict_file.as_deref(),
            Some(comments_only.as_path())
        );
        std::fs::remove_file(empty).ok();
        std::fs::remove_file(comments_only).ok();
    }

    #[test]
    fn yaml非法形态拒启动() {
        let bad = custom_tmp_file("compat-bad.yaml", ":\n: :\n- \n???\n");
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            bad.to_string_lossy().into_owned(),
        );
        let err = Config::load_from(&env).unwrap_err();
        assert!(err.to_string().contains("PII_CUSTOM_RULES_FILE"));
        std::fs::remove_file(bad).ok();
    }

    #[test]
    fn 示例yaml启动可加载() {
        let mut env = base_env();
        env.insert(
            "PII_CUSTOM_RULES_FILE".to_string(),
            "examples/pii-custom.yaml".to_string(),
        );
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            cfg.pii_custom_rules_file.as_deref(),
            Some(std::path::Path::new("examples/pii-custom.yaml"))
        );
    }

    #[test]
    fn 占位符off关闭复用falsy() {
        for raw in ["off", "OFF", "  off  "] {
            let mut env = base_env();
            env.insert("PII_PLACEHOLDER_PROMPT".to_string(), raw.to_string());
            let cfg = Config::load_from(&env).unwrap();
            assert!(!cfg.placeholder_prompt_enabled, "{raw}");
        }
    }

    #[test]
    fn 审批双模与pii持久默认关闭() {
        let cfg = Config::load_from(&base_env()).unwrap();
        assert!(!cfg.credential_block_wait);
        assert!(!cfg.pii_global_persist);
        for raw in ["1", "true", "yes", "on"] {
            let mut env = base_env();
            env.insert("CREDENTIAL_BLOCK_WAIT".to_string(), raw.to_string());
            assert!(
                Config::load_from(&env).unwrap().credential_block_wait,
                "{raw}"
            );
            let mut env = base_env();
            env.insert("PII_GLOBAL_PERSIST".to_string(), raw.to_string());
            assert!(Config::load_from(&env).unwrap().pii_global_persist, "{raw}");
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

    #[test]
    fn 无库返回空() {
        let dir = std::env::temp_dir().join(format!(
            "veil-resolve-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("note.txt"), b"x").unwrap();
        assert!(resolve_kdbx(&dir).is_none());
        assert!(resolve_kdbx(&dir.join("不存在的子目录")).is_none());
        std::fs::remove_dir_all(&dir).ok();
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
    fn 入口端口命中对应上游() {
        let cfg = Config::load_from(&upstream_env()).unwrap();
        assert_eq!(
            resolve_upstream_with_ingress(&cfg, Some(8878)).as_deref(),
            Some("http://八七七八上游:11434")
        );
        assert_eq!(
            resolve_upstream_with_ingress(&cfg, Some(8879)).as_deref(),
            Some("http://八七七九上游:11434")
        );
    }

    #[test]
    fn 未命中端口与空上下文回落缺省() {
        let cfg = Config::load_from(&upstream_env()).unwrap();
        for port in [None, Some(8877), Some(9999)] {
            assert_eq!(
                resolve_upstream_with_ingress(&cfg, port).as_deref(),
                Some("http://缺省上游:11434"),
                "端口 {port:?} 须回落缺省而非猜测"
            );
        }
    }

    #[test]
    fn 无缺省时回落任一端口上游() {
        let mut env = upstream_env();
        env.remove("LLM_UPSTREAM");
        let cfg = Config::load_from(&env).unwrap();
        let got = resolve_upstream_with_ingress(&cfg, Some(9999)).expect("须有回落");
        assert!(
            got == "http://八七七八上游:11434" || got == "http://八七七九上游:11434",
            "回落须为已知端口上游之一，实际: {got}"
        );
        assert!(resolve_upstream_with_ingress(&cfg, None).is_some());
    }

    #[test]
    fn 遗留变量名不被读取() {
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
        assert!(resolve_upstream_with_ingress(&cfg, Some(9999)).is_none());
    }
}
