//! 环境解析：常量/三枚举/`Config`/`load_from`/`resolve_kdbx`/入口选路。
//!
//! A2 拆分：`load_from` 按域拆为 `load_auth`/`load_limits`/`load_audit`/
//! `load_storage`/`load_redaction`/`load_llm`/`load_keepass_backend`，调用顺序
//! 与原实现逐语句同序（默认值、错误顺序与错误消息不变）；单测与共享测试
//! 基准拆至 `env_parse/tests.rs`、`env_parse/test_support.rs`（行数红线保持）。
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
    crate::{
        error::{Result, VeilError},
        service::audit::audit_enabled_compat,
    },
    std::{collections::HashMap, path::PathBuf, time::Duration},
};

mod pii_scope;
pub use pii_scope::PiiScopeMode;

/// 审计审批默认超时（秒）。
pub const AUDIT_TIMEOUT_DEFAULT: i64 = 90;
/// `AUDIT_TIMEOUT` 禁区下限（含端点）：上游约 120s 断连窗口两侧各留约 10s 余量。
pub const AUDIT_TIMEOUT_RACE_MIN: i64 = 110;
/// `AUDIT_TIMEOUT` 禁区上限（含端点）。
pub const AUDIT_TIMEOUT_RACE_MAX: i64 = 130;
/// `PII_HOLD_MAX` 默认值。
pub const PII_HOLD_MAX_DEFAULT: i64 = 64;
/// `PII_HOLD_MAX` 上界（1MB，`ARH-6`/D32）：超上界钳位并 warn，防无界缝窗缓冲；
/// 与 `AUDIT_HOLD_MAX_BYTES` 默认值同值，但维度不同（响应侧缝窗字符 vs 审计 hold 字节）。
pub const PII_HOLD_MAX_UPPER_BOUND: i64 = 1_048_576;
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
/// `NONSTREAM_MAX_BYTES` 默认值 8MB（对齐 Python `_llm.py:139`）：非流对话响应体入口上限，
/// 严格 `len >` 本值触发 502 `response_too_large`；与 `AUDIT_SUBLIMIT_CEILING_BYTES`
/// （审计子限锚点、非入口 enforcement）分属不同检查点（见 `veil-parity-gap-closeout` D2）。
pub const NONSTREAM_MAX_BYTES_DEFAULT: usize = 8 * 1024 * 1024;
/// SSE 单行上限 16KB（D5 下沉自 `service::sse`，只搬不改值；`sse.rs` 原位转发）：
/// 超长行按 C11 截断并记 `truncated_line_dropped_bytes`；
/// 理由：SSE 帧语义要求行完整，16KB 覆盖正常事件体（含 usage 完成帧），
/// 超限即异常上游，截断不断链；放宽会放大单行内存占用，改值须复核泵测试。
pub const LINE_LIMIT_BYTES: usize = 16 * 1024;
/// 上游事件空闲超时 30s（D5 下沉自 `service::sse`，只搬不改值；`sse.rs` 原位转发）：
/// 30s 无任何字节即收尾，避免半开连接永久挂起；
/// 理由：与 `HTTP_TIMEOUT_SECS`（默认 30s）同数量级有意对齐，任一先到先收尾。
pub const EVENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 流内保活帧间隔 10s（D5 下沉自 `service::sse`，只搬不改值；`sse.rs` 原位转发；
/// `service::audit::RequestKeepalive::spawn_gated` 接线、于 `src/handler/llm/pump/spawn/setup.rs`
/// 消费）： 理由：10s 远小于常见代理 NAT 空闲超时（60s+）且带宽可忽略，
/// 与管理面 60s SSE ping 分属不同链路（流内保活 vs 管理推送），差异有意。
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
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
    /// 可观测性总开关（`OBSERVABILITY_DISABLE`，仅精确 `1` 生效）：
    /// 置位时网关入口拒绝管理面（`/_admin` 全 404，与 token 有效性无关）。
    pub observability_disabled: bool,
    pub audit_mode: AuditMode,
    /// `POL-2`/D2：审计模式是否由环境来源显式给出（`AUDIT_MODE` 非空或 `AUDIT_ENABLED`
    /// 真值回退）。 用于区分「显式 `AUDIT_MODE=off`」与「未设置」，决定策略文件 `mode`
    /// 是否生效。
    pub audit_mode_explicit: bool,
    pub audit_timeout_secs: i64,
    pub approval_whitelist: Vec<String>,
    pub pii_hold_max: i64,
    pub audit_hold_max_bytes: i64,
    /// 非流对话响应体上限（`NONSTREAM_MAX_BYTES`，默认 8MB；严格超限 502）。
    pub nonstream_max_bytes: usize,
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
    /// PII 作用域模式（`PII_SCOPE_MODE`，默认 `request`）：`conversation` 时
    /// PII 映射按会话键跨轮共享（凭据仍请求级，B3 不变）；`request` 逐请求。
    pub pii_scope_mode: PiiScopeMode,
    /// 会话条目空闲 TTL（`PII_SCOPE_TTL_SECS`，默认 1800s；非正整数拒启动）。
    pub pii_scope_ttl_secs: i64,
    /// 会话条目上限（`PII_SCOPE_MAX_CONVERSATIONS`，默认 1024；非正整数拒启动）。
    pub pii_scope_max_conversations: usize,
    /// 显式会话键请求头名（`PII_SCOPE_KEY_HEADER`，默认
    /// `x-veil-conversation-id`；该头 MUST NOT 转发上游）。
    pub pii_scope_key_header: String,
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
    ///
    /// A2 按域拆分后仍按原语句顺序编排：认证 → 限额（PII hold/审计 hold/
    /// 非流上限）→ 审计（模式/超时/白名单）→ 存储/入口 → 脱敏（自定义
    /// 文件）→ LLM（上游/HTTP）→ KeePass 后端，保证错误顺序与错误消息
    /// 逐项不变。
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

        // 可观测性总开关：仅精确 `1`（去空白后）生效，其余值（含 true/yes）不触发，
        // 与 B1 Verify 边缘（值非 1 时不 404）对齐；提前求值以豁免 token 门禁。
        let observability_disabled = matches!(
            get("OBSERVABILITY_DISABLE").as_deref().map(str::trim),
            Some("1")
        );

        let AuthParts {
            observability_admin_token,
            homeserver,
            room_id,
            matrix_access_token,
        } = load_auth(&get, observability_disabled)?;
        let LimitParts {
            pii_hold_max,
            audit_hold_max_bytes,
            nonstream_max_bytes,
        } = load_limits(&get)?;
        let AuditParts {
            audit_mode,
            audit_mode_explicit,
            audit_timeout_secs,
            approval_whitelist,
            audit_policy_file,
        } = load_audit(env, &get)?;
        let StorageParts {
            data_dir,
            credential_secret,
            get_binary_hash,
            auto_approve,
            entry_mode,
            registry_path,
            db_dir,
            tpm_dir,
            credential_block_wait,
        } = load_storage(&get)?;
        let RedactionParts {
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
            placeholder_prompt_enabled,
            placeholder_prompt_text,
        } = load_redaction(&get)?;
        let pii_scope::PiiScopeParts {
            mode: pii_scope_mode,
            ttl_secs: pii_scope_ttl_secs,
            max_conversations: pii_scope_max_conversations,
            key_header: pii_scope_key_header,
        } = pii_scope::load(&get)?;
        let LlmParts {
            llm_upstreams,
            llm_default_upstream,
            normalize_json_whitespace,
            http_timeout_secs,
            http_pool_max_idle_per_host,
            http_pool_idle_timeout_secs,
        } = load_llm(env, &get)?;
        let keepass_backend = load_keepass_backend(&get)?;

        Ok(Self {
            homeserver,
            room_id,
            matrix_access_token,
            observability_admin_token,
            observability_disabled,
            audit_mode,
            audit_mode_explicit,
            audit_timeout_secs,
            approval_whitelist,
            pii_hold_max,
            audit_hold_max_bytes,
            nonstream_max_bytes,
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
            pii_scope_mode,
            pii_scope_ttl_secs,
            pii_scope_max_conversations,
            pii_scope_key_header,
            pii_custom_rules_file,
            pii_custom_patterns_file,
            pii_custom_dict_file,
            pii_value_sample_enabled,
            pii_value_sample_persist,
            pii_value_sample_hmac_key,
            placeholder_prompt_enabled,
            placeholder_prompt_text,
            normalize_json_whitespace,
            audit_policy_file,
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

/// 认证/服务身份域（A2；最先校验，错误顺序与原实现一致）。
struct AuthParts {
    observability_admin_token: String,
    homeserver: String,
    room_id: String,
    matrix_access_token: String,
}

fn load_auth(
    get: &dyn Fn(&str) -> Option<String>,
    observability_disabled: bool,
) -> Result<AuthParts> {
    // `OBSERVABILITY_DISABLE=1`（精确）时管理面全 404，token 非必填：缺 token 不拒启动，
    // 也不做独立/长度校验（禁用即不要求 token，见 config-legacy-compat spec）。
    let observability_admin_token = if observability_disabled {
        get("OBSERVABILITY_ADMIN_TOKEN").unwrap_or_default()
    } else {
        require_non_empty(get, "OBSERVABILITY_ADMIN_TOKEN")?
    };
    if !observability_disabled
        && let Some(cred) = get("CREDENTIAL_ADMIN_TOKEN")
        && !cred.is_empty()
        && cred == observability_admin_token
    {
        return Err(config_error(
            "OBSERVABILITY_ADMIN_TOKEN",
            "OBSERVABILITY_ADMIN_TOKEN 须独立，不得复用 CREDENTIAL_ADMIN_TOKEN",
        ));
    }
    let homeserver = require_non_empty(get, "HOMESERVER")?;
    let room_id = require_non_empty(get, "ROOM_ID")?;
    let matrix_access_token = require_non_empty(get, "MATRIX_ACCESS_TOKEN")?;
    if !observability_disabled && observability_admin_token == matrix_access_token {
        return Err(config_error(
            "OBSERVABILITY_ADMIN_TOKEN",
            "OBSERVABILITY_ADMIN_TOKEN 须独立，不得复用 MATRIX_ACCESS_TOKEN",
        ));
    }
    if !observability_disabled && observability_admin_token.len() < ADMIN_TOKEN_MIN_LEN {
        tracing::warn!(
            "OBSERVABILITY_ADMIN_TOKEN 长度不足 {ADMIN_TOKEN_MIN_LEN}，建议使用更长随机值"
        );
    }
    Ok(AuthParts {
        observability_admin_token,
        homeserver,
        room_id,
        matrix_access_token,
    })
}

/// 限额域（A2）：三个限额早于审计模式解析，错误顺序与原实现一致。
struct LimitParts {
    pii_hold_max: i64,
    audit_hold_max_bytes: i64,
    nonstream_max_bytes: usize,
}

fn load_limits(get: &dyn Fn(&str) -> Option<String>) -> Result<LimitParts> {
    let pii_hold_max = parse_positive(get, "PII_HOLD_MAX", PII_HOLD_MAX_DEFAULT)?;
    let pii_hold_max = if pii_hold_max > PII_HOLD_MAX_UPPER_BOUND {
        tracing::warn!(
            "PII_HOLD_MAX={pii_hold_max} 超上界 {PII_HOLD_MAX_UPPER_BOUND}，已钳位（ARH-6，防无界缝窗缓冲）"
        );
        PII_HOLD_MAX_UPPER_BOUND
    } else {
        pii_hold_max
    };
    Ok(LimitParts {
        pii_hold_max,
        audit_hold_max_bytes: parse_positive(
            get,
            "AUDIT_HOLD_MAX_BYTES",
            AUDIT_HOLD_MAX_BYTES_DEFAULT,
        )?,
        nonstream_max_bytes: parse_positive_usize(
            get,
            "NONSTREAM_MAX_BYTES",
            NONSTREAM_MAX_BYTES_DEFAULT,
        )?,
    })
}

/// 审计域（A2）：模式（含遗留 `AUDIT_ENABLED` 回退）/超时/白名单/策略文件。
struct AuditParts {
    audit_mode: AuditMode,
    audit_mode_explicit: bool,
    audit_timeout_secs: i64,
    approval_whitelist: Vec<String>,
    audit_policy_file: Option<PathBuf>,
}

/// `POL-9`/D9：`approve` + 空白名单的启动门禁（env 与文件两来源共用）。
pub fn validate_approve_whitelist(mode: AuditMode, whitelist: &[String]) -> Result<()> {
    if mode == AuditMode::Approve && whitelist.is_empty() {
        return Err(config_error(
            "APPROVAL_WHITELIST",
            "AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST（审批人 Matrix user id），否则拒绝启动",
        ));
    }
    Ok(())
}

fn load_audit(
    env: &HashMap<String, String>,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<AuditParts> {
    let (audit_mode, audit_mode_explicit): (AuditMode, bool) = match get("AUDIT_MODE") {
        Some(v) if !v.is_empty() => (
            v.parse().map_err(|message| VeilError::Config {
                var: "AUDIT_MODE".to_string(),
                message,
            })?,
            true,
        ),
        // X1/D1 遗留兼容回退（fail-closed）：`AUDIT_MODE` 缺失/空白时读
        // `AUDIT_ENABLED`（真值 `1/true/yes/on` → `block`），显式非空优先。
        _ => match audit_enabled_compat(env) {
            Some(mode) => {
                tracing::warn!(
                    "AUDIT_MODE 缺失或空白，采用遗留 AUDIT_ENABLED 兼容回退：audit_mode={mode:?}\
                    （fail-closed；如需关闭请显式设置 AUDIT_MODE=off）"
                );
                (mode, true)
            }
            None => (AuditMode::Off, false),
        },
    };
    let audit_timeout_secs = parse_audit_timeout(get)?;
    let approval_whitelist = parse_whitelist(get)?;
    validate_approve_whitelist(audit_mode, &approval_whitelist)?;
    let audit_policy_file = get("AUDIT_POLICY_FILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    Ok(AuditParts {
        audit_mode,
        audit_mode_explicit,
        audit_timeout_secs,
        approval_whitelist,
        audit_policy_file,
    })
}

/// 存储/入口域（A2）：目录派生、三因子密钥、入口三态与审批双模开关。
struct StorageParts {
    data_dir: PathBuf,
    credential_secret: Option<String>,
    get_binary_hash: Option<String>,
    auto_approve: AutoApprove,
    entry_mode: EntryMode,
    registry_path: PathBuf,
    db_dir: PathBuf,
    tpm_dir: PathBuf,
    credential_block_wait: bool,
}

fn load_storage(get: &dyn Fn(&str) -> Option<String>) -> Result<StorageParts> {
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
    let db_dir = get("DB_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| data_dir.join("db"), PathBuf::from);
    let tpm_dir = get("TPM_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| data_dir.join("tpm"), PathBuf::from);
    let credential_block_wait = parse_bool_off(get, "CREDENTIAL_BLOCK_WAIT");
    Ok(StorageParts {
        data_dir,
        credential_secret,
        get_binary_hash,
        auto_approve,
        entry_mode,
        registry_path,
        db_dir,
        tpm_dir,
        credential_block_wait,
    })
}

/// 脱敏域（A2）：总开关/三语义开关/自定义文件/值级采样/占位符说明。
struct RedactionParts {
    redaction_enabled: bool,
    pii_response_side: bool,
    pii_fuzzy_restore: bool,
    pii_detection_hardening: bool,
    pii_custom_rules_file: Option<PathBuf>,
    pii_custom_patterns_file: Option<PathBuf>,
    pii_custom_dict_file: Option<PathBuf>,
    pii_value_sample_enabled: bool,
    pii_value_sample_persist: bool,
    pii_value_sample_hmac_key: Option<String>,
    placeholder_prompt_enabled: bool,
    placeholder_prompt_text: String,
}

fn load_redaction(get: &dyn Fn(&str) -> Option<String>) -> Result<RedactionParts> {
    // 脱敏总开关：`REDACTION_ENABLED` 优先，`PII_REDACTION_ENABLED` 为原仓别名；
    // 两者皆空默认开启，显式假值（0/false/no/off）关闭。
    let redaction_enabled = match get("REDACTION_ENABLED").filter(|v| !v.is_empty()) {
        Some(v) => !is_falsy(&v),
        None => match get("PII_REDACTION_ENABLED").filter(|v| !v.is_empty()) {
            Some(v) => !is_falsy(&v),
            None => true,
        },
    };
    let pii_response_side = parse_bool_on(get, "PII_RESPONSE_SIDE");
    let pii_fuzzy_restore = parse_bool_off(get, "PII_FUZZY_RESTORE");
    let pii_detection_hardening = parse_bool_off(get, "PII_DETECTION_HARDENING");
    let pii_custom_rules_file = load_custom_file(
        get,
        &[
            "PII_CUSTOM_RULES_FILE",
            "PII_RULES_FILE",
            "PII_CUSTOM_RULES",
        ],
    )?;
    let pii_custom_patterns_file = load_custom_file(
        get,
        &[
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_PATTERN_FILE",
            "PII_CUSTOM_PATTERNS",
        ],
    )?;
    let pii_custom_dict_file = load_custom_file(
        get,
        &[
            "PII_CUSTOM_DICT_FILE",
            "PII_DICT_FILE",
            "PII_SENSITIVE_DICT_FILE",
            "PII_SENSITIVE_NAMES_FILE",
            "PII_CUSTOM_DICT",
        ],
    )?;
    let pii_value_sample_enabled = parse_bool_off(get, "PII_VALUE_SAMPLE_ENABLED");
    let pii_value_sample_persist = parse_bool_on(get, "PII_VALUE_SAMPLE_PERSIST");
    let pii_value_sample_hmac_key = get("PII_VALUE_SAMPLE_HMAC_KEY").filter(|v| !v.is_empty());
    let (placeholder_prompt_enabled, placeholder_prompt_text) = parse_placeholder_prompt(get);
    Ok(RedactionParts {
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
        placeholder_prompt_enabled,
        placeholder_prompt_text,
    })
}

/// LLM 网关域（A2）：端口上游表/缺省上游/空白归一/HTTP 客户端参数。
struct LlmParts {
    llm_upstreams: HashMap<u16, String>,
    llm_default_upstream: Option<String>,
    normalize_json_whitespace: bool,
    http_timeout_secs: u64,
    http_pool_max_idle_per_host: usize,
    http_pool_idle_timeout_secs: u64,
}

fn load_llm(
    env: &HashMap<String, String>,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<LlmParts> {
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
    let normalize_json_whitespace =
        matches!(get("NORMALIZE_JSON_WHITESPACE").as_deref(), Some("1"));
    let http_timeout_secs =
        parse_positive_u64(get, "HTTP_TIMEOUT_SECS", HTTP_TIMEOUT_SECS_DEFAULT)?;
    let http_pool_max_idle_per_host = parse_positive_usize(
        get,
        "HTTP_POOL_MAX_IDLE_PER_HOST",
        HTTP_POOL_MAX_IDLE_PER_HOST_DEFAULT,
    )?;
    let http_pool_idle_timeout_secs = parse_positive_u64(
        get,
        "HTTP_POOL_IDLE_TIMEOUT_SECS",
        HTTP_POOL_IDLE_TIMEOUT_SECS_DEFAULT,
    )?;
    Ok(LlmParts {
        llm_upstreams,
        llm_default_upstream,
        normalize_json_whitespace,
        http_timeout_secs,
        http_pool_max_idle_per_host,
        http_pool_idle_timeout_secs,
    })
}

/// KeePass 后端选路（A2；置于 HTTP 校验之后，保持原错误顺序）。
fn load_keepass_backend(get: &dyn Fn(&str) -> Option<String>) -> Result<KeepassBackendKind> {
    match get("VEIL_KEEPASS_BACKEND") {
        Some(v) if !v.is_empty() => {
            let parsed: KeepassBackendKind = v.parse().map_err(|message| VeilError::Config {
                var: "VEIL_KEEPASS_BACKEND".to_string(),
                message,
            })?;
            Ok(parsed)
        }
        _ => Ok(KeepassBackendKind::Real),
    }
}

/// 跨子模块测试共享基准（见 `test_support.rs`）。
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod redline {
    #[test]
    fn file_len_redline() {
        crate::test_support::file_len_under_800_or_split(
            "env_parse.rs",
            include_str!("env_parse.rs"),
        );
    }
}
