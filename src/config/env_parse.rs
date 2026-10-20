//! 环境解析：常量/三枚举/`Config`/`load_from`/`resolve_kdbx`/入口选路。
//!
//! 拆分：`load_from` 按域拆为 `load_auth`/`load_limits`/`load_audit`/
//! `load_storage`/`load_redaction`/`load_llm`/`load_keepass_backend`，调用顺序
//! 与原实现逐语句同序（默认值、错误顺序与错误消息不变）；单测与共享测试
//! 基准拆至 `env_parse/tests.rs`、`env_parse/test_support.rs`（行数红线保持）。
//!
//! 跨子模块引用：自定义文件经 `super::custom_file`，校验器经
//! `super::validate`（同级 `use` 成环无碍，Rust 允许）。

use {
    super::{
        command::CommandConfig,
        custom_file::load_custom_file,
        targets::{LlmTargets, validate_target_upstreams},
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
        },
    },
    crate::error::{Result, VeilError},
    std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration},
};

mod entry_mode;
mod keepass;
pub(crate) mod pii_scope;
pub use {
    entry_mode::{EntryMode, entry_mode_notice},
    keepass::KeepassBackendKind,
    pii_scope::PiiScopeMode,
};

/// 默认监听地址：本机回环（容器部署在 `[server].bind` 显式写 `0.0.0.0:8877`）。
pub const DEFAULT_SERVER_BIND: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::new(127, 0, 0, 1),
    8877,
));

/// 审计审批默认超时（秒）。
pub const AUDIT_TIMEOUT_DEFAULT: i64 = 90;
/// `AUDIT_TIMEOUT` 禁区下限（含端点）：上游约 120s 断连窗口两侧各留约 10s 余量。
pub const AUDIT_TIMEOUT_RACE_MIN: i64 = 110;
/// `AUDIT_TIMEOUT` 禁区上限（含端点）。
pub const AUDIT_TIMEOUT_RACE_MAX: i64 = 130;
/// `AUDIT_HOLD_MAX_BYTES` 默认值。
pub const AUDIT_HOLD_MAX_BYTES_DEFAULT: i64 = 1_048_576;
/// 管理 token 建议最小长度，不足仅告警不断链。
pub const ADMIN_TOKEN_MIN_LEN: usize = 32;
/// 通用网关 ingress JSON 上限 10MB（检查点：`handler::llm` 入口 `to_bytes`；
/// 与 8MB 审计/扫描类上限分属不同检查点，
/// 差异为有意设计；超限返回 413）。
pub const GATEWAY_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
/// 审计/扫描类子限 ceiling 8MB（检查点归属声明：审计 hold 与扫描上限类）。
/// 现网可配子限（`AUDIT_HOLD_MAX_BYTES` 默认 1MB）均不得超过本 ceiling；
/// 本常量为回归锚点，不接任何请求入口，不改变现行子限行为。
/// 归属 `config.rs`（常量下沉），`handler::llm` 原位 `pub use` 转发。
pub const AUDIT_SUBLIMIT_CEILING_BYTES: usize = 8 * 1024 * 1024;
/// `NONSTREAM_MAX_BYTES` 默认值 8MB：非流对话响应体入口上限，
/// 严格 `len >` 本值触发 502 `response_too_large`；与 `AUDIT_SUBLIMIT_CEILING_BYTES`
/// （审计子限锚点、非入口 enforcement）分属不同检查点。
pub const NONSTREAM_MAX_BYTES_DEFAULT: usize = 8 * 1024 * 1024;
/// SSE 单行/单事件**软限** 1MiB（仅观测）：超过仅记 `oversize_frame_bytes` /
/// `oversize_frames`，帧仍**完整交付**并正常参与 carry/还原/审计，SHALL NOT 截断交付半帧。
/// 理由：软限给出「大于常态但合法」的预警口径；真正的内存有界由硬上限 fail-closed 兜底。
pub const SSE_FRAME_SOFT_BYTES: usize = 1024 * 1024;
/// SSE 单行/单事件与未终结行尾（`text_carry`）的**硬上限**默认值 8MiB
/// （env/TOML 键 `SSE_FRAME_HARD_BYTES` 可覆盖，默认值即本常量；解析器经 `service::sse`
/// 转发消费）： 超限即 fail-closed（置 `carry_fatal`），按协议合成正确终止帧，SHALL NOT
/// 向客户端交付截断 JSON、 SHALL NOT 无界累积缓冲。理由：合法超大帧（审计 hold
/// 本已要求整帧）完整处理，异常超大帧不拖垮内存。
pub const SSE_FRAME_HARD_BYTES: usize = 8 * 1024 * 1024;
/// 上游事件空闲超时 30s（下沉自 `service::sse`，只搬不改值；`sse.rs` 原位转发）：
/// 30s 无任何字节即收尾，避免半开连接永久挂起；
/// 理由：与 `HTTP_TIMEOUT_SECS`（默认 30s）同数量级有意对齐，任一先到先收尾。
pub const EVENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 流内保活帧间隔 10s（下沉自 `service::sse`，只搬不改值；`sse.rs` 原位转发；
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
/// 内置默认占位符说明文案：
/// 静态文本，不含真实 PII 值；用 `*` 通配形态描述，不命中真实占位符形态。
pub const PLACEHOLDER_PROMPT_DEFAULT: &str = "说明：消息中形如 __PII_*__ 和 __CRED_*__ 的标记是安全网关的敏感信息脱敏占位符，代表被替换的原始值（如手机号、IP 地址、银行卡号、密钥等）。重要：这些占位符出现的位置，其原始内容已被安全网关替换，你无法直接看到原文；因此不要把占位符当作真实数据（不要用它做样例、比对、推断原文，也不要假设原文就是占位符形态）。请原样保留这些占位符（包括 content 与 tool calls/function 参数中的）：不要修改格式、不要校验其合法性、不要推断或补全内容，也不要视为输入错误。它们不是格式问题，直接使用即可。若你需要查看被替换的原文进行分析，请改用不经由此网关的通道（如直接在受信任环境执行命令），不要尝试从占位符本身还原。";

/// 自动放行三态：`True` 放行 / `False` 拒绝 / `None` 转 Matrix 审批。
/// 禁用 `allow`/`deny`/`approve` 虚构命名，统一用此三态。
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
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub homeserver: String,
    pub room_id: String,
    pub matrix_access_token: String,
    pub observability_admin_token: String,
    /// 可观测性总开关（`OBSERVABILITY_DISABLE`，仅精确 `1` 生效）：
    /// 置位时网关入口拒绝管理面（`/_admin` 全 404，与 token 有效性无关）。
    pub observability_disabled: bool,
    /// 监听地址（文件专属 `[server].bind`；缺省 `127.0.0.1:8877`）。
    pub server_bind: SocketAddr,
    pub audit_mode: AuditMode,
    /// 审计模式是否由环境来源显式给出（`AUDIT_MODE` 非空）。
    /// 用于区分「显式 `AUDIT_MODE=off`」与「未设置」，决定策略文件 `mode`
    /// 是否生效。
    pub audit_mode_explicit: bool,
    pub audit_timeout_secs: i64,
    pub approval_whitelist: Vec<String>,
    pub audit_hold_max_bytes: i64,
    /// 非流对话响应体上限（`NONSTREAM_MAX_BYTES`，默认 8MB；严格超限 502）。
    pub nonstream_max_bytes: usize,
    /// SSE 单行/单事件硬上限（`SSE_FRAME_HARD_BYTES`，默认 8MiB；超限 fail-closed）。
    /// 解析器经 `service::sse` 常量消费（默认即 [`SSE_FRAME_HARD_BYTES`]）。
    pub sse_frame_hard_bytes: usize,
    pub data_dir: PathBuf,
    pub veilctl_secret: Option<String>,
    pub veilctl_binary_hash: Option<String>,
    pub auto_approve: AutoApprove,
    pub entry_mode: EntryMode,
    pub registry_path: PathBuf,
    pub credential_approval_timeout_secs: i64,
    pub llm_upstreams: HashMap<u16, String>,
    pub llm_default_upstream: Option<String>,
    /// 文件专属 `[llm.targets]` 上游覆盖（无 env 对应源；未声明为空表，零行为变化）。
    pub llm_targets: LlmTargets,
    /// 文件专属 `[command]`（未声明时 `enabled = false`）。
    pub command: CommandConfig,
    pub redaction_enabled: bool,
    /// 宽松还原开关（`PII_FUZZY_RESTORE`，默认关闭；
    /// 开启时残缺/宽松形态 token 按序号回查请求表还原）。
    pub pii_fuzzy_restore: bool,
    /// 检测强化开关（`PII_DETECTION_HARDENING`，默认关闭；
    /// 开启时内置命中做严格边界复核，丢弃 ASCII 粘连与前导零 IPv4）。
    pub pii_detection_hardening: bool,
    /// PII 作用域模式（`PII_SCOPE_MODE`，默认 `request`）：`conversation` 时
    /// PII 映射按会话键跨轮共享（凭据仍请求级）；`request` 逐请求。
    pub pii_scope_mode: PiiScopeMode,
    /// 会话条目空闲 TTL（`PII_SCOPE_TTL_SECS`，默认 1800s；非正整数拒启动）。
    pub pii_scope_ttl_secs: i64,
    /// 会话条目上限（`PII_SCOPE_MAX_CONVERSATIONS`，默认 1024；非正整数拒启动）。
    pub pii_scope_max_conversations: usize,
    /// 显式会话键请求头名（`PII_SCOPE_KEY_HEADER`，默认
    /// `x-veil-conversation-id`；该头 MUST NOT 转发上游；保留鉴权/传输头名拒启动）。
    pub pii_scope_key_header: String,
    /// `previous_response_id` 映射容量（`PII_PREV_ID_MAX_ENTRIES`；未设置时取
    /// `PII_SCOPE_MAX_CONVERSATIONS` 的生效值，非正整数拒启动）。
    pub pii_prev_id_max_entries: usize,
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
    /// 字节契约开关（`NORMALIZE_JSON_WHITESPACE`，仅 `"1"` 开启；
    /// 默认关闭时请求体除 token 子串替换外保持字节一致）。
    pub normalize_json_whitespace: bool,
    /// §6.11 审计策略文件路径（`AUDIT_POLICY_FILE`，缺省为内建默认策略）。
    pub audit_policy_file: Option<PathBuf>,
    pub http_timeout_secs: u64,
    pub http_pool_max_idle_per_host: usize,
    pub http_pool_idle_timeout_secs: u64,
    pub db_dir: PathBuf,
    pub tpm_dir: PathBuf,
    pub keepass_backend: KeepassBackendKind,
    /// 授权窗口长度（`AUTHORIZATION_TTL_SECS` / `[storage].authorization_ttl_secs`）：
    /// `None` 表示无期限（缺省 `0` 归一为 `None`）。到期即转审批，不自动吊销。
    pub authorization_ttl: Option<u64>,
    /// 凭据审批双模开关（`CREDENTIAL_BLOCK_WAIT`，默认关闭）：
    /// `=1` 时 enrolled 篡改/未 enrolled 待审走 300s 阻塞等 reaction，
    /// 默认保持 202 抛单（建单 + best-effort 发送即返回）。
    /// 接线：`service::credential::approval_dual_mode` 唯一读取方（接线已复核，保留）。
    pub credential_block_wait: bool,
}

/// 遗留兼容声明：`CREDENTIAL_MASTER_PASSWORD`/`CREDENTIAL_PORT` 为遗留变量名，
/// 本二进制不读取（`load_from` 只认下述新名）；主密码口令改走 TPM 解封
/// （`service::tpm::startup_tpm_in`），部署密钥改用 `VEILCTL_SECRET`，
/// 宿主机端口改用 `PORT_8877/8878/8879`（仅改映射不改容器内
/// 监听）。沿用旧名部署不生效（置位仅启动期告警），须改用新名（见 工程参考 §7.4 兼容表）。
impl Config {
    /// 从进程环境变量加载，缺必填或非法值返回 [`VeilError::Config`]。
    pub fn from_env() -> Result<Self> { Self::from_env_map(std::env::vars().collect()) }

    /// 纯缝入口（进程 env → 配置全链）：先对**原始** map 记迁移/遗留置位告警
    /// （warn-before-drop），再按白名单过滤，过滤**先于** `apply_config_file`——
    /// 否则文件注入的 canonical 名会被误判为 env 显式。不触全局 env，供单测直调。
    pub(crate) fn from_env_map(raw: HashMap<String, String>) -> Result<Self> {
        super::env_surface::warn_migrated_and_legacy(&raw);
        let mut map = super::env_surface::filter_process_env(raw);
        let outcome = super::file_layer::apply_config_file(&mut map)?;
        Self::load_from_with_file(&map, outcome)
    }

    /// 公开兼容入口：无文件覆盖，逐字等价于扩展入口传空表。
    pub fn load_from(env: &HashMap<String, String>) -> Result<Self> {
        Self::load_from_with_targets(env, LlmTargets::new())
    }

    /// 扩展入口（文件层产物）：并入 `[llm.targets]` 与 `[command]`。
    pub(crate) fn load_from_with_file(
        env: &HashMap<String, String>,
        outcome: super::file_layer::FileLayerOutcome,
    ) -> Result<Self> {
        Self::load_from_parts(
            env,
            outcome.llm_targets,
            outcome.command,
            outcome.server_bind,
        )
    }

    /// 扩展入口：并入文件层已校验的 `[llm.targets]` 覆盖，复用同一校验链
    /// （按域拆分后语句顺序不变，错误顺序与错误消息逐项保持）。
    pub(crate) fn load_from_with_targets(
        env: &HashMap<String, String>,
        llm_targets: LlmTargets,
    ) -> Result<Self> {
        Self::load_from_parts(env, llm_targets, CommandConfig::default(), None)
    }

    fn load_from_parts(
        env: &HashMap<String, String>,
        llm_targets: LlmTargets,
        command: CommandConfig,
        server_bind: Option<SocketAddr>,
    ) -> Result<Self> {
        let get = |name: &str| env.get(name).map(|v| v.trim().to_string());
        for name in super::validate::legacy_ignored_detected(env) {
            let hint = super::validate::LEGACY_IGNORED_VARS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)
                .unwrap_or("见 工程参考 §7.4");
            tracing::warn!("{name} 已置位但二进制不读取（置位已忽略）：{hint}");
        }

        // 可观测性总开关：仅精确 `1`（去空白后）生效，其余值（含 true/yes）不触发，
        // 与「值非 1 时不 404」的边缘口径对齐；提前求值以豁免 token 门禁。
        let observability_disabled = matches!(
            get("OBSERVABILITY_DISABLE").as_deref().map(str::trim),
            Some("1")
        );

        let AuthParts {
            observability_admin_token,
            homeserver,
            room_id,
            matrix_access_token,
        } = load_auth(&get)?;
        let LimitParts {
            audit_hold_max_bytes,
            nonstream_max_bytes,
            sse_frame_hard_bytes,
        } = load_limits(&get)?;
        let AuditParts {
            audit_mode,
            audit_mode_explicit,
            audit_timeout_secs,
            approval_whitelist,
            audit_policy_file,
        } = load_audit(&get)?;
        let StorageParts {
            data_dir,
            veilctl_secret,
            veilctl_binary_hash,
            auto_approve,
            entry_mode,
            registry_path,
            db_dir,
            tpm_dir,
            credential_block_wait,
            authorization_ttl,
        } = load_storage(&get)?;
        let RedactionParts {
            redaction_enabled,
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
            prev_id_max_entries: pii_prev_id_max_entries,
        } = pii_scope::load(&get)?;
        let LlmParts {
            llm_upstreams,
            llm_default_upstream,
            normalize_json_whitespace,
            http_timeout_secs,
            http_pool_max_idle_per_host,
            http_pool_idle_timeout_secs,
        } = load_llm(env, &get)?;
        let default_upstream = llm_default_upstream.as_deref();
        validate_target_upstreams(&llm_targets, &llm_upstreams, default_upstream)?;
        let keepass_backend = load_keepass_backend(&get)?;

        Ok(Self {
            homeserver,
            room_id,
            matrix_access_token,
            observability_admin_token,
            observability_disabled,
            server_bind: server_bind.unwrap_or(DEFAULT_SERVER_BIND),
            audit_mode,
            audit_mode_explicit,
            audit_timeout_secs,
            approval_whitelist,
            audit_hold_max_bytes,
            nonstream_max_bytes,
            sse_frame_hard_bytes,
            data_dir,
            veilctl_secret,
            veilctl_binary_hash,
            auto_approve,
            entry_mode,
            registry_path,
            credential_approval_timeout_secs: CREDENTIAL_APPROVAL_TIMEOUT_SECS,
            llm_upstreams,
            llm_default_upstream,
            llm_targets,
            command,
            redaction_enabled,
            pii_fuzzy_restore,
            pii_detection_hardening,
            pii_scope_mode,
            pii_scope_ttl_secs,
            pii_scope_max_conversations,
            pii_scope_key_header,
            pii_prev_id_max_entries,
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
            authorization_ttl,
            credential_block_wait,
        })
    }
}

impl Config {
    /// Matrix 通知/审批是否可用：`homeserver`、`room_id`、`matrix_access_token`
    /// 三要素均非空（文件 + env 合并后）；任一缺失即关闭功能，不拒启动。
    pub fn matrix_enabled(&self) -> bool {
        !self.homeserver.is_empty()
            && !self.room_id.is_empty()
            && !self.matrix_access_token.is_empty()
    }

    /// 空白名单告警：Matrix 面启用且审批白名单为空时返回；调用方走裸 stderr。
    pub fn empty_whitelist_warning(&self) -> Option<&'static str> {
        (self.matrix_enabled() && self.approval_whitelist.is_empty()).then_some(
            "警告: [audit].approval_whitelist 为空（空白名单＝不过滤）：审批房间内任意成员可审批注册/命令/吊销/凭据/审计票，并可发送 lock/forget 清理指令；生产部署必须显式配置 [audit].approval_whitelist",
        )
    }

    /// 管理面是否可用：未显式禁用（`OBSERVABILITY_DISABLE` 精确 `1`）且 admin token
    /// 非空；任一不满足即 `/_admin*` 全 404，不影响 LLM 代理。
    pub fn admin_surface_enabled(&self) -> bool {
        !self.observability_disabled && !self.observability_admin_token.is_empty()
    }

    /// Matrix 三要素缺失键清单（顺序固定），供启动告警与审批 fail-closed 早退指名缺失项。
    pub fn missing_matrix_keys(&self) -> Vec<&'static str> {
        [
            (self.homeserver.is_empty(), "HOMESERVER"),
            (self.room_id.is_empty(), "ROOM_ID"),
            (self.matrix_access_token.is_empty(), "MATRIX_ACCESS_TOKEN"),
        ]
        .into_iter()
        .filter_map(|(missing, key)| missing.then_some(key))
        .collect()
    }
}

/// 认证/服务身份域（最先校验，错误顺序与原实现一致）。
struct AuthParts {
    observability_admin_token: String,
    homeserver: String,
    room_id: String,
    matrix_access_token: String,
}

fn load_auth(get: &dyn Fn(&str) -> Option<String>) -> Result<AuthParts> {
    // 四键均可选：缺失/空值一律取空串，不再拒绝启动；对应功能由
    // `Config::matrix_enabled` / `Config::admin_surface_enabled` 在运行期关闭。
    let observability_admin_token = get("OBSERVABILITY_ADMIN_TOKEN").unwrap_or_default();
    let homeserver = get("HOMESERVER").unwrap_or_default();
    let room_id = get("ROOM_ID").unwrap_or_default();
    let matrix_access_token = get("MATRIX_ACCESS_TOKEN").unwrap_or_default();
    // 独立性只在两 token 均非空时校验：空 token 由功能关闭兜底，不参与比对。
    if !observability_admin_token.is_empty()
        && !matrix_access_token.is_empty()
        && observability_admin_token == matrix_access_token
    {
        return Err(config_error(
            "OBSERVABILITY_ADMIN_TOKEN",
            "OBSERVABILITY_ADMIN_TOKEN 须独立，不得复用 MATRIX_ACCESS_TOKEN",
        ));
    }
    // 长度告警只在 token 非空时触发：空 token 即管理面关闭，无需告警长度。
    if !observability_admin_token.is_empty()
        && observability_admin_token.len() < ADMIN_TOKEN_MIN_LEN
    {
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

/// 限额域：限额早于审计模式解析，错误顺序与原实现一致。
struct LimitParts {
    audit_hold_max_bytes: i64,
    nonstream_max_bytes: usize,
    sse_frame_hard_bytes: usize,
}

fn load_limits(get: &dyn Fn(&str) -> Option<String>) -> Result<LimitParts> {
    Ok(LimitParts {
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
        sse_frame_hard_bytes: parse_positive_usize(
            get,
            "SSE_FRAME_HARD_BYTES",
            SSE_FRAME_HARD_BYTES,
        )?,
    })
}

/// 审计域：模式/超时/白名单/策略文件。
struct AuditParts {
    audit_mode: AuditMode,
    audit_mode_explicit: bool,
    audit_timeout_secs: i64,
    approval_whitelist: Vec<String>,
    audit_policy_file: Option<PathBuf>,
}

/// `approve` + 空白名单的启动门禁（env 与文件两来源共用）。
pub fn validate_approve_whitelist(mode: AuditMode, whitelist: &[String]) -> Result<()> {
    if mode == AuditMode::Approve && whitelist.is_empty() {
        return Err(config_error(
            "APPROVAL_WHITELIST",
            "AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST（审批人 Matrix user id），否则拒绝启动",
        ));
    }
    Ok(())
}

fn load_audit(get: &dyn Fn(&str) -> Option<String>) -> Result<AuditParts> {
    let (audit_mode, audit_mode_explicit): (AuditMode, bool) = match get("AUDIT_MODE") {
        Some(v) if !v.is_empty() => (
            v.parse().map_err(|message| VeilError::Config {
                var: "AUDIT_MODE".to_string(),
                message,
            })?,
            true,
        ),
        _ => (AuditMode::Off, false),
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

/// 存储/入口域：目录派生、三因子密钥、入口三态与审批双模开关。
struct StorageParts {
    data_dir: PathBuf,
    veilctl_secret: Option<String>,
    veilctl_binary_hash: Option<String>,
    auto_approve: AutoApprove,
    entry_mode: EntryMode,
    registry_path: PathBuf,
    db_dir: PathBuf,
    tpm_dir: PathBuf,
    credential_block_wait: bool,
    authorization_ttl: Option<u64>,
}

fn load_storage(get: &dyn Fn(&str) -> Option<String>) -> Result<StorageParts> {
    let data_dir = get("DATA_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("/data"), PathBuf::from);
    let veilctl_secret = get("VEILCTL_SECRET").filter(|v| !v.is_empty());
    let veilctl_binary_hash = get("VEILCTL_BINARY_HASH").filter(|v| !v.is_empty());
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
    let authorization_ttl = parse_authorization_ttl(get)?;
    Ok(StorageParts {
        data_dir,
        veilctl_secret,
        veilctl_binary_hash,
        auto_approve,
        entry_mode,
        registry_path,
        db_dir,
        tpm_dir,
        credential_block_wait,
        authorization_ttl,
    })
}

/// 授权窗口长度解析：缺省 `0`（无期限）；非数字/负数拒启动，`0` 归一为 `None`。
fn parse_authorization_ttl(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<u64>> {
    let raw = get("AUTHORIZATION_TTL_SECS")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "0".to_string());
    let ttl: u64 = raw.parse().map_err(|_| VeilError::Config {
        var: "AUTHORIZATION_TTL_SECS".to_string(),
        message: format!("AUTHORIZATION_TTL_SECS 非法整数: {raw:?}"),
    })?;
    Ok(crate::registry::normalize_ttl(Some(ttl)))
}

/// 脱敏域：总开关/语义开关/自定义文件/值级采样/占位符说明。
struct RedactionParts {
    redaction_enabled: bool,
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
    // 脱敏总开关：`REDACTION_ENABLED` 优先，`PII_REDACTION_ENABLED` 为兼容别名；
    // 两者皆空默认开启，显式假值（0/false/no/off）关闭。
    let redaction_enabled = match get("REDACTION_ENABLED").filter(|v| !v.is_empty()) {
        Some(v) => !is_falsy(&v),
        None => match get("PII_REDACTION_ENABLED").filter(|v| !v.is_empty()) {
            Some(v) => !is_falsy(&v),
            None => true,
        },
    };
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

/// LLM 网关域：端口上游表/缺省上游/空白归一/HTTP 客户端参数。
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
        if let Some(port) = super::env_surface::parse_llm_port(k) {
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

/// KeePass 后端选路（置于 HTTP 校验之后，保持原错误顺序）。
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
