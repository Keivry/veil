//! 可选 TOML 配置文件层（补充层，`env 显式 > 文件 > 内建默认`）。
//!
//! 仅当 `VEIL_CONFIG_FILE` 非空（trim 后）时加载：强类型 [`FileConfig`]
//! （顶层与各分节 `deny_unknown_fields`、枚举钉死取值）经封闭映射表翻译为
//! 「规范 env 名 + 规范字符串」并入 env map，复用既有 `Config::load_from`
//! 唯一校验链；任何失败（缺失/超 1MB/语法/未知键/类型/枚举/越界）fail-closed
//! 拒启动且错误指名 `VEIL_CONFIG_FILE`。未设置引导变量时零行为差异、不读盘。
//!
//! 防反向覆盖：每个文件键携带「env 显式名集合」（规范名 ∪ 全部兼容别名），
//! 集合内任一非空（trim 后）即 env 显式，跳过文件写入并记冲突 warn。
//!
//! 密钥门禁：文件声明 5 个密钥类键任一（`matrix_access_token`/
//! `observability_admin_token`/`veilctl_secret`/`veilctl_binary_hash`/
//! `value_sample_hmac_key`）时，Unix 下要求 `mode & 0o077 == 0`，否则拒启动；
//! env 覆盖不豁免（密钥文本已落盘）。

use {
    super::{
        command::{CommandConfig, CommandSection, validate_command},
        custom_file::CUSTOM_FILE_MAX_BYTES,
        targets::{LlmTargets, RawTargets, validate_targets},
        validate::config_error,
    },
    crate::error::Result,
    serde::{Deserialize, Deserializer, Serialize, de},
    serde_json::Value,
    std::{
        collections::{BTreeMap, HashMap},
        net::SocketAddr,
        path::{Path, PathBuf},
    },
};

/// 引导变量：唯一文件路径入口，仅从进程 env 读取，不作为文件内可声明键。
pub(crate) const BOOTSTRAP_VAR: &str = "VEIL_CONFIG_FILE";

/// `[llm.upstreams]` 端口表展平后的键前缀（`llm.upstreams.<port>`）。
const UPSTREAMS_KEY: &str = "llm.upstreams";
const UPSTREAMS_KEY_PREFIX: &str = "llm.upstreams.";

/// 文件专属结构键根（无 env 映射，不参与逐键合并）：内部结构由
/// `config::targets` 校验与结构性键锁步测试覆盖；工程参考 §1 与锁步测试须保持同步。
///
/// `server` 是键根级文件专属概念：`[server].bind` 属部署参数，不进 env 白名单
/// （design D1），故以根名登记、由 `FileLayerOutcome.server_bind` 单值进 `Config`。
pub(crate) const FILE_ONLY_KEYS: &[&str] = &["llm.targets", "command", "server"];

/// 命中文件专属结构键根：`key == root` 或以 `root.` 开头时返回该根，否则 `None`。
fn file_only_root(key: &str) -> Option<&'static str> {
    FILE_ONLY_KEYS.iter().copied().find(|root| {
        key == *root
            || key
                .strip_prefix(*root)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// `[audit].mode` 文件取值：空串/集合外取值在 `toml::from_str` 即失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileAuditMode {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "approve")]
    Approve,
}

/// `[storage].entry_mode` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEntryMode {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "credential-only")]
    CredentialOnly,
    #[serde(rename = "llm-only")]
    LlmOnly,
}

/// `[storage].auto_approve` 文件取值（映射为 env 令牌 `true/false/pending`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileAutoApprove {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "pending")]
    Pending,
}

/// `[pii_scope].mode` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FilePiiScopeMode {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "conversation")]
    Conversation,
}

/// `[keepass].backend` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileKeepassBackend {
    #[serde(rename = "real")]
    Real,
    #[serde(rename = "mock")]
    Mock,
}

/// 配置文件根：分节可选（缺省合法），顶层未知键拒启动。
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub auth: Option<AuthSection>,
    pub limits: Option<LimitsSection>,
    pub audit: Option<AuditSection>,
    pub storage: Option<StorageSection>,
    pub redaction: Option<RedactionSection>,
    pub pii_scope: Option<PiiScopeSection>,
    pub llm: Option<LlmSection>,
    pub keepass: Option<KeepassSection>,
    pub command: Option<CommandSection>,
    pub server: Option<ServerSection>,
}

/// `[server]`：监听地址（文件专属；`bind` 必须是 `IP:PORT` 字面量）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default, deserialize_with = "deserialize_bind")]
    pub bind: Option<SocketAddr>,
}

/// `bind` 专属反序列化：把类型/语法错误统一改写为指名 `server.bind` 的 fail-closed
/// 消息（`SocketAddr` 不接受主机名；缺端口/越界/非 IP 字面量一律拒启动）。
fn deserialize_bind<'de, D>(deserializer: D) -> std::result::Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)
        .map_err(|e| de::Error::custom(format!("server.bind 取值非法: {e}")))?;
    raw.map(|text| {
        text.trim().parse::<SocketAddr>().map_err(|e| {
            de::Error::custom(format!(
                "server.bind 取值非法: {text:?}（{e}）；须为 IP:PORT 字面量，如 \"127.0.0.1:8877\""
            ))
        })
    })
    .transpose()
}

/// `[auth]`：认证/服务身份（目录键见 `MAPPINGS`）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    pub homeserver: Option<String>,
    pub room_id: Option<String>,
    pub matrix_access_token: Option<String>,
    pub observability_admin_token: Option<String>,
    pub observability_disable: Option<bool>,
}

/// `[limits]`：限额域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub audit_hold_max_bytes: Option<i64>,
    pub nonstream_max_bytes: Option<i64>,
    pub sse_frame_hard_bytes: Option<i64>,
}

/// `[audit]`：审计域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    pub mode: Option<FileAuditMode>,
    pub timeout: Option<i64>,
    pub approval_whitelist: Option<Vec<String>>,
    pub policy_file: Option<String>,
}

/// `[storage]`：存储/入口域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub data_dir: Option<String>,
    pub db_dir: Option<String>,
    pub tpm_dir: Option<String>,
    pub caller_registry_path: Option<String>,
    pub veilctl_secret: Option<String>,
    pub veilctl_binary_hash: Option<String>,
    pub auto_approve: Option<FileAutoApprove>,
    pub entry_mode: Option<FileEntryMode>,
    pub credential_block_wait: Option<bool>,
}

/// `[redaction]`：脱敏域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionSection {
    pub enabled: Option<bool>,
    pub fuzzy_restore: Option<bool>,
    pub detection_hardening: Option<bool>,
    pub custom_rules_file: Option<String>,
    pub custom_patterns_file: Option<String>,
    pub custom_dict_file: Option<String>,
    pub value_sample_enabled: Option<bool>,
    pub value_sample_persist: Option<bool>,
    pub value_sample_hmac_key: Option<String>,
    pub placeholder_prompt: Option<bool>,
    pub placeholder_prompt_text: Option<String>,
    pub normalize_json_whitespace: Option<bool>,
}

/// `[pii_scope]`：PII 会话作用域域。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PiiScopeSection {
    pub mode: Option<FilePiiScopeMode>,
    pub ttl_secs: Option<i64>,
    pub max_conversations: Option<i64>,
    pub key_header: Option<String>,
    pub prev_id_max_entries: Option<i64>,
}

/// `[llm]`：LLM 网关域；`upstreams` 为端口表（端口字符串 → URL）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmSection {
    pub default_upstream: Option<String>,
    pub timeout_secs: Option<i64>,
    pub pool_max_idle_per_host: Option<i64>,
    pub pool_idle_timeout_secs: Option<i64>,
    pub upstreams: Option<BTreeMap<String, String>>,
    /// 文件专属 `[llm.targets]`：端口 / `default` 目标的上游头与参数覆盖
    /// （无 env 对应源，字段级校验见 `config::targets`）。
    pub targets: Option<RawTargets>,
}

/// `[keepass]`：KeePass 后端选型。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeepassSection {
    pub backend: Option<FileKeepassBackend>,
}

/// 映射目标：静态规范 env 名，或端口表（`[llm.upstreams]` 逐端口展开为
/// `LLM_<port>`，目标名按端口动态生成）。
enum MappingTarget {
    Env(&'static str),
    PortTable,
}

/// 规范化口径：标量按 serde 类型直译；`AutoApprove` 做 env 令牌重映射
/// （`allow→"true"`、`deny→"false"`、`pending→"pending"`）。
#[derive(Clone, Copy)]
enum Coercion {
    Plain,
    AutoApprove,
}

/// 封闭映射表条目：文件键 → 规范 env 目标 + env 显式名集合 + 规范化口径。
struct MappingDef {
    key: &'static str,
    target: MappingTarget,
    env_explicit_names: &'static [&'static str],
    coercion: Coercion,
}

const fn env(key: &'static str, name: &'static str, names: &'static [&'static str]) -> MappingDef {
    MappingDef {
        key,
        target: MappingTarget::Env(name),
        env_explicit_names: names,
        coercion: Coercion::Plain,
    }
}

/// 文件键封闭清单（`FileConfig` 可声明键集单一真源；键与目标 env 名逐项对齐
/// 工程参考 §1 与 `env_parse` 读取名）。
const MAPPINGS: &[MappingDef] = &[
    env("auth.homeserver", "HOMESERVER", &["HOMESERVER"]),
    env("auth.room_id", "ROOM_ID", &["ROOM_ID"]),
    env(
        "auth.matrix_access_token",
        "MATRIX_ACCESS_TOKEN",
        &["MATRIX_ACCESS_TOKEN"],
    ),
    env(
        "auth.observability_admin_token",
        "OBSERVABILITY_ADMIN_TOKEN",
        &["OBSERVABILITY_ADMIN_TOKEN"],
    ),
    env(
        "auth.observability_disable",
        "OBSERVABILITY_DISABLE",
        &["OBSERVABILITY_DISABLE"],
    ),
    env(
        "limits.audit_hold_max_bytes",
        "AUDIT_HOLD_MAX_BYTES",
        &["AUDIT_HOLD_MAX_BYTES"],
    ),
    env(
        "limits.nonstream_max_bytes",
        "NONSTREAM_MAX_BYTES",
        &["NONSTREAM_MAX_BYTES"],
    ),
    env(
        "limits.sse_frame_hard_bytes",
        "SSE_FRAME_HARD_BYTES",
        &["SSE_FRAME_HARD_BYTES"],
    ),
    env("audit.mode", "AUDIT_MODE", &["AUDIT_MODE"]),
    env("audit.timeout", "AUDIT_TIMEOUT", &["AUDIT_TIMEOUT"]),
    env(
        "audit.approval_whitelist",
        "APPROVAL_WHITELIST",
        &["APPROVAL_WHITELIST"],
    ),
    env(
        "audit.policy_file",
        "AUDIT_POLICY_FILE",
        &["AUDIT_POLICY_FILE"],
    ),
    env("storage.data_dir", "DATA_DIR", &["DATA_DIR"]),
    env("storage.db_dir", "DB_DIR", &["DB_DIR"]),
    env("storage.tpm_dir", "TPM_DIR", &["TPM_DIR"]),
    env(
        "storage.caller_registry_path",
        "CALLER_REGISTRY_PATH",
        &["CALLER_REGISTRY_PATH"],
    ),
    env(
        "storage.veilctl_secret",
        "VEILCTL_SECRET",
        &["VEILCTL_SECRET"],
    ),
    env(
        "storage.veilctl_binary_hash",
        "VEILCTL_BINARY_HASH",
        &["VEILCTL_BINARY_HASH"],
    ),
    MappingDef {
        key: "storage.auto_approve",
        target: MappingTarget::Env("AUTO_APPROVE"),
        env_explicit_names: &["AUTO_APPROVE"],
        coercion: Coercion::AutoApprove,
    },
    env(
        "storage.entry_mode",
        "VEIL_ENTRY_MODE",
        &["VEIL_ENTRY_MODE"],
    ),
    env(
        "storage.credential_block_wait",
        "CREDENTIAL_BLOCK_WAIT",
        &["CREDENTIAL_BLOCK_WAIT"],
    ),
    env(
        "redaction.enabled",
        "REDACTION_ENABLED",
        &["REDACTION_ENABLED", "PII_REDACTION_ENABLED"],
    ),
    env(
        "redaction.fuzzy_restore",
        "PII_FUZZY_RESTORE",
        &["PII_FUZZY_RESTORE"],
    ),
    env(
        "redaction.detection_hardening",
        "PII_DETECTION_HARDENING",
        &["PII_DETECTION_HARDENING"],
    ),
    env(
        "redaction.custom_rules_file",
        "PII_CUSTOM_RULES_FILE",
        &[
            "PII_CUSTOM_RULES_FILE",
            "PII_RULES_FILE",
            "PII_CUSTOM_RULES",
        ],
    ),
    env(
        "redaction.custom_patterns_file",
        "PII_CUSTOM_PATTERNS_FILE",
        &[
            "PII_CUSTOM_PATTERNS_FILE",
            "PII_CUSTOM_PATTERN_FILE",
            "PII_CUSTOM_PATTERNS",
        ],
    ),
    env(
        "redaction.custom_dict_file",
        "PII_CUSTOM_DICT_FILE",
        &[
            "PII_CUSTOM_DICT_FILE",
            "PII_DICT_FILE",
            "PII_SENSITIVE_DICT_FILE",
            "PII_SENSITIVE_NAMES_FILE",
            "PII_CUSTOM_DICT",
        ],
    ),
    env(
        "redaction.value_sample_enabled",
        "PII_VALUE_SAMPLE_ENABLED",
        &["PII_VALUE_SAMPLE_ENABLED"],
    ),
    env(
        "redaction.value_sample_persist",
        "PII_VALUE_SAMPLE_PERSIST",
        &["PII_VALUE_SAMPLE_PERSIST"],
    ),
    env(
        "redaction.value_sample_hmac_key",
        "PII_VALUE_SAMPLE_HMAC_KEY",
        &["PII_VALUE_SAMPLE_HMAC_KEY"],
    ),
    env(
        "redaction.placeholder_prompt",
        "PII_PLACEHOLDER_PROMPT",
        &["PII_PLACEHOLDER_PROMPT"],
    ),
    env(
        "redaction.placeholder_prompt_text",
        "PII_PLACEHOLDER_PROMPT_TEXT",
        &["PII_PLACEHOLDER_PROMPT_TEXT"],
    ),
    env(
        "redaction.normalize_json_whitespace",
        "NORMALIZE_JSON_WHITESPACE",
        &["NORMALIZE_JSON_WHITESPACE"],
    ),
    env("pii_scope.mode", "PII_SCOPE_MODE", &["PII_SCOPE_MODE"]),
    env(
        "pii_scope.ttl_secs",
        "PII_SCOPE_TTL_SECS",
        &["PII_SCOPE_TTL_SECS"],
    ),
    env(
        "pii_scope.max_conversations",
        "PII_SCOPE_MAX_CONVERSATIONS",
        &["PII_SCOPE_MAX_CONVERSATIONS"],
    ),
    env(
        "pii_scope.key_header",
        "PII_SCOPE_KEY_HEADER",
        &["PII_SCOPE_KEY_HEADER"],
    ),
    env(
        "pii_scope.prev_id_max_entries",
        "PII_PREV_ID_MAX_ENTRIES",
        &["PII_PREV_ID_MAX_ENTRIES"],
    ),
    env("llm.default_upstream", "LLM_UPSTREAM", &["LLM_UPSTREAM"]),
    env(
        "llm.timeout_secs",
        "HTTP_TIMEOUT_SECS",
        &["HTTP_TIMEOUT_SECS"],
    ),
    env(
        "llm.pool_max_idle_per_host",
        "HTTP_POOL_MAX_IDLE_PER_HOST",
        &["HTTP_POOL_MAX_IDLE_PER_HOST"],
    ),
    env(
        "llm.pool_idle_timeout_secs",
        "HTTP_POOL_IDLE_TIMEOUT_SECS",
        &["HTTP_POOL_IDLE_TIMEOUT_SECS"],
    ),
    MappingDef {
        key: UPSTREAMS_KEY,
        target: MappingTarget::PortTable,
        env_explicit_names: &[],
        coercion: Coercion::Plain,
    },
    env(
        "keepass.backend",
        "VEIL_KEEPASS_BACKEND",
        &["VEIL_KEEPASS_BACKEND"],
    ),
];

/// 一条已解析的文件声明：规范 env 目标 + 规范字符串 + env 显式名集合。
#[derive(Debug)]
struct ResolvedEntry {
    key: String,
    canonical_env: String,
    env_explicit_names: Vec<String>,
    value: String,
}

/// 文件层校验产物：文件专属结构分节（无 env 逐键映射）与逐键合并结果。
#[derive(Debug, Default)]
pub struct FileLayerOutcome {
    pub llm_targets: LlmTargets,
    pub command: CommandConfig,
    pub server_bind: Option<SocketAddr>,
}

/// 文件补充层入口：引导读取 → fail-closed 解析 → 密钥权限门禁 → 覆盖字段校验 →
/// 逐键合并；返回校验后的 `[llm.targets]` 覆盖与 `[command]` 配置（供装载路径
/// 并入 `Config`）。未设/空白 `VEIL_CONFIG_FILE` 时零副作用（不访问文件系统），
/// 返回缺省产物；任一失败拒绝启动。
pub fn apply_config_file(env: &mut HashMap<String, String>) -> Result<FileLayerOutcome> {
    let Some(path) = bootstrap_path(env) else {
        return Ok(FileLayerOutcome::default());
    };
    let cfg = load_file_config(&path)?;
    enforce_secret_permissions(&path, &cfg)?;
    let llm_targets = validate_targets(
        cfg.llm
            .as_ref()
            .and_then(|section| section.targets.as_ref()),
    )?;
    let command = validate_command(cfg.command.as_ref())?;
    let server_bind = cfg.server.as_ref().and_then(|section| section.bind);
    merge_entries(env, resolve_entries(&cfg)?);
    Ok(FileLayerOutcome {
        llm_targets,
        command,
        server_bind,
    })
}

/// 引导路径：`VEIL_CONFIG_FILE` trim 后非空才返回（空/缺失 = 不读盘）。
fn bootstrap_path(env: &HashMap<String, String>) -> Option<PathBuf> {
    env.get(BOOTSTRAP_VAR)
        .map(|raw| raw.trim())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
}

/// fail-closed 读取 + 反序列化：缺失/非普通文件/超 1MB/语法/未知键/类型/枚举
/// 一律拒启动；空文件合法（等价无文件覆盖，仅 warn）。
fn load_file_config(path: &Path) -> Result<FileConfig> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 指向的文件不存在或不可读 {}: {e}，拒绝启动",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 指向的不是普通文件 {}，拒绝启动",
                path.display()
            ),
        ));
    }
    let size = metadata.len();
    if size > CUSTOM_FILE_MAX_BYTES {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 文件 {} 超过 1MB 上限（{size} 字节），拒绝启动",
                path.display()
            ),
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 文件读取失败 {}: {e}，拒绝启动",
                path.display()
            ),
        )
    })?;
    if text.trim().is_empty() {
        tracing::warn!(
            "{BOOTSTRAP_VAR} 文件 {} 为空，跳过文件层（等价无文件覆盖）",
            path.display()
        );
        return Ok(FileConfig::default());
    }
    toml::from_str::<FileConfig>(&text).map_err(|e| {
        config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 文件 {} TOML 解析失败: {e}，拒绝启动",
                path.display()
            ),
        )
    })
}

/// 把 `FileConfig` 的 serde 值展平为「点分键 → 叶子值」；`None`（null）跳过。
fn collect_leaves(value: Value, path: &str, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (field, child) in map {
                let child_path = if path.is_empty() {
                    field
                } else {
                    format!("{path}.{field}")
                };
                collect_leaves(child, &child_path, out);
            }
        }
        Value::Null => {}
        leaf => out.push((path.to_string(), leaf)),
    }
}

/// 逐声明键解析为规范 env 名 + 规范字符串；端口表逐端口展开为 `LLM_<port>`，
/// 端口不可 parse 为 `u16` 即拒启动；任一键未登记映射表按内部错误 fail-closed。
fn resolve_entries(cfg: &FileConfig) -> Result<Vec<ResolvedEntry>> {
    let root = serde_json::to_value(cfg).map_err(|e| {
        config_error(
            BOOTSTRAP_VAR,
            &format!("配置文件内部序列化失败: {e}，拒绝启动"),
        )
    })?;
    let mut leaves = Vec::new();
    collect_leaves(root, "", &mut leaves);
    let mut out = Vec::with_capacity(leaves.len());
    for (key, leaf) in leaves {
        // 文件专属结构键（如 `[llm.targets]`）：无 env 映射，经 `validate_targets`
        // 进入 `Config` 字段，跳过逐键合并与未登记映射表判定。
        if file_only_root(&key).is_some() {
            continue;
        }
        if let Some(port_raw) = key.strip_prefix(UPSTREAMS_KEY_PREFIX) {
            let port = port_raw.parse::<u16>().map_err(|_| {
                config_error(
                    BOOTSTRAP_VAR,
                    &format!(
                        "[{UPSTREAMS_KEY}] 端口键 {port_raw:?} 不是合法 u16 端口（1-65535），拒绝启动"
                    ),
                )
            })?;
            let canonical = format!("LLM_{port}");
            let value = coerce_value(&key, &leaf, Coercion::Plain)?;
            out.push(ResolvedEntry {
                key,
                canonical_env: canonical.clone(),
                env_explicit_names: vec![canonical],
                value,
            });
            continue;
        }
        let mapping = MAPPINGS.iter().find(|m| m.key == key).ok_or_else(|| {
            config_error(
                BOOTSTRAP_VAR,
                &format!("文件键 {key} 未登记映射表（内部错误），拒绝启动"),
            )
        })?;
        let canonical_env = match mapping.target {
            MappingTarget::Env(name) => name,
            MappingTarget::PortTable => {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("文件键 {key} 端口表形态非法，拒绝启动"),
                ));
            }
        };
        let value = coerce_value(&key, &leaf, mapping.coercion)?;
        out.push(ResolvedEntry {
            key,
            canonical_env: canonical_env.to_string(),
            env_explicit_names: mapping
                .env_explicit_names
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            value,
        });
    }
    Ok(out)
}

/// 规范化：bool→`"1"/"0"`、整数→十进制、字符串原样（`AutoApprove` 重映射为
/// env 令牌）、字符串数组→逗号连接。
fn coerce_value(key: &str, value: &Value, coercion: Coercion) -> Result<String> {
    match value {
        Value::Bool(raw) => Ok(if *raw { "1" } else { "0" }.to_string()),
        Value::Number(raw) => Ok(raw.to_string()),
        Value::String(raw) => match coercion {
            Coercion::Plain => Ok(raw.clone()),
            Coercion::AutoApprove => match raw.as_str() {
                "allow" => Ok("true".to_string()),
                "deny" => Ok("false".to_string()),
                "pending" => Ok("pending".to_string()),
                other => Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!("文件键 {key} 取值 {other:?} 非法（枚举反序列化应已拒绝），拒绝启动"),
                )),
            },
        },
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => parts.push(s.clone()),
                    _ => {
                        return Err(config_error(
                            BOOTSTRAP_VAR,
                            &format!("文件键 {key} 列表元素须为字符串，拒绝启动"),
                        ));
                    }
                }
            }
            Ok(parts.join(","))
        }
        _ => Err(config_error(
            BOOTSTRAP_VAR,
            &format!("文件键 {key} 类型不受支持（对象/空值），拒绝启动"),
        )),
    }
}

/// 逐键合并：env 显式名集合内任一非空（trim 后）即 env 胜、跳过文件写入并记
/// 一条指名概念的冲突 warn。
fn merge_entries(env: &mut HashMap<String, String>, entries: Vec<ResolvedEntry>) {
    for entry in entries {
        let explicit_name = entry.env_explicit_names.iter().find(|name| {
            env.get(name.as_str())
                .is_some_and(|raw| !raw.trim().is_empty())
        });
        if let Some(name) = explicit_name {
            tracing::warn!(
                "配置文件键 {} 与 env 显式变量 {name} 冲突，以 env 为准（env 恒胜）",
                entry.key
            );
            continue;
        }
        env.insert(entry.canonical_env, entry.value);
    }
}

/// 文件是否声明任一密钥类键（5 个概念，首项两键同概念只计一次）。
fn declares_secret_keys(cfg: &FileConfig) -> bool {
    let auth = cfg.auth.as_ref().is_some_and(|section| {
        section.matrix_access_token.is_some() || section.observability_admin_token.is_some()
    });
    let storage = cfg.storage.as_ref().is_some_and(|section| {
        section.veilctl_secret.is_some() || section.veilctl_binary_hash.is_some()
    });
    let redaction = cfg
        .redaction
        .as_ref()
        .is_some_and(|section| section.value_sample_hmac_key.is_some());
    auth || storage || redaction
}

/// Unix：声明密钥类键的文件须满足 `mode & 0o077 == 0`（group/other 读写执行位
/// 全无），否则拒启动并给 `chmod 600` 指引；env 覆盖不豁免（密钥已落盘）。
#[cfg(unix)]
fn enforce_secret_permissions(path: &Path, cfg: &FileConfig) -> Result<()> {
    if !declares_secret_keys(cfg) {
        return Ok(());
    }
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(|e| {
            config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{BOOTSTRAP_VAR} 文件元数据读取失败 {}: {e}，拒绝启动",
                    path.display()
                ),
            )
        })?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{BOOTSTRAP_VAR} 文件 {} 声明了密钥类键但权限过宽（mode {:03o}，要求 mode & 0o077 == 0）：\
                请 chmod 600 {} 或改用 env 注入；env 覆盖不豁免该门禁（密钥已落盘）",
                path.display(),
                mode & 0o777,
                path.display()
            ),
        ));
    }
    Ok(())
}

/// 非 Unix：无 POSIX 权限位语义，该门禁不适用（文档声明，不静默记为通过）。
#[cfg(not(unix))]
fn enforce_secret_permissions(_path: &Path, _cfg: &FileConfig) -> Result<()> { Ok(()) }

#[cfg(test)]
mod tests;
