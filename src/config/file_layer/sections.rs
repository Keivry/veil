//! 文件层各分节 schema（自 `file_layer/mod.rs` 拆出，导出路径不变）。
//!
//! 分节按迁移后的语义布局组织：`server` / `admin` / `matrix` / `audit` /
//! `credential` / `request_log` / `storage` / `llm` / `pii_scope` / `redaction` /
//! `command`。每个分节 `deny_unknown_fields`；取值受限的分节用封闭枚举钉死
//! （枚举空串/集合外取值在反序列化阶段即失败）。旧分节（`auth` / `limits` /
//! `keepass`）与旧键名已删除，现按未知键/非法枚举值 fail-closed 拒启动。
//!
//! 数值宽度：时长/字节/天数类一律 `u64`（负值在反序列化阶段即失败），
//! 计数类（`max_conversations` / `prev_id_max_entries` / `pool_max_idle_per_host`）
//! 为 `usize`（容器容量语义，非时长/字节预算）。

use {
    super::storage::StorageSection,
    crate::config::{command::CommandSection, targets::RawTargets},
    serde::{Deserialize, Deserializer, Serialize, de},
    std::{collections::BTreeMap, net::SocketAddr},
};

/// `[audit].mode` 文件取值：空串/集合外取值在 `toml` 解析即失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileAuditMode {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "block")]
    Block,
    #[serde(rename = "approve")]
    Approve,
}

/// `[pii_scope].mode` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FilePiiScopeMode {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "conversation")]
    Conversation,
}

/// `[credential].vault_backend` 文件取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileKeepassBackend {
    #[serde(rename = "real")]
    Real,
    #[serde(rename = "mock")]
    Mock,
}

/// `[credential].default_decision` 文件取值（映射为 env 令牌
/// `allow→true`、`deny→false`、`pending→pending`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileAutoApprove {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
    #[serde(rename = "pending")]
    Pending,
}

/// `[server].surface_mode` 文件取值：只接受 `full` / `llm_only`。
///
/// 0.1.x 的三个历史拼写（连字符与下划线两种写法）已随别名层在 0.2.0 移除，
/// 现按枚举反序列化错误拒启动。序列化只产出规范拼写。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileSurfaceMode {
    #[serde(rename = "full")]
    Full,
    #[serde(rename = "llm_only")]
    LlmOnly,
}

/// `[server]`：监听地址与暴露面模式。
///
/// `listen_addr` 为文件专属部署参数（须 `IP:PORT` 字面量）；
/// `surface_mode` 有 env 映射（`VEIL_ENTRY_MODE`），经封闭映射表逐键并入。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    #[serde(default, deserialize_with = "deserialize_listen_addr")]
    pub listen_addr: Option<SocketAddr>,
    pub surface_mode: Option<FileSurfaceMode>,
}

/// `listen_addr` 专属反序列化：把类型/语法错误统一改写为指名 `server.listen_addr`
/// 的 fail-closed 消息（`SocketAddr` 不接受主机名；缺端口/越界/非 IP 字面量一律拒启动）。
fn deserialize_listen_addr<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(deserializer)
        .map_err(|e| de::Error::custom(format!("server.listen_addr 取值非法: {e}")))?;
    raw.map(|text| {
        text.trim().parse::<SocketAddr>().map_err(|e| {
            de::Error::custom(format!(
                "server.listen_addr 取值非法: {text:?}（{e}）；\
                 须为 IP:PORT 字面量，如 \"127.0.0.1:8877\""
            ))
        })
    })
    .transpose()
}

/// `[admin]`：管理面正向开关与鉴权 token。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    /// `true` 才挂载 `/_admin*`；缺省 `true`（极性与旧 `auth.observability_disable` 相反）。
    pub enabled: Option<bool>,
    /// `/_admin` 鉴权 token（密钥类）；空则管理面不启用。
    pub token: Option<String>,
}

/// `[matrix]`：Matrix 部署参数（空则审批/同步关闭）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MatrixSection {
    pub homeserver: Option<String>,
    pub room_id: Option<String>,
    pub access_token: Option<String>,
}

/// `[audit]`：审计模式、超时与 hold 暂存双维度上限。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    pub mode: Option<FileAuditMode>,
    pub timeout_secs: Option<u64>,
    pub approval_whitelist: Option<Vec<String>>,
    pub policy_file: Option<String>,
    /// 审计 hold 暂存**载荷字节**上限（与帧数维度相互独立）。
    pub hold_max_bytes: Option<u64>,
    /// 审计 hold 暂存 **tool 帧数**上限（不得由字节预算隐式推导）。
    pub hold_max_frames: Option<u64>,
}

/// `[credential]`：凭据域（缺省裁决、后端、审批与授权窗口）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSection {
    pub default_decision: Option<FileAutoApprove>,
    pub vault_backend: Option<FileKeepassBackend>,
    pub approval: Option<CredentialApprovalSection>,
    pub authorization: Option<CredentialAuthorizationSection>,
}

/// `[credential.approval]`。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialApprovalSection {
    /// `true` 时取用阻塞至审批终态（超时口径固定 300s）。
    pub block_wait: Option<bool>,
}

/// `[credential.authorization]`。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAuthorizationSection {
    /// 授权窗口秒数；`0` = 无期限（归一为 `None`）。
    pub ttl_secs: Option<u64>,
}

/// `[request_log]`：逐请求记录开关与保留天数。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLogSection {
    pub enabled: Option<bool>,
    /// 保留天数；`0` = 不清理。
    pub retention_days: Option<u64>,
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
    /// 会话条目空闲 TTL 秒；须 ≥ 1（`0` 拒启动）。
    pub ttl_secs: Option<u64>,
    pub max_conversations: Option<usize>,
    pub key_header: Option<String>,
    pub prev_id_max_entries: Option<usize>,
}

/// `[llm]`：LLM 网关域；`upstreams` 为端口表（端口字符串 → URL）。
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmSection {
    pub default_upstream: Option<String>,
    pub timeout_secs: Option<u64>,
    /// 每上游空闲连接上限（`usize`，容器容量语义）。
    pub pool_max_idle_per_host: Option<usize>,
    pub pool_idle_timeout_secs: Option<u64>,
    /// 非流对话响应体上限（软限，严格 `len >` 触发 502）。
    pub nonstream_max_bytes: Option<u64>,
    /// SSE 单帧/单行硬上限（超限 fail-closed 并按协议合成终止帧）。
    pub sse_frame_hard_bytes: Option<u64>,
    pub upstreams: Option<BTreeMap<String, String>>,
    /// 文件专属 `[llm.targets]`：端口 / `default` 目标的上游头与参数覆盖
    /// （无 env 对应源，字段级校验见 `config::targets`）。
    pub targets: Option<RawTargets>,
}

/// 文件层可声明的全部分节（分节缺省合法，顶层未知键拒启动）。
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub server: Option<ServerSection>,
    pub admin: Option<AdminSection>,
    pub matrix: Option<MatrixSection>,
    pub audit: Option<AuditSection>,
    pub credential: Option<CredentialSection>,
    pub request_log: Option<RequestLogSection>,
    pub storage: Option<StorageSection>,
    pub llm: Option<LlmSection>,
    pub pii_scope: Option<PiiScopeSection>,
    pub redaction: Option<RedactionSection>,
    pub command: Option<CommandSection>,
}
