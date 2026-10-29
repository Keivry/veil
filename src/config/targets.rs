//! `[llm.targets]` 上游覆盖：文件专属 schema（design D1/D2）与 fail-closed 校验。
//!
//! 目标键：可解析为 `u16` 的入口端口字符串，或指代缺省上游的保留键 `default`。
//! 每个目标仅接受 `headers`（出站头表，值支持 `$` 插值或静态）、`params`（按协议
//! 分表的请求体参数覆盖）、`override`（冲突策略开关）、`user_agent`（出站 UA
//! 恒胜覆盖值）与 `drop_headers`（显式剔除的出站头名）；全层
//! `deny_unknown_fields`。强类型产物（[`LlmTargets`]）并入
//! `Config::llm_targets`，由装载路径在 env / 文件合并后做孤儿目标与 `default`
//! 依赖校验（[`validate_target_upstreams`]）。本模块无 env 对应源：未声明时为空表，
//! 逐项零行为变化（覆盖 schema 与目标键 / 目标解析与上游选路同源）。

use {
    super::{file_layer::BOOTSTRAP_VAR, validate::config_error},
    crate::error::{Result, VeilError},
    axum::http::{HeaderMap, HeaderName, HeaderValue, header},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::collections::{BTreeMap, HashMap},
};

/// 目标键：入口端口，或指代缺省上游的保留键 `default`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKey {
    Port(u16),
    Default,
}

impl TargetKey {
    /// TOML 键面字面量（错误消息用）：端口带引号，`default` 不带。
    pub fn literal(self) -> String {
        match self {
            Self::Port(port) => format!("\"{port}\""),
            Self::Default => "default".to_string(),
        }
    }

    /// 完整键路径前缀（如 `llm.targets."8878"`），错误消息指名用。
    pub fn path_prefix(self) -> String { format!("llm.targets.{}", self.literal()) }
}

/// `[llm.targets]` 分节原始 schema：键为 TOML 字符串（校验后转 [`TargetKey`]）。
pub type RawTargets = BTreeMap<String, TargetSection>;

/// 单个目标声明：仅 `headers` / `params` / `override_existing` / `user_agent` /
/// `drop_headers`，未知键（含错误嵌套层级）拒启动。
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSection {
    /// 出站请求头名 → 值（合法性与硬拒清单在 [`validate_targets`] 校验）。
    pub headers: Option<BTreeMap<String, String>>,
    /// 协议 → 三段参数覆盖（键集恰为 `chat` / `anthropic` / `responses`）。
    pub params: Option<TargetParams>,
    /// 冲突策略开关（文件键 `override_existing`；缺省 `true` = 恒胜，
    /// `false` = 合并模式，仅补缺）。键名与 [`UpstreamOverrides::override_existing`]
    /// 字段一致，故与协议段表 `params.<proto>.override` 不再碰撞。
    pub override_existing: Option<bool>,
    /// 出站 `User-Agent` 恒胜覆盖值（与 `r#override` 开关正交；值校验与
    /// `headers."user-agent"` 互斥规则见 [`validate_target`]）。
    pub user_agent: Option<String>,
    /// 显式剔除的出站头名列表（装配期在内部头/逐跳头过滤之后、配置头注入之前
    /// 逐名删除，两态均生效；合法性与冲突规则见 [`validate_drop_headers`]）。
    pub drop_headers: Option<Vec<String>>,
}

/// `params` 协议子表：协议键集合受限，其余键拒启动。
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetParams {
    pub chat: Option<ParamSegments>,
    pub anthropic: Option<ParamSegments>,
    pub responses: Option<ParamSegments>,
}

/// 单协议三段覆盖：`default`（缺则补）/ `override`（恒写）/ `drop`（删顶层键）。
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSegments {
    /// 键缺失才注入的默认值表。
    pub default: Option<BTreeMap<String, Value>>,
    /// 恒写入（存在则覆盖）的值表。
    pub r#override: Option<BTreeMap<String, Value>>,
    /// 删除的顶层键（键不存在时静默忽略）。
    pub drop: Option<Vec<String>>,
}

/// 校验后的目标覆盖表：`Config::llm_targets` 的载荷类型。
pub type LlmTargets = BTreeMap<TargetKey, UpstreamOverrides>;

/// 单协议三段覆盖的强类型形态（值为配置原文，不参与脱敏替换）。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParamOverrides {
    pub default: BTreeMap<String, Value>,
    pub r#override: BTreeMap<String, Value>,
    pub drop: Vec<String>,
}

/// 单个目标的上游覆盖：静态出站头 + 按协议分表的参数覆盖 + 冲突策略 + UA 恒胜覆盖。
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamOverrides {
    /// 加载期已完成合法性与大小写归一唯一性校验（`HeaderMap` 名字唯一）；
    /// 值为静态或预编译插值模板（[`HeaderValueSpec`]）。
    pub headers: HeaderMap<HeaderValueSpec>,
    /// 协议 → 三段覆盖；未声明的协议不在表中。
    pub params: BTreeMap<ParamProtocol, ParamOverrides>,
    /// 冲突策略：`true` = 配置恒胜（缺省）；`false` = 合并模式（仅补缺）。
    pub override_existing: bool,
    /// 出站 `User-Agent` 恒胜覆盖值（独立于 `override_existing` 两态；
    /// `None` 时 UA 装配逐项零变化）。
    pub user_agent: Option<HeaderValue>,
    /// 显式剔除的出站头名（装配期在内部头/逐跳头过滤之后、配置头注入之前删除，
    /// 两态均生效）；空表 = 未声明。已过加载期合法性与冲突校验，故装配期不再判定。
    pub drop_headers: Vec<HeaderName>,
}

impl Default for UpstreamOverrides {
    /// 缺省即恒胜，与 schema `override_existing` 缺省 `true` 对齐；手写不派生，
    /// 避免 `bool` 的 `false` 派生默认值把空载荷误置为合并模式。
    fn default() -> Self {
        Self {
            // 泛型 `HeaderMap<HeaderValueSpec>` 无 `new()`（仅 `HeaderValue` 特化提供），以
            // `with_capacity(0)` 构造空表。
            headers: HeaderMap::<HeaderValueSpec>::with_capacity(0),
            params: BTreeMap::new(),
            override_existing: true,
            user_agent: None,
            drop_headers: Vec::new(),
        }
    }
}

/// 头值动态插值的单片段（`parse_header_value_spec` 预编译产物）。
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValueSegment {
    /// 字面段（`$$` 转义产生的 `$` 并入相邻字面）。
    Literal(String),
    /// `$conversation`：会话键头（`PII_SCOPE_KEY_HEADER` 所指入站头）的原始值。
    Conversation,
    /// `$request-id`：入站 `x-request-id` 的首个值。
    RequestId,
    /// `$header(<入站头名>)`：镜像指定入站头的首个值（匹配大小写不敏感）。
    Mirror(HeaderName),
}

/// 目标 `headers` 的单值表示：无 `$` 走静态快路径；含 `$` 预编译为模板段列表，
/// 非法插值形态在加载期即拒启动（fail-closed）。
#[derive(Debug, Clone, PartialEq)]
pub enum HeaderValueSpec {
    /// 静态值（行为与本 change 前逐项一致）。
    Static(HeaderValue),
    /// 插值模板（段序即书写序；字面段已合并并通过头值语义校验）。
    Template(Vec<HeaderValueSegment>),
}

impl From<HeaderValue> for HeaderValueSpec {
    /// 静态值便捷转换（既有构造点适配用）。
    fn from(value: HeaderValue) -> Self { Self::Static(value) }
}

/// 参数注入的协议维度：恰为 `chat` / `anthropic` / `responses`（无跨协议映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamProtocol {
    Chat,
    Anthropic,
    Responses,
}

impl ParamProtocol {
    /// 协议子表名（错误消息与参数注入匹配共用）。
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Anthropic => "anthropic",
            Self::Responses => "responses",
        }
    }
}

/// 保留键：在 `default` / `override` / `drop` 任一段出现即拒启动
/// （保护路由、SSE 泵、占位符注入与用量计费口径）。
const RESERVED_PARAM_KEYS: [&str; 7] = [
    "model",
    "stream",
    "messages",
    "input",
    "instructions",
    "system",
    "stream_options",
];

/// 硬拒头：保留/长度与编码头（出站装配由网关统一决定；`accept-encoding` 由装配期
/// 剔除以保证 reqwest 仅声明支持集，配置重注入会破坏「上游只回可解码编码」不变量）。
const RESERVED_HEADERS: [&str; 5] = [
    "host",
    "content-length",
    "content-encoding",
    "accept-encoding",
    "transfer-encoding",
];

/// 硬拒头：逐跳头（RFC 9110 §7.6.1，不得配置注入）。
const HOP_BY_HOP_HEADERS: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
];

/// 硬拒头：鉴权/身份类（本轮不代持密钥，见 design D5）。
const AUTH_HEADERS: [&str; 4] = ["authorization", "x-api-key", "api-key", "cookie"];

/// 内部头前缀：`x-veil-*` 一律禁止配置注入。
const VEIL_INTERNAL_PREFIX: &str = "x-veil-";

/// 校验 `[llm.targets]` 原始 schema 并转换为强类型目标表；任一违例 fail-closed。
///
/// 校验面：目标键（端口或 `default`，归一重复拒启动）、头名/头值语义、硬拒清单、
/// 归一重复头、保留键（三段全覆盖）；未知键与类型错误在 TOML 反序列化层拒绝。
pub fn validate_targets(raw: Option<&RawTargets>) -> Result<LlmTargets> {
    let Some(raw) = raw else {
        return Ok(LlmTargets::new());
    };
    let mut targets = LlmTargets::new();
    let mut seen: BTreeMap<TargetKey, String> = BTreeMap::new();
    for (raw_key, section) in raw {
        let key = parse_target_key(raw_key)?;
        if let Some(previous) = seen.insert(key, raw_key.clone()) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "llm.targets 目标键 {previous:?} 与 {raw_key:?} 归一后重复（同指 {}），拒绝启动",
                    key.literal()
                ),
            ));
        }
        targets.insert(key, validate_target(key, section)?);
    }
    Ok(targets)
}

/// 孤儿目标与 `default` 依赖校验：env / 文件合并完成后执行，fail-closed。
pub fn validate_target_upstreams(
    targets: &LlmTargets,
    upstreams: &HashMap<u16, String>,
    default_upstream: Option<&str>,
) -> Result<()> {
    for key in targets.keys() {
        match key {
            TargetKey::Port(port) if !upstreams.contains_key(port) => {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    &format!(
                        "llm.targets.\"{port}\" 为孤儿目标：LLM_{port} 与 [llm.upstreams] 均无对应上游，拒绝启动"
                    ),
                ));
            }
            TargetKey::Default if default_upstream.is_none() => {
                return Err(config_error(
                    BOOTSTRAP_VAR,
                    "llm.targets.default 需要缺省上游：[llm].default_upstream 未定义\
                     （LLM_UPSTREAM 已不再从进程 env 读取，仅认文件键），拒绝启动",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// 目标键解析：保留键 `default` 或可解析为 `u16` 的端口字符串，其余指名拒启动。
fn parse_target_key(raw: &str) -> Result<TargetKey> {
    if raw == "default" {
        return Ok(TargetKey::Default);
    }
    raw.parse::<u16>().map(TargetKey::Port).map_err(|_| {
        config_error(
            BOOTSTRAP_VAR,
            &format!(
                "llm.targets 目标键 {raw:?} 非法：须为可解析为 u16 的入口端口字符串或保留键 default，拒绝启动"
            ),
        )
    })
}

/// 单目标全量校验：头表 + 协议参数表 + 冲突策略 + UA 恒胜覆盖 + 显式剔除头。
fn validate_target(key: TargetKey, section: &TargetSection) -> Result<UpstreamOverrides> {
    let headers = validate_headers(key, section.headers.as_ref())?;
    Ok(UpstreamOverrides {
        user_agent: validate_user_agent(key, section.user_agent.as_deref(), &headers)?,
        drop_headers: validate_drop_headers(key, section.drop_headers.as_deref(), &headers)?,
        headers,
        params: validate_params(key, section.params.as_ref())?,
        override_existing: section.override_existing.unwrap_or(true),
    })
}

/// `drop_headers` 校验（错误消息指名完整键路径）：头名须合法、归一后唯一、
/// 不与同目标 `headers` 键重复（注入与剔除同名即歧义）、不属 `x-veil-*` 内部命名空间
/// （该命名空间在装配期恒被剔除，配置无意义）。空数组合法，等同未声明。
///
/// 允许剔除 `user-agent`：与 `user_agent` 字段并存时不报错——装配期剔除先于配置头
/// 注入与 UA 字段写入，后者恒胜（与 `override_existing` 无关）。
fn validate_drop_headers(
    key: TargetKey,
    raw: Option<&[String]>,
    headers: &HeaderMap<HeaderValueSpec>,
) -> Result<Vec<HeaderName>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let prefix = key.path_prefix();
    let path = format!("{prefix}.drop_headers");
    let mut dropped: Vec<HeaderName> = Vec::with_capacity(raw.len());
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for name in raw {
        let parsed_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 元素 {name:?} 头名非法（不符合 http 头名语义），拒绝启动"),
            )
        })?;
        let normalized = parsed_name.as_str().to_string();
        if let Some(previous) = seen.get(&normalized) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 元素 {name:?} 与 {previous:?} 大小写归一后重复，拒绝启动"),
            ));
        }
        if normalized.starts_with(VEIL_INTERNAL_PREFIX) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 元素 {name:?} 属 x-veil-* 内部命名空间（装配期恒被剔除，配置无意义），拒绝启动"
                ),
            ));
        }
        if headers.contains_key(&parsed_name) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!(
                    "{path} 元素 {name:?} 与 {prefix}.headers 同名（同一目标既注入又剔除即歧义），拒绝启动"
                ),
            ));
        }
        seen.insert(normalized, name.clone());
        dropped.push(parsed_name);
    }
    Ok(dropped)
}

/// `user_agent` 值校验与互斥判定：空/全空白/含首尾空白拒启动；与 `headers` 归一后
/// `user-agent` 并存拒启动（字段无条件恒胜、表受 `override` 开关治理，并存即歧义）。
fn validate_user_agent(
    key: TargetKey,
    raw: Option<&str>,
    headers: &HeaderMap<HeaderValueSpec>,
) -> Result<Option<HeaderValue>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let prefix = key.path_prefix();
    let path = format!("{prefix}.user_agent");
    if raw.trim().is_empty() {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{path} 为空或全空白（须为合法 HTTP 头值），拒绝启动"),
        ));
    }
    if raw.trim() != raw {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{path} 含首尾空白（须为精确头值，不静默修剪），拒绝启动"),
        ));
    }
    if headers.contains_key(header::USER_AGENT) {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!(
                "{path} 与 {prefix}.headers.\"user-agent\" 为同一目标的两条 User-Agent 覆盖通道（字段恒胜与表语义并存歧义），拒绝启动"
            ),
        ));
    }
    if raw.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
        return Err(config_error(
            BOOTSTRAP_VAR,
            &format!("{path} 含 CR/LF 等非法字节，拒绝启动"),
        ));
    }
    HeaderValue::from_str(raw).map(Some).map_err(|_| {
        config_error(
            BOOTSTRAP_VAR,
            &format!("{path} 值非法（不符合 http 头值语义），拒绝启动"),
        )
    })
}

/// 头表校验：`http::HeaderName` / `HeaderValue` 语义、硬拒清单、归一重复；
/// 值经 [`parse_header_value_spec`] 产出静态或预编译模板。
fn validate_headers(
    key: TargetKey,
    raw: Option<&BTreeMap<String, String>>,
) -> Result<HeaderMap<HeaderValueSpec>> {
    let Some(raw) = raw else {
        return Ok(HeaderMap::<HeaderValueSpec>::with_capacity(0));
    };
    let prefix = key.path_prefix();
    // 泛型 `HeaderMap<HeaderValueSpec>` 无 `new()`（仅 `HeaderValue` 特化提供），以
    // `with_capacity(0)` 构造空表。
    let mut headers: HeaderMap<HeaderValueSpec> = HeaderMap::with_capacity(0);
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in raw {
        let path = format!("{prefix}.headers.{name}");
        let parsed_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 头名非法（不符合 http 头名语义），拒绝启动"),
            )
        })?;
        let normalized = parsed_name.as_str().to_string();
        if let Some(previous) = seen.get(&normalized) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 与 {prefix}.headers.{previous} 大小写归一后重复，拒绝启动"),
            ));
        }
        if let Some(reason) = denied_header_reason(&normalized) {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 属硬拒清单（{reason}），禁止配置注入，拒绝启动"),
            ));
        }
        if value.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(config_error(
                BOOTSTRAP_VAR,
                &format!("{path} 头值含 CR/LF 等非法字节，拒绝启动"),
            ));
        }
        let parsed_value = parse_header_value_spec(key, name, value)?;
        seen.insert(normalized, name.clone());
        headers.insert(parsed_name, parsed_value);
    }
    Ok(headers)
}

/// `$request-id` 插值的入站来源头名（装配期取首个值）。
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// 头值解析：无 `$` → `Static` 快路径；含 `$` → 预编译 `Template`。
///
/// 拒启动形态（错误消息指名完整键路径）：未知变量（含大小写不符的 `$Conversation`）、
/// 结尾孤立 `$`、未闭合/嵌套 `$header(`、空 `$header()`、非法镜像头名、
/// 含 `$` 的镜像名、`x-veil-*` 内部命名空间镜像、字面段含非法字节。
fn parse_header_value_spec(key: TargetKey, name: &str, value: &str) -> Result<HeaderValueSpec> {
    let invalid = |reason: String| {
        config_error(
            BOOTSTRAP_VAR,
            &format!("{}.headers.{name} {reason}，拒绝启动", key.path_prefix()),
        )
    };
    if !value.contains('$') {
        return HeaderValue::from_str(value)
            .map(HeaderValueSpec::Static)
            .map_err(|_| invalid("头值非法（不符合 http 头值语义）".to_string()));
    }
    let mut segments = Vec::new();
    let mut literal = String::new();
    let mut rest = value;
    while let Some(index) = rest.find('$') {
        literal.push_str(&rest[..index]);
        let after = &rest[index + 1..];
        if let Some(after) = after.strip_prefix('$') {
            literal.push('$');
            rest = after;
            continue;
        }
        if after.is_empty() {
            return Err(invalid("结尾孤立 `$`（字面 `$` 须写作 `$$`）".to_string()));
        }
        if let Some(after) = strip_interpolation_keyword(after, "conversation") {
            flush_literal(&mut literal, &mut segments).map_err(invalid)?;
            segments.push(HeaderValueSegment::Conversation);
            rest = after;
            continue;
        }
        if let Some(after) = strip_interpolation_keyword(after, "request-id") {
            flush_literal(&mut literal, &mut segments).map_err(invalid)?;
            segments.push(HeaderValueSegment::RequestId);
            rest = after;
            continue;
        }
        if let Some(head) = after.strip_prefix("header(") {
            let Some(close) = head.find(')') else {
                return Err(invalid("`$header(` 未闭合（缺少 `)`）".to_string()));
            };
            let mirror = parse_mirror_name(&head[..close]).map_err(invalid)?;
            flush_literal(&mut literal, &mut segments).map_err(invalid)?;
            segments.push(HeaderValueSegment::Mirror(mirror));
            rest = &head[close + 1..];
            continue;
        }
        return Err(invalid(unknown_interpolation_reason(after)));
    }
    literal.push_str(rest);
    flush_literal(&mut literal, &mut segments).map_err(invalid)?;
    Ok(HeaderValueSpec::Template(segments))
}

/// `$<关键字>` 精确匹配：关键字后须为词边界（下一字符非 `A-Za-z0-9_`），
/// 防 `$conversationx` 被前缀误匹配；变量名大小写敏感（`$Conversation` 不匹配即未知形态）。
fn strip_interpolation_keyword<'a>(after: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = after.strip_prefix(keyword)?;
    match rest.chars().next() {
        Some(ch) if ch.is_ascii_alphanumeric() || ch == '_' => None,
        _ => Some(rest),
    }
}

/// `$header(<名>)` 头名解析：空名、嵌套（名内出现 `(`）、含 `$`、非法头名、`x-veil-*`
/// 内部命名空间均返回指名理由（调用方补完整键路径）。
fn parse_mirror_name(raw: &str) -> std::result::Result<HeaderName, String> {
    if raw.is_empty() {
        return Err("`$header()` 头名为空（须给出合法入站头名）".to_string());
    }
    if raw.contains('(') {
        return Err(format!(
            "`$header({raw})` 嵌套（未闭合/嵌套的 `$header(` 拒启动）"
        ));
    }
    if raw.contains('$') {
        return Err(format!(
            "`$header({raw})` 镜像名含 `$`（禁止镜像含 `$` 的头名，防与插值语法混淆）"
        ));
    }
    let name = HeaderName::from_bytes(raw.as_bytes())
        .map_err(|_| format!("`$header({raw})` 头名非法（不符合 http 头名语义）"))?;
    if name.as_str().starts_with(VEIL_INTERNAL_PREFIX) {
        return Err(format!(
            "`$header({raw})` 引用 x-veil-* 内部命名空间（禁止镜像内部头）"
        ));
    }
    Ok(name)
}

/// 字面暂存落段：校验头值语义后并入段列表（空段忽略；连续字面自动合并）。
fn flush_literal(
    literal: &mut String,
    segments: &mut Vec<HeaderValueSegment>,
) -> std::result::Result<(), String> {
    if literal.is_empty() {
        return Ok(());
    }
    HeaderValue::from_str(literal)
        .map_err(|_| format!("字面段 {literal:?} 含非法字节（不符合 http 头值语义）"))?;
    segments.push(HeaderValueSegment::Literal(std::mem::take(literal)));
    Ok(())
}

/// 未知插值形态理由：附现场片段（最多 16 字符）并列出全部合法形态。
fn unknown_interpolation_reason(after: &str) -> String {
    let snippet: String = after.chars().take(16).collect();
    format!(
        "未知插值形态 `${snippet}`（仅支持 $conversation / $request-id / $header(名) 与 $$ 转义；字面 $ 须写作 $$）"
    )
}

/// 硬拒清单判定：命中即返回指名理由（归一后小写名）。
fn denied_header_reason(normalized: &str) -> Option<&'static str> {
    if normalized.starts_with(VEIL_INTERNAL_PREFIX) {
        return Some("x-veil-* 内部头");
    }
    if RESERVED_HEADERS.contains(&normalized) {
        return Some("保留/长度与编码头");
    }
    if HOP_BY_HOP_HEADERS.contains(&normalized) {
        return Some("逐跳头");
    }
    if AUTH_HEADERS.contains(&normalized) {
        return Some("鉴权/身份类头禁止代持");
    }
    None
}

/// 协议参数校验：逐协议（`chat` / `anthropic` / `responses`）逐段（三段）展开。
fn validate_params(
    key: TargetKey,
    raw: Option<&TargetParams>,
) -> Result<BTreeMap<ParamProtocol, ParamOverrides>> {
    let Some(raw) = raw else {
        return Ok(BTreeMap::new());
    };
    let mut params = BTreeMap::new();
    for (protocol, segments) in [
        (ParamProtocol::Chat, raw.chat.as_ref()),
        (ParamProtocol::Anthropic, raw.anthropic.as_ref()),
        (ParamProtocol::Responses, raw.responses.as_ref()),
    ] {
        if let Some(segments) = segments {
            params.insert(protocol, validate_segments(key, protocol, segments)?);
        }
    }
    Ok(params)
}

/// 单协议三段校验：`default` / `override` 逐键保留键检查，`drop` 逐元素检查。
fn validate_segments(
    key: TargetKey,
    protocol: ParamProtocol,
    raw: &ParamSegments,
) -> Result<ParamOverrides> {
    Ok(ParamOverrides {
        default: validate_segment_map(key, protocol, "default", raw.default.as_ref())?,
        r#override: validate_segment_map(key, protocol, "override", raw.r#override.as_ref())?,
        drop: validate_drop(key, protocol, raw.drop.as_deref())?,
    })
}

/// `default` / `override` 表：任一保留键出现即拒启动（值类型不限）。
fn validate_segment_map(
    key: TargetKey,
    protocol: ParamProtocol,
    segment: &str,
    raw: Option<&BTreeMap<String, Value>>,
) -> Result<BTreeMap<String, Value>> {
    let Some(raw) = raw else {
        return Ok(BTreeMap::new());
    };
    for name in raw.keys() {
        if RESERVED_PARAM_KEYS.contains(&name.as_str()) {
            let path = format!(
                "{}.params.{}.{segment}",
                key.path_prefix(),
                protocol.wire_name()
            );
            return Err(reserved_key_error(&path, name));
        }
    }
    Ok(raw.clone())
}

/// `drop` 列表：任一元素为保留键即拒启动。
fn validate_drop(
    key: TargetKey,
    protocol: ParamProtocol,
    raw: Option<&[String]>,
) -> Result<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    for name in raw {
        if RESERVED_PARAM_KEYS.contains(&name.as_str()) {
            let path = format!("{}.params.{}.drop", key.path_prefix(), protocol.wire_name());
            return Err(reserved_key_error(&path, name));
        }
    }
    Ok(raw.to_vec())
}

/// 保留键拒启动错误：指名完整键路径与保留键本体。
fn reserved_key_error(path: &str, name: &str) -> VeilError {
    config_error(
        BOOTSTRAP_VAR,
        &format!("{path} 含保留键 {name}（保护路由/SSE 泵/占位符注入/用量计费口径），拒绝启动"),
    )
}

/// `[llm.targets]` 结构性键闭集（分组 = 所在层级）：用户自定义键（端口号/头名/参数名）
/// 不属此列；锁步测试据此与工程参考 §1 结构性键表比对，schema 侧增删改须同步。
#[cfg(test)]
pub(crate) const TARGETS_STRUCTURAL_KEYS: &[(&str, &[&str])] = &[
    (
        "目标内",
        &[
            "headers",
            "params",
            "override_existing",
            "user_agent",
            "drop_headers",
        ],
    ),
    ("params 内", &["chat", "anthropic", "responses"]),
    ("协议段内", &["default", "override", "drop"]),
];

#[cfg(test)]
mod tests;
