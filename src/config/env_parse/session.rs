//! 会话身份配置域（`[session]`，文件专属，无 env 名）。
//!
//! 承载**唯一**会话头链与别名表容量：头链有序，首个合法非空值胜出；PII 作用域、
//! 请求记录与 `$conversation` 共用同一链（实现见后续阶段）。
//!
//! 启动期校验（fail-closed，任一不满足即拒启动）：头链非空、每个头名通过
//! `HeaderName::from_bytes` 合法性校验、大小写归一后不重复、不含保留鉴权/传输头与
//! `cookie`、不含三个不可信客户端标识头；`alias_max_entries ≥ 1`。
//!
//! 隐私：`headers` 是头**名**列表（不是头值），但同样按敏感配置处理——[`SessionHeaders`]
//! 与 [`SessionParts`]、[`SessionFileConfig`] 的 `Debug` 一律脱敏，避免 `AppState` 的
//! debug 日志输出头名（仅启动期配置错误可指名具体头名）。

use {super::super::validate::config_error, crate::error::Result, axum::http::HeaderName};

/// 默认会话头链（唯一链；顺序即优先级，首个合法非空值胜出）。
pub const SESSION_HEADER_DEFAULTS: [&str; 3] = [
    "x-veil-conversation-id",
    "x-opencode-session",
    "x-opencode-session-id",
];

/// 默认别名表容量（按**别名条目**计；每个 Responses 响应最多写 2 条）。
pub const SESSION_ALIAS_MAX_ENTRIES_DEFAULT: usize = 1024;

/// 保留头名（大小写不敏感）：鉴权/传输类。作会话键时凭据会被卷入键派生，
/// 或该头在出站装配期被剔除导致取值不稳定；`cookie` 另属会话/凭据载体。
const RESERVED_SESSION_HEADERS: [&str; 9] = [
    "authorization",
    "x-api-key",
    "api-key",
    "host",
    "content-length",
    "content-encoding",
    "accept-encoding",
    "transfer-encoding",
    "cookie",
];

/// 不可信客户端标识头（大小写不敏感）：指向父会话、路由亲和性提示、或过于通用
/// 而被代理/sidecar 复用，作会话隔离边界会把两个逻辑客户端并进同一作用域。
const UNTRUSTED_SESSION_HEADERS: [&str; 3] = [
    "x-opencode-parent-session-id",
    "x-session-affinity",
    "x-session-id",
];

/// 头名被拒绝的理由（`None` = 可用）。判定口径单一，错误文本与迁移建议共用。
fn reject_reason(name: &str) -> Option<&'static str> {
    let lower = name.trim().to_ascii_lowercase();
    if RESERVED_SESSION_HEADERS.contains(&lower.as_str())
        || crate::service::llm_gateway::HOP_HEADERS.contains(&lower.as_str())
    {
        return Some("保留鉴权/传输头名（装配期被剔除或会卷入凭据，不能作会话键）");
    }
    if UNTRUSTED_SESSION_HEADERS.contains(&lower.as_str()) {
        return Some(
            "不可信客户端标识头（父会话指针 / 路由亲和性提示 / 过于通用，作隔离边界会串会话）",
        );
    }
    None
}

/// 已校验的会话设置（`Config` 字段的装配输入）。
///
/// 手写 `Debug`：`headers` 输出 `[redacted]`，头名不进入任何运行时 debug 日志。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionParts {
    pub headers: Vec<String>,
    pub alias_max_entries: usize,
}

impl Default for SessionParts {
    fn default() -> Self {
        Self {
            headers: SESSION_HEADER_DEFAULTS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            alias_max_entries: SESSION_ALIAS_MAX_ENTRIES_DEFAULT,
        }
    }
}

impl std::fmt::Debug for SessionParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionParts")
            .field("headers", &"[redacted]")
            .field("alias_max_entries", &self.alias_max_entries)
            .finish()
    }
}

/// 唯一会话头链（新建型包装：`Debug` 脱敏，行为等价 `Vec<String>`）。
///
/// 之所以用包装而非裸 `Vec`：`Config`/`AppState` 均 `derive(Debug)`，裸 `Vec` 会把
/// 头名打进 debug 日志；单靠 `Config` 手写 `Debug` 容易在新增字段时静默漏项。
#[derive(Clone, PartialEq, Eq)]
pub struct SessionHeaders(Vec<String>);

impl SessionHeaders {
    /// 以已校验的头链构造。
    pub fn new(headers: Vec<String>) -> Self { Self(headers) }

    /// 默认链。
    pub fn default_chain() -> Self { Self::new(default_headers()) }

    /// 头链首项（`$conversation`、PII 键推导与遥测的临时消费点用）。
    ///
    /// 构造期已保证非空，故缺失时回落默认首项而非空串。
    pub fn primary(&self) -> &str {
        self.0
            .first()
            .map(String::as_str)
            .unwrap_or(SESSION_HEADER_DEFAULTS[0])
    }

    /// 头链切片。
    pub fn as_slice(&self) -> &[String] { &self.0 }

    /// 迭代头名。
    pub fn iter(&self) -> std::slice::Iter<'_, String> { self.0.iter() }

    /// 头链长度。
    pub fn len(&self) -> usize { self.0.len() }

    /// 是否为空（正常构造下恒 `false`，仅为 lint 完整性提供）。
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl std::ops::Deref for SessionHeaders {
    type Target = [String];

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Default for SessionHeaders {
    fn default() -> Self { Self::default_chain() }
}

impl std::fmt::Debug for SessionHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionHeaders([redacted])")
    }
}

/// 文件层 `[session]` 的原始声明（未校验；由 [`load`] 补默认并校验）。
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SessionFileConfig {
    pub headers: Option<Vec<String>>,
    pub alias_max_entries: Option<usize>,
}

impl std::fmt::Debug for SessionFileConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFileConfig")
            .field("headers", &self.headers.as_ref().map(|_| "[redacted]"))
            .field("alias_max_entries", &self.alias_max_entries)
            .finish()
    }
}

fn default_headers() -> Vec<String> {
    SESSION_HEADER_DEFAULTS
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

/// 解析 `[session]`：缺省补默认链与默认容量，随后整体校验。
pub fn load(file: Option<SessionFileConfig>) -> Result<SessionParts> {
    let (headers, alias_max_entries) = match file {
        Some(cfg) => (
            cfg.headers.unwrap_or_else(default_headers),
            cfg.alias_max_entries
                .unwrap_or(SESSION_ALIAS_MAX_ENTRIES_DEFAULT),
        ),
        None => (default_headers(), SESSION_ALIAS_MAX_ENTRIES_DEFAULT),
    };
    validate(headers, alias_max_entries)
}

/// 校验并规范化头链（trim 后保留原拼写）与别名容量。
fn validate(headers: Vec<String>, alias_max_entries: usize) -> Result<SessionParts> {
    if headers.is_empty() {
        return Err(config_error(
            "[session].headers",
            "[session].headers 不能为空数组：须声明至少一个可信会话头\
             （不提供「无头链」形态；只用协议原生键者也须显式声明一个可信头）",
        ));
    }
    let mut seen: Vec<String> = Vec::with_capacity(headers.len());
    for (index, raw) in headers.iter().enumerate() {
        // 不做 trim：头名两端空白同样是非法输入，静默修剪会掩盖 CRLF 注入形态。
        let parsed = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            config_error(
                "[session].headers",
                &format!(
                    "[session].headers 第 {} 项 {raw:?} 不是合法 HTTP 头名，拒绝启动",
                    index + 1
                ),
            )
        })?;
        // `HeaderName` 规范化为小写，故后续去重与保留名判定均天然大小写不敏感。
        let lower = parsed.as_str().to_string();
        if let Some(reason) = reject_reason(&lower) {
            return Err(config_error(
                "[session].headers",
                &format!("[session].headers 取值 {raw:?} 被拒绝：{reason}，拒绝启动"),
            ));
        }
        if seen.iter().any(|name| name == &lower) {
            return Err(config_error(
                "[session].headers",
                &format!("[session].headers 头名 {raw:?} 在大小写归一后重复，拒绝启动"),
            ));
        }
        seen.push(lower);
    }
    if alias_max_entries < 1 {
        return Err(config_error(
            "[session].alias_max_entries",
            &format!(
                "[session].alias_max_entries 须 ≥ 1（别名表按条目标注容量，0 等于禁用别名表），\
                 实际 {alias_max_entries}，拒绝启动"
            ),
        ));
    }
    Ok(SessionParts {
        headers,
        alias_max_entries,
    })
}

/// 已删除的会话 env 规范名与替代文件键（fail-closed 预扫描的唯一真源）。
///
/// 二者承载安全相关的会话隔离配置：静默失效会让 PII 作用域意外退化，或把两个客户端
/// 折叠进同一作用域。故与任意未知 env 不同形——非空置位即拒启动。
pub(crate) const REMOVED_SESSION_ENV_VARS: [(&str, &str); 2] = [
    ("PII_SCOPE_KEY_HEADER", "[session].headers"),
    (
        "PII_SCOPE_PREV_ID_MAX_ENTRIES",
        "[session].alias_max_entries",
    ),
];

/// 已删除描述：错误文本中的补充说明（指名语义替代而非仅改名）。
const REMOVED_SESSION_ENV_NOTES: [&str; 2] = [
    "会话头已收敛为唯一有序链 [session].headers（有序，首个合法非空值胜出）",
    "别名表容量改由 [session].alias_max_entries 承载（按别名条目计，默认 1024）",
];

/// fail-closed 预扫描：在**原始** env map 上（`filter_process_env` 之前）检出两个已删除
/// 的会话规范名，非空置位即拒启动并指名替代文件键。
///
/// 旧拼写不在本清单内：它与任意未知 env 完全同形，静默。
pub(crate) fn check_removed_session_env(
    raw: &std::collections::HashMap<String, String>,
) -> Result<()> {
    for (index, (name, replacement)) in REMOVED_SESSION_ENV_VARS.iter().enumerate() {
        if raw.get(*name).is_some_and(|value| !value.trim().is_empty()) {
            return Err(config_error(
                name,
                &format!(
                    "{name} 已删除（不再从进程 env 读取，也不提供兼容读取）；\
                     请删除该部署变量并改用配置文件键 {replacement}：{}",
                    REMOVED_SESSION_ENV_NOTES[index]
                ),
            ));
        }
    }
    Ok(())
}

/// 旧文件键 `[pii_scope].key_header` 的迁移建议（预扫描错误文本用）。
///
/// 按 design「Migration Plan」：取旧**生效值**（空串/缺失归一为默认首项）；若命中
/// 任何新保留/不可信头名则**无法等价迁移**并明确告知；否则以生效值为首项，依次追加
/// 默认链的后两项，按头名大小写归一后去重，输出完整 `headers = [...]` 数组。
pub(crate) fn headers_migration_suggestion(old: Option<&str>) -> String {
    let effective = old
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(SESSION_HEADER_DEFAULTS[0]);
    if HeaderName::from_bytes(effective.as_bytes()).is_err() {
        return format!(
            "旧生效值 {effective:?} 不是合法 HTTP 头名，**无法等价迁移**：\
             请改选一个合法且可信的客户端会话头后显式声明 [session].headers"
        );
    }
    if let Some(reason) = reject_reason(effective) {
        return format!(
            "旧生效值 {effective:?} 命中不可用头名（{reason}），**无法等价迁移**：\
             请改选一个可信的客户端会话头后显式声明 [session].headers"
        );
    }
    let mut suggested: Vec<String> = Vec::with_capacity(SESSION_HEADER_DEFAULTS.len());
    for candidate in [
        effective,
        SESSION_HEADER_DEFAULTS[1],
        SESSION_HEADER_DEFAULTS[2],
    ] {
        let lower = candidate.to_ascii_lowercase();
        if !suggested
            .iter()
            .any(|name| name.to_ascii_lowercase() == lower)
        {
            suggested.push(candidate.to_string());
        }
    }
    let list = suggested
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "建议改用 [session] headers = [{list}]（已按头名大小写归一后去重）；\
         旧配置未自定义 key_header 时可直接省略该键使用默认链"
    )
}

/// 旧文件键 `[pii_scope].prev_id_max_entries` 的迁移建议（预扫描错误文本用）。
///
/// 旧默认取 `[pii_scope].max_conversations` 的生效值，新键缺省固定
/// [`SESSION_ALIAS_MAX_ENTRIES_DEFAULT`]，且按**别名条目**计（每响应最多 2 条）。
pub(crate) fn alias_migration_suggestion(old: Option<i64>) -> String {
    match old {
        Some(value) => format!(
            "建议改用 [session] alias_max_entries = {value}；注意新键按别名条目计\
             （每个 Responses 响应最多写 response.id 与 conversation.id 两条），\
             与旧映射容量语义不完全等价，需要旧容量时通常应设为 2 × 会话数"
        ),
        None => format!(
            "建议改用 [session].alias_max_entries；旧缺省取 [pii_scope].max_conversations 的生效值，\
             新缺省固定 {SESSION_ALIAS_MAX_ENTRIES_DEFAULT}（按别名条目计，每响应最多 2 条），\
             需要旧容量时须显式声明"
        ),
    }
}

#[cfg(test)]
mod tests;
