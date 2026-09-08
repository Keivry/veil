use {
    crate::config::Config,
    axum::http::HeaderMap,
    serde_json::Value,
    std::{
        collections::HashMap,
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    },
};

pub const RETRY_DELAYS_MS: [u64; 3] = [500, 1000, 2000];
pub const MAX_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Chat,
    Anthropic,
    Responses,
    NonDialog,
}

impl Protocol {
    pub fn as_tail(&self) -> &'static str {
        match self {
            Self::Chat => "chat/completions",
            Self::Anthropic => "v1/messages",
            Self::Responses => "v1/responses",
            Self::NonDialog => "non-dialog",
        }
    }
}

#[derive(Debug, Default)]
pub struct GatewayMetrics {
    lenient: Mutex<HashMap<String, u64>>,
    truncated: Mutex<HashMap<String, u64>>,
    hop_filtered: Mutex<HashMap<String, u64>>,
    conv_missing: Mutex<HashMap<String, u64>>,
    sse_events: AtomicU64,
}

impl GatewayMetrics {
    pub fn record_lenient(&self, tail: &str) {
        if let Ok(mut g) = self.lenient.lock() {
            *g.entry(tail.to_string()).or_insert(0) += 1;
        }
    }

    pub fn lenient_count(&self, tail: &str) -> u64 {
        self.lenient
            .lock()
            .map(|g| g.get(tail).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn record_truncated(&self, mode: &str) {
        if let Ok(mut g) = self.truncated.lock() {
            *g.entry(mode.to_string()).or_insert(0) += 1;
        }
    }

    pub fn truncated_count(&self, mode: &str) -> u64 {
        self.truncated
            .lock()
            .map(|g| g.get(mode).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn add_sse_event(&self) { self.sse_events.fetch_add(1, Ordering::Relaxed); }

    pub fn sse_event_total(&self) -> u64 { self.sse_events.load(Ordering::Relaxed) }

    pub fn record_hop_filtered(&self, dir: &str, count: u64) {
        if count == 0 {
            return;
        }
        if let Ok(mut g) = self.hop_filtered.lock() {
            *g.entry(dir.to_string()).or_insert(0) += count;
        }
    }

    pub fn hop_filtered_count(&self, dir: &str) -> u64 {
        self.hop_filtered
            .lock()
            .map(|g| g.get(dir).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    pub fn record_conv_missing(&self, reason: &str) {
        if let Ok(mut g) = self.conv_missing.lock() {
            *g.entry(reason.to_string()).or_insert(0) += 1;
        }
    }

    pub fn conv_missing_count(&self, reason: &str) -> u64 {
        self.conv_missing
            .lock()
            .map(|g| g.get(reason).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

const STRICT_TAILS: [(&str, Protocol); 3] = [
    ("chat/completions", Protocol::Chat),
    ("v1/messages", Protocol::Anthropic),
    ("v1/responses", Protocol::Responses),
];

fn strip_query(path: &str) -> &str { path.split(['?', '#']).next().unwrap_or(path) }

fn strict_match(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    for (suffix, proto) in STRICT_TAILS {
        if p == format!("/{suffix}") || p == suffix {
            return Some(proto);
        }
        if p.len() > suffix.len() + 1
            && p.as_bytes()[p.len() - suffix.len() - 1] == b'/'
            && p[p.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return Some(proto);
        }
    }
    None
}

fn lenient_match(path: &str) -> Option<(Protocol, String)> {
    let p = strip_query(path);
    let trimmed = p.strip_suffix('/').unwrap_or(p);
    if trimmed != p
        && let Some(proto) = strict_match(trimmed)
    {
        return Some((proto, proto.as_tail().to_string()));
    }
    if let Some(slash) = p.rfind('/')
        && slash > 0
    {
        let parent = &p[..slash];
        if parent.contains('/') || parent.is_empty() {
            if let Some(proto) = strict_match(parent) {
                let rest = &p[slash + 1..];
                if !rest.is_empty() && !rest.contains('/') {
                    return Some((proto, proto.as_tail().to_string()));
                }
            }
        } else {
            return None;
        }
    }
    None
}

pub fn is_chat_tail(path: &str, metrics: Option<&GatewayMetrics>) -> (bool, Protocol) {
    if let Some(proto) = strict_match(path) {
        return (true, proto);
    }
    if let Some((proto, tail)) = lenient_match(path) {
        if let Some(m) = metrics {
            m.record_lenient(&tail);
        }
        tracing::debug!(path = %path, tail = %tail, "chat tail 宽容命中");
        return (true, proto);
    }
    (false, Protocol::NonDialog)
}

pub fn resolve_protocol(
    tail: &str,
    content_type: Option<&str>,
    metrics: Option<&GatewayMetrics>,
) -> Protocol {
    let (hit, proto) = is_chat_tail(tail, metrics);
    if let Some(ct) = content_type {
        tracing::debug!(tail = %tail, content_type = %ct, is_chat = %hit, "tail 优先分发，Content-Type 仅日志参考");
    }
    if hit { proto } else { Protocol::NonDialog }
}

pub fn is_stream_body(body: &Value) -> bool {
    body.as_object().is_some_and(|m| {
        m.get("stream")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    })
}

pub fn should_inject_stream_options(protocol: Protocol, body: &Value) -> bool {
    match protocol {
        Protocol::Chat | Protocol::Responses => {
            if !is_stream_body(body) {
                return false;
            }
            match body.as_object().and_then(|m| m.get("stream_options")) {
                // 键内合并语义（对齐 Python setdefault）：整键缺失或
                // `include_usage` 缺失即需注入，保留用户自带其他键。
                None => true,
                Some(Value::Object(opts)) => opts.get("include_usage").is_none(),
                // 非对象形态视为缺失，由 inject 整体替换 + warn。
                Some(_) => true,
            }
        }
        Protocol::Anthropic | Protocol::NonDialog => false,
    }
}

pub fn inject_stream_options(body: &mut Value) {
    if let Some(map) = body.as_object_mut() {
        match map.get_mut("stream_options") {
            Some(Value::Object(opts)) => {
                opts.entry("include_usage".to_string())
                    .or_insert(serde_json::json!(true));
            }
            Some(slot) => {
                tracing::warn!("stream_options 非对象形态，已整体替换为 include_usage");
                *slot = serde_json::json!({"include_usage": true});
            }
            None => {
                map.insert(
                    "stream_options".to_string(),
                    serde_json::json!({"include_usage": true}),
                );
            }
        }
    }
}

pub fn should_inject_placeholders(
    is_chat: bool,
    redaction_enabled: bool,
    body_has_values: bool,
) -> bool {
    is_chat && redaction_enabled && body_has_values
}

pub fn has_placeholder_tokens(body: &[u8]) -> bool {
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(b"__PII_") || body[i..].starts_with(b"__VG_CRED_") {
            return true;
        }
        i += 1;
    }
    false
}

fn append_prompt_text(field: &mut Value, prompt: &str) {
    match field {
        Value::String(s) => {
            if s.is_empty() {
                *s = prompt.to_string();
            } else {
                s.push_str("\n\n");
                s.push_str(prompt);
            }
        }
        Value::Array(arr) => {
            if let Some(Value::Object(last)) = arr.last_mut()
                && last.get("type").and_then(|v| v.as_str()) == Some("text")
                && let Some(text) = last.get_mut("text")
                && let Some(t) = text.as_str()
            {
                let merged = if t.is_empty() {
                    prompt.to_string()
                } else {
                    format!("{t}\n\n{prompt}")
                };
                last.insert("text".to_string(), Value::String(merged));
                return;
            }
            arr.push(serde_json::json!({"type": "text", "text": prompt}));
        }
        _ => {}
    }
}

/// Responses 数组前插 system 说明（与 Chat `messages` 同语义）：
/// 空数组追加首条；首条为 system 则合并 `content`；否则头部插入。
fn front_insert_system(msgs: &mut Vec<Value>, prompt: &str) {
    if msgs.is_empty() {
        msgs.push(serde_json::json!({"role": "system", "content": prompt}));
        return;
    }
    if let Some(Value::Object(first)) = msgs.first_mut()
        && first.get("role").and_then(|v| v.as_str()) == Some("system")
    {
        match first.get_mut("content") {
            Some(content @ (Value::String(_) | Value::Array(_))) => {
                append_prompt_text(content, prompt);
            }
            Some(other) => {
                let base = other.as_str().unwrap_or_default().to_string();
                let merged = if base.is_empty() {
                    prompt.to_string()
                } else {
                    format!("{base}\n\n{prompt}")
                };
                first.insert("content".to_string(), Value::String(merged));
            }
            None => {
                first.insert("content".to_string(), Value::String(prompt.to_string()));
            }
        }
        return;
    }
    msgs.insert(0, serde_json::json!({"role": "system", "content": prompt}));
}

/// Responses 文本字段注入（`input` 与 `instructions` 同等语义，§2.1）：
/// - `String`：末尾追加说明（与 Anthropic `system` 字符串形态一致）；
/// - `Array`：首条 system 前插；
/// - 非法形态（数字/对象等）：warn 后不注入，调用方回退原体。
fn inject_responses_text_field(field: &mut Value, key: &str, prompt: &str) -> bool {
    match field {
        Value::String(_) | Value::Array(_) => {}
        _ => {
            tracing::warn!("Responses {key} 非法形态不注入，原体透传");
            return false;
        }
    }
    match field {
        Value::String(_) => {
            append_prompt_text(field, prompt);
            true
        }
        Value::Array(arr) => {
            front_insert_system(arr, prompt);
            true
        }
        _ => false,
    }
}

/// 占位符说明注入（§2.1）：chat 前插 `messages` 首条 system；
/// anthropic 合并 `system`；responses 对 `input` 与 `instructions`
/// 同等注入（string 追加 / array 前插），非法形态 warn 后不注入。
pub fn placeholder_inject_obj(body: &mut Value, prompt: &str, protocol: Protocol) -> bool {
    if protocol == Protocol::Anthropic {
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        if let Some(sys) = map.get_mut("system") {
            if matches!(sys, Value::String(_) | Value::Array(_)) {
                append_prompt_text(sys, prompt);
                return true;
            }
            tracing::warn!("Anthropic system 非法形态不注入，原体透传");
            return false;
        }
        map.insert("system".to_string(), Value::String(prompt.to_string()));
        return true;
    }
    // §2.1：Responses `input` 与 `instructions` 同等注入；string 按串追加、
    // array 按首条前插；非法形态 warn 后不注入（回退原体）。
    if protocol == Protocol::Responses {
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        let mut injected = false;
        for key in ["input", "instructions"] {
            let Some(field) = map.get_mut(key) else {
                continue;
            };
            injected |= inject_responses_text_field(field, key, prompt);
        }
        if !injected {
            tracing::warn!("Responses input/instructions 缺失或非法，不注入");
        }
        return injected;
    }
    let key = "messages";
    let Some(map) = body.as_object_mut() else {
        return false;
    };
    let Some(field) = map.get_mut(key) else {
        return false;
    };
    let Some(msgs) = field.as_array_mut() else {
        return false;
    };
    front_insert_system(msgs, prompt);
    true
}

pub fn placeholder_schema_ok(body: &Value, protocol: Protocol) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    match protocol {
        Protocol::Anthropic => match map.get("system") {
            None => true,
            Some(Value::String(_)) | Some(Value::Array(_)) => true,
            Some(_) => false,
        },
        // §2.1：Responses 允许 `input`/`instructions` 各为 string|array；
        // 存在者须形态合法，且至少存在其一；非法回退不注入。
        Protocol::Responses => {
            let field_ok = |v: Option<&Value>| match v {
                None => true,
                Some(Value::String(_) | Value::Array(_)) => true,
                Some(_) => false,
            };
            (map.get("input").is_some() || map.get("instructions").is_some())
                && field_ok(map.get("input"))
                && field_ok(map.get("instructions"))
        }
        Protocol::Chat => map.get("messages").is_some_and(|v| v.is_array()),
        Protocol::NonDialog => false,
    }
}

pub fn inject_placeholder_prompt(
    body_text: &str,
    prompt: &str,
    protocol: Protocol,
) -> Option<String> {
    if body_text.is_empty() || prompt.is_empty() {
        return None;
    }
    let stripped = body_text.trim_start_matches('\u{feff}').trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return None;
    }
    let mut obj: Value = serde_json::from_str(body_text.trim_start_matches('\u{feff}')).ok()?;
    if !obj.is_object() {
        return None;
    }
    if !placeholder_inject_obj(&mut obj, prompt, protocol) {
        return None;
    }
    if !placeholder_schema_ok(&obj, protocol) {
        tracing::warn!("占位符说明注入 schema 校验失败，回退不注入");
        return None;
    }
    serde_json::to_string(&obj).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

fn usage_from_obj(obj: &serde_json::Map<String, Value>) -> Option<Usage> {
    let has_known = [
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "total",
    ]
    .iter()
    .any(|k| obj.contains_key(*k));
    if !has_known {
        return None;
    }
    let prompt = obj
        .get("prompt_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("input_tokens").and_then(as_u64))
        .unwrap_or(0);
    let completion = obj
        .get("completion_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("output_tokens").and_then(as_u64))
        .unwrap_or(0);
    let total = obj
        .get("total_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("total").and_then(as_u64))
        .unwrap_or_else(|| prompt.saturating_add(completion));
    Some(Usage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: total,
    })
}

fn usage_in(obj: &serde_json::Map<String, Value>) -> Option<Usage> {
    obj.get("usage")?.as_object().and_then(usage_from_obj)
}

fn merge_usage(acc: &mut Option<Usage>, next: Usage) {
    match acc {
        Some(a) => {
            a.prompt_tokens = a.prompt_tokens.max(next.prompt_tokens);
            a.completion_tokens = a.completion_tokens.max(next.completion_tokens);
            a.total_tokens = a.total_tokens.max(next.total_tokens);
        }
        None => *acc = Some(next),
    }
}

pub fn extract_usage_nonstream(protocol: Protocol, body: &Value) -> Option<Usage> {
    match protocol {
        Protocol::Chat => body.get("usage")?.as_object().and_then(usage_from_obj),
        Protocol::Responses => {
            let outer = body.get("response")?.as_object()?;
            if let Some(u) = outer
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(usage_from_obj)
            {
                return Some(u);
            }
            outer
                .get("response")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(usage_from_obj)
        }
        Protocol::Anthropic => {
            if let Some(u) = body
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(usage_from_obj)
            {
                return Some(u);
            }
            body.get("message")?
                .get("usage")?
                .as_object()
                .and_then(usage_from_obj)
        }
        Protocol::NonDialog => None,
    }
}

/// 流式 SSE 事件载荷捕获 usage（对标 Python `_capture_usage_ctx`）。
///
/// 口径：顶层 `usage` 优先；Responses 单层 `response.usage` 优先、双层
/// `response.response.usage` 回退；Anthropic `delta.usage` / `message.usage`
/// 回退；缺失返回 `None` 不估算。数值归一与 [`extract_usage_nonstream`] 同口径
/// （`input_tokens`/`output_tokens`/`total` 回退，`total` 缺失时 `prompt+completion`）。
pub fn extract_usage_stream(protocol: Protocol, payload: &Value) -> Option<Usage> {
    let obj = payload.as_object()?;
    // 快路径：无 usage/cached_tokens/裸 token 键的心跳分片直接跳过，避免全量归一。
    let raw = payload.to_string();
    if !raw.contains("\"usage\"")
        && !raw.contains("\"cached_tokens\"")
        && !raw.contains("input_tokens")
        && !raw.contains("output_tokens")
    {
        return None;
    }
    if let Some(u) = usage_in(obj) {
        return Some(u);
    }
    match protocol {
        Protocol::Chat => None,
        Protocol::Responses => {
            let resp = obj.get("response")?.as_object()?;
            if let Some(u) = resp
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(usage_from_obj)
            {
                return Some(u);
            }
            resp.get("response")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(usage_from_obj)
        }
        Protocol::Anthropic => {
            if let Some(u) = obj
                .get("delta")
                .and_then(|v| v.as_object())
                .and_then(usage_in)
            {
                return Some(u);
            }
            obj.get("message")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(usage_from_obj)
        }
        Protocol::NonDialog => None,
    }
}

/// 流式 usage 累加（§2.7 口径：统一 `max`，禁用 `sum`）。
/// 上游分片语义为累计值（`message_start` 给全量、`message_delta` 给累计），
/// 按字段单调取大；`sum` 会把同一 token 算两次（双计），此处禁止。
pub fn accumulate_usage(acc: &mut Option<Usage>, next: Option<Usage>) {
    if let Some(u) = next {
        merge_usage(acc, u);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyAction {
    StreamInjectThen502,
    NonStreamTo502,
    Passthrough502_401,
    NonDialogExempt,
    PassthroughOk,
}

pub fn classify_empty(
    is_chat: bool,
    is_stream: bool,
    body_len: usize,
    is_json: bool,
    upstream_status: u16,
) -> EmptyAction {
    if !is_chat {
        return EmptyAction::NonDialogExempt;
    }
    if upstream_status == 502 || upstream_status == 401 {
        return EmptyAction::Passthrough502_401;
    }
    if is_stream {
        if body_len == 0 {
            return EmptyAction::StreamInjectThen502;
        }
        return EmptyAction::PassthroughOk;
    }
    if body_len == 0 || !is_json {
        return EmptyAction::NonStreamTo502;
    }
    EmptyAction::PassthroughOk
}

pub fn retry_delay(attempt: usize) -> Duration {
    Duration::from_millis(RETRY_DELAYS_MS.get(attempt).copied().unwrap_or(2000))
}

pub fn resolve_upstream(config: &Config, local_port: Option<u16>) -> Option<String> {
    if let Some(port) = local_port
        && let Some(u) = config.llm_upstreams.get(&port)
    {
        return Some(u.clone());
    }
    if let Some(u) = config.llm_default_upstream.clone() {
        return Some(u);
    }
    config.llm_upstreams.values().next().cloned()
}

/// FIX-1：RFC 9110 §7.6.1 逐跳头全集，双向过滤，大小写不敏感。
/// 固定集 8 项 + `Connection` 头内列名的动态项。
pub const HOP_HEADERS: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// `reqwest` 编解码开关配对标记：网关 `Client` 以本常量驱动
/// `gzip/brotli/deflate` 三开关（见 handler 网关路径），对外统一 `identity`。
pub const DECODE_ENABLED: bool = true;

/// 兼容旧单参调用：默认按响应方向计数（`dir="downstream"`），解码配对按 [`DECODE_ENABLED`]。
pub fn filter_hop_headers(headers: &mut HeaderMap) {
    filter_hop_headers_counted(headers, "downstream", DECODE_ENABLED, None);
}

/// FIX-1 全集双向过滤 + 编解码配对。
/// - 先剥 hop 全集（含 `Connection` 动态项），再做编码改写（顺序固定）；
/// - `decode_enabled=true` 时剥 `content-encoding`/`content-length`（已解码，长度已变）；
/// - 每次剥离记 `hop_filtered_total{dir}`（经 `record_hop_filtered`）。
///
/// 返回剥离总数。
pub fn filter_hop_headers_counted(
    headers: &mut HeaderMap,
    dir: &str,
    decode_enabled: bool,
    metrics: Option<&GatewayMetrics>,
) -> u64 {
    use std::collections::HashSet;
    let mut hop: HashSet<String> = HOP_HEADERS.iter().map(|s| s.to_string()).collect();
    // `Connection` 头内动态项（逗号分隔，大小写不敏感）。
    let conn_vals: Vec<String> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|t| t.trim().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for t in conn_vals {
        hop.insert(t);
    }
    // 快照键后逐个移除（`HeaderMap` 键已规范小写，比较用小写）。
    let keys: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
    let mut removed: u64 = 0;
    for k in keys {
        if hop.contains(&k.to_lowercase()) && headers.remove(k.as_str()).is_some() {
            removed += 1;
        }
    }
    // 编码配对：解码开启则对外 `identity`，剥编码与长度（在 hop 剥离之后执行）。
    if decode_enabled {
        for enc in ["content-encoding", "content-length"] {
            if headers.remove(enc).is_some() {
                removed += 1;
            }
        }
    }
    if let Some(m) = metrics {
        m.record_hop_filtered(dir, removed);
    }
    removed
}

pub async fn fetch_upstream_with_retry(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> anyhow::Result<reqwest::Response> {
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 0..=MAX_RETRY_ATTEMPTS {
        let mut req = client.request(method.clone(), url);
        for (k, v) in headers.iter() {
            if let Ok(val) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) {
                req = req.header(k.clone(), val);
            }
        }
        if !body.is_empty() {
            req = req.body(body.clone());
        }
        match req.send().await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                if e.is_connect() || e.is_timeout() {
                    last_err = Some(e);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        tokio::time::sleep(retry_delay(attempt)).await;
                        continue;
                    }
                    break;
                }
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    Err(anyhow::anyhow!(
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "上游拿头前连续失败".to_string())
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub index: u32,
    pub id: String,
    pub name: Option<String>,
    pub args: String,
    pub id_synth: bool,
}

pub fn normalize_tool_args(raw: Option<&Value>) -> String {
    match raw {
        None => {
            tracing::warn!("tool args 缺失，已记告警不断链（置空串审计暂缓）");
            String::new()
        }
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => {
            tracing::warn!("tool args 为 null，已记告警不断链");
            String::new()
        }
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn synth_id(index: u32, present: Option<&str>) -> (String, bool) {
    match present.filter(|s| !s.is_empty()) {
        Some(s) => (s.to_string(), false),
        None => {
            tracing::warn!("tool id 缺失，已合成 call_stable_<index> 不断链");
            (format!("call_stable_{index}"), true)
        }
    }
}

fn custom_obj_to_call(index: u32, obj: &serde_json::Map<String, Value>) -> Option<ToolCall> {
    let id_raw = obj
        .get("id")
        .or_else(|| obj.get("call_id"))
        .or_else(|| obj.get("tool_call_id"))
        .and_then(|v| v.as_str());
    let name = obj
        .get("name")
        .or_else(|| obj.get("tool_name"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());
    let args_raw = obj
        .get("arguments")
        .or_else(|| obj.get("input"))
        .or_else(|| obj.get("args"));
    let (id, id_synth) = synth_id(index, id_raw);
    let args = normalize_tool_args(args_raw);
    if name.is_none() && args.is_empty() && !id_synth {
        tracing::warn!("tool 三元组缺失（id/name/args 全空），暂缓审计放行");
    }
    Some(ToolCall {
        index,
        id,
        name,
        args,
        id_synth,
    })
}

pub fn extract_tool_calls(protocol: Protocol, payload: &Value) -> Vec<ToolCall> {
    let mut out = Vec::new();
    match protocol {
        Protocol::Chat => {
            if let Some(choices) = payload.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
                    for key in ["delta", "message"] {
                        if let Some(container) = ch.get(key) {
                            if let Some(calls) =
                                container.get("tool_calls").and_then(|c| c.as_array())
                            {
                                for (i, call) in calls.iter().enumerate() {
                                    let idx = call
                                        .get("index")
                                        .and_then(|x| x.as_u64())
                                        .unwrap_or(i as u64)
                                        as u32;
                                    let (id, id_synth) =
                                        synth_id(idx, call.get("id").and_then(|x| x.as_str()));
                                    let name = call
                                        .get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = normalize_tool_args(
                                        call.get("function").and_then(|f| f.get("arguments")),
                                    );
                                    if name.is_none() && args.is_empty() {
                                        tracing::warn!("chat tool 三元组缺失，暂缓审计放行");
                                    }
                                    out.push(ToolCall {
                                        index: idx,
                                        id,
                                        name,
                                        args,
                                        id_synth,
                                    });
                                }
                            }
                            for legacy_key in ["function_call", "custom_tool_call"] {
                                if let Some(legacy) = container.get(legacy_key) {
                                    let items: Vec<&Value> = match legacy {
                                        Value::Array(a) => a.iter().collect(),
                                        Value::Object(_) => vec![legacy],
                                        _ => vec![],
                                    };
                                    for (i, item) in items.iter().enumerate() {
                                        if let Some(obj) = item.as_object() {
                                            if legacy_key == "function_call" {
                                                let idx = ci as u32;
                                                let (id, id_synth) = synth_id(idx, None);
                                                let name = obj
                                                    .get("name")
                                                    .and_then(|v| v.as_str())
                                                    .map(|s| s.to_string());
                                                let args =
                                                    normalize_tool_args(obj.get("arguments"));
                                                out.push(ToolCall {
                                                    index: idx,
                                                    id,
                                                    name,
                                                    args,
                                                    id_synth,
                                                });
                                            } else if let Some(c) =
                                                custom_obj_to_call(i as u32, obj)
                                            {
                                                out.push(c);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Protocol::Anthropic => {
            let mut blocks: Vec<&Value> = Vec::new();
            for key in ["content_block", "delta"] {
                if let Some(b) = payload.get(key) {
                    blocks.push(b);
                }
            }
            if let Some(arr) = payload.get("content").and_then(|c| c.as_array()) {
                for b in arr {
                    blocks.push(b);
                }
            }
            if let Some(msg) = payload.get("message").and_then(|m| m.get("content")) {
                if let Some(arr) = msg.as_array() {
                    for b in arr {
                        blocks.push(b);
                    }
                } else if msg.is_object() {
                    blocks.push(msg);
                }
            }
            // §2.4：按外层事件 `index` 分桶（官方 `content_block_start.index` /
            // `content_block_delta.index` 在事件顶层，内层 `content_block` /
            // `delta` 常无 index）；内层 index 优先、外层回退、缺失才用枚举下标。
            let outer_index: Option<u32> = payload
                .get("index")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32);
            let bucket_index = |b: &Value, fallback: u32| -> u32 {
                b.get("index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .or(outer_index)
                    .unwrap_or(fallback)
            };
            for (i, b) in blocks.iter().enumerate() {
                let bucket = bucket_index(b, i as u32);
                let is_tool = b.get("type").and_then(|v| v.as_str()).is_some_and(|t| {
                    t.contains("tool_use") || t.contains("function") || t.contains("custom")
                }) || b.get("name").is_some()
                    || b.get("partial_json").is_some()
                    || b.get("input").is_some()
                    || b.get("function_call").is_some()
                    || b.get("custom_tool_call").is_some();
                if !is_tool {
                    continue;
                }
                if let Some(fc) = b.get("function_call").and_then(|v| v.as_object()) {
                    let (id, id_synth) = synth_id(bucket, None);
                    let name = fc
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let args = normalize_tool_args(fc.get("arguments"));
                    out.push(ToolCall {
                        index: bucket,
                        id,
                        name,
                        args,
                        id_synth,
                    });
                    continue;
                }
                if let Some(cc) = b.get("custom_tool_call") {
                    match cc {
                        Value::Object(obj) => {
                            if let Some(c) = custom_obj_to_call(bucket, obj) {
                                out.push(c);
                            }
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object()
                                    && let Some(c) = custom_obj_to_call(j as u32, obj)
                                {
                                    out.push(c);
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let id_raw = b.get("id").and_then(|v| v.as_str());
                let name = b
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let args_raw = b
                    .get("partial_json")
                    .or_else(|| b.get("input"))
                    .or_else(|| b.get("arguments"));
                let args = normalize_tool_args(args_raw);
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                let (id, id_synth) = synth_id(bucket, id_raw);
                out.push(ToolCall {
                    index: bucket,
                    id,
                    name,
                    args,
                    id_synth,
                });
            }
        }
        Protocol::Responses => {
            // 5.1：单事件形态优先（delta 只累积不解析、done 全量才审计）。
            // 三级键：`output_index` 为桶号、`item_id/id` 为槽键、
            // `sequence_number` 由 AuditHold 保序；此处只做提取不排序不解析。
            let ev_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                let id_raw = payload
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .or_else(|| payload.get("id").and_then(|v| v.as_str()));
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = payload
                        .get("delta")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if !delta.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_id(idx, id_raw);
                        out.push(ToolCall {
                            index: idx,
                            id,
                            name,
                            args: delta.to_string(),
                            id_synth,
                        });
                    }
                    return out;
                }
                if ev_type.ends_with(".done") {
                    let args = match payload.get("arguments") {
                        Some(Value::String(s)) => s.clone(),
                        Some(other) => serde_json::to_string(other).unwrap_or_default(),
                        None => String::new(),
                    };
                    if !args.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_id(idx, id_raw);
                        out.push(ToolCall {
                            index: idx,
                            id,
                            name,
                            args,
                            id_synth,
                        });
                    }
                    return out;
                }
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = payload.get("item")
                && item.get("type").and_then(|v| v.as_str()) == Some("function_call")
            {
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                let args = match item.get("arguments") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                    None => String::new(),
                };
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let id_raw = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
                if !args.is_empty() || name.is_some() {
                    let (id, id_synth) = synth_id(idx, id_raw);
                    out.push(ToolCall {
                        index: idx,
                        id,
                        name,
                        args,
                        id_synth,
                    });
                }
                return out;
            }
            if payload.get("item").is_some() {
                return out;
            }
            if let Some(output) = payload.get("output").and_then(|o| o.as_array()) {
                for (i, item) in output.iter().enumerate() {
                    let bucket = item
                        .get("output_index")
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u32)
                        .unwrap_or(i as u32);
                    let is_tool = item.get("type").and_then(|v| v.as_str()).is_some_and(|t| {
                        t.contains("function_call")
                            || t.contains("custom_tool_call")
                            || t.contains("tool")
                    }) || item.get("name").is_some()
                        || item.get("arguments").is_some()
                        || item.get("input").is_some();
                    if !is_tool {
                        continue;
                    }
                    if let Some(obj) = item.as_object()
                        && let Some(Value::Object(inner)) = obj.get("custom_tool_call")
                        && let Some(c) = custom_obj_to_call(bucket, inner)
                    {
                        out.push(c);
                        continue;
                    }
                    if let Some(obj) = item.as_object()
                        && let Some(c) = custom_obj_to_call(bucket, obj)
                    {
                        let meaningful = c.name.is_some() || !c.args.is_empty() || !c.id_synth;
                        if meaningful {
                            out.push(c);
                        }
                    }
                }
            }
        }
        Protocol::NonDialog => {}
    }
    out
}

pub fn extract_conv_id(data: &Value) -> Option<String> {
    let non_empty = |v: Option<&Value>| -> Option<String> {
        v.and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    if let Some(id) = non_empty(data.get("id")) {
        return Some(id);
    }
    if let Some(resp) = data.get("response")
        && let Some(id) = non_empty(resp.get("id"))
    {
        return Some(id);
    }
    if let Some(inner) = data.get("data") {
        if let Some(id) = non_empty(inner.get("id")) {
            return Some(id);
        }
        if let Some(resp) = inner.get("response")
            && let Some(id) = non_empty(resp.get("id"))
        {
            return Some(id);
        }
    }
    if let Some(err) = data.get("error") {
        match err {
            Value::String(s) if !s.is_empty() => return Some(s.clone()),
            Value::Object(obj) => {
                if let Some(id) = obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    return Some(id.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

pub fn archive_unknown_id(payload: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    format!("unknown_{}", hex::encode(&digest[..4]))
}

pub fn resolve_conv_id(
    header_id: Option<&str>,
    body: &Value,
    metrics: Option<&GatewayMetrics>,
    reason: &str,
) -> (String, bool) {
    let clean = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(|s| s.to_string());
    if let Some(h) = clean(header_id) {
        return (h, true);
    }
    if let Some(id) = extract_conv_id(body) {
        return (id, false);
    }
    let archived = archive_unknown_id(body);
    if let Some(m) = metrics {
        m.record_conv_missing(reason);
    }
    tracing::debug!(reason = %reason, archived = %archived, "conv_id 缺失已归档不断链");
    (archived, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 对话尾严格命中三协议() {
        let m = GatewayMetrics::default();
        for (path, want) in [
            ("/v1/chat/completions", Protocol::Chat),
            ("https://x/v1/messages", Protocol::Anthropic),
            ("/v1/responses", Protocol::Responses),
        ] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(hit && proto == want, "{path}");
        }
    }

    #[test]
    fn 非对话不命中且不计数() {
        let m = GatewayMetrics::default();
        let (hit, proto) = is_chat_tail("/v1/models", Some(&m));
        assert!(!hit && proto == Protocol::NonDialog);
        assert_eq!(m.lenient_count("chat/completions"), 0);
        let (hit2, _) = is_chat_tail("/v1/fake-chat/completions-extra", Some(&m));
        assert!(!hit2);
    }

    #[test]
    fn 一层后缀宽容计数() {
        let m = GatewayMetrics::default();
        let (hit, proto) = is_chat_tail("/v1/chat/completions/", Some(&m));
        assert!(hit && proto == Protocol::Chat);
        assert_eq!(m.lenient_count("chat/completions"), 1);
        let (hit2, _) = is_chat_tail("/v1/chat/completions/extra", Some(&m));
        assert!(hit2);
        assert_eq!(m.lenient_count("chat/completions"), 2);
        let (hit3, _) = is_chat_tail("/v1/chat/completions/a/b", Some(&m));
        assert!(!hit3);
    }

    #[test]
    fn tail优先于content_type() {
        let m = GatewayMetrics::default();
        assert_eq!(
            resolve_protocol("/v1/models", Some("text/event-stream"), Some(&m)),
            Protocol::NonDialog
        );
        assert_eq!(
            resolve_protocol("/v1/chat/completions", Some("application/json"), Some(&m)),
            Protocol::Chat
        );
    }

    #[test]
    fn stream_options仅chat_responses注入() {
        let chat_stream = serde_json::json!({"model":"m","stream":true});
        let resp_stream = serde_json::json!({"model":"m","stream":true});
        let anth_stream = serde_json::json!({"model":"m","stream":true});
        let chat_nostream = serde_json::json!({"model":"m"});
        assert!(should_inject_stream_options(Protocol::Chat, &chat_stream));
        assert!(should_inject_stream_options(
            Protocol::Responses,
            &resp_stream
        ));
        assert!(!should_inject_stream_options(
            Protocol::Anthropic,
            &anth_stream
        ));
        assert!(!should_inject_stream_options(
            Protocol::Chat,
            &chat_nostream
        ));
        let with_opt = serde_json::json!({"stream":true,"stream_options":{"include_usage":true}});
        assert!(!should_inject_stream_options(Protocol::Chat, &with_opt));
        let partial_opt = serde_json::json!({"stream":true,"stream_options":{"other":1}});
        assert!(
            should_inject_stream_options(Protocol::Chat, &partial_opt),
            "用户自带其他键但缺 include_usage 时须合并注入"
        );
        let mut merged = partial_opt.clone();
        inject_stream_options(&mut merged);
        assert_eq!(merged["stream_options"]["include_usage"], true);
        assert_eq!(merged["stream_options"]["other"], 1);
        let bad_opt = serde_json::json!({"stream":true,"stream_options":"yes"});
        assert!(should_inject_stream_options(Protocol::Chat, &bad_opt));
        let mut fixed = bad_opt.clone();
        inject_stream_options(&mut fixed);
        assert_eq!(fixed["stream_options"]["include_usage"], true);
        let anth_partial = serde_json::json!({"stream":true,"stream_options":{"other":1}});
        assert!(
            !should_inject_stream_options(Protocol::Anthropic, &anth_partial),
            "Anthropic 永不注入"
        );
        let non_dict = serde_json::json!([1, 2]);
        assert!(!should_inject_stream_options(Protocol::Chat, &non_dict));
        let mut body = chat_stream.clone();
        inject_stream_options(&mut body);
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn 占位符三条件() {
        assert!(should_inject_placeholders(true, true, true));
        assert!(!should_inject_placeholders(false, true, true));
        assert!(!should_inject_placeholders(true, false, true));
        assert!(!should_inject_placeholders(true, true, false));
    }

    #[test]
    fn 占位符注入三协议形态() {
        let prompt = "PROMPT";
        let openai = serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&openai).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["role"], "system");
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains(prompt)
        );

        let sys_first = serde_json::json!({"messages":[{"role":"system","content":"你是助手"},{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&sys_first).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("你是助手")
        );
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains(prompt)
        );

        let empty_msgs = serde_json::json!({"messages":[]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&empty_msgs).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["content"].as_str().unwrap(), prompt);

        let anth = serde_json::json!({"model":"m","system":"你是助手"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&anth).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["system"].as_str().unwrap().contains(prompt));

        let anth_none = serde_json::json!({"model":"m"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&anth_none).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["system"].as_str().unwrap(), prompt);

        let resp = serde_json::json!({"input":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["input"][0]["role"], "system");

        assert!(inject_placeholder_prompt("plain text", prompt, Protocol::Chat).is_none());
        assert!(inject_placeholder_prompt("[1,2]", prompt, Protocol::Chat).is_none());
        assert!(inject_placeholder_prompt("", prompt, Protocol::Chat).is_none());
        assert!(!has_placeholder_tokens(b"no tokens here"));
        assert!(has_placeholder_tokens(b"a __PII_1_ab12cd34__ b"));
        assert!(has_placeholder_tokens(b"a __VG_CRED_000001__ b"));
    }

    #[test]
    fn 非流式usage同流式口径() {
        let chat =
            serde_json::json!({"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Chat, &chat)
                .unwrap()
                .total_tokens,
            3
        );
        let resp = serde_json::json!({"response":{"usage":{"prompt_tokens":4,"completion_tokens":5,"total_tokens":9}}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Responses, &resp)
                .unwrap()
                .total_tokens,
            9
        );
        let bad_resp = serde_json::json!({"usage":{"total_tokens":9}});
        assert!(extract_usage_nonstream(Protocol::Responses, &bad_resp).is_none());
        let anth =
            serde_json::json!({"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Anthropic, &anth)
                .unwrap()
                .total_tokens,
            5
        );
        let anth_nested = serde_json::json!({"message":{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Anthropic, &anth_nested)
                .unwrap()
                .total_tokens,
            2
        );
        assert!(extract_usage_nonstream(Protocol::NonDialog, &chat).is_none());
    }

    #[test]
    fn responses双层回退与归一别名() {
        let double = serde_json::json!({"response":{"response":{"usage":{"prompt_tokens":7,"completion_tokens":8,"total_tokens":15}}}});
        let u = extract_usage_nonstream(Protocol::Responses, &double).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (7, 8, 15)
        );
        let single = serde_json::json!({"response":{"usage":{"input_tokens":4,"output_tokens":6}}});
        let u = extract_usage_nonstream(Protocol::Responses, &single).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (4, 6, 10)
        );
        let stream_double = serde_json::json!({"type":"response.completed","response":{"response":{"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}}});
        let u = extract_usage_stream(Protocol::Responses, &stream_double).unwrap();
        assert_eq!(u.total_tokens, 5);
        let stream_single = serde_json::json!({"type":"response.completed","response":{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}});
        let u = extract_usage_stream(Protocol::Responses, &stream_single).unwrap();
        assert_eq!(u.total_tokens, 3);
        let chat_ev =
            serde_json::json!({"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}});
        assert!(extract_usage_stream(Protocol::Chat, &chat_ev).is_some());
        assert!(extract_usage_stream(Protocol::Chat, &serde_json::json!({"delta":"hi"})).is_none());
        let anth_delta = serde_json::json!({"delta":{"usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30}}});
        assert_eq!(
            extract_usage_stream(Protocol::Anthropic, &anth_delta)
                .unwrap()
                .total_tokens,
            30
        );
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"message":{"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}}),
            ),
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(Protocol::Anthropic, &anth_delta),
        );
        let a = acc.unwrap();
        assert_eq!(
            (a.prompt_tokens, a.completion_tokens, a.total_tokens),
            (10, 20, 30),
            "双段按字段单调 max，不求和双计"
        );
    }

    #[test]
    fn 流式usage双段单调max不双计且快路径兼查裸键() {
        let start =
            serde_json::json!({"type":"message_start","message":{"usage":{"input_tokens":5}}});
        let delta = serde_json::json!({"type":"message_delta","usage":{"output_tokens":20}});
        let mut acc: Option<Usage> = None;
        accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &start));
        accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &delta));
        let a = acc.unwrap();
        assert_eq!((a.prompt_tokens, a.completion_tokens), (5, 20));
        let bare = serde_json::json!({"delta":{"input_tokens":5}});
        assert!(
            extract_usage_stream(Protocol::Anthropic, &bare).is_none(),
            "裸键分片过快路径门后仍按归一口径返回 None，不估算"
        );
        let heartbeat = serde_json::json!({"delta":"hi"});
        assert!(extract_usage_stream(Protocol::Anthropic, &heartbeat).is_none());
    }

    #[test]
    fn responses流式单层usage优先于双层() {
        let both = serde_json::json!({"response":{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"response":{"usage":{"prompt_tokens":9,"completion_tokens":9,"total_tokens":18}}}});
        let u = extract_usage_stream(Protocol::Responses, &both).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (1, 1, 2)
        );
    }

    #[test]
    fn 空体502四分支() {
        assert_eq!(
            classify_empty(true, true, 0, false, 200),
            EmptyAction::StreamInjectThen502
        );
        assert_eq!(
            classify_empty(true, false, 0, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, false, 10, false, 200),
            EmptyAction::NonStreamTo502
        );
        assert_eq!(
            classify_empty(true, false, 10, true, 502),
            EmptyAction::Passthrough502_401
        );
        assert_eq!(
            classify_empty(true, true, 5, true, 401),
            EmptyAction::Passthrough502_401
        );
        assert_eq!(
            classify_empty(false, false, 0, false, 200),
            EmptyAction::NonDialogExempt
        );
    }

    #[test]
    fn 上游端口映射解析() {
        use std::collections::HashMap;
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://m.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
            (
                "LLM_8877".to_string(),
                "https://up-a.example.com".to_string(),
            ),
            (
                "LLM_8878".to_string(),
                "https://up-b.example.com".to_string(),
            ),
        ]);
        let cfg = Config::load_from(&env).unwrap();
        assert_eq!(
            resolve_upstream(&cfg, Some(8877)).as_deref(),
            Some("https://up-a.example.com")
        );
        assert_eq!(
            resolve_upstream(&cfg, Some(8878)).as_deref(),
            Some("https://up-b.example.com")
        );
        assert!(resolve_upstream(&cfg, Some(9999)).is_some());
    }

    #[test]
    fn 重试退避曲线() {
        assert_eq!(retry_delay(0), Duration::from_millis(500));
        assert_eq!(retry_delay(1), Duration::from_millis(1000));
        assert_eq!(retry_delay(2), Duration::from_millis(2000));
    }

    #[tokio::test]
    async fn 断开重试退避封顶且最终失败() {
        use axum::http::HeaderMap;
        assert_eq!(retry_delay(3), Duration::from_millis(2000));
        assert_eq!(retry_delay(99), Duration::from_millis(2000));
        assert_eq!(MAX_RETRY_ATTEMPTS, 3);
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let err = fetch_upstream_with_retry(
            &client,
            reqwest::Method::POST,
            "http://127.0.0.1:9/v1/chat/completions",
            HeaderMap::new(),
            b"{}".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(
            start.elapsed() >= Duration::from_millis(3000),
            "三次退避(500+1000+2000)须走完，实测 {:?}",
            start.elapsed()
        );
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn 首连拒收重试后成功() {
        use axum::http::HeaderMap;
        // 预留端口后释放：首连 ECONNREFUSED（可重试类），600ms 后起真服务；
        // 两次退避（500+1000）后第三次命中，验证首连失败仍能恢复。
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("预留端口须成功")
            .local_addr()
            .expect("回环地址须可读")
            .port();
        let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .expect("延迟服务须监听成功");
            let (mut sock, _) = listener.accept().await.expect("须收到重试连接");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 65536];
            let _ = sock.read(&mut buf).await;
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
        });
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let resp = fetch_upstream_with_retry(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            b"{}".to_vec(),
        )
        .await
        .expect("退避后服务就绪须成功");
        assert_eq!(resp.status().as_u16(), 200);
        assert!(
            start.elapsed() >= Duration::from_millis(1200),
            "须走完两次退避才成功，实测 {:?}",
            start.elapsed()
        );
        server.abort();
    }

    #[test]
    fn fix1全集双向大小写不敏感加动态项() {
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("X-Custom-Hop, keep-alive"),
        );
        h.insert("x-custom-hop", HeaderValue::from_static("1"));
        h.insert("TE", HeaderValue::from_static("trailers"));
        h.insert("trailer", HeaderValue::from_static("x"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("proxy-authenticate", HeaderValue::from_static("Basic"));
        h.insert("proxy-authorization", HeaderValue::from_static("Basic x"));
        h.insert("content-encoding", HeaderValue::from_static("gzip"));
        h.insert("content-length", HeaderValue::from_static("10"));
        h.insert("x-real", HeaderValue::from_static("keep"));
        let n = filter_hop_headers_counted(&mut h, "downstream", true, Some(&m));
        assert_eq!(n, 11);
        assert!(h.get("x-real").is_some());
        assert!(h.get("connection").is_none());
        assert!(h.get("x-custom-hop").is_none());
        assert!(h.get("te").is_none());
        assert!(h.get("content-encoding").is_none());
        assert!(h.get("content-length").is_none());
        assert_eq!(m.hop_filtered_count("downstream"), 11);
    }

    #[test]
    fn fix1关闭解码透传编码且双向计数() {
        use axum::http::{HeaderMap, HeaderValue};
        let m = GatewayMetrics::default();
        let mut up = HeaderMap::new();
        up.insert("content-encoding", HeaderValue::from_static("br"));
        up.insert("x-a", HeaderValue::from_static("1"));
        let n = filter_hop_headers_counted(&mut up, "upstream", false, Some(&m));
        assert_eq!(n, 0);
        assert!(up.get("content-encoding").is_some());
        let mut dn = HeaderMap::new();
        dn.insert("connection", HeaderValue::from_static("close"));
        let n2 = filter_hop_headers_counted(&mut dn, "downstream", false, Some(&m));
        assert_eq!(n2, 1);
        assert_eq!(m.hop_filtered_count("upstream"), 0);
        assert_eq!(m.hop_filtered_count("downstream"), 1);
    }

    #[test]
    fn fix3缺id合成call_stable标id_synth() {
        let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"name":"run","arguments":"{}"}}]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_stable_2");
        assert!(calls[0].id_synth);
        assert_eq!(calls[0].name.as_deref(), Some("run"));
    }

    #[test]
    fn fix3保留id且非string_args规范化() {
        let v = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"q","arguments":{"a":1}}}]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "c1");
        assert!(!calls[0].id_synth);
        assert_eq!(calls[0].args, r#"{"a":1}"#);
        let v2 = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"id":"c2","function":{"name":"q"}}]}}]});
        let calls2 = extract_tool_calls(Protocol::Chat, &v2);
        assert_eq!(calls2[0].args, "");
    }

    #[test]
    fn fix3兼容legacy与custom方言() {
        let legacy = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let calls = extract_tool_calls(Protocol::Chat, &legacy);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), Some("old"));
        assert!(calls[0].id_synth);
        let custom = serde_json::json!({"choices":[{"message":{"custom_tool_call":{"id":"k1","name":"t","input":{"p":2}}}}]});
        let calls2 = extract_tool_calls(Protocol::Chat, &custom);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].id, "k1");
        assert_eq!(calls2[0].args, r#"{"p":2}"#);
        let anth = serde_json::json!({"content_block":{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}});
        let calls3 = extract_tool_calls(Protocol::Anthropic, &anth);
        assert_eq!(calls3.len(), 1);
        assert_eq!(calls3[0].args, r#"{"cmd":"ls"}"#);
        let resp = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
        let calls4 = extract_tool_calls(Protocol::Responses, &resp);
        assert_eq!(calls4.len(), 1);
        assert!(calls4[0].id_synth);
    }

    #[test]
    fn fix4宽容计数加models零统计() {
        let m = GatewayMetrics::default();
        for p in [
            "/v1/models",
            "/v1/models/",
            "/v1/models/extra",
            "/v1/fake-chat/completions-extra",
        ] {
            let (hit, _) = is_chat_tail(p, Some(&m));
            assert!(!hit, "{p}");
        }
        assert_eq!(m.lenient_count("chat/completions"), 0);
        assert_eq!(m.lenient_count("v1/messages"), 0);
        assert_eq!(m.lenient_count("v1/responses"), 0);
        let (hit, _) = is_chat_tail("/v1/chat/completions/", Some(&m));
        assert!(hit);
        assert_eq!(m.lenient_count("chat/completions"), 1);
    }

    #[test]
    fn responses增量delta按三级键提取且文本事件放行() {
        let d1 = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":1,"item_id":"item-7","sequence_number":0,"delta":"{\"x\":"});
        let calls = extract_tool_calls(Protocol::Responses, &d1);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 1);
        assert_eq!(calls[0].id, "item-7");
        assert!(!calls[0].id_synth);
        assert_eq!(calls[0].args, "{\"x\":");
        let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":1,"item_id":"item-7","sequence_number":2,"name":"run","arguments":"{\"x\":1}"});
        let calls2 = extract_tool_calls(Protocol::Responses, &done);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].name.as_deref(), Some("run"));
        assert_eq!(calls2[0].args, "{\"x\":1}");
        let text =
            serde_json::json!({"type":"response.output_text.delta","output_index":0,"delta":"hi"});
        assert!(extract_tool_calls(Protocol::Responses, &text).is_empty());
        let item_done = serde_json::json!({"type":"response.output_item.done","output_index":2,"item":{"type":"function_call","id":"c9","name":"q","arguments":"{}"}});
        let calls3 = extract_tool_calls(Protocol::Responses, &item_done);
        assert_eq!(calls3.len(), 1);
        assert_eq!((calls3[0].index, calls3[0].id.as_str()), (2, "c9"));
    }

    #[test]
    fn anthropic多index交错按事件index分桶() {
        let b0 = serde_json::json!({"content_block":{"type":"tool_use","index":3,"id":"a3","name":"t3","input":{}}});
        let calls = extract_tool_calls(Protocol::Anthropic, &b0);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 3);
        let d1 = serde_json::json!({"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"a\":"}});
        let calls2 = extract_tool_calls(Protocol::Anthropic, &d1);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].index, 5);
        assert_eq!(calls2[0].args, "{\"a\":");
        assert!(calls2[0].id_synth);
    }

    #[test]
    fn 占位符四形态注入回退() {
        let prompt = "PROMPT";
        // §2.1：Responses 字符串 input 按串追加注入（与 input 数组同等）。
        let resp_str = serde_json::json!({"model":"m","input":"hello"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp_str).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("字符串 input 须可注入");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["input"].as_str().unwrap().contains(prompt));
        assert!(parsed["input"].as_str().unwrap().contains("hello"));
        let mut v = resp_str.clone();
        assert!(placeholder_inject_obj(&mut v, prompt, Protocol::Responses));
        assert!(placeholder_schema_ok(&v, Protocol::Responses));
        // 非法形态（数字 input）仍回退不注入。
        let resp_bad = serde_json::json!({"model":"m","input":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&resp_bad).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
        let mut vb = resp_bad.clone();
        assert!(!placeholder_inject_obj(&mut vb, prompt, Protocol::Responses));
        assert!(!placeholder_schema_ok(&vb, Protocol::Responses));
        let anth_bad = serde_json::json!({"model":"m","system":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&anth_bad).unwrap(),
                prompt,
                Protocol::Anthropic,
            )
            .is_none()
        );
        let mut v2 = anth_bad.clone();
        assert!(!placeholder_inject_obj(
            &mut v2,
            prompt,
            Protocol::Anthropic
        ));
        assert!(!placeholder_schema_ok(&v2, Protocol::Anthropic));
        let resp_arr = serde_json::json!({"input":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp_arr).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["input"][0]["role"], "system");
        let anth_ok = serde_json::json!({"model":"m","system":"base"});
        let out2 = inject_placeholder_prompt(
            &serde_json::to_string(&anth_ok).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let parsed2: Value = serde_json::from_str(&out2).unwrap();
        assert!(parsed2["system"].as_str().unwrap().contains(prompt));
    }

    #[test]
    fn responses_instructions与input同等注入() {
        let prompt = "PROMPT";
        // instructions 字符串与 input 字符串同时注入。
        let both = serde_json::json!({"input":"hi","instructions":"be nice"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&both).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("双字段须可注入");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["input"].as_str().unwrap().contains(prompt));
        assert!(v["instructions"].as_str().unwrap().contains("be nice"));
        assert!(v["instructions"].as_str().unwrap().contains(prompt));
        // 仅 instructions（无 input）同样可注入。
        let only = serde_json::json!({"instructions":["a"]});
        let out2 = inject_placeholder_prompt(
            &serde_json::to_string(&only).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("仅 instructions 须可注入");
        let v2: Value = serde_json::from_str(&out2).unwrap();
        assert_eq!(v2["instructions"][0]["role"], "system");
        // instructions 非法形态不注入整体回退。
        let bad = serde_json::json!({"input":[{"role":"user","content":"hi"}],"instructions":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&bad).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
        // 两字段皆缺失不注入。
        let none = serde_json::json!({"model":"m"});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&none).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
    }

    #[test]
    fn anthropic外层index交错分桶不串() {
        let start0 = serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a0","name":"run"}});
        let start1 = serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"a1","name":"run"}});
        let d0 = serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":"}});
        let d1 = serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"y\":"}});
        let c0 = extract_tool_calls(Protocol::Anthropic, &start0);
        assert_eq!((c0.len(), c0[0].index), (1, 0));
        assert_eq!(c0[0].id, "a0");
        let c1 = extract_tool_calls(Protocol::Anthropic, &start1);
        assert_eq!((c1.len(), c1[0].index), (1, 1));
        let p0 = extract_tool_calls(Protocol::Anthropic, &d0);
        assert_eq!((p0.len(), p0[0].index), (1, 0));
        assert_eq!(p0[0].args, "{\"x\":");
        let p1 = extract_tool_calls(Protocol::Anthropic, &d1);
        assert_eq!((p1.len(), p1[0].index), (1, 1));
        assert_eq!(p1[0].args, "{\"y\":");
        let inner = serde_json::json!({"content":[{"type":"tool_use","index":7,"id":"z","name":"q","input":{}}]});
        let ci = extract_tool_calls(Protocol::Anthropic, &inner);
        assert_eq!(ci[0].index, 7);
    }

    #[test]
    fn usage累计值分片取max不双计() {
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"message":{"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}}),
            ),
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"delta":{"usage":{"input_tokens":30,"output_tokens":0,"total_tokens":30}}}),
            ),
        );
        let a = acc.as_ref().expect("须有累计值");
        assert_eq!((a.prompt_tokens, a.total_tokens), (30, 30));
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"delta":{"usage":{"input_tokens":9,"output_tokens":1,"total_tokens":10}}}),
            ),
        );
        let a2 = acc.as_ref().expect("须保持累计值");
        assert_eq!(
            (a2.prompt_tokens, a2.completion_tokens, a2.total_tokens),
            (30, 1, 30)
        );
    }

    #[test]
    fn fix6单双层与data_response回退加缺失归档() {
        let m = GatewayMetrics::default();
        let single = serde_json::json!({"type":"response.failed","id":"r1"});
        assert_eq!(extract_conv_id(&single).as_deref(), Some("r1"));
        let dbl = serde_json::json!({"type":"response.incomplete","response":{"id":"r2"}});
        assert_eq!(extract_conv_id(&dbl).as_deref(), Some("r2"));
        let nested = serde_json::json!({"type":"error","data":{"response":{"id":"r3"}}});
        assert_eq!(extract_conv_id(&nested).as_deref(), Some("r3"));
        let err_obj = serde_json::json!({"type":"error","error":{"id":"e1"}});
        assert_eq!(extract_conv_id(&err_obj).as_deref(), Some("e1"));
        let empty = serde_json::json!({"type":"response.failed"});
        assert!(extract_conv_id(&empty).is_none());
        let (archived, exempt) = resolve_conv_id(None, &empty, Some(&m), "failed");
        assert!(archived.starts_with("unknown_") && archived.len() == 8 + 8);
        assert!(!exempt);
        assert_eq!(m.conv_missing_count("failed"), 1);
        let (hid, hexempt) = resolve_conv_id(
            Some("h1"),
            &serde_json::json!({"id":"b1"}),
            Some(&m),
            "failed",
        );
        assert_eq!(hid, "h1");
        assert!(hexempt);
        assert_eq!(m.conv_missing_count("failed"), 1);
    }
}
