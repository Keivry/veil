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
            body.as_object()
                .is_some_and(|m| m.get("stream_options").is_none())
        }
        Protocol::Anthropic | Protocol::NonDialog => false,
    }
}

pub fn inject_stream_options(body: &mut Value) {
    if let Some(map) = body.as_object_mut() {
        map.insert(
            "stream_options".to_string(),
            serde_json::json!({"include_usage": true}),
        );
    }
}

pub fn should_inject_placeholders(
    is_chat: bool,
    redaction_enabled: bool,
    body_has_values: bool,
) -> bool {
    is_chat && redaction_enabled && body_has_values
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

fn usage_from_obj(obj: &serde_json::Map<String, Value>) -> Option<Usage> {
    Some(Usage {
        prompt_tokens: obj
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        completion_tokens: obj
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        total_tokens: obj
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    })
}

pub fn extract_usage_nonstream(protocol: Protocol, body: &Value) -> Option<Usage> {
    match protocol {
        Protocol::Chat => body.get("usage")?.as_object().and_then(usage_from_obj),
        Protocol::Responses => body
            .get("response")?
            .get("usage")?
            .as_object()
            .and_then(usage_from_obj),
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
            for (i, b) in blocks.iter().enumerate() {
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
                    let (id, id_synth) = synth_id(i as u32, None);
                    let name = fc
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let args = normalize_tool_args(fc.get("arguments"));
                    out.push(ToolCall {
                        index: i as u32,
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
                            if let Some(c) = custom_obj_to_call(i as u32, obj) {
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
                let (id, id_synth) = synth_id(i as u32, id_raw);
                out.push(ToolCall {
                    index: i as u32,
                    id,
                    name,
                    args,
                    id_synth,
                });
            }
        }
        Protocol::Responses => {
            if let Some(output) = payload.get("output").and_then(|o| o.as_array()) {
                for (i, item) in output.iter().enumerate() {
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
                        && let Some(c) = custom_obj_to_call(i as u32, inner)
                    {
                        out.push(c);
                        continue;
                    }
                    if let Some(obj) = item.as_object()
                        && let Some(c) = custom_obj_to_call(i as u32, obj)
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
