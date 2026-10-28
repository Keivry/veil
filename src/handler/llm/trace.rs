//! 请求级追踪与终态投影（design §1/§4/§5/§6）。
//!
//! 分工：
//! - [`Outcome`]：非流终态枚举。所有早退（上游未配置、脱敏 fail-closed、空体/非 JSON、
//!   oversize、`redact_only`、非对话透传、上游 4xx/5xx、fetch 失败）都归一为变体， `gateway_serve`
//!   依此在**单点**落行——不依赖 `Drop`，热路径零互斥；
//! - [`NonstreamDetail`]：`serve_nonstream` / `serve_nondialog_passthrough` 的写回点，
//!   承载响应侧用量、回显模型、上游标识、结束原因与 `record_chat*` 的计入返回值；
//! - [`RequestTrace`]：`req_start` 之后立即创建（早于 `resolve_target` 与 NonDialog 分支），
//!   请求体解析后补齐 `model`/会话标识，脱敏后补摘要，终态投影为 [`RequestRow`]；
//! - [`StreamLog`]：流式泵的落行凭据（守卫 + 存储句柄 + 真实上游状态）。流式完成点在
//!   派生任务里，故由 `pump/spawn/finish.rs` 调 `StreamGuard::finish` 落行。
//!
//! 隐私边界（design §6）：`upstream` 只记 `host:port`；会话原文不进行/日志，只留带域
//! 分离的 HMAC 摘要；摘要取自请求侧**已脱敏**正文的白名单投影，
//! `[redaction].enabled=false` 时恒 `NULL`。

use {
    crate::{
        config::Config,
        service::{
            audit::log::sanitize_for_log,
            llm_gateway::{Protocol, Usage, is_passthrough},
            metrics::normalize_model,
            request_log::{
                RequestLog,
                RequestRow,
                SessionInputs,
                SessionScope,
                SessionSource,
                StreamGuard,
                cache_input_tokens,
                derive_session,
            },
        },
    },
    axum::http::HeaderMap,
    serde_json::Value,
    std::{sync::Arc, time::Instant},
};

/// 摘要字符上限（spec「摘要长度有界」）。
pub const SUMMARY_MAX_CHARS: usize = 512;
/// 摘要正文文本叶子累计上限（构造期截断，避免为超长正文分配大字符串）。
const SUMMARY_TEXT_CAP: usize = 8_192;
/// 采样参数白名单（design §6「仅模型、采样参数与对话正文文本叶子」）。
const SAMPLE_KEYS: [&str; 8] = [
    "temperature",
    "top_p",
    "top_k",
    "max_tokens",
    "max_output_tokens",
    "stop",
    "seed",
    "n",
];

/// 非流终态（design §1.1）：所有早退归一为变体，`gateway_serve` 依此单点落行。
#[derive(Debug, Clone)]
pub enum Outcome {
    /// 可解析 JSON 的对话响应（已走完整后处理链），含上游 4xx/5xx 的 JSON 错误体。
    Ok { status: u16, usage: Option<Usage> },
    /// `redact_only` 变体（`count_tokens`）：请求侧脱敏、响应字节保真透传。
    RedactOnly { status: u16 },
    /// 上游不可达/请求失败（网关映射为 502）。
    NoUpstream,
    /// 请求侧脱敏链 fail-closed（502 `E_PII_UNAVAILABLE`）。
    PiiUnavailable,
    /// 请求体不可解析（保留判别位；当前实现按改写语义转发，不拒绝）。
    BadRequest,
    /// 上游 200 但正文为空（网关映射为 502）。
    EmptyBody,
    /// 上游 200 但正文非 JSON（网关映射为 502）。
    NonJson { status: u16 },
    /// 上游正文超 `NONSTREAM_MAX_BYTES`（网关映射为 502）。
    Oversize,
    /// 字节透传（非对话端点，或非 200 非错误状态，或错误状态的非 JSON 正文）。
    Passthrough { status: u16, is_chat: bool },
}

impl Outcome {
    /// 落库状态码（网关自有映射在此单点声明；`NonJson` 的网关响应恒 502）。
    fn status(&self) -> Option<u16> {
        match self {
            Self::Ok { status, .. }
            | Self::RedactOnly { status }
            | Self::Passthrough { status, .. } => Some(*status),
            Self::NoUpstream
            | Self::PiiUnavailable
            | Self::EmptyBody
            | Self::NonJson { .. }
            | Self::Oversize => Some(502),
            Self::BadRequest => Some(400),
        }
    }

    /// 错误分类（成功路径为 `None`）。
    fn error_kind(&self) -> Option<&'static str> {
        match self {
            Self::Ok { status, .. }
            | Self::RedactOnly { status }
            | Self::Passthrough { status, .. } => (*status >= 400).then_some("upstream_status"),
            Self::NoUpstream => Some("upstream_unreachable"),
            Self::PiiUnavailable => Some("pii_fail_closed"),
            Self::BadRequest => Some("bad_request"),
            Self::EmptyBody => Some("empty_body"),
            Self::NonJson { .. } => Some("non_json"),
            Self::Oversize => Some("response_too_large"),
        }
    }
}

/// 非流终态详情：由 `serve_nonstream` / `serve_nondialog_passthrough` 写回，
/// `gateway_serve` 读取后单点落行。
#[derive(Debug, Clone, Default)]
pub struct NonstreamDetail {
    /// 终态枚举（`None` = 该单元未声明，落行按 502 兜底）。
    pub outcome: Option<Outcome>,
    /// 上游回显模型（优先于请求侧 model）。
    pub model: Option<String>,
    /// 上游响应标识（`chatcmpl-…` / `resp_…` / `msg_…`）。
    pub upstream_id: Option<String>,
    /// 结束原因（Chat `finish_reason` / Anthropic `stop_reason` / Responses `status`）。
    pub finish_reason: Option<String>,
    /// `record_chat*` 的返回值——与 KPI `requests` 同集合的唯一桥接。
    pub counted_metrics: bool,
}

impl NonstreamDetail {
    /// 记录终态枚举（其余字段由调用方按需写入）。
    pub fn set_outcome(&mut self, outcome: Outcome) { self.outcome = Some(outcome); }
}

/// 流式落行凭据（随 `StreamPumpCtx` 进派生任务）。
pub struct StreamLog {
    pub guard: StreamGuard,
    pub request_log: Arc<RequestLog>,
    /// 真实上游状态码（成功 2xx、上游 5xx 照抄、fetch 失败 502）。
    pub upstream_status: u16,
}

/// 请求级追踪快照（`req_start` 之后、`resolve_target` 之前创建）。
pub struct RequestTrace {
    request_id: String,
    ts_secs: i64,
    protocol: Protocol,
    upstream: Option<String>,
    ingress_port: Option<u16>,
    stream: bool,
    is_chat: bool,
    req_model: String,
    session_id: Option<String>,
    session_source: SessionSource,
    session_scope: SessionScope,
    req_summary: Option<String>,
    redaction_enabled: bool,
    req_start: Instant,
}

impl RequestTrace {
    /// 建追踪：只取此刻已确定的请求级字段（协议、入口端口、起始时刻）。
    pub fn new(
        request_id: String,
        protocol: Protocol,
        ingress_port: Option<u16>,
        redaction_enabled: bool,
        req_start: Instant,
    ) -> Self {
        Self {
            request_id,
            ts_secs: crate::handler::llm::pump::now_secs(),
            protocol,
            upstream: None,
            ingress_port,
            stream: false,
            is_chat: !is_passthrough(protocol),
            req_model: String::new(),
            session_id: None,
            session_source: SessionSource::None,
            session_scope: SessionScope::None,
            req_summary: None,
            redaction_enabled,
            req_start,
        }
    }

    pub fn protocol(&self) -> Protocol { self.protocol }

    pub fn ingress_port(&self) -> Option<u16> { self.ingress_port }

    pub fn is_chat(&self) -> bool { self.is_chat }

    /// 显式覆写落行的 `is_chat` 判别位。
    ///
    /// 默认值由协议推导（`!is_passthrough(protocol)`），但 `count_tokens` 这类
    /// `redact_only` 变体虽复用 Anthropic 协议线、走对话臂做请求侧脱敏，其语义
    /// **不是**对话请求，落行须显式置 `false`（不改分派臂，仅改投影）。
    pub fn set_is_chat(&mut self, is_chat: bool) { self.is_chat = is_chat; }

    pub fn req_start(&self) -> Instant { self.req_start }

    /// 选路结果确定后写入 `upstream`（只留 `host:port`）。
    pub fn set_upstream(&mut self, authority: Option<String>) { self.upstream = authority; }

    /// 客户端是否要求流式（`redact_only` 恒走非流有界读，故不置位）。
    pub fn mark_stream(&mut self, stream: bool) { self.stream = stream; }

    /// 请求体解析后补齐 `model` 与会话标识（design §4）。
    ///
    /// 会话解析与 PII 作用域解耦：`request` 模式下同样能取到显式头与各协议标识字段；
    /// 原文不落库，只留 HMAC 摘要。`body` 为 `None` 时（非对话端点）仅显式头可派生。
    pub fn attach_identity(&mut self, body: Option<&Value>, headers: &HeaderMap, config: &Config) {
        let header = headers
            .get(config.pii_scope_key_header.as_str())
            .and_then(|v| v.to_str().ok());
        // `conversation` 的 `{id}` 形态需折算为字符串，故在此持有所有权。
        let conversation = body.and_then(|v| match v.get("conversation") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Object(o)) => o.get("id").and_then(Value::as_str).map(str::to_owned),
            _ => None,
        });
        let inputs = SessionInputs {
            header,
            conversation: conversation.as_deref(),
            previous_response_id: text_at(body, &["previous_response_id"]),
            previous_message_id: text_at(body, &["diagnostics", "previous_message_id"]),
            prompt_cache_key: text_at(body, &["prompt_cache_key"]),
            metadata_user_id: text_at(body, &["metadata", "user_id"]),
            safety_identifier: text_at(body, &["safety_identifier"]),
            user: text_at(body, &["user"]),
        };
        // 密钥只取既有可选 env（空串已由配置层过滤为 `None`）——缺失即「无会话」，
        // 不退化为无密钥哈希或进程随机盐（design §4）。
        let key = config
            .pii_value_sample_hmac_key
            .as_deref()
            .map(str::as_bytes);
        match derive_session(&inputs, key, self.protocol.wire_name()) {
            Some((id, source, scope)) => {
                self.session_id = Some(id);
                self.session_source = source;
                self.session_scope = scope;
            }
            None => {
                self.session_id = None;
                self.session_source = SessionSource::None;
                self.session_scope = SessionScope::None;
            }
        }
        self.req_model = body
            .and_then(|v| v.get("model"))
            .and_then(Value::as_str)
            .filter(|m| !m.is_empty())
            .unwrap_or("")
            .to_string();
    }

    /// 拿到脱敏后请求体后立即生成摘要（design §6）；脱敏关闭时恒 `None`。
    pub fn attach_summary(&mut self, redacted_body: Option<&Value>) {
        self.req_summary = if self.redaction_enabled {
            project_summary(redacted_body)
        } else {
            None
        };
    }

    /// 终态投影：非流路径的**唯一**落行构造点（调用方随即 [`record_row`]）。
    pub fn finish(&self, outcome: &Outcome, detail: &NonstreamDetail) -> RequestRow {
        let mut row = self.row_base();
        if let Some(model) = detail.model.as_deref().filter(|m| !m.is_empty()) {
            row.model = normalize_model(model);
        }
        if let Outcome::Passthrough { is_chat, .. } = outcome {
            row.is_chat = *is_chat;
        }
        row.upstream_id = detail.upstream_id.clone();
        row.finish_reason = detail.finish_reason.clone();
        row.status = outcome.status();
        row.error_kind = outcome.error_kind().map(str::to_string);
        row.counted_metrics = detail.counted_metrics;
        if let Outcome::Ok { usage, .. } = outcome {
            apply_usage(&mut row, usage.as_ref());
        }
        row.latency_ms = elapsed_ms(self.req_start);
        row
    }

    /// 建待写行（流式交给 [`StreamGuard`]，终态由泵侧补全）。
    pub fn into_row(&self) -> RequestRow {
        let mut row = self.row_base();
        row.latency_ms = elapsed_ms(self.req_start);
        row
    }

    fn row_base(&self) -> RequestRow {
        RequestRow {
            ts_secs: self.ts_secs,
            request_id: self.request_id.clone(),
            protocol: self.protocol.wire_name().to_string(),
            model: normalize_model(&self.req_model),
            upstream: self.upstream.clone(),
            ingress_port: self.ingress_port,
            stream: self.stream,
            is_chat: self.is_chat,
            session_id: self.session_id.clone(),
            session_source: self.session_source.as_str().to_string(),
            session_scope: self.session_scope.as_str().to_string(),
            req_summary: self.req_summary.clone(),
            ..RequestRow::default()
        }
    }
}

/// 唯一落库助手：`RequestLog::record` 在 handler 层的唯一调用点。
pub fn record_row(log: &RequestLog, row: RequestRow) { log.record(row); }

/// token 四列 + 输入缓存命中率分母（与 `RequestRow` 落列口径一致）。
fn apply_usage(row: &mut RequestRow, usage: Option<&Usage>) {
    let Some(usage) = usage else {
        return;
    };
    row.prompt_tokens = usage.prompt_tokens;
    row.completion_tokens = usage.completion_tokens;
    row.total_tokens = usage.total_tokens;
    row.cached_read = usage.cached_read;
    row.cached_write = usage.cached_write;
    row.cache_input_tokens = cache_input_tokens(
        &row.protocol,
        usage.prompt_tokens,
        usage.cached_read,
        usage.cached_write,
    );
}

fn elapsed_ms(start: Instant) -> u64 { start.elapsed().as_millis() as u64 }

/// 按路径取非空字符串叶子（缺失/非字符串/空串一律 `None`）。
fn text_at<'a>(body: Option<&'a Value>, path: &[&str]) -> Option<&'a str> {
    let mut cur = body?;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().filter(|s| !s.is_empty())
}

/// 上游 `host:port`（剥 scheme、路径、查询串与 userinfo；design §6）。
pub fn upstream_authority(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, tail)| tail);
    let authority = rest.split(['/', '?', '#']).next()?.trim();
    if authority.is_empty() {
        return None;
    }
    // `user:pass@host:port` 形态不得把凭据写进行。
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!host.is_empty()).then(|| host.to_string())
}

/// 结束原因（响应体/流事件）：Chat `finish_reason`、Anthropic `stop_reason`、
/// Responses `incomplete_details.reason`（回退 `status`）。
///
/// Responses 的流式事件把终态放在 `response` 信封内（`response.completed` /
/// `response.incomplete` / `response.failed`），故顶层缺失时回退读取
/// `value.response.incomplete_details.reason` 与 `value.response.status`。
/// 非流响应体的字段在顶层，两处口径一致。
pub fn finish_reason_of(protocol: Protocol, value: &Value) -> Option<String> {
    let non_empty = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    if protocol.is_chat() {
        return non_empty(value.get("finish_reason")).or_else(|| {
            value
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|choices| {
                    choices
                        .iter()
                        .find_map(|c| non_empty(c.get("finish_reason")))
                })
        });
    }
    if protocol.is_anthropic() {
        return non_empty(value.get("stop_reason"))
            .or_else(|| non_empty(value.get("delta").and_then(|d| d.get("stop_reason"))));
    }
    non_empty(
        value
            .get("incomplete_details")
            .and_then(|d| d.get("reason")),
    )
    .or_else(|| non_empty(value.get("status")))
    .or_else(|| {
        let response = value.get("response")?;
        non_empty(
            response
                .get("incomplete_details")
                .and_then(|d| d.get("reason")),
        )
        .or_else(|| non_empty(response.get("status")))
    })
}

/// 脱敏摘要白名单投影（design §6）：仅 `model`、采样参数与对话正文文本叶子。
///
/// 只按下表取值，结构上不可能把 `prompt_cache_key`/`user`/`safety_identifier`/
/// `metadata`/`conversation`/`previous_response_id`/`diagnostics` 等标识字段带进摘要。
/// 正文只收 `content`/`text` 叶子，`role`/`type`/`id` 等结构键不透出。
fn project_summary(body: Option<&Value>) -> Option<String> {
    let body = body?;
    if !body.is_object() {
        return None;
    }
    let mut projected = serde_json::Map::new();
    if let Some(model) = body.get("model") {
        projected.insert("model".to_string(), model.clone());
    }
    for key in SAMPLE_KEYS {
        if let Some(value) = body.get(key) {
            projected.insert(key.to_string(), value.clone());
        }
    }
    let mut text = String::new();
    for key in ["messages", "system", "input"] {
        if let Some(node) = body.get(key) {
            push_text_leaves(node, &mut text);
        }
    }
    if !text.is_empty() {
        projected.insert("text".to_string(), Value::String(text));
    }
    if projected.is_empty() {
        return None;
    }
    let json = serde_json::to_string(&Value::Object(projected)).ok()?;
    // 先脱敏（控制字符/密钥形态）后截断，与审计面同一入口。
    let clean = sanitize_for_log(&json);
    let bounded: String = clean.chars().take(SUMMARY_MAX_CHARS).collect();
    (!bounded.is_empty()).then_some(bounded)
}

/// 递归收集文本叶子：只认 `content`/`text` 键。
///
/// 每个候选取**剩余字节预算**内的前缀再入 `out`——单个超长叶子（如 10MB 正文）
/// 不会被整体克隆进中间串，累计长度恒 ≤ [`SUMMARY_TEXT_CAP`]。
fn push_text_leaves(node: &Value, out: &mut String) {
    if out.len() >= SUMMARY_TEXT_CAP {
        return;
    }
    match node {
        Value::String(s) => {
            if s.is_empty() {
                return;
            }
            let budget = SUMMARY_TEXT_CAP
                .saturating_sub(out.len())
                .saturating_sub(usize::from(!out.is_empty()));
            if budget == 0 {
                return;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(prefix_within(s, budget));
        }
        Value::Array(items) => items.iter().for_each(|item| push_text_leaves(item, out)),
        Value::Object(map) => {
            for key in ["content", "text"] {
                if let Some(child) = map.get(key) {
                    push_text_leaves(child, out);
                }
            }
        }
        _ => {}
    }
}

/// 取 `s` 前 `max_bytes` 字节内的前缀，回退到最近的 UTF-8 字符边界。
fn prefix_within(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests;
