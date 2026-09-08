use {
    crate::{
        error::{Result, VeilError},
        service::{self, AuthBlock, CredentialBody, CredentialHeaders},
        state::AppState,
    },
    axum::{
        Json,
        body::Body,
        extract::{ConnectInfo, Request, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    std::net::SocketAddr,
};

pub async fn health_handler(State(state): State<AppState>) -> Json<Value> {
    let health = service::health_status(&state);
    Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "status": if health.sqlite_ok { "ok" } else { "degraded" },
        "unlocked": state.keepass.is_unlocked(),
    }))
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

fn credential_headers(headers: &HeaderMap) -> CredentialHeaders {
    CredentialHeaders::new(
        header_str(headers, "x-get-binary-hash"),
        header_str(headers, "x-get-binary-secret"),
    )
}

pub async fn credential_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CredentialBody>,
) -> Result<Json<Value>> {
    let payload = service::handle_credential(&state, &credential_headers(&headers), &body).await?;
    Ok(Json(json!({ "ok": true, "credential": payload })))
}

pub async fn registrations_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let views = service::list_registrations(
        &state,
        header_str(&headers, "x-admin-token").as_deref(),
        header_str(&headers, "x-get-binary-secret").as_deref(),
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registrations": views })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterBody {
    #[serde(default, alias = "script_path", alias = "path")]
    pub caller_path: String,
    #[serde(default, alias = "script_hash", alias = "hash")]
    pub caller_hash: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default, alias = "desc")]
    pub description: String,
    #[serde(default)]
    pub entries: Option<serde_json::Value>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub fields: Option<serde_json::Value>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default, alias = "auto_approve", alias = "allowMode")]
    pub allow_mode: Option<String>,
    #[serde(default)]
    pub auto: Option<bool>,
}

fn parse_register_entries(body: &RegisterBody) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(v) = body.entries.as_ref() {
        match v {
            serde_json::Value::Object(map) => {
                for (k, fv) in map {
                    let key = k.trim();
                    if key.is_empty() {
                        continue;
                    }
                    let fields = match fv {
                        serde_json::Value::String(s) => {
                            let s = s.trim();
                            if s.is_empty() {
                                vec![]
                            } else {
                                vec![s.to_string()]
                            }
                        }
                        serde_json::Value::Array(items) => items
                            .iter()
                            .filter_map(|i| i.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                            .collect(),
                        _ => vec![],
                    };
                    out.insert(key.to_string(), fields);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    match item {
                        serde_json::Value::String(s) => {
                            let s = s.trim();
                            if !s.is_empty() {
                                out.entry(s.to_string()).or_default();
                            }
                        }
                        serde_json::Value::Object(map) => {
                            for (k, fv) in map {
                                let key = k.trim();
                                if key.is_empty() {
                                    continue;
                                }
                                let fields = match fv {
                                    serde_json::Value::String(s) => {
                                        let s = s.trim();
                                        if s.is_empty() {
                                            vec![]
                                        } else {
                                            vec![s.to_string()]
                                        }
                                    }
                                    serde_json::Value::Array(a) => a
                                        .iter()
                                        .filter_map(|i| i.as_str())
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(str::to_string)
                                        .collect(),
                                    _ => vec![],
                                };
                                out.insert(key.to_string(), fields);
                            }
                        }
                        _ => {}
                    }
                }
            }
            serde_json::Value::String(s) => {
                let s = s.trim();
                if !s.is_empty() {
                    out.entry(s.to_string()).or_default();
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        let single_entry = body
            .entry
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(e) = single_entry {
            let mut fields: Vec<String> = vec![];
            if let Some(f) = body
                .field
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                fields.push(f.to_string());
            }
            if let Some(fv) = body.fields.as_ref() {
                match fv {
                    serde_json::Value::String(s) => {
                        let s = s.trim();
                        if !s.is_empty() && !fields.contains(&s.to_string()) {
                            fields.push(s.to_string());
                        }
                    }
                    serde_json::Value::Array(items) => {
                        for i in items {
                            if let Some(s) = i.as_str().map(str::trim).filter(|s| !s.is_empty())
                                && !fields.contains(&s.to_string())
                            {
                                fields.push(s.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            out.insert(e.to_string(), fields);
        }
    }
    out
}

fn parse_register_allow_mode(body: &RegisterBody) -> Option<crate::config::AutoApprove> {
    use std::str::FromStr as _;
    if let Some(raw) = body
        .allow_mode
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && let Ok(mode) = crate::config::AutoApprove::from_str(raw)
    {
        return Some(mode);
    }
    body.auto.map(|a| {
        if a {
            crate::config::AutoApprove::Allow
        } else {
            crate::config::AutoApprove::Deny
        }
    })
}

pub async fn register_caller_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<Json<Value>> {
    let source = body
        .source
        .clone()
        .or_else(|| header_str(&headers, "x-source").or_else(|| Some("unknown".to_string())));
    let params = crate::registry::RegisterParams {
        caller_path: if body.caller_path.trim().is_empty() {
            String::new()
        } else {
            body.caller_path.trim().to_string()
        },
        caller_hash: body.caller_hash.trim().to_string(),
        name: body.name.trim().to_string(),
        description: body.description.trim().to_string(),
        entries: parse_register_entries(&body),
        allow_mode: parse_register_allow_mode(&body),
    };
    let view =
        service::register_caller_extended(&state, &params, source.as_deref().unwrap_or("unknown"))
            .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct RevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
}

fn revoke_key(body: &RevokeBody) -> Result<String> {
    body.key
        .clone()
        .or_else(|| body.caller_path.clone())
        .or_else(|| body.caller_hash.clone())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| VeilError::BadRequest {
            message: "key/caller_path/caller_hash 三选一必填".to_string(),
        })
}

pub async fn revoke_handler(
    State(state): State<AppState>,
    Json(body): Json<RevokeBody>,
) -> Result<Json<Value>> {
    let view = service::revoke_caller(&state, &revoke_key(&body)?).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmergencyRevokeBody {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub caller_path: Option<String>,
    #[serde(default)]
    pub caller_hash: Option<String>,
    #[serde(default)]
    pub admin_token: Option<String>,
    #[serde(default)]
    pub file_present: bool,
}

pub struct PeerIp(pub Option<String>);

impl<S> axum::extract::FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip().to_string());
        Ok(Self(ip))
    }
}

pub async fn emergency_revoke_handler(
    State(state): State<AppState>,
    peer: PeerIp,
    headers: HeaderMap,
    Json(body): Json<EmergencyRevokeBody>,
) -> Result<Json<Value>> {
    let key = revoke_key(&RevokeBody {
        key: body.key.clone(),
        caller_path: body.caller_path.clone(),
        caller_hash: body.caller_hash.clone(),
    })?;
    let admin_token = body
        .admin_token
        .clone()
        .or_else(|| header_str(&headers, "x-admin-token"));
    // 安全契约（security-compat-fix）：紧急吊销只认 TCP 远端 `ConnectInfo`，
    // MUST NOT 回退 `X-Forwarded-For` 等代理头（伪造头可绕过内网豁免）。
    let peer_ip = peer.0;
    let view = service::emergency_revoke(
        &state,
        &key,
        admin_token.as_deref(),
        peer_ip.as_deref(),
        body.file_present,
    )
    .await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApproveHashChangeBody {
    #[serde(default)]
    pub caller_path: String,
    #[serde(default)]
    pub new_hash: String,
}

pub async fn approve_hash_change_handler(
    State(state): State<AppState>,
    Json(body): Json<ApproveHashChangeBody>,
) -> Result<Json<Value>> {
    let view = service::approve_hash_change(&state, &body.caller_path, &body.new_hash).await?;
    Ok(Json(json!({ "ok": true, "registration": view })))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialRequestBody {
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub auth: Option<AuthBlock>,
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub fields: Option<Value>,
    #[serde(default)]
    pub token: Option<bool>,
}

/// 通用网关 ingress JSON 上限 10MB（检查点：`llm_proxy_handler` 的 `to_bytes`）。
/// spec `admin-ratelimit-contract` + design D4：与 8MB 审计/扫描类上限分属
/// 不同检查点，差异为有意设计；超限返回 413。
pub const GATEWAY_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
/// 审计/扫描类子限 ceiling 8MB（检查点归属声明：审计 hold 与扫描上限类）。
/// 现网可配子限（`AUDIT_HOLD_MAX_BYTES` 默认 1MB、`SCAN_INPUT_LIMIT` 1MB）均
/// 不得超过本 ceiling；本常量由 `audit_scan_body_over_limit` 锁定归属，不改变
/// 现行子限行为，不接任何请求入口（纯回归锚点）。
pub const AUDIT_SUBLIMIT_CEILING_BYTES: usize = 8 * 1024 * 1024;

/// 审计/扫描类体长归属判定（spec 8MB 上限的回归锚点，不接请求路径）。
pub fn audit_scan_body_over_limit(len: usize) -> bool { len > AUDIT_SUBLIMIT_CEILING_BYTES }

/// 通用 ingress 超限响应：413 + 错误码 `E_PAYLOAD_TOO_LARGE`（spec 锁定）。
fn payload_too_large(limit: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({"error":{"code":"E_PAYLOAD_TOO_LARGE","message":format!("请求体超过上限 {limit} 字节")}})),
    )
        .into_response()
}

pub async fn llm_proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let outcome = tokio::spawn(async move {
        // 通用 ingress JSON 检查点 10MB（spec `admin-ratelimit-contract` + design D4）：
        // 超限返回 413，MUST NOT 以 `unwrap_or_default` 静默为空体继续处理。
        let body_bytes = match axum::body::to_bytes(body, GATEWAY_BODY_LIMIT_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => return payload_too_large(GATEWAY_BODY_LIMIT_BYTES),
        };
        gateway_serve(&state, &mut parts, &path, body_bytes).await
    })
    .await;
    match outcome {
        Ok(resp) => resp,
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":{"code":"E_INTERNAL","message":"内部错误"}})),
        )
            .into_response(),
    }
}

// ================= 2.x 网关三单元（veil-hardening D2） =================
// dispatcher（`gateway_serve`）仅保留 protocol/url 分发；
// 改写 / 非流 / 流泵三单元职责单一、可独立单测。
// 约定：Scope/vault/detector 一律经 `Arc` 显式传入，不共享可变全局；
// `spawn` 闭包全 `Arc move`；Client 单例由 1.x 负责，各单元只接受
// `&reqwest::Client` 只读引用，缺失时调用方传入局部分享句柄，不重做。

use {
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::{AuditMode, Config, effective_placeholder_prompt, resolve_upstream_with_ingress},
        service::{
            audit::{self, AuditPolicy},
            audit_hold::{AuditHold, RequestKeepalive},
            block_inject,
            credential_vault::CredentialVault,
            llm_gateway::{
                self,
                EmptyAction,
                GatewayMetrics,
                Protocol,
                classify_empty,
                extract_usage_nonstream,
                is_stream_body,
                resolve_protocol,
            },
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::Scope,
            sse::{
                Speed, SseParser, classify_residue, is_done_payload, set_truncated, strip_sse_bom,
            },
        },
    },
    std::{path::PathBuf, sync::Arc, time::Instant},
};

/// `request_rewrite` 的输出：改写后请求体 + 声明头（纯数据，不触网络）。
pub struct RewriteOutput {
    /// 改写后请求体（默认与输入字节等价，仅 token 子串替换/注入时变化）。
    pub body: Vec<u8>,
    /// 是否做了空白归一化（下游以 `x-veil-normalized` 声明）。
    pub normalized_out: bool,
    /// 客户端是否要求流式（`stream: true`）。
    pub stream_flag: bool,
    /// 改写后请求体中的会话标识（供阻断帧/截断帧复用）。
    pub init_conv: Option<String>,
}

/// 2.1 `request_rewrite` 纯改写：仅做 token 子串替换、stream 选项注入、
/// 占位符说明注入与声明头计算，MUST NOT 发起任何网络 I/O。
/// 仅在对话路径调用（`is_chat` 恒为真，保持原 `should_inject_placeholders(true, ..)` 语义）。
pub async fn request_rewrite(
    body_bytes: Vec<u8>,
    protocol: Protocol,
    config: &Config,
    scope: Arc<Scope>,
    vault: Arc<CredentialVault>,
    detector: Arc<PiiDetector>,
) -> RewriteOutput {
    let original_valid = std::str::from_utf8(&body_bytes).is_ok();
    let original_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let mut body_value: Option<Value> = serde_json::from_slice(&body_bytes).ok();
    let mut normalized_out = false;
    let mut body_bytes = body_bytes;
    let mut redacted_text = original_text.clone();
    if llm_gateway::should_inject_placeholders(
        true,
        config.redaction_enabled,
        !body_bytes.is_empty(),
    ) {
        redacted_text = scope
            .redact_request(&vault, &detector, &original_text)
            .await;
    }
    let need_inject = body_value
        .as_ref()
        .is_some_and(|v| llm_gateway::should_inject_stream_options(protocol, v));
    if need_inject {
        normalized_out = config.normalize_json_whitespace;
        if let Ok(mut v) = serde_json::from_str::<Value>(&redacted_text) {
            llm_gateway::inject_stream_options(&mut v);
            body_value = Some(v);
            body_bytes = serde_json::to_vec(body_value.as_ref().expect("刚注入的请求体"))
                .unwrap_or_default();
        } else if let Some(v) = body_value.as_ref() {
            body_bytes = serde_json::to_vec(v).unwrap_or_default();
        }
    } else if redacted_text != original_text && original_valid {
        body_bytes = redacted_text.into_bytes();
    } else if config.normalize_json_whitespace
        && let Some(v) = body_value.as_ref()
    {
        body_bytes = serde_json::to_vec(v).unwrap_or_default();
        normalized_out = true;
    }
    let stream_flag: bool = serde_json::from_slice::<Value>(&body_bytes)
        .ok()
        .as_ref()
        .is_some_and(is_stream_body)
        || body_value.as_ref().is_some_and(is_stream_body);
    if config.placeholder_prompt_enabled
        && llm_gateway::has_placeholder_tokens(&body_bytes)
        && let Ok(text) = std::str::from_utf8(&body_bytes)
        && let Some(injected) = llm_gateway::inject_placeholder_prompt(
            text,
            effective_placeholder_prompt(&config.placeholder_prompt_text),
            protocol,
        )
    {
        body_bytes = injected.into_bytes();
    }
    let init_conv = body_value.as_ref().and_then(llm_gateway::extract_conv_id);
    RewriteOutput {
        body: body_bytes,
        normalized_out,
        stream_flag,
        init_conv,
    }
}

/// 上游转发头：剥 `host`/`content-length`/`content-encoding` 后做 hop 头过滤并计数。
pub fn forward_headers(incoming: &HeaderMap, metrics: &GatewayMetrics) -> HeaderMap {
    let mut fwd = incoming.clone();
    fwd.remove(header::HOST);
    fwd.remove(header::CONTENT_LENGTH);
    fwd.remove(header::CONTENT_ENCODING);
    llm_gateway::filter_hop_headers_counted(
        &mut fwd,
        "upstream",
        llm_gateway::DECODE_ENABLED,
        Some(metrics),
    );
    fwd
}

fn protocol_header_value(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Chat => "chat",
        Protocol::Anthropic => "anthropic",
        Protocol::Responses => "responses",
        Protocol::NonDialog => "passthrough",
    }
}

fn empty_body_response() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
    )
        .into_response()
}

/// 2.2 `nonstream` 一发一收的上下文：显式传入的请求级依赖快照。
/// `req_start`/`sqlite_precise` 以快照值传入，保持 `record_chat` 快照语义。
pub struct NonstreamCtx {
    pub protocol: Protocol,
    pub normalized_out: bool,
    pub stream_flag: bool,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub audit_mode: AuditMode,
    pub audit_policy_file: Option<PathBuf>,
}

/// `serve_nonstream` 的结果：完整响应，或上游意外回 SSE 时把未消费的
/// `reqwest::Response` 交回调用方转流泵（原 `looks_sse` 语义）。
pub enum NonstreamOutcome {
    Responded(Response),
    Stream(reqwest::Response),
}

/// 2.2 `nonstream` 一发一收：接收改写后请求，返回完整上游响应；
/// 上游超时/不可达映射为网关级错误状态码而非挂起。
/// `client` 为只读引用（单例由 1.x 负责），本单元内不新建 Client。
pub async fn serve_nonstream(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    headers: HeaderMap,
    body: Vec<u8>,
    ctx: NonstreamCtx,
) -> NonstreamOutcome {
    let fwd_headers = forward_headers(&headers, &ctx.gateway_metrics);
    let up = match llm_gateway::fetch_upstream_with_retry(client, method, url, fwd_headers, body)
        .await
    {
        Ok(up) => up,
        Err(_) => return NonstreamOutcome::Responded(empty_body_response()),
    };
    if ctx.protocol == Protocol::NonDialog {
        let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut builder = Response::builder().status(status);
        let mut resp_headers = HeaderMap::new();
        for (k, v) in up.headers().iter() {
            if let (Ok(n), Ok(val)) = (
                k.to_string().parse::<axum::http::HeaderName>(),
                axum::http::HeaderValue::from_bytes(v.as_bytes()),
            ) {
                resp_headers.insert(n, val);
            }
        }
        llm_gateway::filter_hop_headers_counted(
            &mut resp_headers,
            "downstream",
            llm_gateway::DECODE_ENABLED,
            Some(&ctx.gateway_metrics),
        );
        for (k, v) in resp_headers.iter() {
            builder = builder.header(k, v);
        }
        return NonstreamOutcome::Responded(
            builder
                .body(Body::from_stream(up.bytes_stream()))
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "upstream").into_response()),
        );
    }
    let status_u16 = up.status().as_u16();
    if status_u16 == 502 || status_u16 == 401 {
        let status = StatusCode::from_u16(status_u16).unwrap_or(StatusCode::BAD_GATEWAY);
        let bytes = up.bytes().await.unwrap_or_default();
        return NonstreamOutcome::Responded((status, bytes.to_vec()).into_response());
    }
    let resp_ct = up
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let looks_sse = resp_ct.contains("text/event-stream") || ctx.stream_flag;
    if looks_sse {
        return NonstreamOutcome::Stream(up);
    }
    let bytes = up.bytes().await.unwrap_or_default();
    let is_json = serde_json::from_slice::<Value>(&bytes).is_ok();
    if classify_empty(true, false, bytes.len(), is_json, status_u16) == EmptyAction::NonStreamTo502
    {
        return NonstreamOutcome::Responded(empty_body_response());
    }
    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
        let usage = extract_usage_nonstream(ctx.protocol, &v);
        ctx.admin_metrics.record_chat(
            ctx.protocol,
            ctx.req_start.elapsed().as_millis() as u64,
            usage.as_ref(),
            None,
            ctx.sqlite_precise,
            now_secs(),
        );
        // 非流 tool 提取 + 审计（§2.3）：阻断时返回协议正确的 block 体代替上游响应。
        let audit_policy = match ctx.audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let conv_id = llm_gateway::extract_conv_id(&v).unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(None, &v, Some(&ctx.gateway_metrics), "nonstream-block")
                .0
        });
        if let Some(block_body) =
            block_inject::evaluate_nonstream(ctx.protocol, &v, ctx.audit_mode, &audit_policy, &conv_id)
        {
            ctx.admin_metrics.record_aux_counts(
                ctx.protocol,
                now_secs(),
                0,
                0,
                1,
            );
            let mut resp = (
                StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
                Json(block_body),
            )
                .into_response();
            if ctx.normalized_out {
                resp.headers_mut().insert(
                    "x-veil-normalized",
                    header::HeaderValue::from_static("json-whitespace"),
                );
            }
            resp.headers_mut().insert(
                "x-veil-protocol",
                header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
            );
            return NonstreamOutcome::Responded(resp);
        }
        ctx.admin_metrics.record_aux_counts(
            ctx.protocol,
            now_secs(),
            0,
            0,
            0,
        );
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (restored, spans) = ctx.scope.restore_response_with_spans(&ctx.vault, &text);
        let restored = ctx
            .scope
            .redact_response_new_pii_with_skip(&ctx.vault, &ctx.detector, &restored, &spans)
            .await;
        let mut resp = (
            StatusCode::from_u16(status_u16).unwrap_or(StatusCode::OK),
            restored,
        )
            .into_response();
        if ctx.normalized_out {
            resp.headers_mut().insert(
                "x-veil-normalized",
                header::HeaderValue::from_static("json-whitespace"),
            );
        }
        resp.headers_mut().insert(
            "x-veil-protocol",
            header::HeaderValue::from_static(protocol_header_value(ctx.protocol)),
        );
        return NonstreamOutcome::Responded(resp);
    }
    NonstreamOutcome::Responded(empty_body_response())
}

/// 2.3 `stream_pump` 字节泵的上下文：全 `Arc`，`spawn` 闭包全 `Arc move`。
pub struct StreamPumpCtx {
    pub protocol: Protocol,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub audit_mode: AuditMode,
    pub audit_policy_file: Option<PathBuf>,
    pub approval_whitelist: Vec<String>,
    pub hold_max: usize,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub pending: Arc<PendingApprovals>,
    pub init_conv: Option<String>,
    pub normalized_out: bool,
}

/// 流泵结束时的可观测结果（单测断言用）。
pub struct PumpOutcome {
    /// 转发出的 SSE 帧数（含最终 flush）。
    pub forwarded: usize,
    /// 是否注入过阻断帧。
    pub block_injected: bool,
    /// 终止标记是否落到 `StreamMeta`（`terminal_injected`）。
    pub terminal_injected: bool,
}

/// 2.3 `spawn_stream_pump`：把上游字节流泵为下游 SSE 帧流，保证终止闭合；
/// 阻断或合成终止时注入终止标记。`upstream` 所有权移入 task，不解析业务语义之外的状态。
pub fn spawn_stream_pump(
    upstream: reqwest::Response,
    tx: tokio::sync::mpsc::Sender<String>,
    ctx: StreamPumpCtx,
) -> tokio::task::JoinHandle<PumpOutcome> {
    tokio::spawn(async move {
        let StreamPumpCtx {
            protocol,
            scope: resp_scope,
            vault: resp_vault,
            detector: resp_detector,
            audit_mode,
            audit_policy_file,
            approval_whitelist,
            hold_max,
            gateway_metrics: metrics,
            admin_metrics,
            sqlite_precise,
            req_start,
            pending: audit_pending,
            init_conv,
            normalized_out: _,
        } = ctx;
        let mut conv_id = init_conv;
        let hold_gate = Arc::new(std::sync::atomic::AtomicBool::new(!matches!(
            audit_mode,
            AuditMode::Off
        )));
        let keepalive = RequestKeepalive::spawn_gated(tx.clone(), hold_gate.clone());
        let audit_policy = match audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let mut upstream = upstream;
        let pump_tx = tx.clone();
        let speed = if matches!(audit_mode, AuditMode::Off) {
            Speed::Fast
        } else {
            Speed::Slow
        };
        let _keep = keepalive;
        let _gate = hold_gate;
        let mut parser = SseParser::new();
        let mut hold = AuditHold::new(hold_max);
        let mut meta = crate::service::sse::StreamMeta::default();
        let mut forwarded: usize = 0;
        let mut agg = String::new();
        let mut terminated = false;
        let mut rejected_sticky = false;
        let mut block_injected = false;
        // 审计驱动的阻断（策略阻断/超限 fail-closed），与空流/截断合成区分口径。
        let mut audit_blocked = false;
        // 终端去重（§2.6 流式等价）：每协议恰一终止帧，多余 `[DONE]/message_stop/completed` 丢弃。
        let mut terminal_sent = false;
        let mut stream_usage: Option<llm_gateway::Usage> = None;
        // Responses 终端去重旗：上游 `failed` 直接透传、`incomplete`/`error`
        // 合成为单个 `response.failed`，恒恰其一。
        let mut responses_failed_sent = false;
        while let Ok(chunk) = upstream.chunk().await {
            let bytes = match chunk {
                Some(b) => b,
                None => break,
            };
            if bytes.is_empty() {
                continue;
            }
            for ev in parser.push_bytes(&bytes) {
                if ev.is_comment_only {
                    let _ = pump_tx
                        .send(format!(":{}\n\n", ev.comments.join("\n:")))
                        .await;
                    continue;
                }
                if !ev.data.is_empty()
                    && !is_done_payload(&ev.data)
                    && let Ok(v) = serde_json::from_str::<Value>(strip_sse_bom(&ev.data))
                {
                    if let Some(id) = llm_gateway::extract_conv_id(&v) {
                        conv_id = Some(id);
                    }
                    llm_gateway::accumulate_usage(
                        &mut stream_usage,
                        llm_gateway::extract_usage_stream(protocol, &v),
                    );
                }
                _gate.store(
                    hold.held() && !matches!(audit_mode, AuditMode::Off),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if rejected_sticky {
                    if is_done_payload(&ev.data) {
                        continue;
                    }
                    if !ev.data.is_empty() {
                        let terminal = match protocol {
                            Protocol::Anthropic => {
                                ev.data.contains("content_block_stop")
                                    || ev.data.contains("message_delta")
                                    || ev.data.contains("message_stop")
                            }
                            Protocol::Responses => {
                                ev.data.contains("response.completed")
                                    || ev.data.contains("response.failed")
                                    || ev.data.contains("response.incomplete")
                                    || ev.data.contains("\"type\":\"error\"")
                                    || ev.data.contains("\"type\": \"error\"")
                            }
                            _ => false,
                        };
                        if terminal {
                            continue;
                        }
                    }
                    if !ev.data.is_empty()
                        && !is_done_payload(&ev.data)
                        && let Ok(v) = serde_json::from_str::<Value>(strip_sse_bom(&ev.data))
                        && (!extract_tool_fragments(protocol, &v).is_empty()
                            || AuditHold::is_complete_event(&v))
                    {
                        continue;
                    }
                }
                if protocol == Protocol::Responses && !ev.data.is_empty() {
                    let is_failed = ev.data.contains("response.failed");
                    let is_incomplete = ev.data.contains("response.incomplete");
                    let is_error = ev.data.contains("\"type\":\"error\"")
                        || ev.data.contains("\"type\": \"error\"");
                    if is_incomplete || is_error {
                        if !responses_failed_sent {
                            responses_failed_sent = true;
                            terminal_sent = true;
                            let fid = conv_id.clone().unwrap_or_else(|| {
                                llm_gateway::resolve_conv_id(
                                    None,
                                    &serde_json::Value::Null,
                                    Some(&metrics),
                                    "failed",
                                )
                                .0
                            });
                            for f in block_inject::ensure_event_lines(
                                block_inject::responses_truncated_frames(&fid),
                            ) {
                                metrics.add_sse_event();
                                forwarded += 1;
                                if pump_tx.send(f).await.is_err() {
                                    break;
                                }
                            }
                            block_inject::mark_terminal(&mut meta);
                        }
                        terminated = true;
                        continue;
                    }
                    if is_failed {
                        if responses_failed_sent {
                            terminated = true;
                            continue;
                        }
                        responses_failed_sent = true;
                    }
                }
                if !ev.data.is_empty() && !is_done_payload(&ev.data) {
                    if let Ok(v) = serde_json::from_str::<Value>(strip_sse_bom(&ev.data)) {
                        // 终端后不再透出任何数据帧：恰一终止帧且其后无内容。
                        if terminal_sent {
                            continue;
                        }
                        let event_terminal = is_terminal_event(protocol, &v);
                        let frags = extract_tool_fragments(protocol, &v);
                        let is_tool_event = !frags.is_empty();
                        let minor = !is_tool_event && is_minor_event(protocol, &v);
                        if rejected_sticky && is_tool_event {
                            continue;
                        }
                        let mut reject_reason: Option<String> = None;
                        if minor {
                            // 次要事件透传且审计声明放行：不进 hold、不审计。
                        } else if protocol == Protocol::Responses {
                            for frag in &frags {
                                let key = AuditHold::responses_key(frag.1.as_deref(), frag.0);
                                let seq = extract_responses_seq(&v);
                                let verdict = hold.push_responses_fragment(
                                    &key,
                                    frag.0,
                                    seq,
                                    frag.1.as_deref(),
                                    frag.2.as_deref(),
                                    &frag.3,
                                );
                                if verdict == crate::service::audit_hold::HoldVerdict::Rejected {
                                    reject_reason = Some("audit-hold-overflow".to_string());
                                    break;
                                }
                                if AuditHold::is_complete_event(&v) {
                                    hold.mark_responses_done(&key, Some(&frag.3));
                                }
                            }
                        } else {
                            for frag in &frags {
                                if hold.push_fragment(
                                    frag.0,
                                    frag.1.as_deref(),
                                    frag.2.as_deref(),
                                    &frag.3,
                                ) == crate::service::audit_hold::HoldVerdict::Rejected
                                {
                                    reject_reason = Some("audit-hold-overflow".to_string());
                                    break;
                                }
                            }
                        }
                        let mut approve_held = false;
                        if reject_reason.is_none()
                            && !hold.is_rejected()
                            && AuditHold::is_complete_event(&v)
                            && !matches!(audit_mode, AuditMode::Off)
                        {
                            for (idx, name, args) in hold.tool_triples() {
                                match audit::evaluate_with_whitelist(
                                    audit_mode,
                                    &name,
                                    &args,
                                    &audit_policy,
                                    &approval_whitelist,
                                ) {
                                    audit::AuditVerdict::Block { .. } => {
                                        hold.mark_rejected();
                                        reject_reason = Some("audit-policy-block".to_string());
                                        break;
                                    }
                                    audit::AuditVerdict::NeedApproval { reason, summary } => {
                                        audit_pending.insert(PendingRecord::new(
                                            &format!("audit-hold-{idx}-{name}"),
                                            &format!("{reason}: {summary}"),
                                        ));
                                        approve_held = true;
                                    }
                                    audit::AuditVerdict::Allow => {}
                                }
                            }
                        }
                        // §2.5 前置：stop/item_done 只审计并清理对应 index 的槽
                        //（外层序号），不得标记全局完成，后续块照常审计；
                        // 命中阻断落 reject_reason，走下方统一阻断臂注入。
                        if reject_reason.is_none()
                            && !hold.is_rejected()
                            && !matches!(audit_mode, AuditMode::Off)
                            && AuditHold::is_index_complete_event(&v)
                            && let Some(idx) = outer_event_index(protocol, &v)
                        {
                            for (_, name, args) in
                                hold.tool_triples().into_iter().filter(|(i, _, _)| *i == idx)
                            {
                                match audit::evaluate_with_whitelist(
                                    audit_mode,
                                    &name,
                                    &args,
                                    &audit_policy,
                                    &approval_whitelist,
                                ) {
                                    audit::AuditVerdict::Block { .. } => {
                                        hold.mark_rejected();
                                        reject_reason = Some("audit-policy-block".to_string());
                                        break;
                                    }
                                    audit::AuditVerdict::NeedApproval { reason, summary } => {
                                        audit_pending.insert(PendingRecord::new(
                                            &format!("audit-hold-{idx}-{name}"),
                                            &format!("{reason}: {summary}"),
                                        ));
                                    }
                                    audit::AuditVerdict::Allow => {}
                                }
                            }
                            hold.clear_index(idx);
                        }
                        if let Some(reason) = reject_reason {
                            rejected_sticky = true;
                            audit_blocked = true;
                            terminal_sent = true;
                            agg.clear();
                            if !block_injected {
                                block_injected = true;
                                for f in block_inject::ensure_event_lines(match protocol {
                                    Protocol::Chat => block_inject::chat_block_frames(&reason),
                                    Protocol::Anthropic => {
                                        block_inject::anthropic_block_frames(&reason)
                                    }
                                    Protocol::Responses => {
                                        let bid = conv_id.clone().unwrap_or_else(|| {
                                            llm_gateway::resolve_conv_id(
                                                None,
                                                &serde_json::Value::Null,
                                                Some(&metrics),
                                                "block",
                                            )
                                            .0
                                        });
                                        block_inject::responses_block_frames(&bid)
                                    }
                                    Protocol::NonDialog => vec![],
                                }) {
                                    let _ = pump_tx.send(f).await;
                                }
                                block_inject::mark_terminal(&mut meta);
                            }
                            if is_tool_event
                                || AuditHold::is_complete_event(&v)
                                || AuditHold::is_index_complete_event(&v)
                            {
                                continue;
                            }
                        } else if AuditHold::is_complete_event(&v) && !approve_held {
                            hold.mark_completed();
                        }
                        let (restored, spans) =
                            resp_scope.restore_response_with_spans(&resp_vault, &ev.data);
                        let scanned = resp_scope
                            .redact_response_new_pii_with_skip(
                                &resp_vault,
                                &resp_detector,
                                &restored,
                                &spans,
                            )
                            .await;
                        let restored_data = crate::service::sse::json_aware_line(&scanned, |s| s);
                        let prefix = ev
                            .event_type
                            .as_ref()
                            .map(|t| format!("event: {t}\n"))
                            .unwrap_or_default();
                        if event_terminal {
                            terminal_sent = true;
                        }
                        agg.push_str(&prefix);
                        agg.push_str(&format!("data: {restored_data}\n\n"));
                        if !minor && hold.held() && !restored_data.is_empty() {
                            continue;
                        }
                    } else {
                        // 非 JSON 文本同样走 span 跳过还原，终端后不再透出。
                        if terminal_sent {
                            continue;
                        }
                        let (restored, spans) =
                            resp_scope.restore_response_with_spans(&resp_vault, &ev.data);
                        let scanned = resp_scope
                            .redact_response_new_pii_with_skip(
                                &resp_vault,
                                &resp_detector,
                                &restored,
                                &spans,
                            )
                            .await;
                        let prefix = ev
                            .event_type
                            .as_ref()
                            .map(|t| format!("event: {t}\n"))
                            .unwrap_or_default();
                        agg.push_str(&prefix);
                        agg.push_str(&format!("data: {scanned}\n\n"));
                    }
                } else if ev.data.is_empty() {
                    // 空心跳帧：原样透出，不参与终端计数。
                    let prefix = ev
                        .event_type
                        .as_ref()
                        .map(|t| format!("event: {t}\n"))
                        .unwrap_or_default();
                    agg.push_str(&format!("{prefix}data: {}\n\n", ev.data));
                } else {
                    // `[DONE]`（含 BOM 前缀）：恰一终止帧，多余去重。
                    if terminal_sent {
                        continue;
                    }
                    terminal_sent = true;
                    let prefix = ev
                        .event_type
                        .as_ref()
                        .map(|t| format!("event: {t}\n"))
                        .unwrap_or_default();
                    agg.push_str(&format!("{prefix}data: [DONE]\n\n"));
                }
                if let Some(out) = crate::service::sse::select_emit(&mut agg, speed) {
                    metrics.add_sse_event();
                    forwarded += 1;
                    if pump_tx.send(out).await.is_err() {
                        break;
                    }
                }
            }
            if terminated {
                break;
            }
        }
        if !agg.is_empty() {
            metrics.add_sse_event();
            let _ = pump_tx.send(std::mem::take(&mut agg)).await;
            forwarded += 1;
        }
        let residual = parser.residual_json_aware();
        // 残余分类（§2.6）：None 直接丢弃，不得 `data:` 直发；
        // BOM/`[DONE]`/空白同样归入丢弃，终端去重已处理。
        if let Some(classified) = classify_residue(&residual) {
            let (restored, spans) =
                resp_scope.restore_response_with_spans(&resp_vault, &classified);
            let scanned = resp_scope
                .redact_response_new_pii_with_skip(&resp_vault, &resp_detector, &restored, &spans)
                .await;
            if !scanned.is_empty() {
                let _ = pump_tx.send(format!("data: {scanned}\n\n")).await;
            }
        }
        if forwarded == 0 && !block_injected {
            block_injected = true;
            let proto_name = protocol_header_value(protocol);
            let tid = conv_id.clone().unwrap_or_else(|| {
                llm_gateway::resolve_conv_id(
                    None,
                    &serde_json::Value::Null,
                    Some(&metrics),
                    "truncated",
                )
                .0
            });
            for f in block_inject::ensure_event_lines(block_inject::empty_stream_frames(
                proto_name, &tid,
            )) {
                let _ = pump_tx.send(f).await;
            }
            let _ = set_truncated(
                &mut meta,
                protocol,
                if protocol == Protocol::Responses {
                    crate::service::sse::TruncatedMode::SynthesizedFailed
                } else {
                    crate::service::sse::TruncatedMode::OpenEnded
                },
                Some(&metrics),
            );
            block_inject::mark_terminal(&mut meta);
            terminated = true;
        }
        let _ = terminated;
        _gate.store(false, std::sync::atomic::Ordering::Relaxed);
        admin_metrics.record_chat(
            protocol,
            req_start.elapsed().as_millis() as u64,
            stream_usage.as_ref(),
            meta.truncated_mode.as_ref().map(|m| m.as_str()),
            sqlite_precise,
            now_secs(),
        );
        admin_metrics.record_aux_counts(
            protocol,
            now_secs(),
            0,
            0,
            u64::from(audit_blocked),
        );
        PumpOutcome {
            forwarded,
            block_injected,
            terminal_injected: meta.terminal_injected,
        }
    })
}

/// 2.3 `build_sse_response`：把泵出的帧通道装成下游 SSE 响应，保留
/// `x-veil-normalized` 声明与 `X-Accel-Buffering: no`。
pub fn build_sse_response(
    rx: tokio::sync::mpsc::Receiver<String>,
    normalized_out: bool,
) -> Response {
    use bytes::Bytes;
    let stream = async_stream::stream! {
        let mut rx = rx;
        while let Some(msg) = rx.recv().await {
            yield Ok::<_, anyhow::Error>(Bytes::from(msg));
        }
    };
    let mut stream_builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache");
    if normalized_out {
        stream_builder = stream_builder.header("x-veil-normalized", "json-whitespace");
    }
    stream_builder
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "stream").into_response())
}

async fn gateway_serve(
    state: &AppState,
    parts: &mut axum::http::request::Parts,
    path: &str,
    body_bytes: Vec<u8>,
) -> Response {
    let req_start = Instant::now();
    let ct = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // dispatcher 仅保留 protocol/url 分发。
    let protocol = resolve_protocol(path, ct.as_deref(), Some(&state.gateway_metrics));
    let is_chat = protocol != Protocol::NonDialog;
    // 入口宿主机端口（entry-transport）：`Host: ip:port` 尾段解析，
    // 缺失/非法回退 None（缺省上游），不猜测。
    let ingress_port: Option<u16> = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .and_then(|host| {
            host.rsplit(':').next().and_then(|tail| {
                if host.contains(':') {
                    tail.trim().parse::<u16>().ok()
                } else {
                    None
                }
            })
        });
    let upstream_base = match resolve_upstream_with_ingress(&state.config, ingress_port) {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游未配置"}})),
            )
                .into_response();
        }
    };
    let url = format!("{}{}", upstream_base.trim_end_matches('/'), path);
    let client: &reqwest::Client = &state.http_client;
    let scope = Arc::new(Scope::with_opts(
        state.config.pii_response_side,
        state.config.pii_fuzzy_restore,
    ));
    // 全局单例快照（credential-vault-singleton）：网关只读复用进程级
    // vault/detector，不得每请求新建空映射致还原断链。
    let vault = state.vault.clone();
    let detector = state.detector.clone();
    let sqlite_precise = state.sqlite_ok();
    let hold_max = state.config.audit_hold_max_bytes.max(1) as usize;
    let audit_mode = state.config.audit_mode;
    let audit_policy_file = state.config.audit_policy_file.clone();
    let approval_whitelist = state.config.approval_whitelist.clone();

    if !is_chat {
        let upstream_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
            .unwrap_or(reqwest::Method::GET);
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy_file: audit_policy_file.clone(),
        };
        return match serve_nonstream(
            client,
            upstream_method,
            &url,
            parts.headers.clone(),
            body_bytes,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 非对话本不应回 SSE；上游意外回流时仍按字节泵闭合。
            NonstreamOutcome::Stream(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let pctx = StreamPumpCtx {
                    protocol,
                    scope,
                    vault,
                    detector,
                    audit_mode: state.config.audit_mode,
                    audit_policy_file: state.config.audit_policy_file.clone(),
                    approval_whitelist: state.config.approval_whitelist.clone(),
                    hold_max,
                    gateway_metrics: state.gateway_metrics.clone(),
                    admin_metrics: state.admin.metrics.clone(),
                    sqlite_precise,
                    req_start,
                    pending: state.pending.clone(),
                    init_conv: None,
                    normalized_out: false,
                };
                let _pump = spawn_stream_pump(up, tx, pctx);
                build_sse_response(rx, false)
            }
        };
    }

    let rw = request_rewrite(
        body_bytes,
        protocol,
        &state.config,
        scope.clone(),
        vault.clone(),
        detector.clone(),
    )
    .await;
    let dialog_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let pump_ctx = || StreamPumpCtx {
        protocol,
        scope: scope.clone(),
        vault: vault.clone(),
        detector: detector.clone(),
        audit_mode,
        audit_policy_file: audit_policy_file.clone(),
        approval_whitelist: approval_whitelist.clone(),
        hold_max,
        gateway_metrics: state.gateway_metrics.clone(),
        admin_metrics: state.admin.metrics.clone(),
        sqlite_precise,
        req_start,
        pending: state.pending.clone(),
        init_conv: rw.init_conv.clone(),
        normalized_out: rw.normalized_out,
    };
    if rw.stream_flag {
        let fwd_headers = forward_headers(&parts.headers, &state.gateway_metrics);
        match llm_gateway::fetch_upstream_with_retry(
            client,
            dialog_method,
            &url,
            fwd_headers,
            rw.body,
        )
        .await
        {
            Ok(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
            Err(_) => empty_body_response(),
        }
    } else {
        let nctx = NonstreamCtx {
            protocol,
            normalized_out: rw.normalized_out,
            stream_flag: false,
            scope: scope.clone(),
            vault: vault.clone(),
            detector: detector.clone(),
            gateway_metrics: state.gateway_metrics.clone(),
            admin_metrics: state.admin.metrics.clone(),
            sqlite_precise,
            req_start,
            audit_mode,
            audit_policy_file: audit_policy_file.clone(),
        };
        match serve_nonstream(
            client,
            dialog_method,
            &url,
            parts.headers.clone(),
            rw.body,
            nctx,
        )
        .await
        {
            NonstreamOutcome::Responded(resp) => resp,
            // 客户端未要求流但上游回 SSE 时，转字节泵保证终止闭合。
            NonstreamOutcome::Stream(up) => {
                let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);
                let _pump = spawn_stream_pump(up, tx, pump_ctx());
                build_sse_response(rx, rw.normalized_out)
            }
        }
    }
}

#[cfg(test)]
mod gateway_units_tests {
    use {super::*, std::collections::HashMap};

    fn base_env() -> HashMap<String, String> {
        HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
        ])
    }

    fn test_config(extra: &[(&str, &str)]) -> Config {
        let mut env = base_env();
        for (k, v) in extra {
            env.insert((*k).to_string(), (*v).to_string());
        }
        Config::load_from(&env).expect("测试配置须合法")
    }

    fn fresh_arcs() -> (Arc<Scope>, Arc<CredentialVault>, Arc<PiiDetector>) {
        (
            Arc::new(Scope::new()),
            Arc::new(CredentialVault::new()),
            Arc::new(PiiDetector::new()),
        )
    }

    fn nonstream_ctx(
        protocol: Protocol,
        scope: Arc<Scope>,
        vault: Arc<CredentialVault>,
        detector: Arc<PiiDetector>,
    ) -> NonstreamCtx {
        NonstreamCtx {
            protocol,
            normalized_out: false,
            stream_flag: false,
            scope,
            vault,
            detector,
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            audit_mode: AuditMode::Off,
            audit_policy_file: None,
        }
    }

    fn pump_ctx(
        protocol: Protocol,
        scope: Arc<Scope>,
        vault: Arc<CredentialVault>,
        detector: Arc<PiiDetector>,
    ) -> StreamPumpCtx {
        StreamPumpCtx {
            protocol,
            scope,
            vault,
            detector,
            audit_mode: AuditMode::Off,
            audit_policy_file: None,
            approval_whitelist: Vec::new(),
            hold_max: 1_048_576,
            gateway_metrics: Arc::new(GatewayMetrics::default()),
            admin_metrics: Arc::new(MetricsStore::new(std::path::PathBuf::from(
                "/tmp/veil-gateway-units-test.sqlite",
            ))),
            sqlite_precise: false,
            req_start: Instant::now(),
            pending: Arc::new(PendingApprovals::default()),
            init_conv: None,
            normalized_out: false,
        }
    }

    /// 回环上游：固定状态码/内容类型/体，供非流与流泵回放单测（无外网依赖）。
    async fn loopback_server(
        status: u16,
        content_type: &str,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("回环监听须成功");
        let url = format!(
            "http://{}/v1/chat/completions",
            listener.local_addr().expect("回环地址须可读")
        );
        let reason = match status {
            200 => "OK",
            401 => "Unauthorized",
            502 => "Bad Gateway",
            _ => "OK",
        };
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 65536];
                let _ = sock.read(&mut buf).await;
                if sock.write_all(head.as_bytes()).await.is_err() {
                    continue;
                }
                if sock.write_all(&body).await.is_err() {
                    continue;
                }
                let _ = sock.shutdown().await;
            }
        });
        (url, handle)
    }

    /// 预留端口后立即释放，后续连接恒被拒绝（超时/不可达映射单测用）。
    async fn refused_url() -> String {
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("回环监听须成功")
            .local_addr()
            .expect("回环地址须可读")
            .port();
        format!("http://127.0.0.1:{port}/v1/chat/completions")
    }

    #[tokio::test]
    async fn 改写默认字节等价且无网络() {
        let config = test_config(&[]);
        assert!(!config.normalize_json_whitespace);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","messages":[{"role":"user","content":"hello"}]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert_eq!(out.body, raw, "默认关闭空白压缩时除 token 替换外须字节等价");
        assert!(!out.normalized_out);
        assert!(!out.stream_flag);
        assert!(out.init_conv.is_none());
    }

    #[tokio::test]
    async fn 改写注入stream选项并声明归一化() {
        let config = test_config(&[("NORMALIZE_JSON_WHITESPACE", "1")]);
        let (scope, vault, detector) = fresh_arcs();
        let raw = br#"{"model":"m","stream":true,"messages":[]}"#;
        let out = request_rewrite(
            raw.to_vec(),
            Protocol::Chat,
            &config,
            scope,
            vault,
            detector,
        )
        .await;
        assert!(out.stream_flag);
        assert!(out.normalized_out);
        let v: Value = serde_json::from_slice(&out.body).expect("改写后仍为合法 JSON");
        assert_eq!(
            v.get("stream_options")
                .and_then(|o| o.get("include_usage"))
                .and_then(|b| b.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn 非流转发成功原样返回() {
        let up_body = br#"{"id":"x","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_vec();
        let (url, server) = loopback_server(200, "application/json", up_body).await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let admin = Arc::new(MetricsStore::new(std::path::PathBuf::from(
            "/tmp/veil-gateway-units-test.sqlite",
        )));
        let mut ctx = nonstream_ctx(Protocol::Chat, scope, vault, detector);
        ctx.admin_metrics = admin.clone();
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::POST,
            &url,
            HeaderMap::new(),
            br#"{"model":"m","messages":[]}"#.to_vec(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(_) => panic!("JSON 上游不得转流泵"),
        };
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-veil-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("chat")
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        assert!(
            body.windows(2).any(|w| w == b"hi"),
            "响应体须原样返回上游内容"
        );
        assert_eq!(admin.ring_len(), 1, "非流成功须记一条 record_chat 快照");
        server.abort();
    }

    #[tokio::test]
    async fn 非流上游不可达映射502而非挂起() {
        let url = refused_url().await;
        let client = reqwest::Client::new();
        let (scope, vault, detector) = fresh_arcs();
        let ctx = nonstream_ctx(Protocol::NonDialog, scope, vault, detector);
        let outcome = serve_nonstream(
            &client,
            reqwest::Method::GET,
            &url,
            HeaderMap::new(),
            Vec::new(),
            ctx,
        )
        .await;
        let resp = match outcome {
            NonstreamOutcome::Responded(r) => r,
            NonstreamOutcome::Stream(_) => panic!("不可达上游不得转流泵"),
        };
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("响应体须可读");
        assert!(
            body.windows(12).any(|w| w == b"E_EMPTY_BODY"),
            "网关级错误码须为 E_EMPTY_BODY"
        );
    }

    async fn collect_pump(
        upstream: reqwest::Response,
        ctx: StreamPumpCtx,
    ) -> (PumpOutcome, Vec<String>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
        let handle = spawn_stream_pump(upstream, tx, ctx);
        let outcome = handle.await.expect("流泵任务不得崩");
        let mut frames = Vec::new();
        while let Some(f) = rx.recv().await {
            frames.push(f);
        }
        (outcome, frames)
    }

    #[tokio::test]
    async fn 流泵正常收尾恰一个终止帧() {
        let sse =
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(!outcome.block_injected);
        let joined = frames.join("");
        assert!(joined.contains("hi"), "录制流内容须泵到下游");
        let done_count = frames.iter().filter(|f| f.contains("data: [DONE]")).count();
        assert_eq!(done_count, 1, "正常收尾恰一个终止帧，不追加多余终止");
        assert!(
            frames.last().is_some_and(|f| f.contains("data: [DONE]")),
            "下游须以终止帧收尾"
        );
        server.abort();
    }

    #[tokio::test]
    async fn 流泵空流注入阻断并标记终止() {
        let (url, server) = loopback_server(200, "text/event-stream", Vec::new()).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) =
            collect_pump(upstream, pump_ctx(Protocol::Chat, scope, vault, detector)).await;
        assert!(outcome.block_injected, "空流须注入阻断帧");
        assert!(
            outcome.terminal_injected,
            "阻断注入后 terminal_injected 须为真"
        );
        let joined = frames.join("");
        assert!(joined.contains("empty-stream"), "下游须收到阻断事件");
        assert!(
            frames.iter().any(|f| f.contains("data: [DONE]")),
            "阻断事件后恒有终止帧"
        );
        server.abort();
    }

    #[tokio::test]
    async fn responses_incomplete与error合成单个failed() {
        let sse = b"data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r9\",\"status\":\"incomplete\"}}\n\ndata: {\"type\":\"error\",\"error\":{\"message\":\"boom\"}}\n\n".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let client = reqwest::Client::new();
        let upstream = client.get(&url).send().await.expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let (outcome, frames) = collect_pump(
            upstream,
            pump_ctx(Protocol::Responses, scope, vault, detector),
        )
        .await;
        let joined = frames.join("");
        assert!(
            joined.contains("response.failed"),
            "incomplete/error 须映射为 failed"
        );
        assert!(
            !joined.contains("response.incomplete"),
            "原始 incomplete 不得透出"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.contains("response.failed"))
                .count(),
            1,
            "恒恰一个 failed 终止帧"
        );
        assert!(outcome.terminal_injected, "映射后 terminal 须落位");
        server.abort();
    }

    #[test]
    fn sse响应构建头合规() {
        let (_tx, rx) = tokio::sync::mpsc::channel::<String>(64);
        let resp = build_sse_response(rx, true);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(
            resp.headers()
                .get("x-veil-normalized")
                .and_then(|v| v.to_str().ok()),
            Some("json-whitespace")
        );
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 流式终端事件判定（§2.6 去重用）：chat 以 `[DONE]` 为准（非 JSON 分支处理，
/// 此处恒 false）；anthropic 仅 `message_stop`；responses 仅 `completed/failed`
///（`incomplete/error` 已提前映射为单个 `failed`）。
fn is_terminal_event(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => v
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "message_stop"),
        P::Responses => v
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "response.completed" || t == "response.failed"),
        _ => false,
    }
}

/// 外层事件序号（§2.5/§2.4）：anthropic 取事件级 `index`
///（`content_block_start/delta.index`），responses 取 `output_index`；
/// 缺失返回 None（调用方跳过按槽清理，不误清）。
fn outer_event_index(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> Option<u32> {
    use crate::service::llm_gateway::Protocol as P;
    let n = match protocol {
        P::Anthropic => v.get("index")?.as_u64()?,
        P::Responses => v
            .get("output_index")
            .or_else(|| v.get("index"))?
            .as_u64()?,
        _ => return None,
    };
    Some(n as u32)
}

fn extract_responses_seq(v: &Value) -> Option<u64> {
    v.get("sequence_number").and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

fn is_minor_event(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            t.contains("thinking")
                || t.contains("signature")
                || t.contains("redacted")
                || t.contains("citation")
                || v.get("delta")
                    .and_then(|d| d.get("type"))
                    .and_then(|x| x.as_str())
                    .is_some_and(|dt| {
                        dt.contains("thinking")
                            || dt.contains("signature")
                            || dt.contains("citation")
                    })
        }
        P::Responses => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            [
                "reasoning",
                "mcp",
                "file_search",
                "web_search",
                "code_interpreter",
                "image_gen",
            ]
            .iter()
            .any(|k| t.contains(k))
        }
        P::Chat => v
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|choices| {
                choices.iter().any(|ch| {
                    ["delta", "message"]
                        .iter()
                        .any(|k| ch.get(k).and_then(|c| c.get("refusal")).is_some())
                })
            }),
        P::NonDialog => false,
    }
}

fn extract_tool_fragments(
    protocol: crate::service::llm_gateway::Protocol,
    v: &Value,
) -> Vec<(u32, Option<String>, Option<String>, String)> {
    use crate::service::llm_gateway::Protocol as P;
    let mut out = Vec::new();
    match protocol {
        P::Chat => {
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
            if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
                    for key in ["delta", "message"] {
                        let Some(container) = ch.get(key) else {
                            continue;
                        };
                        if let Some(calls) = container.get("tool_calls").and_then(|c| c.as_array())
                        {
                            for (i, call) in calls.iter().enumerate() {
                                let idx = call
                                    .get("index")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(i as u64)
                                    as u32;
                                let id = synth(idx, call.get("id").and_then(|x| x.as_str()));
                                let name = call
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let args = norm_args(
                                    call.get("function").and_then(|f| f.get("arguments")),
                                );
                                out.push((idx, Some(id), name, args));
                            }
                        }
                        for legacy_key in ["function_call", "custom_tool_call"] {
                            let Some(legacy) = container.get(legacy_key) else {
                                continue;
                            };
                            let items: Vec<&Value> = match legacy {
                                Value::Array(a) => a.iter().collect(),
                                Value::Object(_) => vec![legacy],
                                _ => vec![],
                            };
                            for (i, item) in items.iter().enumerate() {
                                let Some(obj) = item.as_object() else {
                                    continue;
                                };
                                if legacy_key == "function_call" {
                                    let idx = ci as u32;
                                    let name = obj
                                        .get("name")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = norm_args(obj.get("arguments"));
                                    out.push((idx, Some(synth(idx, None)), name, args));
                                } else {
                                    let idx = i as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    if name.is_some() || !args.is_empty() || id_raw.is_some() {
                                        out.push((idx, Some(synth(idx, id_raw)), name, args));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        P::Anthropic => {
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
            let mut blocks: Vec<&Value> = Vec::new();
            for key in ["content_block", "delta"] {
                if let Some(b) = v.get(key) {
                    blocks.push(b);
                }
            }
            // §2.4 外层序号优先：`content_block_start/delta.index` 为事件级序号，
            // 内层 `content_block/delta.index` 仅作回退，缺失再回退枚举下标。
            let outer_index = v.get("index").and_then(|x| x.as_u64()).map(|n| n as u32);
            if let Some(arr) = v.get("content").and_then(|c| c.as_array()) {
                blocks.extend(arr.iter());
            }
            if let Some(msg) = v.get("message").and_then(|m| m.get("content")) {
                if let Some(arr) = msg.as_array() {
                    blocks.extend(arr.iter());
                } else if msg.is_object() {
                    blocks.push(msg);
                }
            }
            for (i, b) in blocks.iter().enumerate() {
                let idx = outer_index.or_else(|| {
                    b.get("index")
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u32)
                }).unwrap_or(i as u32);
                if let Some(fc) = b.get("function_call").and_then(|x| x.as_object()) {
                    let name = fc
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let args = norm_args(fc.get("arguments"));
                    out.push((idx, Some(synth(idx, None)), name, args));
                    continue;
                }
                if let Some(cc) = b.get("custom_tool_call") {
                    match cc {
                        Value::Object(obj) => {
                            let id_raw = obj
                                .get("id")
                                .or_else(|| obj.get("call_id"))
                                .or_else(|| obj.get("tool_call_id"))
                                .and_then(|x| x.as_str());
                            let name = obj
                                .get("name")
                                .or_else(|| obj.get("tool_name"))
                                .and_then(|x| x.as_str())
                                .or_else(|| {
                                    obj.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|x| x.as_str())
                                })
                                .map(|s| s.to_string());
                            let args = norm_args(
                                obj.get("arguments")
                                    .or_else(|| obj.get("input"))
                                    .or_else(|| obj.get("args")),
                            );
                            out.push((idx, Some(synth(idx, id_raw)), name, args));
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    let jdx = j as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    out.push((jdx, Some(synth(jdx, id_raw)), name, args));
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let is_tool = b.get("type").and_then(|x| x.as_str()).is_some_and(|t| {
                    t.contains("tool_use") || t.contains("function") || t.contains("custom")
                }) || b.get("name").is_some()
                    || b.get("partial_json").is_some()
                    || b.get("input").is_some()
                    || b.get("function_call").is_some()
                    || b.get("custom_tool_call").is_some();
                if !is_tool {
                    continue;
                }
                let id_raw = b.get("id").and_then(|x| x.as_str());
                let name = b
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let args = norm_args(
                    b.get("partial_json")
                        .or_else(|| b.get("input"))
                        .or_else(|| b.get("arguments")),
                );
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                out.push((idx, Some(synth(idx, id_raw)), name, args));
            }
        }
        P::Responses => {
            let ev_type = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = v
                        .get("delta")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !delta.is_empty() || name.is_some() {
                        out.push((idx, id, name, delta));
                    }
                } else if ev_type.ends_with(".done") {
                    let args = v
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !args.is_empty() || name.is_some() {
                        out.push((idx, id, name, args));
                    }
                }
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = v.get("item")
                && item.get("type").and_then(|x| x.as_str()) == Some("function_call")
            {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let args = item
                    .get("arguments")
                    .map(|a| {
                        if let Some(s) = a.as_str() {
                            s.to_string()
                        } else {
                            a.to_string()
                        }
                    })
                    .unwrap_or_default();
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                if !args.is_empty() || name.is_some() {
                    out.push((idx, id, name, args));
                }
                return out;
            }
            if v.get("item").is_some() {
                return out;
            }
            if let Some(output) = v.get("output").and_then(|o| o.as_array()) {
                for (i, item) in output.iter().enumerate() {
                    let args = item
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let name = item
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let id = item
                        .get("id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    if !args.is_empty() || name.is_some() {
                        out.push((i as u32, id, name, args));
                    }
                }
            }
        }
        P::NonDialog => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{config::Config, state::SqliteOutcome},
        std::{collections::HashMap, path::PathBuf},
    };

    #[tokio::test]
    async fn 健康处理器透出服务层状态() {
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
        ]);
        let state = AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        );
        let Json(body) = health_handler(State(state)).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["sqlite_ok"], true);
    }

    #[test]
    fn 流式legacy_function_call与非流式口径统一() {
        use crate::service::llm_gateway::Protocol as P;
        let stream_delta = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags = extract_tool_fragments(P::Chat, &stream_delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 0);
        assert_eq!(frags[0].1.as_deref(), Some("call_stable_0"));
        assert_eq!(frags[0].2.as_deref(), Some("old"));
        assert_eq!(frags[0].3, "{\"x\":1}");
        let non_stream = serde_json::json!({"choices":[{"message":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags2 = extract_tool_fragments(P::Chat, &non_stream);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("old"));
        assert_eq!(frags2[0].1.as_deref(), Some("call_stable_0"));
        let legacy_arr = serde_json::json!({"choices":[{"delta":{"function_call":[{"name":"a","arguments":"{}"}]}}]});
        let frags3 = extract_tool_fragments(P::Chat, &legacy_arr);
        assert!(frags3.is_empty() || frags3.len() == 1);
    }

    #[test]
    fn anthropic数组形态content与message_content对齐网关() {
        use crate::service::llm_gateway::Protocol as P;
        let content_arr = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}]});
        let frags = extract_tool_fragments(P::Anthropic, &content_arr);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].1.as_deref(), Some("a1"));
        assert_eq!(frags[0].2.as_deref(), Some("bash"));
        assert_eq!(frags[0].3, r#"{"cmd":"ls"}"#);
        let msg_content = serde_json::json!({"message":{"content":[{"type":"tool_use","id":"m1","name":"run","input":{"p":2}}]}});
        let frags2 = extract_tool_fragments(P::Anthropic, &msg_content);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].1.as_deref(), Some("m1"));
        let delta =
            serde_json::json!({"delta":{"type":"tool_use","name":"t","partial_json":"{\"a\":"}});
        let frags3 = extract_tool_fragments(P::Anthropic, &delta);
        assert_eq!(frags3.len(), 1);
        assert_eq!(frags3[0].1.as_deref(), Some("call_stable_0"));
        let text_only = serde_json::json!({"delta":{"type":"text","text":"hi"}});
        assert!(extract_tool_fragments(P::Anthropic, &text_only).is_empty());
    }

    #[test]
    fn anthropic按事件index分桶而非枚举下标() {
        use crate::service::llm_gateway::Protocol as P;
        let first = serde_json::json!({"content_block":{"type":"tool_use","index":4,"id":"a4","name":"t","input":{}}});
        let frags = extract_tool_fragments(P::Anthropic, &first);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 4);
        let second =
            serde_json::json!({"delta":{"type":"input_json_delta","index":4,"partial_json":"{}"}});
        let frags2 = extract_tool_fragments(P::Anthropic, &second);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].0, 4);
        assert_eq!(frags2[0].3, "{}");
    }

    #[test]
    fn responses增量带序号且done全量() {
        use crate::service::llm_gateway::Protocol as P;
        let delta = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"it1","sequence_number":3,"delta":"{\"a\":"});
        let frags = extract_tool_fragments(P::Responses, &delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(extract_responses_seq(&delta), Some(3));
        assert!(!AuditHold::is_complete_event(&delta));
        let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"it1","sequence_number":4,"name":"run","arguments":"{\"a\":1}"});
        let frags2 = extract_tool_fragments(P::Responses, &done);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("run"));
        assert!(AuditHold::is_complete_event(&done));
    }

    #[test]
    fn 次要事件透传不审计() {
        use crate::service::llm_gateway::Protocol as P;
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"type":"thinking_delta","thinking":"hmm"})
        ));
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"delta":{"type":"signature_delta","signature":"s"}})
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.reasoning.delta","delta":"x"})
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.mcp_call.in_progress"})
        ));
        assert!(is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"delta":{"refusal":"no"}}]})
        ));
        assert!(!is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"delta":{"content":"hi"}}]})
        ));
        assert!(!is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"x"})
        ));
    }

    #[test]
    fn refusal消息形态同样次要透传() {
        use crate::service::llm_gateway::Protocol as P;
        assert!(is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"message":{"refusal":"no"}}]})
        ));
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"type":"redacted_thinking","redacted_data":"x"})
        ));
        assert!(!is_minor_event(
            P::NonDialog,
            &serde_json::json!({"refusal":"no"})
        ));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn 体上限分级取值与spec一致() {
        assert_eq!(GATEWAY_BODY_LIMIT_BYTES, 10 * 1024 * 1024);
        assert_eq!(AUDIT_SUBLIMIT_CEILING_BYTES, 8 * 1024 * 1024);
        assert!(GATEWAY_BODY_LIMIT_BYTES > AUDIT_SUBLIMIT_CEILING_BYTES);
        assert!(!audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES));
        assert!(audit_scan_body_over_limit(AUDIT_SUBLIMIT_CEILING_BYTES + 1));
    }

    #[tokio::test]
    async fn 体超限响应413携带错误码() {
        let resp = payload_too_large(GATEWAY_BODY_LIMIT_BYTES);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "E_PAYLOAD_TOO_LARGE");
    }

    #[tokio::test]
    async fn 超限体被to_bytes拒绝而非静默空体() {
        let over = vec![b'x'; 64];
        let err = axum::body::to_bytes(axum::body::Body::from(over), 16).await;
        assert!(err.is_err());
        let ok = axum::body::to_bytes(axum::body::Body::from(vec![b'x'; 16]), 16).await;
        assert!(ok.is_ok());
    }

    fn revoke_test_state() -> AppState {
        let env = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
        ]);
        AppState::new(
            Config::load_from(&env).unwrap(),
            SqliteOutcome {
                sqlite_ok: true,
                sqlite_error: None,
                db_path: PathBuf::from("/tmp/x.sqlite"),
                memory_only: false,
            },
        )
    }

    fn revoke_body(key: &str) -> Json<EmergencyRevokeBody> {
        Json(EmergencyRevokeBody {
            key: Some(key.to_string()),
            caller_path: None,
            caller_hash: None,
            admin_token: None,
            file_present: false,
        })
    }

    #[tokio::test]
    async fn 伪造代理头不绕过吊销判定() {
        // 内网豁免只认 TCP 远端：公网对端携带伪造内网 XFF 仍转审批，不直接吊销。
        let state = revoke_test_state();
        service::register_caller(&state, "/s/xff.sh", "h-xff", "src-xff")
            .await
            .unwrap();
        let mut forged = HeaderMap::new();
        forged.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let err = emergency_revoke_handler(
            State(state.clone()),
            PeerIp(Some("203.0.113.9".to_string())),
            forged,
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::ACCEPTED);
        // 回环 TCP 对端无头时豁免路径仍可用。
        let ok = emergency_revoke_handler(
            State(state),
            PeerIp(Some("127.0.0.1".to_string())),
            HeaderMap::new(),
            revoke_body("/s/xff.sh"),
        )
        .await
        .unwrap();
        assert_eq!(ok.0["ok"], true);
    }
}
