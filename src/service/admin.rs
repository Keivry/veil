//! §7.2 六 admin 路由：鉴权 + 限流 + SSE + 事件查询。
//!
//! 唯一表（精确注册先于通配，MUST NOT 被 `/{*tail}` 吞没）：
//! `/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、
//! `/_admin/events`、`/_admin/events/stream`；未知子路径 404。
//! 鉴权优先级 `X-Admin-Token` > `__Host-admin_token` Cookie >
//! `?access_token`（仅 SSE）；非 SSE 带 query 恒 401；HMAC 等长比较；
//! `OBSERVABILITY_ADMIN_TOKEN` 必填独立性沿用 `Config`。
//! 限流按直连对端 IP（`ConnectInfo`，不读代理头）：通用 10/min/IP 429 +
//! `Retry-After`；SSE 5 并发/IP + 60s ping + 5min 强制重连（axum SSE 语义
//! 与 §4 注释 keepalive 对齐：注释帧不计事件）。
//!
//! 单向依赖：本模块只读 `state`（`Config`/`gateway_metrics`/`MetricsStore`），
//! 不触网关/脱敏/审计业务文件（§5§6 并行施工零交叉）。

use {
    crate::{
        error::VeilError,
        service::metrics::{
            MetricsStore,
            PiiSamplerConfig,
            PiiValueSampler,
            SUMMARY_MAX_CHARS,
            summarize,
        },
        state::AppState,
    },
    axum::{
        Json,
        extract::{ConnectInfo, FromRequestParts, Query, State},
        http::{HeaderMap, StatusCode, request::Parts},
        response::{
            IntoResponse,
            Response,
            sse::{Event, KeepAlive, Sse},
        },
    },
    serde_json::json,
    std::{
        collections::{HashMap, VecDeque},
        net::{IpAddr, SocketAddr},
        sync::Mutex,
        time::{Duration, Instant},
    },
};

/// 通用管理接口限流：10/min/IP。
pub const ADMIN_RATE_LIMIT: usize = 10;
/// 限流窗口（秒）。
pub const ADMIN_RATE_WINDOW_SECS: u64 = 60;
/// SSE 并发上限/IP。
pub const SSE_MAX_PER_IP: usize = 5;
/// SSE 保活 ping 间隔（60s）。
pub const SSE_PING_INTERVAL: Duration = Duration::from_secs(60);
/// SSE 强制重连（5min，服务端主动关闭）。
pub const SSE_MAX_AGE: Duration = Duration::from_secs(300);
/// 事件环容量。
pub const EVENT_RING_CAP: usize = 512;
/// 事件查询默认上限。
pub const EVENT_DEFAULT_LIMIT: usize = 100;

/// HMAC 等长比较（`hmac` 依赖）：域分隔固定 key 下分别 MAC 后等长比较，
/// 输入长度不等仍走等长比较再判假，不泄露匹配前缀长度。
pub fn admin_token_eq(provided: &str, expected: &str) -> bool {
    use {
        hmac::{KeyInit as _, Mac as _},
        subtle::ConstantTimeEq as _,
    };
    type H = hmac::Hmac<sha2::Sha256>;
    let mut mac_p = H::new_from_slice(b"veil-admin-token-v1").expect("HMAC key 恒合法");
    mac_p.update(provided.as_bytes());
    let mut mac_e = H::new_from_slice(b"veil-admin-token-v1").expect("HMAC key 恒合法");
    mac_e.update(expected.as_bytes());
    let p = mac_p.finalize().into_bytes();
    let e = mac_e.finalize().into_bytes();
    let tags_eq: bool = p.ct_eq(&e).into();
    // 长度门与 tag 比较结果“与”合并（无短路，保持等时）。
    let len_eq: bool =
        provided.as_bytes().ct_eq(expected.as_bytes()).into() && provided.len() == expected.len();
    // 变长输入 `ct_eq` 按实现可能早退；此处以 tag 比较耗时为主导，
    // 长度不等仍已执行等长 tag 比较。
    tags_eq && len_eq && provided.len() == expected.len()
}

/// 从 `Cookie` 头提取 `__Host-admin_token`。
pub fn cookie_admin_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("__Host-admin_token=") {
            let v = v.trim().trim_matches('"').to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// 管理事件（摘要落盘前已 `redact → truncate`，零明文）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminEvent {
    pub id: u64,
    pub ts_secs: i64,
    pub kind: String,
    pub summary: String,
    #[serde(default)]
    pub protocol: Option<String>,
}

/// 可观测聚合状态（`AppState` 持有，`Clone` 共享）。
pub struct AdminState {
    pub metrics: std::sync::Arc<MetricsStore>,
    pub sampler: std::sync::Arc<PiiValueSampler>,
    rate: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    sse_count: Mutex<HashMap<IpAddr, usize>>,
    events: Mutex<VecDeque<AdminEvent>>,
    broadcaster: tokio::sync::broadcast::Sender<String>,
    next_id: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState").finish()
    }
}

impl AdminState {
    /// 新建（`db_path` 与 metrics 共库；采样开关读进程环境，默认关闭）。
    pub fn new(db_path: std::path::PathBuf) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            metrics: std::sync::Arc::new(MetricsStore::new(db_path.clone())),
            sampler: std::sync::Arc::new(PiiValueSampler::new(
                PiiSamplerConfig::from_env(),
                db_path,
            )),
            rate: Mutex::new(HashMap::new()),
            sse_count: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAP)),
            broadcaster: tx,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    #[cfg(test)]
    fn new_for_test(db_path: std::path::PathBuf, sampler: PiiValueSampler) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            metrics: std::sync::Arc::new(MetricsStore::new(db_path.clone())),
            sampler: std::sync::Arc::new(sampler),
            rate: Mutex::new(HashMap::new()),
            sse_count: Mutex::new(HashMap::new()),
            events: Mutex::new(VecDeque::with_capacity(EVENT_RING_CAP)),
            broadcaster: tx,
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// 通用限流（10/min/IP）：超限返回 `Retry-After` 秒数。
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), u64> {
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs(ADMIN_RATE_WINDOW_SECS);
        let hits = guard.entry(ip).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= ADMIN_RATE_LIMIT {
            let oldest = hits.iter().min().copied().unwrap_or(now);
            let retry = window
                .saturating_sub(now.duration_since(oldest))
                .as_secs()
                .max(1);
            return Err(retry);
        }
        hits.push(now);
        Ok(())
    }

    /// SSE 并发守卫（5/IP）：持有至连接结束自动释放；满时返回 `None`（429）。
    pub fn acquire_sse(&self, ip: IpAddr) -> Option<SseGuard> {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n >= SSE_MAX_PER_IP {
            return None;
        }
        guard.insert(ip, n + 1);
        Some(SseGuard {
            ip,
            released: false,
        })
    }

    /// 释放 SSE 计数（连接结束）。
    pub fn release_sse_for(&self, ip: IpAddr) {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&ip);
        } else {
            guard.insert(ip, n - 1);
        }
    }

    /// 当前 IP 的 SSE 并发数（单测用）。
    pub fn sse_current(&self, ip: IpAddr) -> usize {
        self.sse_count
            .lock()
            .map(|g| g.get(&ip).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// 推入事件：摘要经单一路径 `redact → truncate` 后落环 + 广播。
    /// TODO(§7): §6 审计 hook 接入时调用本函数（`kind`=`audit`），当前仅网关/单测直调。
    pub fn push_event(
        &self,
        kind: &str,
        raw_summary: &str,
        protocol: Option<String>,
    ) -> AdminEvent {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ts_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let ev = AdminEvent {
            id,
            ts_secs,
            kind: kind.to_string(),
            summary: summarize(raw_summary, SUMMARY_MAX_CHARS),
            protocol,
        };
        if let Ok(mut ring) = self.events.lock() {
            if ring.len() >= EVENT_RING_CAP {
                ring.pop_front();
            }
            ring.push_back(ev.clone());
        }
        let _ = self
            .broadcaster
            .send(serde_json::to_string(&ev).unwrap_or_default());
        ev
    }

    /// 查询事件（`kind`/`since`/`limit` 过滤）。
    pub fn query_events(
        &self,
        kind: Option<&str>,
        since: Option<i64>,
        limit: usize,
    ) -> Vec<AdminEvent> {
        let ring = self.events.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .filter(|e| kind.is_none_or(|k| e.kind == k))
            .filter(|e| since.is_none_or(|s| e.ts_secs >= s))
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(limit.clamp(1, 500))
            .collect()
    }

    /// 订阅实时流。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.broadcaster.subscribe()
    }
}

/// SSE 并发守卫标记（释放由 handler 调用 `release_sse_for`）。
pub struct SseGuard {
    pub ip: IpAddr,
    #[allow(dead_code)]
    released: bool,
}

/// 直连对端 IP 提取器（只读 `ConnectInfo`，MUST NOT 读代理头）。
///
/// `ConnectInfo` 缺失时回退本地回环（单测直调 `serve` 场景），生产入口
/// 由 `main.rs` 以 `into_make_service_with_connect_info` 注入真实对端。
pub struct PeerIp(pub IpAddr);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]));
        Ok(PeerIp(ip))
    }
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": {"code": "E_UNAUTHORIZED", "message": message}})),
    )
        .into_response()
}

fn rate_limited(retry_after: u64) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error": {"code": "E_RATE_LIMITED", "message": format!("请求过于频繁，请 {retry_after}s 后重试")}})),
    )
        .into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut().insert("retry-after", v);
    }
    resp
}

/// 鉴权（优先级：`X-Admin-Token` > Cookie > 仅 SSE 的 `?access_token`）。
///
/// 非 SSE 带 query token 恒 401（即使 token 有效，强制使用请求头或 Cookie）。
fn authorize(
    expected: &str,
    headers: &HeaderMap,
    query_token: Option<&str>,
    has_query_token: bool,
    is_sse: bool,
) -> Option<Response> {
    if !is_sse && has_query_token {
        return Some(unauthorized("非 SSE 管理接口不得以 query 携带 token"));
    }
    if let Some(got) = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        && admin_token_eq(got, expected)
    {
        return None;
    }
    // 头存在但无效 → 直接 401（不再降级校验低优先级，防探测混淆）。
    let header_present = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.is_empty());
    if header_present {
        return Some(unauthorized("管理鉴权失败"));
    }
    if let Some(got) = cookie_admin_token(headers)
        && admin_token_eq(&got, expected)
    {
        return None;
    }
    let cookie_present = cookie_admin_token(headers).is_some();
    if cookie_present {
        return Some(unauthorized("管理鉴权失败"));
    }
    if is_sse
        && let Some(got) = query_token
        && admin_token_eq(got, expected)
    {
        return None;
    }
    Some(unauthorized("管理鉴权失败"))
}

fn check_admin_rate(state: &AppState, ip: IpAddr) -> Option<Response> {
    match state.admin.check_rate(ip) {
        Ok(()) => None,
        Err(retry) => Some(rate_limited(retry)),
    }
}

/// `GET /_admin/`：静态页占位（§8 复用 `admin.html`，本任务只交付 JSON API + SSE 流）。
pub async fn admin_index(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    Json(json!({
        "ok": true,
        "admin": "veil observability",
        "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
        "note": "静态页占位：JSON API + SSE 流已就绪，admin.html 复用见后续部署事项",
    }))
    .into_response()
}

/// `GET /_admin/health`：存活探针（透出 sqlite 健康）。
pub async fn admin_health(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let health = crate::service::health_status(&state);
    Json(json!({"ok": true, "sqlite_ok": health.sqlite_ok, "sqlite_error": health.sqlite_error}))
        .into_response()
}

/// `GET /_admin/metrics`：指标快照（聚合环 + 网关只读计数合并）。
pub async fn admin_metrics(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let snap = state.admin.metrics.snapshot();
    let gm = &state.gateway_metrics;
    Json(json!({
        "ok": true,
        "is_precise": snap.is_precise,
        "requests": snap.requests,
        "tokens": {"prompt": snap.prompt_tokens, "completion": snap.completion_tokens, "total": snap.total_tokens},
        "per_protocol": snap.per_protocol,
        "latency_buckets": snap.latency_buckets,
        "p95_ms": snap.p95_ms,
        "truncated": {
            "silent_discard": snap.truncated_silent_discard,
            "open_ended": snap.truncated_open_ended,
            "synthesized_failed": snap.truncated_synthesized_failed,
        },
        "chat_tail_lenient": {
            "chat/completions": gm.lenient_count("chat/completions"),
            "v1/messages": gm.lenient_count("v1/messages"),
            "v1/responses": gm.lenient_count("v1/responses"),
        },
        "sse_events": gm.sse_event_total(),
        "ring_len": snap.ring_len,
        "dropped": snap.dropped,
    }))
    .into_response()
}

/// `GET /_admin/series`：时序查询（`?granularity=daily|hourly|five_min&since=&protocol=`）。
pub async fn admin_series(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let granularity = query
        .get("granularity")
        .map(|s| s.as_str())
        .unwrap_or("hourly");
    if !matches!(granularity, "daily" | "hourly" | "five_min" | "5min") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "E_BAD_REQUEST", "message": "granularity 取值 daily/hourly/five_min"}})),
        )
            .into_response();
    }
    let since = query.get("since").cloned();
    let protocol = query.get("protocol").cloned();
    match state
        .admin
        .metrics
        .query_series(granularity, since, protocol)
        .await
    {
        Ok(points) => {
            Json(json!({"ok": true, "granularity": granularity, "points": points})).into_response()
        }
        Err(e) => VeilError::internal(e).into_response(),
    }
}

/// `GET /_admin/events`：审计事件查询（`?kind=&since=&limit=`，摘要已脱敏）。
pub async fn admin_events(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let kind = query.get("kind").cloned();
    let since: Option<i64> = query.get("since").and_then(|s| s.parse().ok());
    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(EVENT_DEFAULT_LIMIT);
    let events = state.admin.query_events(kind.as_deref(), since, limit);
    // hover 口径：附掩码 TopN（不含明文）。
    let samples = state.admin.sampler.top_n(20);
    Json(json!({"ok": true, "events": events, "pii_value_samples": samples})).into_response()
}

/// `GET /_admin/events/stream`：SSE 实时推送（query 鉴权仅此路由有效）。
pub async fn admin_events_stream(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
    }
    let qtok = query.get("access_token").cloned();
    let has_q = qtok.is_some();
    if let Some(r) = authorize(
        &state.config.observability_admin_token,
        &headers,
        qtok.as_deref(),
        has_q,
        true,
    ) {
        return r;
    }
    if state.admin.acquire_sse(ip).is_none() {
        return rate_limited(60);
    }
    let rx = state.admin.subscribe();
    let admin = state.admin.clone();
    // 近环回放（最近 20 条，已脱敏）。
    let backlog: Vec<String> = admin
        .query_events(None, None, 20)
        .into_iter()
        .rev()
        .filter_map(|e| serde_json::to_string(&e).ok())
        .collect();
    let stream = async_stream::stream! {
        for item in backlog {
            yield Ok::<_, anyhow::Error>(Event::default().data(item).event("message"));
        }
        let mut rx = rx;
        let deadline = tokio::time::Instant::now() + SSE_MAX_AGE;
        loop {
            let timeout = tokio::time::timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), rx.recv()).await;
            match timeout {
                Ok(Ok(msg)) => {
                    yield Ok::<_, anyhow::Error>(Event::default().data(msg).event("message"));
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        // 5min 强制重连：服务端关闭流，客户端按 retry 重连。
        admin.release_sse_for(ip);
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(SSE_PING_INTERVAL).text("ping"))
        .into_response()
}

/// 未知 admin 子路径 404（精确路由之后、通配之前注册）。
pub async fn admin_not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": {"code": "E_NOT_FOUND", "message": "未知管理子路径"}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ip() -> IpAddr { IpAddr::from([127, 0, 0, 1]) }

    fn test_admin_state() -> AdminState {
        let dir = std::env::temp_dir().join(format!("veil-admin-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let db = dir.join("metrics.sqlite");
        let sampler = PiiValueSampler::new(
            PiiSamplerConfig {
                enabled: false,
                persist: false,
                hmac_key: None,
            },
            db.clone(),
        );
        AdminState::new_for_test(db, sampler)
    }

    fn headers_with(token: Option<&str>, cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert("x-admin-token", t.parse().unwrap());
        }
        if let Some(c) = cookie {
            h.insert("cookie", format!("__Host-admin_token={c}").parse().unwrap());
        }
        h
    }

    #[test]
    fn hmac等长比较语义() {
        assert!(admin_token_eq("tok-abc-123", "tok-abc-123"));
        assert!(!admin_token_eq("tok-abc-124", "tok-abc-123"));
        assert!(!admin_token_eq("short", "much-longer-expected-value"));
        assert!(!admin_token_eq("", "x"));
        assert!(admin_token_eq("", ""));
    }

    #[test]
    fn 鉴权优先级与401语义() {
        let expected = "observability-admin-token-0123456789";
        // 头优先：头有效不再校验低优先级。
        assert!(
            authorize(
                expected,
                &headers_with(Some(expected), Some("wrong")),
                None,
                false,
                false
            )
            .is_none()
        );
        // 头无效直接 401（不降级 Cookie）。
        assert!(
            authorize(
                expected,
                &headers_with(Some("wrong"), Some(expected)),
                None,
                false,
                false
            )
            .is_some()
        );
        // Cookie 次优。
        assert!(
            authorize(
                expected,
                &headers_with(None, Some(expected)),
                None,
                false,
                false
            )
            .is_none()
        );
        // SSE query 有效放行。
        assert!(
            authorize(
                expected,
                &headers_with(None, None),
                Some(expected),
                true,
                true
            )
            .is_none()
        );
        // 非 SSE 带 query 恒 401（即使有效）。
        assert!(
            authorize(
                expected,
                &headers_with(None, None),
                Some(expected),
                true,
                false
            )
            .is_some()
        );
        assert!(
            authorize(
                expected,
                &headers_with(Some(expected), None),
                Some(expected),
                true,
                false
            )
            .is_some()
        );
        // 全失败 401。
        assert!(authorize(expected, &headers_with(None, None), None, false, false).is_some());
        // SSE query 无效 401。
        assert!(
            authorize(
                expected,
                &headers_with(None, None),
                Some("wrong"),
                true,
                true
            )
            .is_some()
        );
    }

    #[test]
    fn cookie解析形态() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            "a=1; __Host-admin_token=tok123; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_admin_token(&h).as_deref(), Some("tok123"));
        let empty = HeaderMap::new();
        assert_eq!(cookie_admin_token(&empty), None);
    }

    #[test]
    fn 限流按直连对端ip计数() {
        let st = test_admin_state();
        // 同一 IP 10 次放行，第 11 次 429。
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(test_ip()).is_ok());
        }
        let retry = st.check_rate(test_ip()).unwrap_err();
        assert!(retry >= 1);
        // 不同 IP 不受影响（不读代理头：伪造 XFF 无法逃逸——本函数只收直连 IP）。
        assert!(st.check_rate(IpAddr::from([10, 0, 0, 2])).is_ok());
    }

    #[test]
    fn sse每ip五并发第六路拒绝() {
        let st = test_admin_state();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
            // 持有守卫期间计数递增（守卫释放由 handler 在流结束时显式调用）。
        }
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        assert!(st.acquire_sse(test_ip()).is_none());
        // 释放一路后可再建。
        st.release_sse_for(test_ip());
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP - 1);
        assert!(st.acquire_sse(test_ip()).is_some());
        let _ = guards;
    }

    #[test]
    fn 未知子路径404() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let resp = admin_not_found().await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        });
    }

    #[test]
    fn 事件摘要落盘已脱敏() {
        let st = test_admin_state();
        let ev = st.push_event(
            "audit",
            r#"{"password":"hunter2"} sk-abcDEF1234567890"#,
            None,
        );
        assert!(!ev.summary.contains("hunter2"), "{}", ev.summary);
        assert!(!ev.summary.contains("sk-abcDEF"), "{}", ev.summary);
        let got = st.query_events(Some("audit"), None, 10);
        assert_eq!(got.len(), 1);
        assert!(st.query_events(Some("other"), None, 10).is_empty());
    }

    #[test]
    fn admin_index占位文案含六路由() {
        let body = json!({
            "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
        });
        assert_eq!(body["routes"].as_array().unwrap().len(), 6);
    }
}
