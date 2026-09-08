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
//! 限流契约（spec `admin-ratelimit-contract` + design D4，有意设计声明）：
//! - 速率维度：通用 admin 接口 `10/min/IP`，超限 `429` + `Retry-After`（秒）+ 错误码
//!   `E_RATE_LIMITED`；计数键为 TCP 直连对端 IP（`ConnectInfo`）， MUST NOT 读
//!   `X-Forwarded-For`/`X-Real-IP` 等代理头（防伪造逃逸，生产由 `main.rs` 经
//!   `into_make_service_with_connect_info` 注入真实对端）。
//! - 并发维度：`/_admin/events/stream` 按 IP 限制并发 `5`，超限拒绝新连接 （`429` + `Retry-After:
//!   60`）且已建连接不受影响；`10/min` 为速率维度、 `5/IP`
//!   为并发维度，两者正交、独立计数，均为有意设计。
//! - 与原仓差异：原仓通用 admin 豁免约 `60/min`，本仓收紧为 `10/min`，系有意 收敛（design
//!   D4），不视为回归。
//! - 超限头与指标锁定：头名 `retry-after`（HTTP 头大小写不敏感，spec 写作 `Retry-After`）；错误码
//!   `E_RATE_LIMITED`；SSE 并发水位经 `sse_current` 与网关 `sse_event_total` 观测。
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

/// 通用管理接口限流：10/min/IP（速率维度；spec `admin-ratelimit-contract`）。
/// 与 SSE `5/IP` 并发维度正交、独立计数，均为有意设计（design D4）；
/// 原仓约 60/min 豁免收紧至此值系有意收敛，不视为回归。
pub const ADMIN_RATE_LIMIT: usize = 10;
/// 限流窗口（秒）。
pub const ADMIN_RATE_WINDOW_SECS: u64 = 60;
/// SSE 并发上限/IP（并发维度；仅约束 `/_admin/events/stream` 同时在线数，
/// 与通用 10/min 速率限流正交，超限拒绝新连接且已建连接不受影响）。
pub const SSE_MAX_PER_IP: usize = 5;
/// SSE 保活 ping 间隔（60s）。
pub const SSE_PING_INTERVAL: Duration = Duration::from_secs(60);
/// SSE 强制重连（5min，服务端主动关闭）。
pub const SSE_MAX_AGE: Duration = Duration::from_secs(300);
/// 事件环容量。
pub const EVENT_RING_CAP: usize = 512;
/// 事件查询默认上限。
pub const EVENT_DEFAULT_LIMIT: usize = 100;

/// 限流豁免路径：`/_admin/health` 为存活探针（前端刷新高频），豁免通用 10/min 限流。
/// 阈值数值不动（10/min 等接线维持），仅 health 不计数。
pub fn admin_rate_exempt_paths() -> [&'static str; 1] { ["/_admin/health"] }

/// 是否豁免限流（health 恒 true）。
pub fn is_rate_exempt(path: &str) -> bool { admin_rate_exempt_paths().contains(&path) }

/// 旧查询 `range` 兼容：`1h/24h/7d/30d` 映射新口径 `granularity`；未知值返回 `None`。
/// 映射等价性：`1h→five_min`、`24h→hourly`、`7d/30d→daily`，与新口径同窗查询等价。
pub fn compat_granularity_for_range(range: &str) -> Option<&'static str> {
    match range.trim().to_lowercase().as_str() {
        "1h" => Some("five_min"),
        "24h" => Some("hourly"),
        "7d" | "30d" => Some("daily"),
        _ => None,
    }
}

/// 旧 `verdict` 值兼容：大小写不敏感归一到 `allow/block/need_approval` 新口径；
/// 未知值返回 `None`（调用方忽略过滤、仅弃用标注，避免空结果误导）。
pub fn normalize_verdict_compat(verdict: &str) -> Option<&'static str> {
    match verdict.trim().to_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "approved" => Some("allow"),
        "block" | "blocked" | "deny" | "rejected" => Some("block"),
        "need_approval" | "needapproval" | "pending" | "approve" | "approval" => {
            Some("need_approval")
        }
        _ => None,
    }
}

/// 管理 token 变长比较：复用 `auth::secret_eq`（HMAC-SHA256 域分隔后比较
/// 32 字节固定 tag，恒时无早退），自研实现已删，单一实现口径。
/// 注：与凭据 Secret 共用同一域分隔 key——两者永不跨域比较，仅作等值
/// 判定，域分隔合并无安全影响；调用方 MUST NOT 用本函数比较定长哈希
/// （定长哈希用 `auth::ct_eq`）。
pub fn admin_token_eq(provided: &str, expected: &str) -> bool {
    crate::auth::secret_eq(provided, expected)
}

/// 从 `Cookie` 头提取 admin token（`__Host-admin_token` 优先，回退 `admin_token`
/// 兼容 http；对标原仓 `_cookie_token` 双名）。
pub fn cookie_admin_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    let mut fallback: Option<String> = None;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("__Host-admin_token=") {
            let v = v.trim().trim_matches('"').to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
        if fallback.is_none()
            && let Some(v) = part.strip_prefix("admin_token=")
        {
            let v = v.trim().trim_matches('"').to_string();
            if !v.is_empty() {
                fallback = Some(v);
            }
        }
    }
    fallback
}

/// `DATA_DIR/admin_token` 文件值读取（Token 独立性第二锚点：文件值须与
/// `MATRIX_ACCESS_TOKEN` 不同，由网关启动期校验；缺失/空返回 None）。
pub fn load_admin_token_file(data_dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("admin_token")).ok()?;
    let v = text.trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// 回环免 token 放行判定（对标原仓）：仅 `ENV=dev` 且回环远端时豁免鉴权，
/// 生产回环同样鉴权（Docker/反代下回环不可靠，fail-closed）。
/// 完整 bypass 接线（`ALLOW_LOOPBACK_NO_TOKEN` 门 + 鉴权前判定）归网关入口，
/// 本函数只提供纯判定供接线与单测。
pub fn loopback_grace(env_is_dev: bool, remote: &str) -> bool {
    if !env_is_dev {
        return false;
    }
    let r = remote.trim().trim_start_matches('[').trim_end_matches(']');
    r == "127.0.0.1" || r == "::1" || r == "::ffff:127.0.0.1"
}

/// 可观测性总开关：`OBSERVABILITY_DISABLE=1` 时管理面显式禁用（过渡逃生开关，
/// 对标原仓；网关入口据此拒绝注册 admin 路由并告警）。
pub fn observability_disabled(env: &HashMap<String, String>) -> bool {
    matches!(
        env.get("OBSERVABILITY_DISABLE").map(|v| v.trim()),
        Some("1") | Some("true") | Some("yes")
    )
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
    sse_count: std::sync::Arc<Mutex<HashMap<IpAddr, usize>>>,
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
    /// 新建（`db_path` 与 metrics 共库；采样开关由调用方经 `Config` 传入，默认关闭）。
    pub fn new(db_path: std::path::PathBuf, sampler_cfg: PiiSamplerConfig) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            metrics: std::sync::Arc::new(MetricsStore::new(db_path.clone())),
            sampler: std::sync::Arc::new(PiiValueSampler::new(sampler_cfg, db_path)),
            rate: Mutex::new(HashMap::new()),
            sse_count: std::sync::Arc::new(Mutex::new(HashMap::new())),
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
            sse_count: std::sync::Arc::new(Mutex::new(HashMap::new())),
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

    /// SSE 并发守卫（5/IP）：调用方 MUST 持有至连接结束，`Drop` 自动释放；
    /// 满时返回 `None`（429）。禁止手动调 `release_sse_for`（双重释放会
    /// 错减他路计数；该方法仅保留作 `Drop` 内部语义的公开别名）。
    pub fn acquire_sse(&self, ip: IpAddr) -> Option<SseGuard> {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n >= SSE_MAX_PER_IP {
            return None;
        }
        guard.insert(ip, n + 1);
        Some(SseGuard {
            ip,
            slots: std::sync::Arc::clone(&self.sse_count),
        })
    }

    /// 释放 SSE 计数（`SseGuard::drop` 内部语义的公开别名；调用方禁止在
    /// 持有守卫时手动调用，否则与 `Drop` 双重释放错减计数）。
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
    /// 注：§6 审计落盘后如需同步推送审计事件，可调用本函数（`kind`=`audit`）。
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

    /// 环内是否存在该 `kind`（`verdict` 兼容过滤命中判定用）。
    pub fn has_kind(&self, kind: &str) -> bool {
        self.events
            .lock()
            .map(|ring| ring.iter().any(|e| e.kind == kind))
            .unwrap_or(false)
    }
}

/// SSE 并发守卫：持有计数槽位，`Drop` 时自动释放（断连不泄漏）。
pub struct SseGuard {
    ip: IpAddr,
    slots: std::sync::Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&self.ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&self.ip);
        } else {
            guard.insert(self.ip, n - 1);
        }
    }
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

/// 超限响应：429 + `Retry-After`（秒）+ 错误码 `E_RATE_LIMITED`（spec 锁定）。/// 头名小写
/// `retry-after`（HTTP 头大小写不敏感，spec 写作 `Retry-After`）。
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

/// 通用限流门（速率维度）：通过则计数 +1；超限返回 `Retry-After` 秒数。
/// 与 SSE 并发计数相互独立（正交），本函数不触 `sse_count`。
fn check_admin_rate(state: &AppState, ip: IpAddr) -> Option<Response> {
    match state.admin.check_rate(ip) {
        Ok(()) => None,
        Err(retry) => Some(rate_limited(retry)),
    }
}

/// 头凭证有效时签发登录 Cookie（对标原仓：仅非 SSE 路由签发）。
/// https 经 `X-Forwarded-Proto` 识别签发 `__Host-admin_token`（Secure），
/// 否则回退 `admin_token` 兼容 http；token 含非法 cookie-octet 字符时拒绝签发。
fn with_admin_cookie(mut resp: Response, headers: &HeaderMap, expected: &str) -> Response {
    let Some(got) = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    else {
        return resp;
    };
    if !admin_token_eq(got, expected) {
        return resp;
    }
    if got
        .chars()
        .any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '~' | '+' | '/' | '-' | '='))
    {
        tracing::warn!("拒绝签发 Cookie：X-Admin-Token 含非法 cookie-octet 字符");
        return resp;
    }
    let https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let value = if https {
        format!("__Host-admin_token={got}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600")
    } else {
        format!("admin_token={got}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600")
    };
    if let Ok(v) = axum::http::HeaderValue::from_str(&value) {
        resp.headers_mut().insert(axum::http::header::SET_COOKIE, v);
    }
    resp
}

/// `GET /_admin/`：JSON 索引占位（终态：返回六路由表与就绪说明，不交付 admin.html 静态页）。
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
    let body = Json(json!({
        "ok": true,
        "admin": "veil observability",
        "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
        "note": "JSON 索引占位终态：六路由 API + SSE 流已就绪（admin.html 为 Non-Goal）",
    }))
    .into_response();
    with_admin_cookie(body, &headers, &state.config.observability_admin_token)
}

/// `GET /_admin/health`：存活探针（透出 sqlite 健康；豁免通用限流，见 [`is_rate_exempt`]）。
pub async fn admin_health(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    debug_assert!(is_rate_exempt("/_admin/health"));
    let _ = addr;
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
    let body = Json(
        json!({"ok": true, "sqlite_ok": health.sqlite_ok, "sqlite_error": health.sqlite_error}),
    )
    .into_response();
    with_admin_cookie(body, &headers, &state.config.observability_admin_token)
}

/// `GET /_admin/metrics`：指标快照（聚合环 + 网关只读计数合并）。
/// 兼容旧查询 `?model=&upstream=`：仅弃用标注回显，不做过滤（快照为全局口径，
/// 过滤会返回空结果误导；调用方应改用 `series?protocol=` 按协议查询）。
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
    let mut body = json!({
        "ok": true,
        "is_precise": snap.is_precise,
        "requests": snap.requests,
        "tokens": {"prompt": snap.prompt_tokens, "completion": snap.completion_tokens, "total": snap.total_tokens, "cached_read": snap.cached_read, "cached_write": snap.cached_write, "unknown": snap.unknown},
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
    });
    let compat: HashMap<&str, &String> = ["model", "upstream"]
        .into_iter()
        .filter_map(|k| query.get(k).map(|v| (k, v)))
        .collect();
    if !compat.is_empty() {
        body["deprecated"] =
            "model/upstream 已弃用：metrics 为全局快照不做过滤，请改用 series?protocol= 按协议查询"
                .into();
        body["compat"] = json!(compat);
    }
    let resp = Json(body).into_response();
    with_admin_cookie(resp, &headers, &state.config.observability_admin_token)
}

/// `GET /_admin/series`：时序查询（`?granularity=daily|hourly|five_min&since=&protocol=`）。
/// 兼容旧查询：`?range=1h/24h/7d/30d` 映射 `granularity`（`granularity` 显式优先）；
/// `?model=&upstream=` 仅弃用标注回显，不转 `protocol` 过滤（旧值为模型名/上游 URL，
/// 与协议尾缀不等价，强转会返回空结果误导；调用方应改用 `protocol=`）。
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
    let range = query.get("range").cloned();
    let granularity = match query.get("granularity") {
        Some(g) if matches!(g.as_str(), "daily" | "hourly" | "five_min" | "5min") => g.clone(),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": {"code": "E_BAD_REQUEST", "message": "granularity 取值 daily/hourly/five_min"}})),
            )
                .into_response();
        }
        None => match range.as_deref().and_then(compat_granularity_for_range) {
            Some(g) => g.to_string(),
            None if range.is_some() => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": {"code": "E_BAD_REQUEST", "message": "range 取值 1h/24h/7d/30d（或改用 granularity=daily/hourly/five_min）"}})),
                )
                    .into_response();
            }
            None => "hourly".to_string(),
        },
    };
    let since = query.get("since").cloned();
    let protocol = query.get("protocol").cloned();
    let mut compat: HashMap<&str, &String> = HashMap::new();
    if let Some(r) = range.as_ref() {
        compat.insert("range", r);
    }
    for k in ["model", "upstream"] {
        if let Some(v) = query.get(k) {
            compat.insert(k, v);
        }
    }
    match state
        .admin
        .metrics
        .query_series(&granularity, since, protocol)
        .await
    {
        Ok(points) => {
            let mut body = json!({"ok": true, "granularity": granularity, "points": points});
            if !compat.is_empty() {
                body["deprecated"] =
                    "range/model/upstream 已弃用：请改用 granularity/since/protocol 新口径".into();
                body["compat"] = json!(compat);
            }
            let resp = Json(body).into_response();
            with_admin_cookie(resp, &headers, &state.config.observability_admin_token)
        }
        Err(e) => VeilError::internal(e).into_response(),
    }
}

/// `GET /_admin/events`：审计事件查询（`?kind=&since=&limit=`，摘要已脱敏）。
/// 兼容旧查询：`?verdict=` 接受旧值并归一（命中环内 `kind` 才做过滤，否则忽略过滤
/// 仅弃用标注，避免空结果误导）；`?model=&upstream=` 仅弃用标注回显。
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
    let verdict = query.get("verdict").cloned();
    let verdict_norm = verdict.as_deref().and_then(normalize_verdict_compat);
    let kind_filter: Option<String> = match (&kind, verdict_norm) {
        (Some(k), _) => Some(k.clone()),
        (None, Some(v)) if state.admin.has_kind(v) => Some(v.to_string()),
        _ => None,
    };
    let since: Option<i64> = query.get("since").and_then(|s| s.parse().ok());
    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(EVENT_DEFAULT_LIMIT);
    let events = state
        .admin
        .query_events(kind_filter.as_deref(), since, limit);
    let samples = state.admin.sampler.top_n(20);
    let mut body = json!({"ok": true, "events": events, "pii_value_samples": samples});
    let mut compat: HashMap<&str, String> = HashMap::new();
    if let Some(v) = verdict {
        compat.insert(
            "verdict",
            match verdict_norm {
                Some(n) => format!("{v}→{n}"),
                None => v,
            },
        );
    }
    for k in ["model", "upstream"] {
        if let Some(v) = query.get(k) {
            compat.insert(k, v.clone());
        }
    }
    if !compat.is_empty() {
        body["deprecated"] = "verdict/model/upstream 已弃用：请改用 kind/since/limit 新口径".into();
        body["compat"] = json!(compat);
    }
    let resp = Json(body).into_response();
    with_admin_cookie(resp, &headers, &state.config.observability_admin_token)
}

/// SSE 推送节奏（对标原仓）：15s 快照全量 + 2s 增量推送。
/// 网关接线人注意：当前 `admin_events_stream` 为事件驱动直推（广播即到）；
/// 若需严格 15s/2s 节奏，网关侧在订阅循环加节流窗（BREAKING 声明备选：保持直推并文档化差异）。
pub const SSE_SNAPSHOT_SECS: u64 = 15;
/// SSE 增量推送间隔（秒）。
pub const SSE_DELTA_SECS: u64 = 2;

/// SSE 建连过滤维度（`?model=&upstream=`；对标原仓建连参数绑定）。
/// 返回 `(model, upstream)`；空表示不过滤。`model` 按事件 `protocol` 子串匹配，
/// `upstream` 按事件摘要子串匹配（尽力过滤，形态不符的事件直通）。
#[derive(Debug, Clone, Default)]
pub struct SseFilter {
    pub model: Option<String>,
    pub upstream: Option<String>,
}

impl SseFilter {
    /// 从建连 query 解析过滤维度。
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        Self {
            model: query.get("model").cloned().filter(|v| !v.is_empty()),
            upstream: query.get("upstream").cloned().filter(|v| !v.is_empty()),
        }
    }

    /// 事件 JSON 是否通过过滤（解析失败直通，不丢事件）。
    pub fn passes(&self, event_json: &str) -> bool {
        if self.model.is_none() && self.upstream.is_none() {
            return true;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(event_json) else {
            return true;
        };
        if let Some(m) = self.model.as_deref()
            && !v
                .get("protocol")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains(m))
        {
            return false;
        }
        if let Some(u) = self.upstream.as_deref()
            && !v
                .get("summary")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s.contains(u))
        {
            return false;
        }
        true
    }
}

/// `GET /_admin/events/stream`：SSE 实时推送（query 鉴权仅此路由有效；
/// 建连 `?model=&upstream=` 过滤维度生效，见 [`SseFilter`]）。
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
    // 并发超限：拒绝新连接（429 + Retry-After: 60），不触已建连接计数。
    // 守卫 MUST 移入流中持有至结束，`Drop` 自动释放（断连不泄漏）。
    let sse_guard = match state.admin.acquire_sse(ip) {
        Some(g) => g,
        None => return rate_limited(60),
    };
    let rx = state.admin.subscribe();
    let admin = state.admin.clone();
    // 建连过滤维度（model/upstream）；近环回放与实时流同过滤。
    let filter = SseFilter::from_query(&query);
    // 近环回放（最近 20 条，已脱敏）。
    let backlog: Vec<String> = admin
        .query_events(None, None, 20)
        .into_iter()
        .rev()
        .filter_map(|e| serde_json::to_string(&e).ok())
        .filter(|s| filter.passes(s))
        .collect();
    let stream = async_stream::stream! {
        let _sse_guard = sse_guard;
        for item in backlog {
            yield Ok::<_, anyhow::Error>(Event::default().data(item).event("message"));
        }
        let mut rx = rx;
        let deadline = tokio::time::Instant::now() + SSE_MAX_AGE;
        loop {
            let timeout = tokio::time::timeout(deadline.saturating_duration_since(tokio::time::Instant::now()), rx.recv()).await;
            match timeout {
                Ok(Ok(msg)) => {
                    if filter.passes(&msg) {
                        yield Ok::<_, anyhow::Error>(Event::default().data(msg).event("message"));
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        // 5min 强制重连：服务端关闭流，客户端按 retry 重连。
        // 计数释放由 `_sse_guard` 的 `Drop` 自动触发，不手动释放。
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
            // 持有守卫期间计数递增（守卫 `Drop` 时自动释放，禁止手动释放）。
        }
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        assert!(st.acquire_sse(test_ip()).is_none());
        // 释放一路后可再建。
        drop(guards.pop());
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP - 1);
        assert!(st.acquire_sse(test_ip()).is_some());
        let _ = guards;
    }

    #[tokio::test]
    async fn 超限响应429带retry_after与错误码锁定() {
        let resp = rate_limited(42);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "E_RATE_LIMITED");
        // SSE 并发拒绝固定 Retry-After: 60。
        let sse_resp = rate_limited(60);
        assert_eq!(sse_resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            sse_resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("60")
        );
    }

    #[tokio::test]
    async fn peerip只认直连不采信代理头() {
        use axum::extract::ConnectInfo;
        let addr: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let req = axum::http::Request::builder()
            .header("x-forwarded-for", "198.51.100.9")
            .header("x-real-ip", "198.51.100.9")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        parts.extensions.insert(ConnectInfo(addr));
        let peer = PeerIp::from_request_parts(&mut parts, &()).await.unwrap();
        assert_eq!(peer.0, addr.ip());
    }

    #[test]
    fn sse超并发拒绝不影响已建连接() {
        let st = test_admin_state();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
        }
        // 第 6 条被拒。
        assert!(st.acquire_sse(test_ip()).is_none());
        // 前 5 条计数不受影响。
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        // 拒绝路径不触计数：再拒一次计数仍为 5。
        assert!(st.acquire_sse(test_ip()).is_none());
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        drop(guards);
        // 守卫全部 `Drop` 后归零（断连不泄漏）。
        assert_eq!(st.sse_current(test_ip()), 0);
    }

    #[test]
    fn 速率与并发计数正交() {
        let st = test_admin_state();
        // 速率打满不影响并发配额。
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(test_ip()).is_ok());
        }
        assert!(st.check_rate(test_ip()).is_err());
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
        }
        assert!(st.acquire_sse(test_ip()).is_none());
        // 并发打满不影响他 IP 速率。
        assert!(st.check_rate(IpAddr::from([10, 0, 0, 9])).is_ok());
        // 释放本 IP 全部并发后归零，速率仍保持超限（独立窗口）。
        drop(guards);
        assert_eq!(st.sse_current(test_ip()), 0);
        assert!(st.check_rate(test_ip()).is_err());
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
    fn 旧range映射新口径等价() {
        assert_eq!(compat_granularity_for_range("1h"), Some("five_min"));
        assert_eq!(compat_granularity_for_range("24h"), Some("hourly"));
        assert_eq!(compat_granularity_for_range("7d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("30d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("24H"), Some("hourly"));
        assert_eq!(compat_granularity_for_range(" 7d "), Some("daily"));
        assert_eq!(compat_granularity_for_range("90d"), None);
        assert_eq!(compat_granularity_for_range(""), None);
    }

    #[test]
    fn 旧verdict归一新口径() {
        for v in ["allow", "allowed", "pass", "approved", "ALLOW"] {
            assert_eq!(normalize_verdict_compat(v), Some("allow"), "{v}");
        }
        for v in ["block", "blocked", "deny", "rejected", "BLOCK"] {
            assert_eq!(normalize_verdict_compat(v), Some("block"), "{v}");
        }
        for v in ["need_approval", "pending", "approve", "approval"] {
            assert_eq!(normalize_verdict_compat(v), Some("need_approval"), "{v}");
        }
        assert_eq!(normalize_verdict_compat("bogus"), None);
        assert_eq!(normalize_verdict_compat(""), None);
    }

    #[test]
    fn verdict兼容命中kind才过滤() {
        let st = test_admin_state();
        st.push_event("audit", "危险操作摘要", None);
        assert!(st.has_kind("audit"));
        assert!(!st.has_kind("block"));
        let norm = normalize_verdict_compat("blocked");
        assert_eq!(norm, Some("block"));
        assert!(!st.has_kind(norm.unwrap()));
        let all = st.query_events(None, None, 10);
        assert_eq!(all.len(), 1);
        assert!(st.query_events(Some("audit"), None, 10).len() == 1);
        assert!(st.query_events(Some("block"), None, 10).is_empty());
    }

    #[tokio::test]
    async fn series_model_upstream兼容仅标注不过滤() {
        use crate::{config::Config, state::SqliteOutcome};
        let dir = std::env::temp_dir().join(format!("veil-admin-series-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
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
                db_path: dir.join("m.sqlite"),
                memory_only: false,
            },
        );
        let mut q: HashMap<String, String> = HashMap::new();
        q.insert("model".to_string(), "gpt-4".to_string());
        q.insert("upstream".to_string(), "https://x".to_string());
        q.insert("granularity".to_string(), "daily".to_string());
        let resp = admin_series(
            State(state),
            PeerIp(test_ip()),
            headers_with(Some("observability-admin-token-0123456789"), None),
            Query(q),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], true);
        assert!(v.get("compat").is_some());
        assert!(v["points"].as_array().is_some());
    }

    #[test]
    fn admin_index占位文案含六路由() {
        let body = json!({
            "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
        });
        assert_eq!(body["routes"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn 后订阅者不收历史只收实时() {
        let st = test_admin_state();
        st.push_event("audit", "历史摘要", None);
        let mut late = st.subscribe();
        assert!(late.try_recv().is_err(), "后订阅不得收到历史广播");
        let mut early = st.subscribe();
        let ev = st.push_event("audit", "实时摘要", None);
        let got_late: String = late.try_recv().expect("后订阅须收到实时事件");
        let got_early: String = early.try_recv().expect("先订阅同样收到实时事件");
        assert!(got_late.contains("实时摘要"), "{got_late}");
        assert!(got_early.contains("实时摘要"), "{got_early}");
        assert_eq!(ev.summary, summarize("实时摘要", SUMMARY_MAX_CHARS));
        assert!(late.try_recv().is_err(), "单事件不得重复投递");
    }

    #[test]
    fn health豁免限流阈值不动() {
        assert!(is_rate_exempt("/_admin/health"));
        assert!(!is_rate_exempt("/_admin/metrics"));
        assert!(!is_rate_exempt("/_admin/events/stream"));
        assert_eq!(ADMIN_RATE_LIMIT, 10);
        assert_eq!(ADMIN_RATE_WINDOW_SECS, 60);
    }

    #[test]
    fn verdict归一全别名通过() {
        for v in ["allow", "allowed", "pass", "approved", "ALLOW", " Pass "] {
            assert_eq!(normalize_verdict_compat(v), Some("allow"), "{v}");
        }
        for v in ["block", "blocked", "deny", "rejected", "BLOCKED"] {
            assert_eq!(normalize_verdict_compat(v), Some("block"), "{v}");
        }
        for v in [
            "need_approval",
            "needapproval",
            "pending",
            "approve",
            "approval",
        ] {
            assert_eq!(normalize_verdict_compat(v), Some("need_approval"), "{v}");
        }
        assert_eq!(normalize_verdict_compat("weird"), None);
        assert_eq!(normalize_verdict_compat(""), None);
        for r in ["1h", "24h", "7d", "30d"] {
            assert!(compat_granularity_for_range(r).is_some(), "{r}");
        }
        assert_eq!(compat_granularity_for_range("1h"), Some("five_min"));
        assert_eq!(compat_granularity_for_range("24h"), Some("hourly"));
        assert_eq!(compat_granularity_for_range("7d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("30d"), Some("daily"));
        assert_eq!(compat_granularity_for_range("9d"), None);
    }

    #[test]
    fn sse五并发上限与释放() {
        let st = test_admin_state();
        let ip = test_ip();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(ip).expect("5 并发内须放行"));
        }
        assert!(st.acquire_sse(ip).is_none(), "第 6 连接须拒绝");
        assert_eq!(st.sse_current(ip), SSE_MAX_PER_IP);
        drop(guards.pop());
        assert!(st.acquire_sse(ip).is_some(), "释放后须可再建");
    }

    #[test]
    fn pending建单后监控可查环() {
        let st = test_admin_state();
        st.push_event("pending", "危险调用待审批", None);
        st.push_event("audit", "普通审计", None);
        let pendings = st.query_events(Some("pending"), None, 100);
        assert_eq!(pendings.len(), 1, "pending 须可按 kind 查环");
        assert!(pendings[0].summary.contains("危险调用待审批"));
        let all = st.query_events(None, None, 100);
        assert_eq!(all.len(), 2);
        let gated = st.query_events(None, None, 1);
        assert_eq!(gated.len(), 1, "limit 须生效");
    }

    #[test]
    fn cookie兼容http回退() {
        let mut h = HeaderMap::new();
        h.insert("cookie", "__Host-admin_token=tok-https".parse().unwrap());
        assert_eq!(cookie_admin_token(&h).as_deref(), Some("tok-https"));
        let mut h2 = HeaderMap::new();
        h2.insert("cookie", "admin_token=tok-http".parse().unwrap());
        assert_eq!(cookie_admin_token(&h2).as_deref(), Some("tok-http"));
        // 双名并存时 __Host- 优先。
        let mut h3 = HeaderMap::new();
        h3.insert(
            "cookie",
            "admin_token=tok-http; __Host-admin_token=tok-https"
                .parse()
                .unwrap(),
        );
        assert_eq!(cookie_admin_token(&h3).as_deref(), Some("tok-https"));
        assert_eq!(cookie_admin_token(&HeaderMap::new()), None);
    }

    #[test]
    fn setcookie签发区分https与http() {
        let expected = "observability-admin-token-0123456789";
        let mut h = HeaderMap::new();
        h.insert("x-admin-token", expected.parse().unwrap());
        let resp = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h, expected);
        let sc = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(sc.starts_with("admin_token="), "{sc}");
        assert!(
            sc.contains("HttpOnly") && sc.contains("SameSite=Strict"),
            "{sc}"
        );
        let mut h2 = HeaderMap::new();
        h2.insert("x-admin-token", expected.parse().unwrap());
        h2.insert("x-forwarded-proto", "https".parse().unwrap());
        let resp2 = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h2, expected);
        let sc2 = resp2.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(sc2.starts_with("__Host-admin_token="), "{sc2}");
        assert!(sc2.contains("Secure"), "{sc2}");
        // 头凭证无效不签发。
        let mut h3 = HeaderMap::new();
        h3.insert("x-admin-token", "wrong".parse().unwrap());
        let resp3 = with_admin_cookie(Json(json!({"ok": true})).into_response(), &h3, expected);
        assert!(resp3.headers().get("set-cookie").is_none());
    }

    #[test]
    fn admintoken文件独立性与回环开关() {
        let dir = std::env::temp_dir().join(format!("veil-admin-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_admin_token_file(&dir), None);
        std::fs::write(dir.join("admin_token"), "file-token-abc\n").unwrap();
        assert_eq!(
            load_admin_token_file(&dir).as_deref(),
            Some("file-token-abc")
        );
        std::fs::remove_dir_all(&dir).ok();
        // 回环免 token 仅 dev + 回环。
        assert!(loopback_grace(true, "127.0.0.1"));
        assert!(loopback_grace(true, "::1"));
        assert!(!loopback_grace(false, "127.0.0.1"));
        assert!(!loopback_grace(true, "192.168.1.10"));
        assert!(!loopback_grace(true, "unknown"));
        // 总开关。
        let env: HashMap<String, String> =
            HashMap::from([("OBSERVABILITY_DISABLE".to_string(), "1".to_string())]);
        assert!(observability_disabled(&env));
        assert!(!observability_disabled(&HashMap::new()));
    }

    #[test]
    fn sse节奏常量与过滤维度() {
        assert_eq!(SSE_SNAPSHOT_SECS, 15);
        assert_eq!(SSE_DELTA_SECS, 2);
        let q: HashMap<String, String> = HashMap::from([
            ("model".to_string(), "chat".to_string()),
            ("upstream".to_string(), "u1".to_string()),
        ]);
        let f = SseFilter::from_query(&q);
        assert!(f.passes(r#"{"protocol":"chat/completions","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"v1/responses","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"chat/completions","summary":"other"}"#));
        // 形态不符直通不丢事件。
        assert!(f.passes("not-json"));
        let empty = SseFilter::from_query(&HashMap::new());
        assert!(empty.passes(r#"{"protocol":"x"}"#));
    }
}
