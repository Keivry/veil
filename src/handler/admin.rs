//! 管理面 handler（A1/D1 自 `service::admin` 搬入）：鉴权 + 限流 + SSE + 事件查询。
//!
//! 层归属：实现 `State<AppState>`、读 `HeaderMap`/`Query`、构造 `Response`
//! 的 web 层逻辑归本文件；`service::admin` 仅留守数据源与纯逻辑（限流表、
//! SSE 并发守卫与过滤、事件环、兼容映射、HMAC 等长比较）。七路由经
//! `router.rs` 注册，路径与状态码不变（精确注册先于通配，MUST NOT 被
//! `/{*tail}` 吞没）：`/_admin/`、`/_admin/health`、`/_admin/metrics`、
//! `/_admin/series`、`/_admin/events`、`/_admin/events/stream`；未知子路径 404。
//!
//! 鉴权优先级 `X-Admin-Token` > `__Host-admin_token` Cookie >
//! `?access_token`（仅 SSE）；非 SSE 带 query 恒 401。限流按直连对端 IP
//! （`PeerIp`，不读代理头）：通用 10/min/IP 429 + `Retry-After`；
//! SSE 5 并发/IP + 60s ping + 5min 强制重连。限流契约见 `service::admin`
//! 模块文档（spec `admin-ratelimit-contract` + design D4）。

use {
    crate::{
        error::VeilError,
        handler::PeerIp,
        service::{admin, credential::AppStateParts},
        state::AppState,
    },
    axum::{
        Json,
        extract::{Query, State},
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
    std::{collections::HashMap, net::IpAddr},
};

/// 未鉴权响应（401 + `E_UNAUTHORIZED`；调用方不区分失败细节，防探测）。
fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": {"code": "E_UNAUTHORIZED", "message": message}})),
    )
        .into_response()
}

/// 从 `Cookie` 头提取 admin token（`__Host-admin_token` 优先，回退 `admin_token`
/// 兼容 http；对标原仓 `_cookie_token` 双名）。
pub fn cookie_admin_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
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
        && admin::admin_token_eq(got, expected)
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
        && admin::admin_token_eq(&got, expected)
    {
        return None;
    }
    let cookie_present = cookie_admin_token(headers).is_some();
    if cookie_present {
        return Some(unauthorized("管理鉴权失败"));
    }
    if is_sse
        && let Some(got) = query_token
        && admin::admin_token_eq(got, expected)
    {
        return None;
    }
    Some(unauthorized("管理鉴权失败"))
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
    if !admin::admin_token_eq(got, expected) {
        return resp;
    }
    if got
        .chars()
        .any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '~' | '+' | '/' | '-' | '='))
    {
        tracing::warn!("拒绝签发 Cookie：X-Admin-Token 含非法 cookie-octet 字符");
        return resp;
    }
    let https = cookie_https(headers);
    let value = if https {
        format!("__Host-admin_token={got}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600")
    } else {
        format!("admin_token={got}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600")
    };
    if let Ok(v) = axum::http::HeaderValue::from_str(&value) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// A16/D15：https 双判据——`X-Forwarded-Proto: https` 或 RFC 7239 `Forwarded`
/// 内 `proto=https`（大小写不敏感）任一命中即为 https（Secure Cookie 判据）。
fn cookie_https(headers: &HeaderMap) -> bool {
    let xfp = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("https"));
    if xfp {
        return true;
    }
    headers
        .get_all("forwarded")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(forwarded_proto_https)
}

/// RFC 7239 `Forwarded` 单头解析：逗号/分号分隔元素与参数，仅取 `proto` 值比对 https。
fn forwarded_proto_https(raw: &str) -> bool {
    raw.split([',', ';']).any(|part| {
        let lower = part.trim().to_ascii_lowercase();
        match lower.strip_prefix("proto=") {
            Some(v) => v.trim().trim_matches('"') == "https",
            None => false,
        }
    })
}

/// 超限响应（自 `service::admin::ratelimit` 搬入）：429 + `Retry-After`（秒）
/// 与错误码 `E_RATE_LIMITED`（spec 锁定；头名小写 `retry-after`，HTTP 头
/// 大小写不敏感）。响应构造属 handler 层，`service` 仅返回重试秒数。
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

/// 管理面提取器回退：`ConnectInfo` 缺失（单测直调 `serve` 场景）回退本地回环，
/// 生产入口由 `main.rs` 以 `into_make_service_with_connect_info` 注入真实对端。
fn peer_ip(addr: &PeerIp) -> IpAddr { addr.0.unwrap_or_else(|| IpAddr::from([127, 0, 0, 1])) }

/// `GET /_admin/`：JSON 索引占位（终态：返回六路由表与就绪说明，不交付 admin.html 静态页）。
pub async fn admin_index(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr);
    if let Some(retry) = admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
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
    with_admin_cookie(body, &headers, &state.config().observability_admin_token)
}

/// `GET /_admin/health`：存活探针（透出 sqlite 健康；豁免通用限流，见 `is_rate_exempt`）。
pub async fn admin_health(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    debug_assert!(admin::is_rate_exempt("/_admin/health"));
    let _ = addr;
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let health = crate::service::health_status(&state);
    let body = Json(json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "pii_custom_disabled": state.detector.disabled_snapshot().len(),
    }))
    .into_response();
    with_admin_cookie(body, &headers, &state.config().observability_admin_token)
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
    let ip = peer_ip(&addr);
    if let Some(retry) = admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let snap = state.admin_state().metrics.snapshot();
    let gm = &state.gateway_metrics();
    // `ARC-2`：审批决策表软上限只读观测；锁中毒时按零降级，不影响其余指标。
    let (decision_overflow, decision_size) = state
        .decisions
        .lock()
        .map(|t| (t.overflow_count(), t.entry_count()))
        .unwrap_or((0, 0));
    let mut body = json!({
        "ok": true,
        "is_precise": snap.is_precise,
        "requests": snap.requests,
        "tokens": {"prompt": snap.prompt_tokens, "completion": snap.completion_tokens, "total": snap.total_tokens, "cached_read": snap.cached_read, "cached_write": snap.cached_write, "unknown": snap.unknown},
        "per_protocol": snap.per_protocol,
        "per_model": snap.per_model,
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
        "approval_decision_overflow_total": decision_overflow,
        "decision_table_size": decision_size,
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
    with_admin_cookie(resp, &headers, &state.config().observability_admin_token)
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
    let ip = peer_ip(&addr);
    if let Some(retry) = admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
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
        None => match range
            .as_deref()
            .and_then(admin::compat_granularity_for_range)
        {
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
        .admin_state()
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
            with_admin_cookie(resp, &headers, &state.config().observability_admin_token)
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
    let ip = peer_ip(&addr);
    if let Some(retry) = admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
        &headers,
        None,
        has_q,
        false,
    ) {
        return r;
    }
    let kind = query.get("kind").cloned();
    let verdict = query.get("verdict").cloned();
    let verdict_norm = verdict.as_deref().and_then(admin::normalize_verdict_compat);
    let kind_filter: Option<String> = match (&kind, verdict_norm) {
        (Some(k), _) => Some(k.clone()),
        (None, Some(v)) if state.admin_state().has_kind(v) => Some(v.to_string()),
        _ => None,
    };
    let since: Option<i64> = query.get("since").and_then(|s| s.parse().ok());
    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(admin::EVENT_DEFAULT_LIMIT);
    let events = state
        .admin_state()
        .query_events(kind_filter.as_deref(), since, limit);
    let samples = state.admin_state().sampler.top_n(20);
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
    with_admin_cookie(resp, &headers, &state.config().observability_admin_token)
}

/// A11/D10：SSE 周期快照 payload 六键 `{range, model, upstream, metrics, series, health}`。
/// 取数复用 `/_admin/metrics`、`/_admin/series`、`/_admin/health` 服务口径；
/// `series` 取数失败降级 `{"error":"series_unavailable"}`，不中断事件推送与 60s ping。
pub(crate) async fn build_metrics_sse_payload(
    state: &AppState,
    filter: &admin::SseFilter,
    range: Option<&str>,
    granularity: &str,
) -> serde_json::Value {
    let snap = state.admin_state().metrics.snapshot();
    let gm = state.gateway_metrics();
    let metrics = json!({
        "ok": true,
        "is_precise": snap.is_precise,
        "requests": snap.requests,
        "tokens": {
            "prompt": snap.prompt_tokens,
            "completion": snap.completion_tokens,
            "total": snap.total_tokens,
            "cached_read": snap.cached_read,
            "cached_write": snap.cached_write,
            "unknown": snap.unknown,
        },
        "per_protocol": snap.per_protocol,
        "per_model": snap.per_model,
        "latency_buckets": snap.latency_buckets,
        "p95_ms": snap.p95_ms,
        "truncated": {
            "silent_discard": snap.truncated_silent_discard,
            "open_ended": snap.truncated_open_ended,
            "synthesized_failed": snap.truncated_synthesized_failed,
        },
        "sse_events": gm.sse_event_total(),
        "ring_len": snap.ring_len,
        "dropped": snap.dropped,
    });
    let series = match state
        .admin_state()
        .metrics
        .query_series(granularity, None, None)
        .await
    {
        Ok(points) => json!(points),
        Err(e) => {
            tracing::warn!("SSE metrics 快照 series 取数失败，降级为 series_unavailable: {e}");
            json!({"error": "series_unavailable"})
        }
    };
    let health = crate::service::health_status(state);
    let health = json!({
        "ok": true,
        "sqlite_ok": health.sqlite_ok,
        "sqlite_error": health.sqlite_error,
        "pii_custom_disabled": state.detector.disabled_snapshot().len(),
    });
    json!({
        "range": range,
        "model": filter.model.clone(),
        "upstream": filter.upstream.clone(),
        "metrics": metrics,
        "series": series,
        "health": health,
    })
}

/// A11：生产 15s 周期；单测缩短以在快速窗口验证周期推送（集成测试走非 test lib，恒 15s）。
fn sse_metrics_interval() -> std::time::Duration {
    if cfg!(test) {
        std::time::Duration::from_millis(80)
    } else {
        admin::SSE_METRICS_INTERVAL
    }
}

/// `GET /_admin/events/stream`：SSE 实时推送（query 鉴权仅此路由有效；
/// 建连 `?model=&upstream=` 过滤维度生效，见 `service::admin::SseFilter`）。
///
/// 推送节奏：事件驱动直推（广播即到）+ 每 15s `event: metrics` 周期快照
/// （A11/D10，取数失败降级不中断）。
pub async fn admin_events_stream(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr);
    if let Some(retry) = admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let qtok = query.get("access_token").cloned();
    let has_q = qtok.is_some();
    if let Some(r) = authorize(
        &state.config().observability_admin_token,
        &headers,
        qtok.as_deref(),
        has_q,
        true,
    ) {
        return r;
    }
    // 并发超限：拒绝新连接（429 + Retry-After: 60），不触已建连接计数。
    // 守卫 MUST 移入流中持有至结束，`Drop` 自动释放（断连不泄漏）。
    let sse_guard = match state.admin_state().acquire_sse(ip) {
        Some(g) => g,
        None => return rate_limited(60),
    };
    let rx = state.admin_state().subscribe();
    let admin = state.admin_state().clone();
    // 建连过滤维度（model/upstream）；近环回放与实时流同过滤。
    let filter = admin::SseFilter::from_query(&query);
    let range = query.get("range").cloned();
    let granularity = match query.get("granularity") {
        Some(g) if matches!(g.as_str(), "daily" | "hourly" | "five_min" | "5min") => g.clone(),
        _ => range
            .as_deref()
            .and_then(admin::compat_granularity_for_range)
            .unwrap_or("hourly")
            .to_string(),
    };
    // 近环回放（最近 20 条，已脱敏）。
    let backlog: Vec<String> = admin
        .query_events(None, None, 20)
        .into_iter()
        .rev()
        .filter_map(|e| serde_json::to_string(&e).ok())
        .filter(|s| filter.passes(s))
        .collect();
    let metrics_state = state.clone();
    let metrics_filter = filter.clone();
    let metrics_range = range.clone();
    let mut metrics_ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + sse_metrics_interval(),
        sse_metrics_interval(),
    );
    metrics_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stream = async_stream::stream! {
        let _sse_guard = sse_guard;
        for item in backlog {
            yield Ok::<_, anyhow::Error>(axum::response::sse::Event::default().data(item).event("message"));
        }
        let mut rx = rx;
        let deadline = tokio::time::Instant::now() + admin::SSE_MAX_AGE;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let until_deadline = deadline.saturating_duration_since(now);
            tokio::select! {
                _ = metrics_ticker.tick() => {
                    let payload = build_metrics_sse_payload(
                        &metrics_state,
                        &metrics_filter,
                        metrics_range.as_deref(),
                        &granularity,
                    )
                    .await;
                    yield Ok::<_, anyhow::Error>(
                        axum::response::sse::Event::default()
                            .event("metrics")
                            .data(payload.to_string()),
                    );
                }
                recv = rx.recv() => match recv {
                    Ok(msg) => {
                        if filter.passes(&msg) {
                            yield Ok::<_, anyhow::Error>(axum::response::sse::Event::default().data(msg).event("message"));
                        }
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(until_deadline) => break,
            }
        }
        // 5min 强制重连：服务端关闭流，客户端按 retry 重连。
        // 计数释放由 `_sse_guard` 的 `Drop` 自动触发，不手动释放。
    };
    axum::response::sse::Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(admin::SSE_PING_INTERVAL)
                .text("ping"),
        )
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
mod tests;
