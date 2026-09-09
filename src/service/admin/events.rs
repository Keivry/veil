//! 管理面事件查询：鉴权/兼容标注 + 五个 JSON handler。

use {
    super::{super::credential::AppStateParts, ratelimit::check_admin_rate, sse::PeerIp},
    crate::{error::VeilError, state::AppState},
    axum::{
        Json,
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
    },
    serde_json::json,
    std::collections::HashMap,
};

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
/// D4：仅单测使用，降级为测试可见（生产无读取方）。
#[cfg(test)]
pub fn load_admin_token_file(data_dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("admin_token")).ok()?;
    let v = text.trim().to_string();
    (!v.is_empty()).then_some(v)
}

/// 回环免 token 放行判定（对标原仓）：仅 `ENV=dev` 且回环远端时豁免鉴权，
/// 生产回环同样鉴权（Docker/反代下回环不可靠，fail-closed）。
/// 完整 bypass 接线（`ALLOW_LOOPBACK_NO_TOKEN` 门 + 鉴权前判定）归网关入口，
/// 本函数只提供纯判定供接线与单测。
/// D4：仅单测使用，降级为测试可见（生产无读取方）。
#[cfg(test)]
pub fn loopback_grace(env_is_dev: bool, remote: &str) -> bool {
    if !env_is_dev {
        return false;
    }
    let r = remote.trim().trim_start_matches('[').trim_end_matches(']');
    r == "127.0.0.1" || r == "::1" || r == "::ffff:127.0.0.1"
}

/// 可观测性总开关：`OBSERVABILITY_DISABLE=1` 时管理面显式禁用（过渡逃生开关，
/// 对标原仓；网关入口据此拒绝注册 admin 路由并告警）。
/// D4：仅单测使用，降级为测试可见（生产无读取方）。
#[cfg(test)]
pub fn observability_disabled(env: &HashMap<String, String>) -> bool {
    matches!(
        env.get("OBSERVABILITY_DISABLE").map(|v| v.trim()),
        Some("1") | Some("true") | Some("yes")
    )
}

/// 事件查询默认上限。
pub const EVENT_DEFAULT_LIMIT: usize = 100;

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": {"code": "E_UNAUTHORIZED", "message": message}})),
    )
        .into_response()
}

/// 鉴权（优先级：`X-Admin-Token` > Cookie > 仅 SSE 的 `?access_token`）。
///
/// 非 SSE 带 query token 恒 401（即使 token 有效，强制使用请求头或 Cookie）。
pub(crate) fn authorize(
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
    debug_assert!(super::ratelimit::is_rate_exempt("/_admin/health"));
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
    let body = Json(
        json!({"ok": true, "sqlite_ok": health.sqlite_ok, "sqlite_error": health.sqlite_error}),
    )
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
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
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
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
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
    let ip = addr.0;
    if let Some(r) = check_admin_rate(&state, ip) {
        return r;
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
    let verdict_norm = verdict.as_deref().and_then(normalize_verdict_compat);
    let kind_filter: Option<String> = match (&kind, verdict_norm) {
        (Some(k), _) => Some(k.clone()),
        (None, Some(v)) if state.admin_state().has_kind(v) => Some(v.to_string()),
        _ => None,
    };
    let since: Option<i64> = query.get("since").and_then(|s| s.parse().ok());
    let limit: usize = query
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(EVENT_DEFAULT_LIMIT);
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
    use {
        super::{super::state::test_support::headers_with, *},
        axum::http::HeaderMap,
    };

    #[test]
    fn hmac_constant_time_comparison_semantics() {
        assert!(admin_token_eq("tok-abc-123", "tok-abc-123"));
        assert!(!admin_token_eq("tok-abc-124", "tok-abc-123"));
        assert!(!admin_token_eq("short", "much-longer-expected-value"));
        assert!(!admin_token_eq("", "x"));
        assert!(admin_token_eq("", ""));
    }

    #[test]
    fn auth_priority_header_cookie_query_and_401() {
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
    fn cookie_admin_token_parsing() {
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
    fn unknown_subpath_returns_404() {
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
    fn legacy_range_maps_to_new_granularity() {
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
    fn legacy_verdict_normalizes_to_new_values() {
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
    fn verdict_normalization_covers_all_aliases() {
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
    fn admin_index_lists_six_routes() {
        let body = json!({
            "routes": ["/_admin/", "/_admin/health", "/_admin/metrics", "/_admin/series", "/_admin/events", "/_admin/events/stream"],
        });
        assert_eq!(body["routes"].as_array().unwrap().len(), 6);
    }

    #[test]
    fn cookie_falls_back_to_http_name() {
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
    fn set_cookie_distinguishes_https_from_http() {
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
    fn admin_token_file_isolation_and_loopback_grace() {
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
}
