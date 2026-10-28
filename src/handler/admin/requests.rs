//! `GET /_admin/requests`：逐请求记录分页查询（design §8.3 契约）。
//!
//! 过滤：`range`（四档，折算精确秒级下界）、`model`、`protocol`、
//! `status`（`2xx|4xx|5xx|error`）、`session`（前缀，≥4 字符）、
//! `scope`（`session|user|any`，默认 `any`）、`limit`（默认 50 / 上限 200）、
//! `offset`（上限 10000，超出 400）。
//!
//! 未给 `range` 时响应省略 `range`/`since_ts`/`boundary_slack_secs` 三个键（不以
//! `null` 冒充全局口径），`coverage_secs` 取 `now - 最早记录`、`partial=false`。
//! 记录功能关闭时短路为 `{"ok":true,"enabled":false,"rows":[],"total":0}`。

use {
    super::{
        AppState,
        HashMap,
        HeaderMap,
        IntoResponse,
        Json,
        PeerIp,
        Query,
        Response,
        State,
        authorize,
        peer_ip,
        query::{attach_range, attach_unranged_coverage, bad_request, now_secs, parse_range},
        rate_limited,
        with_admin_cookie,
        with_security_headers,
    },
    crate::{
        error::VeilError,
        service::{
            credential::AppStateParts,
            request_log::{
                MAX_OFFSET,
                MIN_SESSION_PREFIX_CHARS,
                RequestFilter,
                RequestRow,
                SessionScope,
                StatusClass,
            },
        },
    },
    serde_json::{Value, json},
};

/// `GET /_admin/requests`：逐请求记录查询（限流 → 鉴权 → 过滤 → 分页）。
pub async fn admin_requests(
    State(state): State<AppState>,
    addr: PeerIp,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let ip = peer_ip(&addr);
    if let Some(retry) = crate::service::admin::check_admin_rate(&state, ip) {
        return rate_limited(retry);
    }
    let expected = &state.config().observability_admin_token;
    let has_q = query.contains_key("access_token");
    if let Some(r) = authorize(expected, &headers, None, has_q, false) {
        return r;
    }
    let now = now_secs();
    let spec = match parse_range(&query) {
        Ok(spec) => spec,
        Err(message) => return bad_request(message),
    };
    let status_class = match query.get("status") {
        None => None,
        Some(raw) => match StatusClass::parse(raw) {
            Some(class) => Some(class),
            None => {
                return bad_request(format!("status 取值 2xx|4xx|5xx|error（当前值 {raw:?}）"));
            }
        },
    };
    let session_prefix = match query.get("session") {
        None => None,
        Some(raw) if raw.chars().count() < MIN_SESSION_PREFIX_CHARS => {
            return bad_request(format!(
                "session 前缀至少 {MIN_SESSION_PREFIX_CHARS} 个字符（当前值 {raw:?}）"
            ));
        }
        Some(raw) => Some(raw.clone()),
    };
    let scope = match query.get("scope") {
        None => None,
        Some(raw) => match raw.as_str() {
            "any" => None,
            "session" => Some(SessionScope::Session),
            "user" => Some(SessionScope::User),
            _ => return bad_request(format!("scope 取值 session|user|any（当前值 {raw:?}）")),
        },
    };
    let limit = match query.get("limit") {
        None => None,
        Some(raw) => match raw.parse::<usize>() {
            Ok(v) => Some(v),
            Err(_) => return bad_request(format!("limit 须为非负整数（当前值 {raw:?}）")),
        },
    };
    let offset = match query.get("offset") {
        None => None,
        Some(raw) => match raw.parse::<usize>() {
            Ok(v) if v > MAX_OFFSET => {
                return bad_request(format!("offset 上限 {MAX_OFFSET}（当前值 {v}）"));
            }
            Ok(v) => Some(v),
            Err(_) => return bad_request(format!("offset 须为非负整数（当前值 {raw:?}）")),
        },
    };
    // 参数校验先于「未启用」短路：日志关闭时非法 range/limit/offset 仍须 400，
    // 否则调用方无法尽早发现参数错误（启用后同一请求才会突然失败）。
    if !state.request_log.enabled() {
        let body =
            Json(json!({"ok": true, "enabled": false, "rows": [], "total": 0})).into_response();
        return with_admin_cookie(body, &headers, expected);
    }
    let filter = RequestFilter {
        range_start_ts: spec.map(|s| s.range_start(now)),
        model: query.get("model").cloned(),
        protocol: query.get("protocol").cloned(),
        status_class,
        session_prefix,
        scope,
        limit,
        offset,
    };
    // 回显收敛后的分页参数（`limit` 越界收敛至 200，`offset` 已校验上限）。
    let echo_limit = filter.limit();
    let echo_offset = filter.offset();
    let log = state.request_log.clone();
    let page = match tokio::task::spawn_blocking(move || log.query(&filter)).await {
        Ok(Ok(page)) => page,
        Ok(Err(err)) => return storage_error(err),
        Err(err) => return storage_error(anyhow::anyhow!("查询任务异常: {err}")),
    };
    let mut body = json!({
        "ok": true,
        "enabled": true,
        "total": page.total,
        "limit": echo_limit,
        "offset": echo_offset,
        "sum_cached_read": page.sum_cached_read,
        "sum_cache_input_tokens": page.sum_cache_input_tokens,
        "hit_rate": ratio(page.sum_cached_read, page.sum_cache_input_tokens),
        "rows": page.rows.iter().map(row_json).collect::<Vec<_>>(),
    });
    let coverage_earliest = page.retention_earliest_ts.or(page.earliest_ts);
    match spec {
        Some(spec) => {
            let since_ts = spec.range_start(now);
            attach_range(&mut body, spec, since_ts, coverage_earliest, now, 0);
        }
        None => attach_unranged_coverage(&mut body, coverage_earliest, now),
    }
    with_admin_cookie(Json(body).into_response(), &headers, expected)
}

/// 比率（分子/分母；分母 0 → `null`，禁止行均）。
///
/// 行级与范围级同用本函数：范围级 `SUM/SUM` 由调用方先分别求和。
fn ratio(numerator: u64, denominator: u64) -> Value {
    if denominator == 0 {
        Value::Null
    } else {
        json!(numerator as f64 / denominator as f64)
    }
}

/// 单行响应体（字段集与 design §8.3 完全一致）。
fn row_json(row: &RequestRow) -> Value {
    json!({
        "ts_secs": row.ts_secs,
        "request_id": row.request_id,
        "model": row.model,
        "protocol": row.protocol,
        "upstream": row.upstream,
        "ingress_port": row.ingress_port,
        "stream": row.stream,
        "is_chat": row.is_chat,
        "status": row.status,
        "latency_ms": row.latency_ms,
        "prompt_tokens": row.prompt_tokens,
        "completion_tokens": row.completion_tokens,
        "total_tokens": row.total_tokens,
        "cached_read": row.cached_read,
        "cache_input_tokens": row.cache_input_tokens,
        "cache_hit_rate": ratio(row.cached_read, row.cache_input_tokens),
        "cache_write_rate": ratio(row.cached_write, row.cache_input_tokens),
        "session_id": row.session_id,
        "session_source": row.session_source,
        "session_scope": row.session_scope,
        "upstream_id": row.upstream_id,
        "finish_reason": row.finish_reason,
        "summary": row.req_summary,
        "truncated_mode": row.truncated_mode,
        "error_kind": row.error_kind,
    })
}

/// 存储层失败：500 + `E_STORAGE`（对外脱敏，细节仅日志）。
fn storage_error(err: anyhow::Error) -> Response {
    with_security_headers(VeilError::internal(err).into_response())
}
