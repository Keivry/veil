//! 管理面查询公共纯逻辑：`range` 解析、时间下界折算、覆盖时长与统一 400。
//!
//! `metrics`/`series`/`events`/`commands`/`requests` 共用同一份 `range` 口径
//! （design §7.2/§7.5），避免各 handler 各自维护第二份映射。本模块不持有状态，
//! 只做参数校验与 JSON 片段拼装；响应头统一由调用方经
//! `with_admin_cookie`/`with_security_headers` 补齐。

use {
    super::with_security_headers,
    crate::service::metrics::{MetricsSnapshot, RANGE_LABELS, RangeGranularity, RangeSpec},
    axum::{
        Json,
        http::StatusCode,
        response::{IntoResponse, Response},
    },
    serde_json::{Value, json},
    std::collections::HashMap,
};

/// 当前 Unix 秒（管理面查询的唯一时间基准，不读任何请求头）。
pub(super) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `400 + E_BAD_REQUEST`（同样携带管理面统一安全头：非法参数响应也不可缓存）。
pub(super) fn bad_request(message: impl Into<String>) -> Response {
    with_security_headers(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"code": "E_BAD_REQUEST", "message": message.into()}})),
        )
            .into_response(),
    )
}

/// 解析可选 `range`：缺失 → `Ok(None)`；非法 → `Err` 携带 400 消息
/// （已列明合法取值）。错误只回传文本，响应由调用方经 [`bad_request`] 构造
/// （`Response` 体积大，不作 `Err` 变体）。
pub(super) fn parse_range(query: &HashMap<String, String>) -> Result<Option<RangeSpec>, String> {
    match query.get("range") {
        None => Ok(None),
        Some(raw) => RangeSpec::parse(raw)
            .map(Some)
            .map_err(|()| format!("range 取值 {}（当前值 {raw:?}）", RANGE_LABELS.join("|"))),
    }
}

/// 给「已给出 `range`」的响应补五个范围键。
///
/// `range`/`since_ts`/`boundary_slack_secs` 成组出现（未给 `range` 时调用方 MUST NOT
/// 调用本函数，避免以 `null` 冒充「全局口径」）；`coverage_secs` 取
/// `now - max(since_ts, earliest_ts)`，`partial` 为「覆盖短于所选跨度」。
/// `earliest_ts` 为该查询可回答数据的最早时间（`None` = 无数据），
/// `boundary_slack_secs` 为窗口对齐误差上界（按 `ts_secs` 精确过滤的端点传 0）。
pub(super) fn attach_range(
    body: &mut Value,
    spec: RangeSpec,
    since_ts: i64,
    earliest_ts: Option<i64>,
    now: i64,
    boundary_slack_secs: u64,
) {
    let coverage = earliest_ts.map_or(0, |earliest| {
        u64::try_from(now - since_ts.max(earliest)).unwrap_or(0)
    });
    let span = u64::try_from(spec.span_secs).unwrap_or(0);
    body["range"] = json!(spec.label());
    body["since_ts"] = json!(since_ts);
    body["boundary_slack_secs"] = json!(boundary_slack_secs);
    body["coverage_secs"] = json!(coverage);
    body["partial"] = json!(coverage < span);
}

/// 未给 `range` 时的覆盖键：`coverage_secs = now - 最早可用时间`、`partial=false`。
pub(super) fn attach_unranged_coverage(body: &mut Value, earliest_ts: Option<i64>, now: i64) {
    let coverage = earliest_ts.map_or(0, |earliest| u64::try_from(now - earliest).unwrap_or(0));
    body["coverage_secs"] = json!(coverage);
    body["partial"] = json!(false);
}

/// 范围起点的窗口键，按**最终生效**的 `granularity` 折算。
///
/// `/_admin/series` 的 `granularity` 可显式覆盖 `range` 的默认粒度；若仍按
/// `range` 自带粒度产出窗口键，就会与另一种前缀的窗口做字符串序比较而恒空。
/// 故此处在调用方完成 `granularity` 校验后，按同一粒度折算下界，保持
/// `range` 的时间下界语义。
pub(super) fn series_since_for_range_with(
    spec: RangeSpec,
    granularity: &str,
    now_secs: i64,
) -> String {
    let gran = match granularity {
        "daily" => RangeGranularity::Daily,
        "five_min" | "5min" => RangeGranularity::FiveMin,
        _ => RangeGranularity::Hourly,
    };
    gran.window_key(spec.range_start(now_secs))
}

/// 把范围字段补进 `data.metrics`（SSE 六键外壳不动，只改其中的 `metrics` 对象）。
///
/// 仅当快照确实来自范围路径（`snap.range`/`snap.since_ts` 均为 `Some`）时写入；
/// 无范围快照 MUST NOT 出现 `range` 键（否则与「全局口径」混淆）。
pub(super) fn attach_metrics_range(body: &mut Value, snap: &MetricsSnapshot) {
    let (Some(range), Some(since_ts)) = (snap.range.as_deref(), snap.since_ts) else {
        return;
    };
    body["range"] = json!(range);
    body["since_ts"] = json!(since_ts);
    body["boundary_slack_secs"] = json!(snap.boundary_slack_secs);
    body["coverage_secs"] = json!(snap.coverage_secs);
    body["partial"] = json!(snap.partial);
}
