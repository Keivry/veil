//! 管理面指标快照体与 SSE 快照 payload（自 `admin.rs` 拆出守 800 行红线）。
//!
//! `admin_metrics_body` 是 REST `/_admin/metrics` 与 SSE `metrics` 帧的**唯一**
//! 范围分派点（design §7.4）；`build_metrics_sse_payload` 只做六键外壳组装，
//! 取数口径复用前者与 `/_admin/series`、`/_admin/health`。

use {
    super::{AppState, AppStateParts, RangeSpec, admin, json, query},
    crate::service::metrics::series_since_for_range,
};

/// 值级采样样本转嵌套 dict：`{kind: {mask: {count, hash}}}`。
pub(super) fn pii_value_samples_json(
    samples: &[crate::service::metrics::SampleView],
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for s in samples {
        let entry = out
            .entry(s.kind.clone())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(by_mask) = entry.as_object_mut() {
            by_mask.insert(s.mask.clone(), json!({"count": s.hits, "hash": s.hash}));
        }
    }
    serde_json::Value::Object(out)
}

/// 指标快照体（`/_admin/metrics` 与 SSE `metrics` 快照共用，字段集一致）：
/// 含运行时可靠性三计数、值级采样嵌套字段与审批决策表观测。
///
/// 这是 REST 与 SSE 的**唯一**范围分派点：`Some(range)` 走
/// `snapshot_in_range`（窗口/环范围口径），`None` 保持既有全局快照口径。
/// 非法 `range` 在 REST 侧已由调用方拒为 `400`；SSE 建连参数非法时降级为全局
/// 快照并 `warn`（长连接不得因一个查询参数断开）。
///
/// 生产路径在 `spawn_blocking` 内调用：`per_model_counts` 是 sqlite 读取。
pub(super) fn admin_metrics_body(state: &AppState, range: Option<&str>) -> serde_json::Value {
    let now = query::now_secs();
    let log = &state.request_log;
    let mut snap = match range.map(RangeSpec::parse) {
        Some(Ok(spec)) => {
            // 模型分布取自 rollup 投影（与 KPI `requests` 同集合）；粒度由 `RangeSpec`
            // 显式给出，不由 `now - start_ts` 反推（对齐起点会推粗粒度）。不可用时
            // 快照内部回退环样本并置 `per_model_partial`，绝不静默返回空分布。
            let per_model = if log.enabled() {
                match log.per_model_counts(spec.range_start(now), spec.rollup_granularity()) {
                    Ok(rows) => Some(rows),
                    Err(err) => {
                        tracing::warn!("范围快照的模型分布读取失败，降级为空分布: {err:#}");
                        None
                    }
                }
            } else {
                None
            };
            state
                .admin_state()
                .metrics
                .snapshot_in_range(spec, now, per_model.as_deref())
        }
        Some(Err(())) => {
            tracing::warn!(range = ?range, "非法 range 降级为全局快照");
            state.admin_state().metrics.snapshot()
        }
        None => state.admin_state().metrics.snapshot(),
    };
    snap.requests_dropped = log.dropped_total();
    snap.requests_aborted = log.aborted_total();
    // 队列有丢弃即表示 rollup 投影不完整：仅范围口径把分布降级标注，
    // 无范围快照的 `per_model_partial` 语义保持不变。
    if snap.range.is_some() && snap.requests_dropped > 0 {
        snap.per_model_partial = true;
    }
    let gm = state.gateway_metrics();
    // 审批决策表软上限只读观测；锁中毒时按零降级，不影响其余指标。
    let (decision_overflow, decision_size) = state
        .decisions
        .lock()
        .map(|t| (t.overflow_count(), t.entry_count()))
        .unwrap_or((0, 0));
    let samples = state.admin_state().sampler.top_n(20);
    let mut body = json!({
        "ok": true,
        "is_precise": snap.is_precise,
        "requests": snap.requests,
        "pii_hits": snap.pii_hits,
        "pii_miss": snap.pii_miss,
        "cred_hits": snap.cred_hits,
        "tokens": {"prompt": snap.prompt_tokens, "completion": snap.completion_tokens, "total": snap.total_tokens, "cached_read": snap.cached_read, "cached_write": snap.cached_write, "unknown": snap.unknown},
        "per_protocol": snap.per_protocol,
        "per_model": snap.per_model,
        "latency_buckets": snap.latency_buckets,
        "p95_ms": snap.p95_ms,
        "p95_saturated": snap.p95_saturated,
        "truncated": {
            "silent_discard": snap.truncated_silent_discard,
            "open_ended": snap.truncated_open_ended,
            "synthesized_failed": snap.truncated_synthesized_failed,
            "upstream_error": snap.truncated_upstream_error,
        },
        // 超软限观测（只增项，键名对齐 `GatewayMetrics` 同名计数器）：
        // 超软限但完整交付的帧数/字节数。`truncated` 四态保留——fail-closed
        // 收尾仍经 `record_truncated` 落账（`OpenEnded`/`SynthesizedFailed`），
        // 二者是互补口径而非新旧替换。
        "oversize_frames": gm.oversize_frames_count(),
        "oversize_frame_bytes": gm.oversize_frame_bytes_count(),
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
        "upstream_read_errors": gm.upstream_read_error_count(),
        "admin_rate_evicted": gm.admin_rate_evicted_count(),
        "aggs_evicted": snap.aggs_evicted,
        "pii_value_samples": pii_value_samples_json(&samples),
        // 只读会话作用域观测——模式 + 三计数。计数为无锁原子读，恒可用
        // （缺失/锁不可用即降级为 0，绝不使请求失败）；既有键名与语义不变。
        "pii_scope": {
            "mode": if state.config.pii_scope_mode.is_conversation() { "conversation" } else { "request" },
            "conversation_reuse": gm.conversation_reuse_count(),
            "conversation_eviction": gm.conversation_eviction_count(),
            "request_fallback": gm.request_fallback_count(),
        },
        "requests_dropped": snap.requests_dropped,
        "requests_aborted": snap.requests_aborted,
        "per_model_partial": snap.per_model_partial,
    });
    // 范围字段只进 `data.metrics`（REST 顶层）：无范围快照不出现 `range` 键。
    query::attach_metrics_range(&mut body, &snap);
    body
}

/// SSE 周期快照 payload 六键 `{range, model, upstream, metrics, series, health}`。
/// 取数复用 `/_admin/metrics`、`/_admin/series`、`/_admin/health` 服务口径；
/// `series` 取数失败降级 `{"error":"series_unavailable"}`，不中断事件推送与 60s ping。
///
/// `metrics` 与 `series` 均按连接的 `range` 收敛（`data.metrics` 必须与同参 REST
/// `/_admin/metrics` 等值）；六键外壳不因 `range` 增减，`data.range` 缺失为 `null`。
pub(crate) async fn build_metrics_sse_payload(
    state: &AppState,
    filter: &admin::SseFilter,
    range: Option<&str>,
    granularity: &str,
) -> serde_json::Value {
    let snapshot_state = state.clone();
    let metrics_range = range.map(str::to_owned);
    let metrics = tokio::task::spawn_blocking(move || {
        admin_metrics_body(&snapshot_state, metrics_range.as_deref())
    })
    .await
    .unwrap_or_else(|err| {
        tracing::warn!("SSE metrics 快照取数失败，降级为空快照: {err}");
        json!({"ok": false})
    });
    let series_since = range
        .and_then(|raw| RangeSpec::parse(raw).ok())
        .map(|spec| series_since_for_range(spec, query::now_secs()));
    let series = match state
        .admin_state()
        .metrics
        .query_series(granularity, series_since, None)
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

/// 生产 15s 周期；单测缩短以在快速窗口验证周期推送（集成测试走非 test lib，恒 15s）。
pub(super) fn sse_metrics_interval() -> std::time::Duration {
    if cfg!(test) {
        std::time::Duration::from_millis(80)
    } else {
        admin::SSE_METRICS_INTERVAL
    }
}
