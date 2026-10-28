//! 范围语义单测：解析、边界、1h 双路径、覆盖/精确性与无范围快照不变。

use {
    super::{RANGE_LABELS, RangeGranularity, RangeSpec, series_since_for_range},
    crate::service::{
        llm_gateway::Protocol,
        metrics::{
            MetricsStore,
            aggregate::{Granularity, day_key, five_min_key, hour_key, window_ord},
            summarize::test_support::{chat_rec, tmp_db, usage},
        },
        request_log::{RequestLog, RequestRow},
    },
};

/// 对齐整日的固定 `now`（日/时/5min 窗口边界均为整数，避免测试撞窗口沿）。
const NOW: i64 = 86_400 * 20_000;

fn rec_at(store: &MetricsStore, ts: i64, total: u64, precise: bool) {
    store.record_chat(chat_rec(
        Protocol::Chat,
        "m",
        10,
        Some(&usage(total / 2, total - total / 2, total)),
        None,
        precise,
        ts,
    ));
}

/// 具名模型样本（`per_model` 对账用例需要环与 rollup 用同一模型名）。
fn rec_model_at(store: &MetricsStore, ts: i64, model: &str) {
    store.record_chat(chat_rec(
        Protocol::Chat,
        model,
        10,
        Some(&usage(1, 0, 1)),
        None,
        true,
        ts,
    ));
}

/// 与指标样本一一对应的逐请求行（`counted_metrics=1` 才进 rollup 投影）。
fn request_row_at(ts: i64, model: &str) -> RequestRow {
    RequestRow {
        ts_secs: ts,
        request_id: format!("req-{ts}-{model}"),
        protocol: "chat".to_string(),
        model: model.to_string(),
        counted_metrics: true,
        ..RequestRow::default()
    }
}

#[test]
fn range_spec_parse_all_labels_and_reject_others() {
    for label in RANGE_LABELS {
        let spec = RangeSpec::parse(label).expect("合法 range 须可解析");
        assert_eq!(spec.label(), label, "回显标签须与输入同形");
    }
    assert_eq!(RangeSpec::parse("1h").unwrap().span_secs, 3_600);
    assert_eq!(RangeSpec::parse("24h").unwrap().span_secs, 86_400);
    assert_eq!(RangeSpec::parse("7d").unwrap().span_secs, 7 * 86_400);
    assert_eq!(RangeSpec::parse("30d").unwrap().span_secs, 30 * 86_400);
    assert_eq!(
        RangeSpec::parse("1h").unwrap().granularity,
        RangeGranularity::FiveMin
    );
    assert_eq!(
        RangeSpec::parse("24h").unwrap().granularity,
        RangeGranularity::Hourly
    );
    assert_eq!(
        RangeSpec::parse("7d").unwrap().granularity,
        RangeGranularity::Daily
    );
    assert_eq!(
        RangeSpec::parse("30d").unwrap().granularity,
        RangeGranularity::Daily
    );
    assert_eq!(
        RangeSpec::parse("1h").unwrap().fallback_granularity,
        Some(RangeGranularity::FiveMin),
        "1h 档须声明 five_min 兜底粒度"
    );
    assert_eq!(
        RangeSpec::parse("24h").unwrap().fallback_granularity,
        None,
        "非 1h 档无兜底粒度"
    );
    assert!(RangeSpec::parse(" 24H ").is_ok(), "容忍大小写与首尾空白");
    for bad in ["2h", "90d", "", "1", "1d", "1m"] {
        assert!(RangeSpec::parse(bad).is_err(), "非法 range 须 Err: {bad:?}");
    }
}

#[test]
fn series_since_for_range_uses_range_granularity() {
    assert_eq!(
        series_since_for_range(RangeSpec::parse("1h").unwrap(), NOW),
        five_min_key(NOW - 3_600)
    );
    assert_eq!(
        series_since_for_range(RangeSpec::parse("24h").unwrap(), NOW),
        hour_key(NOW - 86_400)
    );
    assert_eq!(
        series_since_for_range(RangeSpec::parse("7d").unwrap(), NOW),
        day_key(NOW - 7 * 86_400)
    );
    assert_eq!(
        series_since_for_range(RangeSpec::parse("30d").unwrap(), NOW),
        day_key(NOW - 30 * 86_400)
    );
}

#[test]
fn ring_range_boundary_is_inclusive_at_range_start() {
    // 环覆盖满 1h：`range_start - 1` 不计，`range_start` 计。
    let store = MetricsStore::new(tmp_db("range-boundary"));
    let range_start = NOW - 3_600;
    rec_at(&store, range_start - 1, 999, true);
    rec_at(&store, range_start, 7, true);
    rec_at(&store, NOW - 100, 3, true);
    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 2, "仅 range_start 及之后计入: {snap:?}");
    assert_eq!(snap.total_tokens, 10, "range_start-1 的 999 须被排除");
    assert_eq!(
        snap.boundary_slack_secs, 300,
        "环路径 requests 秒级，但 pii/cred 走 5min 窗口口径"
    );
    assert_eq!(snap.since_ts, Some(range_start));
    assert_eq!(snap.range.as_deref(), Some("1h"));
}

#[test]
fn one_hour_prefers_ring_when_covered() {
    let store = MetricsStore::new(tmp_db("range-ring-prefers"));
    for i in 0..100 {
        rec_at(&store, NOW - 3_600 + i * 35, 2, true);
    }
    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 100);
    assert_eq!(
        snap.boundary_slack_secs, 300,
        "环覆盖满 1h 仍走秒级路径，但附属计数为 5min 口径"
    );
    assert_eq!(snap.coverage_secs, 3_600);
    assert!(!snap.partial, "完整覆盖不得标 partial");
    assert!(snap.is_precise, "100 样本 + 完整覆盖 + 全精确 → 精确");
}

#[test]
fn one_hour_falls_back_to_five_min_windows_when_ring_short() {
    let store = MetricsStore::new(tmp_db("range-fallback"));
    rec_at(&store, NOW - 3_400, 4, true);
    rec_at(&store, NOW, 6, true);
    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    assert_eq!(snap.boundary_slack_secs, 300, "兜底路径误差上界 = 5min");
    assert_eq!(snap.requests, 2, "五个 5min 窗内的两条样本须被求和");
    assert_eq!(snap.total_tokens, 10);
    assert!(snap.partial, "环未覆盖满 1h 须标 partial");
    assert!(!snap.is_precise);
}

#[tokio::test]
async fn one_hour_fallback_stays_partial_even_with_full_windows() {
    // 环为空（重启后）但 sqlite 回填出覆盖整段的 5min 窗口 → 走兜底路径且判精确。
    let db = tmp_db("range-fallback-precise");
    let _ = std::fs::remove_file(&db);
    let seeded = MetricsStore::new(db.clone());
    for i in 0..100 {
        rec_at(&seeded, NOW - 3_600 + i, 1, true);
    }
    seeded.flush().await.unwrap();

    let store = MetricsStore::new(db.clone());
    store.backfill_from_sqlite().await.unwrap();
    rec_at(&store, NOW - 100, 1, true);
    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    assert_eq!(snap.boundary_slack_secs, 300, "环不足须走 5min 兜底");
    assert!(snap.partial, "1h 兜底恒标 partial（精度口径降级）");
    assert_eq!(snap.requests, 101, "100 条回填 + 1 条环内新样本均计入");
    assert!(!snap.is_precise, "partial 与 is_precise 互斥");
    let _ = std::fs::remove_file(&db);
}

#[test]
fn freshly_started_store_is_partial_and_not_precise() {
    // 刚启动 ~10 分钟：覆盖不足 1h → partial + is_precise=false。
    let store = MetricsStore::new(tmp_db("range-fresh"));
    for i in 0..500 {
        rec_at(&store, NOW - 600 + i, 1, true);
    }
    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    assert_eq!(snap.coverage_secs, 600, "覆盖 = now - 最早样本");
    assert!(snap.partial);
    assert!(!snap.is_precise, "覆盖不足 1h 不得宣称可对账");
    assert_eq!(snap.since_ts, Some(NOW - 3_600));
}

#[test]
fn empty_store_range_snapshot_is_zero_coverage() {
    let store = MetricsStore::new(tmp_db("range-empty"));
    let snap = store.snapshot_in_range(RangeSpec::parse("24h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 0);
    assert_eq!(snap.coverage_secs, 0);
    assert!(snap.partial);
    assert!(!snap.is_precise);
    assert_eq!(snap.boundary_slack_secs, 3_600);
    assert_eq!(snap.since_ts, Some(hour_key_window_start(NOW - 86_400)));
}

fn hour_key_window_start(ts: i64) -> i64 { ts.div_euclid(3_600) * 3_600 }

#[test]
fn daily_range_uses_daily_windows_and_full_coverage_is_precise() {
    let store = MetricsStore::new(tmp_db("range-daily"));
    let range_start = NOW - 30 * 86_400;
    for i in 0..100 {
        rec_at(&store, range_start + i * 60, 1, true);
    }
    let snap = store.snapshot_in_range(RangeSpec::parse("30d").unwrap(), NOW, None);
    assert_eq!(snap.requests, 100);
    assert_eq!(snap.boundary_slack_secs, 86_400);
    assert_eq!(snap.coverage_secs, 30 * 86_400, "日窗起点覆盖整段");
    assert!(!snap.partial);
    assert!(snap.is_precise, "窗口完整覆盖所选范围 → 精确");
}

/// tasks 6.3：同一批请求下 `SUM(per_model) == metrics.requests`，1h 环路径与
/// 24h 窗口路径各一例（rollup 投影与环/agg 样本来自同一批样本）。
#[test]
fn per_model_rollup_sums_match_requests_for_1h_and_24h() {
    // 窗口对齐前置：`NOW` 与 `NOW - span` 均落在 300/3600 秒边界上，且夹具不在
    // `range_start` 外侧留样本。rollup 按窗口取整求和，环按秒、窗口路径按窗口过滤；
    // 边界不齐时 rollup 会多算同窗前段的界外样本，两口径必然不等。
    assert_eq!(NOW % 300, 0, "NOW 须对齐 5min 窗口边界");
    assert_eq!(NOW % 3_600, 0, "NOW 须对齐小时窗口边界");

    // 1h：环覆盖满整段 → 走环路径，requests 为秒级计数。
    let one_hour_db = tmp_db("range-rollup-equality-1h");
    let store = MetricsStore::new(one_hour_db.clone());
    let log = RequestLog::new(one_hour_db, true, 0);
    for i in 0..100i64 {
        let ts = NOW - 3_600 + i * 35;
        let model = if i % 2 == 0 { "m-a" } else { "m-b" };
        rec_model_at(&store, ts, model);
        log.record(request_row_at(ts, model));
    }
    log.flush_blocking().expect("rollup 刷盘须成功");
    let spec_1h = RangeSpec::parse("1h").unwrap();
    let rows_1h = log
        .per_model_counts(spec_1h.range_start(NOW), spec_1h.rollup_granularity())
        .expect("rollup 查询须成功");
    let snap_1h = store.snapshot_in_range(spec_1h, NOW, Some(&rows_1h));
    assert_eq!(snap_1h.boundary_slack_secs, 300, "1h 须走环路径");
    assert!(
        !snap_1h.partial,
        "1h 兜底路径恒 partial；此处须为环路径: {snap_1h:?}"
    );
    let sum_1h: u64 = snap_1h.per_model.values().sum();
    assert_eq!(
        sum_1h, snap_1h.requests,
        "1h 环路径 SUM(rollup) 须等于 requests: {snap_1h:?}"
    );
    assert_eq!(sum_1h, 100, "两侧须为同一批 100 条请求");
    assert_eq!(snap_1h.per_model.get("m-a"), Some(&50));
    assert_eq!(snap_1h.per_model.get("m-b"), Some(&50));
    assert!(!snap_1h.per_model_partial, "有投影时不得标 partial");

    // 24h：不允许环路径 → 走 hourly 窗口求和。
    let day_db = tmp_db("range-rollup-equality-24h");
    let day_store = MetricsStore::new(day_db.clone());
    let day_log = RequestLog::new(day_db, true, 0);
    for i in 0..48i64 {
        let ts = NOW - 86_400 + i * 1_800;
        let model = if i % 2 == 0 { "m-a" } else { "m-b" };
        rec_model_at(&day_store, ts, model);
        day_log.record(request_row_at(ts, model));
    }
    day_log.flush_blocking().expect("rollup 刷盘须成功");
    let spec_24h = RangeSpec::parse("24h").unwrap();
    let rows_24h = day_log
        .per_model_counts(spec_24h.range_start(NOW), spec_24h.rollup_granularity())
        .expect("rollup 查询须成功");
    let snap_24h = day_store.snapshot_in_range(spec_24h, NOW, Some(&rows_24h));
    assert_eq!(snap_24h.boundary_slack_secs, 3_600, "24h 须走窗口路径");
    let sum_24h: u64 = snap_24h.per_model.values().sum();
    assert_eq!(
        sum_24h, snap_24h.requests,
        "24h 窗口路径 SUM(rollup) 须等于 requests: {snap_24h:?}"
    );
    assert_eq!(sum_24h, 48, "两侧须为同一批 48 条请求");
    assert!(!snap_24h.per_model_partial, "有投影时不得标 partial");
}

#[test]
fn per_model_argument_is_summed_and_none_marks_partial() {
    let store = MetricsStore::new(tmp_db("range-per-model"));
    rec_at(&store, NOW - 100, 2, true);
    let spec = RangeSpec::parse("24h").unwrap();
    let rows = [
        ("m-a".to_string(), 3u64),
        ("m-a".to_string(), 2),
        ("m-b".to_string(), 1),
    ];
    let with_rollup = store.snapshot_in_range(spec, NOW, Some(&rows));
    assert_eq!(with_rollup.per_model.get("m-a"), Some(&5));
    assert_eq!(with_rollup.per_model.get("m-b"), Some(&1));
    assert!(!with_rollup.per_model_partial, "提供投影时不标 partial");

    let without_rollup = store.snapshot_in_range(spec, NOW, None);
    assert!(without_rollup.per_model_partial, "无投影须标 partial");
    assert_eq!(
        without_rollup.per_model.get("m"),
        Some(&1),
        "无投影时回退环样本分布"
    );
}

#[test]
fn per_model_falls_back_to_ring_when_rollup_empty_or_missing() {
    let store = MetricsStore::new(tmp_db("range-per-model-ring-fallback"));
    rec_at(&store, NOW - 100, 1, true);
    rec_at(&store, NOW - 50, 1, true);
    let spec = RangeSpec::parse("1h").unwrap();
    let snap_none = store.snapshot_in_range(spec, NOW, None);
    assert!(snap_none.per_model_partial, "None 分布须标 partial");
    assert_eq!(
        snap_none.per_model.get("m"),
        Some(&2),
        "None 时按环样本聚合分布: {:?}",
        snap_none.per_model
    );

    let empty: [(String, u64); 0] = [];
    let snap_empty = store.snapshot_in_range(spec, NOW, Some(&empty));
    assert!(
        snap_empty.per_model_partial,
        "请求数 > 0 但投影为空须标 partial"
    );
    assert_eq!(
        snap_empty.per_model.get("m"),
        Some(&2),
        "空投影在确有请求时回退环样本"
    );

    let no_requests = MetricsStore::new(tmp_db("range-per-model-no-requests"));
    let snap_zero = no_requests.snapshot_in_range(spec, NOW, Some(&empty));
    assert!(!snap_zero.per_model_partial, "零请求的空投影不算降级");
    assert!(snap_zero.per_model.is_empty());
}

#[test]
fn one_hour_ring_path_aux_counts_come_from_aligned_five_min_windows() {
    use crate::service::llm_gateway::Protocol;

    let store = MetricsStore::new(tmp_db("range-ring-aux"));
    // 环覆盖满 1h（ring 路径），但环样本本身不带 pii/cred/audit 列。
    for i in 0..100 {
        rec_at(&store, NOW - 3_600 + i * 35, 1, true);
    }
    let range_start = NOW - 3_600;
    store.record_aux_counts_extended(Protocol::Chat, range_start - 1, 7, 11, 13, 17);
    store.record_aux_counts_extended(Protocol::Chat, NOW - 1_000, 2, 3, 5, 7);
    store.record_aux_counts_extended(Protocol::Chat, NOW - 200, 1, 1, 1, 1);

    let snap = store.snapshot_in_range(RangeSpec::parse("1h").unwrap(), NOW, None);
    let since_ord = range_start.div_euclid(300);
    let (mut pii_hits, mut pii_miss, mut cred_hits, mut audit_blocks) = (0u64, 0u64, 0u64, 0u64);
    for (key, agg) in store.aggs.lock().unwrap().iter() {
        if key.granularity == Granularity::FiveMin && window_ord(&key.window) >= since_ord {
            pii_hits += agg.pii_hits;
            pii_miss += agg.pii_miss;
            cred_hits += agg.cred_hits;
            audit_blocks += agg.audit_blocks;
        }
    }
    assert_eq!(
        (snap.pii_hits, snap.pii_miss, snap.cred_hits),
        (pii_hits, pii_miss, cred_hits),
        "环路径三项脱敏计数须等于对齐 five_min 窗口求和"
    );
    assert_eq!(snap.pii_hits, 3, "range_start-1 的 7 须被排除");
    assert_eq!(snap.pii_miss, 4);
    assert_eq!(snap.cred_hits, 6);
    assert_eq!(audit_blocks, 8, "窗口内 audit_blocks 之和");
    assert!(
        snap.pii_hits > 0 && snap.pii_miss > 0 && snap.cred_hits > 0,
        "环路径附属计数不得为 0: {snap:?}"
    );
    assert_eq!(snap.boundary_slack_secs, 300);
    assert_eq!(snap.requests, 100, "requests 仍取环的秒级口径");
}

#[test]
fn rollup_granularity_follows_range_not_elapsed_span() {
    for (label, gran) in [("1h", 'm'), ("24h", 'h'), ("7d", 'd'), ("30d", 'd')] {
        assert_eq!(
            RangeSpec::parse(label).unwrap().rollup_granularity(),
            gran,
            "{label} 的 rollup 粒度须由范围显式决定"
        );
    }
    let spec = RangeSpec::parse("24h").unwrap();
    let skewed_now = NOW + 5;
    assert!(
        skewed_now - spec.range_start(NOW) > 86_400,
        "时钟轻微后移即可让 span 反推成日粒度"
    );
    assert_eq!(spec.rollup_granularity(), 'h', "显式粒度不受 span 漂移影响");
}

#[test]
fn snapshot_without_range_keeps_legacy_values_and_neutral_defaults() {
    let store = MetricsStore::new(tmp_db("range-legacy-snapshot"));
    rec_at(&store, NOW - 100, 4, true);
    rec_at(&store, NOW, 6, true);
    let snap = store.snapshot();
    assert_eq!(snap.requests, 2, "无范围快照仍为全量口径");
    assert_eq!(snap.total_tokens, 10);
    assert_eq!(snap.ring_len, 2);
    assert_eq!(snap.dropped, 0);
    assert!(snap.range.is_none());
    assert!(snap.since_ts.is_none());
    assert_eq!(snap.coverage_secs, 0);
    assert!(!snap.partial);
    assert_eq!(snap.boundary_slack_secs, 0);
    assert!(!snap.per_model_partial);
    assert_eq!(snap.requests_dropped, 0);
    assert_eq!(snap.requests_aborted, 0);

    let json = serde_json::to_value(&snap).expect("快照须可序列化");
    for key in [
        "coverage_secs",
        "partial",
        "boundary_slack_secs",
        "per_model_partial",
        "requests_dropped",
        "requests_aborted",
    ] {
        assert!(json.get(key).is_some(), "新增 additive 键须存在: {key}");
    }
    assert!(json["range"].is_null(), "无范围时 range 为 null: {json}");
    assert!(json["since_ts"].is_null(), "无范围时 since_ts 为 null");
}

#[test]
fn ranged_snapshot_serializes_range_and_since() {
    let store = MetricsStore::new(tmp_db("range-serialize"));
    rec_at(&store, NOW - 100, 2, true);
    let snap = store.snapshot_in_range(RangeSpec::parse("7d").unwrap(), NOW, None);
    let json = serde_json::to_value(&snap).expect("快照须可序列化");
    assert_eq!(json["range"], "7d");
    assert_eq!(
        json["since_ts"],
        day_key(NOW - 7 * 86_400)
            .get(1..)
            .unwrap()
            .parse::<i64>()
            .unwrap()
            * 86_400
    );
    assert_eq!(json["boundary_slack_secs"], 86_400);
}
