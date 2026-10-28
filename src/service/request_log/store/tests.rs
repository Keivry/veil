//! 队列丢弃计数、刷盘零丢失、保留期、rollup 聚合与查询过滤断言。

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("store.rs", include_str!("../store.rs"));
    crate::test_support::file_len_under_800_or_split("store/tests.rs", include_str!("tests.rs"));
}

use {
    super::*,
    crate::service::request_log::{CLIENT_ABORTED_KIND, SessionScope, StreamGuard, StreamOutcome},
    std::sync::atomic::Ordering,
};

fn temp_db(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "veil-reqlog-{}-{tag}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).ok();
    dir.join("metrics.sqlite")
}

fn row_at(ts: i64, model: &str, counted: bool) -> RequestRow {
    RequestRow {
        ts_secs: ts,
        request_id: format!("req-{ts}-{model}"),
        protocol: "chat".to_string(),
        model: model.to_string(),
        upstream: Some("127.0.0.1:11434".to_string()),
        ingress_port: Some(8877),
        stream: false,
        is_chat: true,
        counted_metrics: counted,
        status: Some(200),
        latency_ms: 12,
        prompt_tokens: 100,
        completion_tokens: 20,
        total_tokens: 120,
        cached_read: 40,
        cached_write: 0,
        cache_input_tokens: 100,
        session_id: Some("9f2c000000000000".to_string()),
        session_source: "header".to_string(),
        session_scope: "session".to_string(),
        ..RequestRow::default()
    }
}

fn count_rows(log: &RequestLog) -> u64 {
    log.query(&RequestFilter {
        limit: Some(1),
        ..RequestFilter::default()
    })
    .map(|page| page.total)
    .unwrap_or_else(|_| panic!("查询须成功"))
}

#[test]
fn queue_drops_oldest_beyond_cap() {
    let log = RequestLog::new(temp_db("cap"), true, 7);
    let total = REQUEST_QUEUE_CAP + 5_904;
    let base = now_secs();
    for i in 0..total {
        log.record(row_at(base + i as i64, "m", true));
    }
    assert_eq!(log.pending_len(), REQUEST_QUEUE_CAP);
    assert_eq!(log.dropped_total(), 5_904);
}

#[test]
fn disabled_log_records_nothing() {
    let log = RequestLog::disabled(temp_db("disabled"));
    log.record(row_at(now_secs(), "m", true));
    assert_eq!(log.pending_len(), 0);
    assert_eq!(log.dropped_total(), 0);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn flush_blocking_drains_everything() {
    let log = RequestLog::new(temp_db("drain"), true, 7);
    let now = now_secs();
    for i in 0..500 {
        log.record(row_at(now + i, "m", true));
    }
    log.flush_blocking().expect("刷盘须成功");
    assert_eq!(log.pending_len(), 0);
    assert_eq!(count_rows(&log), 500);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn flush_is_idempotent_on_repeated_calls() {
    let log = RequestLog::new(temp_db("idem"), true, 7);
    log.record(row_at(now_secs(), "m", true));
    log.flush_blocking().expect("首次刷盘");
    log.flush_blocking().expect("重复刷盘不报错");
    assert_eq!(count_rows(&log), 1, "重复 flush 不得重复写行");
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn flush_failure_requeues_rows_in_order() {
    let parent = std::env::temp_dir().join(format!(
        "veil-reqlog-fail-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(parent.parent().unwrap_or(Path::new("/tmp"))).ok();
    // 父路径被普通文件占位，故打开库必失败。
    std::fs::write(&parent, b"not a dir").expect("占位文件须可写");
    let log = RequestLog::new(parent.join("metrics.sqlite"), true, 0);
    let ts = now_secs();
    for id in ["req-a", "req-b", "req-c"] {
        let mut row = row_at(ts, "m", true);
        row.request_id = id.to_string();
        log.record(row);
    }
    assert!(log.flush_blocking().is_err(), "写库须失败");
    assert_eq!(
        log.pending_ids(),
        vec![
            "req-a".to_string(),
            "req-b".to_string(),
            "req-c".to_string()
        ],
        "失败批次须按原顺序整批回灌队首"
    );
    assert_eq!(log.write_failures_total(), 1);

    std::fs::remove_file(&parent).expect("清占位文件");
    std::fs::create_dir_all(&parent).expect("建父目录");
    log.flush_blocking().expect("恢复后刷盘须成功");
    assert_eq!(log.pending_len(), 0);
    assert_eq!(count_rows(&log), 3, "失败不得丢行");
    std::fs::remove_dir_all(&parent).ok();
}

#[test]
fn cache_input_tokens_per_protocol() {
    assert_eq!(cache_input_tokens("chat", 100, 40, 7), 100);
    assert_eq!(cache_input_tokens("responses", 100, 40, 7), 100);
    assert_eq!(cache_input_tokens("anthropic", 100, 40, 7), 147);
    assert_eq!(cache_input_tokens("chat", 0, 40, 7), 0);
    assert_eq!(cache_input_tokens("anthropic", 0, 0, 0), 0);
}

#[test]
fn retention_deletes_old_rows_only() {
    let log = RequestLog::new(temp_db("retention"), true, 7);
    let now = now_secs();
    log.record(row_at(now - 8 * SECS_PER_DAY, "old", true));
    log.record(row_at(now - 6 * SECS_PER_DAY, "keep", true));
    log.flush_blocking().expect("刷盘");
    let page = log.query(&RequestFilter::default()).expect("查询须成功");
    assert_eq!(page.total, 1, "8 天前记录须被清理");
    assert_eq!(page.rows[0].model, "keep");
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn retention_zero_skips_purge() {
    let log = RequestLog::new(temp_db("retention-zero"), true, 0);
    let now = now_secs();
    log.record(row_at(now - 400 * SECS_PER_DAY, "ancient", true));
    log.flush_blocking().expect("刷盘");
    assert_eq!(count_rows(&log), 1, "retention_days=0 不得删除任何行");
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn rollup_aggregates_only_counted_rows_in_same_window() {
    let log = RequestLog::new(temp_db("rollup"), true, 0);
    let ts = now_secs() - 3_600;
    log.record(row_at(ts, "m1", true));
    log.record(row_at(ts, "m1", true));
    log.record(row_at(ts, "m1", false));
    log.flush_blocking().expect("刷盘");
    let counts = log.per_model_counts(ts, 'm').expect("rollup 查询须成功");
    assert_eq!(counts, vec![("m1".to_string(), 2)], "未计入行不得进 rollup");
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn rollup_sums_across_flushes() {
    let log = RequestLog::new(temp_db("rollup-sum"), true, 0);
    let ts = now_secs() - 600;
    log.record(row_at(ts, "m2", true));
    log.flush_blocking().expect("首批");
    log.record(row_at(ts, "m2", true));
    log.flush_blocking().expect("次批");
    let counts = log.per_model_counts(ts, 'm').expect("rollup 查询");
    assert_eq!(
        counts,
        vec![("m2".to_string(), 2)],
        "同键二次 UPSERT 须累加而非覆盖"
    );
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn rollup_survives_window_position_carry() {
    let log = RequestLog::new(temp_db("rollup-carry"), true, 0);
    let base = 1_700_000_000i64;
    let m9 = base.div_euclid(300) * 300;
    let m10 = m9 + 300;
    for ts in [m9, m9 + 60, m10] {
        log.record(row_at(ts, "carry", true));
    }
    log.flush_blocking().expect("刷盘");
    let counts = log.per_model_counts(m9, 'm').expect("rollup 查询");
    assert_eq!(counts, vec![("carry".to_string(), 3)]);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn rollup_evicts_old_windows_across_digit_carry() {
    let db = temp_db("rollup-evict-carry");
    let log = RequestLog::new(db.clone(), true, 0);
    // 窗口序号 8..=22 共 15 个：跨 9→10 的位数进位，字符串序会误删 m10..m22。
    for ord in 8i64..=22 {
        log.record(row_at(ord * 300, "carry-evict", true));
    }
    log.flush_blocking().expect("刷盘须成功");
    let conn = open_wal(&db).expect("打开库");
    let mut stmt = conn
        .prepare(
            "SELECT window FROM request_model_rollup WHERE granularity = 'm' \
             ORDER BY CAST(substr(window, 2) AS INTEGER) ASC",
        )
        .expect("prepare");
    let windows: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect");
    assert_eq!(windows.len(), 13, "只保留最新 13 窗: {windows:?}");
    assert_eq!(
        windows.first().map(String::as_str),
        Some("m10"),
        "最旧保留窗须为 m10（按整数序而非字符串序）: {windows:?}"
    );
    assert_eq!(
        windows.last().map(String::as_str),
        Some("m22"),
        "最新窗须为 m22: {windows:?}"
    );
    let evicted: Vec<&str> = ["m8", "m9"]
        .into_iter()
        .filter(|w| !windows.iter().any(|kept| kept == w))
        .collect();
    assert_eq!(
        evicted,
        ["m8", "m9"],
        "被驱逐的须恰为最小的两个整数窗: {windows:?}"
    );
    std::fs::remove_dir_all(db.parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn query_filters_and_pagination() {
    let log = RequestLog::new(temp_db("query"), true, 0);
    let now = now_secs();
    for i in 0..5 {
        let mut row = row_at(now - i as i64, "m", true);
        row.protocol = if i % 2 == 0 {
            "chat".into()
        } else {
            "anthropic".into()
        };
        row.status = Some(if i == 0 { 502 } else { 200 });
        row.session_id = Some(format!("abcd{i:012}"));
        log.record(row);
    }
    log.flush_blocking().expect("刷盘");

    let page = log
        .query(&RequestFilter {
            protocol: Some("anthropic".to_string()),
            limit: Some(2),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(page.total, 2);
    assert_eq!(page.rows.len(), 2);

    let errors = log
        .query(&RequestFilter {
            status_class: Some(StatusClass::S5xx),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(errors.total, 1);
    assert_eq!(errors.rows[0].status, Some(502));

    let scoped = log
        .query(&RequestFilter {
            scope: Some(SessionScope::Session),
            session_prefix: Some("abcd".to_string()),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(scoped.total, 5);
    assert_eq!(scoped.sum_cached_read, 200);
    assert_eq!(scoped.sum_cache_input_tokens, 500);
    assert_eq!(scoped.earliest_ts, Some(now - 4));
    assert_eq!(scoped.retention_earliest_ts, Some(now - 4));

    let limited = log
        .query(&RequestFilter {
            limit: Some(500),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(limited.rows.len(), 5);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn retention_earliest_ignores_business_filters() {
    let log = RequestLog::new(temp_db("retention-earliest"), true, 0);
    let now = now_secs();
    let mut old = row_at(now - 3_600, "old-model", true);
    old.status = Some(500);
    old.session_id = Some("beef000000000000".to_string());
    log.record(old);
    log.record(row_at(now - 10, "new-model", true));
    log.flush_blocking().expect("刷盘");

    let filtered = log
        .query(&RequestFilter {
            model: Some("new-model".to_string()),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(filtered.total, 1);
    assert_eq!(filtered.earliest_ts, Some(now - 10), "业务过滤口径");
    assert_eq!(
        filtered.retention_earliest_ts,
        Some(now - 3_600),
        "保留期口径须忽略业务过滤，否则 coverage 假性缩水"
    );

    let ranged = log
        .query(&RequestFilter {
            range_start_ts: Some(now - 10),
            model: Some("new-model".to_string()),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    assert_eq!(
        ranged.retention_earliest_ts,
        Some(now - 10),
        "时间下界仍须生效"
    );
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn per_model_counts_honours_explicit_granularity() {
    let log = RequestLog::new(temp_db("gran"), true, 0);
    let ts = now_secs() - 600;
    log.record(row_at(ts, "m1", true));
    log.flush_blocking().expect("刷盘");

    for gran in ['m', 'h', 'd'] {
        let counts = log.per_model_counts(ts, gran).expect("rollup 查询");
        assert_eq!(
            counts,
            vec![("m1".to_string(), 1)],
            "粒度 {gran} 须各计一行"
        );
    }
    assert!(
        log.per_model_counts(ts, 'x').is_err(),
        "非法粒度须报错而非静默降级"
    );
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn query_rejects_offset_beyond_cap() {
    let log = RequestLog::new(temp_db("offset"), true, 0);
    assert!(
        log.query(&RequestFilter {
            offset: Some(MAX_OFFSET + 1),
            ..RequestFilter::default()
        })
        .is_err()
    );
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn guard_records_one_row_per_finished_stream() {
    let log = Arc::new(RequestLog::new(temp_db("guard"), true, 0));
    let guard: StreamGuard = log.stream_guard(row_at(now_secs(), "streamed", true));
    let clone = guard.clone();
    let outcome = StreamOutcome::default();
    if let Some(row) = clone.finish(&outcome) {
        log.record(row);
    }
    if let Some(row) = guard.finish(&outcome) {
        log.record(row);
    }
    drop(guard);
    log.flush_blocking().expect("刷盘");
    assert_eq!(count_rows(&log), 1, "双 finish 只写一行");
    assert_eq!(log.aborted_total(), 0);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn guard_without_finish_writes_one_client_aborted_row() {
    let log = Arc::new(RequestLog::new(temp_db("guard-abort"), true, 0));
    let before = now_secs();
    {
        let _guard = log.stream_guard(row_at(before - 7, "dropped", true));
    }
    log.flush_blocking().expect("刷盘");
    let page = log.query(&RequestFilter::default()).expect("查询须成功");
    assert_eq!(page.total, 1, "未 finish 须补写恰一行");
    let row = &page.rows[0];
    assert_eq!(row.error_kind.as_deref(), Some(CLIENT_ABORTED_KIND));
    assert_eq!(row.status, None);
    assert_eq!(row.model, "dropped");
    assert!(
        row.latency_ms >= 7_000,
        "延迟须按 now - ts_secs 折算为毫秒: {}",
        row.latency_ms
    );
    assert_eq!(log.aborted_total(), 1);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn guard_without_finish_and_released_log_only_counts() {
    let log = Arc::new(RequestLog::new(temp_db("guard-weak"), true, 0));
    let guard = log.stream_guard(row_at(now_secs(), "weak", true));
    let aborted = Arc::clone(&log.aborted);
    drop(log);
    drop(guard);
    assert_eq!(aborted.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn flush_driver_persists_without_blocking() {
    let log = Arc::new(RequestLog::new(temp_db("driver"), true, 0));
    for i in 0..10 {
        log.record(row_at(now_secs() + i, "driven", true));
    }
    let driver = log.spawn_flush_driver(Duration::from_millis(10));
    let mut persisted = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if count_rows(&log) == 10 {
            persisted = true;
            break;
        }
    }
    driver.abort();
    assert!(persisted, "驱动须在 1s 内落库全部 10 行");
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn schema_contains_required_columns() {
    let db = temp_db("schema");
    let log = RequestLog::new(db.clone(), true, 0);
    log.flush_blocking().expect("建表");
    let conn = open_wal(&db).expect("打开库");
    for table in ["llm_requests", "request_model_rollup"] {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("prepare");
        let cols: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .expect("query")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect");
        for want in ["counted_metrics", "cache_input_tokens"] {
            if table == "llm_requests" {
                assert!(cols.iter().any(|c| c == want), "{table} 缺列 {want}");
            }
        }
        if table == "request_model_rollup" {
            for want in ["granularity", "window", "protocol", "model", "cache_input"] {
                assert!(cols.iter().any(|c| c == want), "{table} 缺列 {want}");
            }
        }
    }
    let indexes: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='llm_requests'")
        .expect("prepare")
        .query_map([], |r| r.get::<_, String>(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect");
    assert!(indexes.iter().any(|i| i == "idx_llm_requests_ts"));
    assert!(indexes.iter().any(|i| i == "idx_llm_requests_session"));
    std::fs::remove_dir_all(db.parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn counted_metrics_matches_record_return_value() {
    let log = RequestLog::new(temp_db("counted"), true, 0);
    let ts = now_secs();
    log.record(row_at(ts, "in", true));
    log.record(row_at(ts, "out", false));
    log.flush_blocking().expect("刷盘");
    let page = log
        .query(&RequestFilter {
            status_class: Some(StatusClass::S2xx),
            ..RequestFilter::default()
        })
        .expect("查询须成功");
    let counted = page.rows.iter().filter(|r| r.counted_metrics).count();
    assert_eq!(counted, 1);
    assert!(
        !page
            .rows
            .iter()
            .any(|r| r.model == "out" && r.counted_metrics)
    );
    assert_eq!(log.aborted_total(), 0, "计数不受守卫影响");
    assert_eq!(log.dropped_total(), 0);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}

#[test]
fn aborted_counter_is_shared_and_atomic() {
    let log = RequestLog::new(temp_db("aborted"), true, 0);
    log.aborted.fetch_add(3, Ordering::Relaxed);
    assert_eq!(log.aborted_total(), 3);
    std::fs::remove_dir_all(log.db_path().parent().unwrap_or(Path::new("/tmp"))).ok();
}
