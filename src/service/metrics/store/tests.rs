#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("store.rs", include_str!("../store.rs"));
    crate::test_support::file_len_under_800_or_split("store/tests.rs", include_str!("tests.rs"));
}

use {
    super::{
        super::{
            aggregate::{ExtendedUsage, p95_approx},
            summarize::test_support::{chat_rec, ext_rec, now, tmp_db, usage},
        },
        *,
    },
    crate::service::llm_gateway::Protocol,
};

#[test]
fn t1_1_gap_closure_locks_queue_flush_window_whitelist() {
    // T-M1 缺口合一锁定：QueueFull 丢最老 + 跨窗不串扰 + `:@` 通过/空回退 `unknown`；
    // flush 2s 去抖等价由覆盖式 UPSERT 保证（见 `b5_repeat_flush_aux_no_double_count`）。
    use super::super::aggregate::{Granularity, normalize_model};
    let store = MetricsStore::new(tmp_db("t1-1-gap"));
    for i in 0..super::super::aggregate::RING_CAP {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "t1-old",
            10,
            None,
            None,
            true,
            now() + i as i64,
        ));
    }
    for i in 0..3 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "t1-newest",
            10,
            None,
            None,
            true,
            now() + 100_000 + i as i64,
        ));
    }
    assert_eq!(store.ring_len(), super::super::aggregate::RING_CAP);
    assert_eq!(store.dropped_total(), 3);
    assert_eq!(
        store.snapshot().per_model.get("t1-newest"),
        Some(&3),
        "满队列须丢最老且最新可查"
    );
    // 跨窗不串扰：两日分属两 daily 窗。
    let d10 = 86_400 * 10 + 100;
    let d11 = 86_400 * 11 + 100;
    store.record_chat(chat_rec(Protocol::Chat, "t1-w", 5, None, None, true, d10));
    store.record_chat(chat_rec(Protocol::Chat, "t1-w", 5, None, None, true, d11));
    let aggs = store.aggs.lock().expect("聚合锁无毒");
    let daily: std::collections::HashSet<_> = aggs
        .keys()
        .filter(|k| k.granularity == Granularity::Daily)
        .map(|k| k.window.clone())
        .collect();
    assert!(daily.len() >= 2, "跨日须落两窗不串扰: {daily:?}");
    drop(aggs);
    // 白名单语义：`:@` 原样通过，非白名单空串回退 `unknown_model`。
    assert_eq!(normalize_model("org:proj@gpt-4o"), "org:proj@gpt-4o");
    assert_eq!(normalize_model(""), "unknown_model");
}

#[test]
fn b5_ring_overflow_newest_retained_queryable() {
    // B5.1：满队列丢最老且最新保留可查（环上限 + dropped 计数 + 快照含最新模型）。
    let store = MetricsStore::new(tmp_db("b5-ring"));
    for i in 0..super::super::aggregate::RING_CAP {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "b5-old",
            10,
            None,
            None,
            true,
            now() + i as i64,
        ));
    }
    for i in 0..3 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "b5-newest",
            10,
            None,
            None,
            true,
            now() + 100_000 + i as i64,
        ));
    }
    assert_eq!(store.ring_len(), super::super::aggregate::RING_CAP);
    assert_eq!(store.dropped_total(), 3);
    let snap = store.snapshot();
    assert!(snap.per_model.get("b5-newest") == Some(&3), "{snap:?}");
    assert_eq!(snap.requests, super::super::aggregate::RING_CAP as u64);
}

#[tokio::test]
async fn b5_repeat_flush_aux_no_double_count() {
    // B5.1/B5.3：重复触发 flush 不翻倍（含附属列）；store 层无定时去抖
    // （Python 原仓 2s 去抖未迁移，本仓事件驱动批量等价，见 `flush_idempotent_window`），
    // 覆盖式 UPSERT 使多次触发效果等价一次。
    let db = tmp_db("b5-flush-aux");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    store.record_chat(chat_rec(
        Protocol::Chat,
        "b5-m",
        12,
        Some(&usage(1, 2, 3)),
        None,
        true,
        ts,
    ));
    store.record_aux_counts(Protocol::Chat, ts, 7, 3, 2);
    store.flush().await.unwrap();
    store.flush().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].requests, 1);
    assert_eq!(pts[0].pii_hits, 7);
    assert_eq!(pts[0].cred_hits, 3);
    assert_eq!(pts[0].audit_blocks, 2);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn b5_aux_same_event_dual_caliber_no_total_double() {
    // B5.3：同一事件计入用量与附属双口径，总量不双计。
    let store = MetricsStore::new(tmp_db("b5-dual"));
    let ts = now();
    store.record_chat(chat_rec(
        Protocol::Chat,
        "b5-dual-m",
        12,
        Some(&usage(4, 5, 9)),
        None,
        true,
        ts,
    ));
    store.record_aux_counts(Protocol::Chat, ts, 2, 1, 1);
    let snap = store.snapshot();
    assert_eq!(snap.requests, 1, "附属计数不得增加总量: {snap:?}");
    assert_eq!(snap.total_tokens, 9);
}

#[test]
fn memory_ring_capped_with_drop_count() {
    let store = MetricsStore::new(tmp_db("ring"));
    for i in 0..(super::super::aggregate::RING_CAP + 5) {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            10,
            None,
            None,
            true,
            now() + i as i64,
        ));
    }
    assert_eq!(store.ring_len(), super::super::aggregate::RING_CAP);
    assert_eq!(store.dropped_total(), 5);
}

#[test]
fn wal_checkpoint_truncate_runs() {
    let db = tmp_db("checkpoint");
    let _ = std::fs::remove_file(&db);
    let conn = open_wal(&db).expect("WAL 库须可建");
    conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('a');")
        .expect("写入须成功");
    drop(conn);
    let (busy, _done) = wal_checkpoint_truncate(&db).expect("检查点须可执行");
    assert_eq!(busy, 0, "单连接无竞争时不得 busy");
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(db.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(db.with_extension("sqlite-shm"));
}

#[test]
fn only_dialog_endpoints_counted_non_dialog_skipped() {
    let store = MetricsStore::new(tmp_db("nondialog"));
    assert!(!store.record_chat(chat_rec(
        Protocol::NonDialog,
        "",
        10,
        None,
        None,
        true,
        now()
    )));
    assert!(store.record_chat(chat_rec(Protocol::Chat, "", 10, None, None, true, now())));
    let snap = store.snapshot();
    assert_eq!(snap.requests, 1);
    assert_eq!(snap.per_protocol.get("non-dialog"), None);
    assert!(snap.per_protocol.contains_key("chat/completions"));
    // `other` 桶不再混入非对话：全量即对话快照一致。
    assert_eq!(snap.ring_len, 1);
}

#[test]
fn extended_usage_columns_with_aux_backfill() {
    let db = tmp_db("ext-usage");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    store.record_chat_extended(ext_rec(
        Protocol::Chat,
        "",
        20,
        Some(&ExtendedUsage {
            prompt_tokens: 1,
            completion_tokens: 2,
            total_tokens: 3,
            cached_read: 40,
            cached_write: 5,
            unknown: 1,
        }),
        None,
        true,
        ts,
    ));
    store.record_aux_counts(Protocol::Chat, ts, 7, 3, 2);
    let snap = store.snapshot();
    assert_eq!(snap.cached_read, 40);
    assert_eq!(snap.cached_write, 5);
    assert_eq!(snap.unknown, 1);
}

#[tokio::test]
async fn aux_columns_persist_query_and_restart_backfill() {
    let db = tmp_db("aux-flush");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        12,
        Some(&usage(1, 2, 3)),
        None,
        true,
        ts,
    ));
    store.record_aux_counts(Protocol::Chat, ts, 7, 3, 2);
    store.flush().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].pii_hits, 7);
    assert_eq!(pts[0].cred_hits, 3);
    assert_eq!(pts[0].audit_blocks, 2);
    // 重启回填：新 store 读旧库恢复窗口累计。
    let store2 = MetricsStore::new(db.clone());
    let n = store2.backfill_from_sqlite().await.unwrap();
    assert!(n >= 3, "三粒度至少各一窗: {n}");
    let _ = std::fs::remove_file(&db);
}

#[test]
fn nonstream_usage_recorded_with_stream_caliber() {
    use crate::service::llm_gateway::extract_usage_nonstream;
    let store = MetricsStore::new(tmp_db("usage"));
    // responses 单层 response.usage。
    let resp = serde_json::json!({"response": {"usage": {"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}}});
    let u = extract_usage_nonstream(Protocol::Responses, &resp).unwrap();
    store.record_chat(chat_rec(
        Protocol::Responses,
        "",
        20,
        Some(&u),
        None,
        true,
        now(),
    ));
    // anthropic message.usage 嵌套。
    let anth = serde_json::json!({"message": {"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}});
    let u2 = extract_usage_nonstream(Protocol::Anthropic, &anth).unwrap();
    store.record_chat(chat_rec(
        Protocol::Anthropic,
        "",
        30,
        Some(&u2),
        None,
        true,
        now(),
    ));
    let snap = store.snapshot();
    assert_eq!(snap.total_tokens, 11);
    assert_eq!(snap.prompt_tokens, 5);
}

#[tokio::test]
async fn overwrite_upsert_no_double_count_restart_consistent() {
    let db = tmp_db("upsert");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        12,
        Some(&usage(1, 2, 3)),
        None,
        true,
        ts,
    ));
    store.flush().await.unwrap();
    // 重复 flush 不翻倍。
    store.flush().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].requests, 1);
    assert_eq!(pts[0].total_tokens, 3);
    // 重启后同库口径一致（新 store 读旧库）。
    let store2 = MetricsStore::new(db.clone());
    let pts2 = store2
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts2.len(), 1);
    assert_eq!(pts2[0].requests, 1);
    // 1h/24h 口径：hourly 同窗可见。
    let h = store.query_series("hourly", None, None).await.unwrap();
    assert!(!h.is_empty());
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn series_four_windows_cross_day_approx_sum_query() {
    let db = tmp_db("series-sem");
    let _ = std::fs::remove_file(&db);
    let day10 = 86_400 * 10 + 100;
    let day11 = 86_400 * 11 + 100;
    let store = MetricsStore::new(db.clone());
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        8,
        Some(&usage(1, 2, 3)),
        None,
        true,
        day10,
    ));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        9,
        Some(&usage(4, 5, 9)),
        None,
        true,
        day10 + 60,
    ));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        9000,
        Some(&usage(0, 0, 0)),
        None,
        true,
        day11,
    ));
    store.flush().await.unwrap();
    let daily = store.query_series("daily", None, None).await.unwrap();
    assert_eq!(daily.len(), 2);
    assert!(daily[0].window < daily[1].window);
    let same_day: u64 = daily
        .iter()
        .filter(|p| p.requests == 2)
        .map(|p| p.total_tokens)
        .sum();
    assert_eq!(same_day, 12);
    let hourly = store.query_series("hourly", None, None).await.unwrap();
    assert!(hourly.len() >= 2);
    let five = store.query_series("five_min", None, None).await.unwrap();
    assert!(!five.is_empty());
    let snap = store.snapshot();
    assert_eq!(snap.requests, 3);
    assert_eq!(snap.total_tokens, 12);
    assert_eq!(snap.p95_ms, p95_approx(&snap.latency_buckets));
    let _ = std::fs::remove_file(&db);
}

#[test]
fn sample_upsert_rollover() {
    use super::super::aggregate::PII_SAMPLE_RETENTION_DAYS;
    // P11/D12：复合键 (day,upstream,kind,hash) 覆盖式 UPSERT（重复 flush 合并不增行），
    // 滚动删除按多 distinct 主键判定——仅超窗行删除，窗口/边界内行保留。
    let db = tmp_db("sample-upsert-rollover");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let window = PII_SAMPLE_RETENTION_DAYS * 86_400;
    let row = |hash: &str, seen: i64| super::SampleRow {
        day: "2026-09-09".to_string(),
        upstream: "https://u.example".to_string(),
        kind: "phone".to_string(),
        hash: hash.to_string(),
        mask: "138****8000".to_string(),
        seen,
    };
    persist_sample_batch(&db, &[row("hash-phone", ts)]).unwrap();
    persist_sample_batch(&db, &[row("hash-phone", ts + 1)]).unwrap();
    let conn = open_wal(&db).unwrap();
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1, "重复 flush 同复合键须合一行");
    let (hits, last): (i64, i64) = conn
        .query_row("SELECT hits, last_seen FROM pii_value_samples", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(hits, 2, "重复 flush hits 须累加为 2");
    assert_eq!(last, ts + 1, "last_seen 须刷新为最近一次");
    drop(conn);
    persist_sample_batch(
        &db,
        &[
            row("fresh", ts - 3 * 86_400),
            row("boundary", ts - window + 60),
            row("expired", ts - window - 60),
        ],
    )
    .unwrap();
    purge_retention_blocking(&db).unwrap();
    let conn = open_wal(&db).unwrap();
    let kept: Vec<String> = conn
        .prepare("SELECT hash FROM pii_value_samples ORDER BY hash")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        kept,
        vec!["boundary", "fresh", "hash-phone"],
        "仅超窗行删除，窗口/边界内行与既有 upsert 行保留"
    );
    drop(conn);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn sample_retention() {
    use super::super::aggregate::PII_SAMPLE_RETENTION_DAYS;
    // P11/D12：7 天滚动窗口边界（窗口内 / 恰入窗前保留，越界删除）。
    let db = tmp_db("sample-retention");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let window = PII_SAMPLE_RETENTION_DAYS * 86_400;
    let row = |hash: &str, seen: i64| super::SampleRow {
        day: "2026-09-09".to_string(),
        upstream: String::new(),
        kind: "phone".to_string(),
        hash: hash.to_string(),
        mask: "***".to_string(),
        seen,
    };
    persist_sample_batch(
        &db,
        &[
            row("fresh", ts - 3 * 86_400),
            row("boundary", ts - window + 60),
            row("expired", ts - window - 60),
        ],
    )
    .unwrap();
    purge_retention_blocking(&db).unwrap();
    let conn = open_wal(&db).unwrap();
    let kept: Vec<String> = conn
        .prepare("SELECT hash FROM pii_value_samples ORDER BY hash")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kept, vec!["boundary", "fresh"], "窗口/边界内保留、越界删除");
    drop(conn);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn pii_value_sample_roll_7d() {
    use super::super::aggregate::PII_SAMPLE_RETENTION_DAYS;
    // P11/G4：复合键覆盖式 UPSERT 合并不增行；超 7 天滚动删除；落盘仅掩码+hash 无明文。
    let db = tmp_db("pii-roll-7d");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let row = |hash: &str, seen: i64| super::SampleRow {
        day: "2026-09-09".to_string(),
        upstream: "8878".to_string(),
        kind: "phone".to_string(),
        hash: hash.to_string(),
        mask: "138****0000".to_string(),
        seen,
    };
    persist_sample_batch(
        &db,
        &[
            row("keep", ts - 3 * 86_400),
            row("old", ts - (PII_SAMPLE_RETENTION_DAYS + 1) * 86_400),
        ],
    )
    .unwrap();
    persist_sample_batch(&db, &[row("keep", ts - 3 * 86_400 + 1)]).unwrap();
    let conn = open_wal(&db).unwrap();
    let cols: std::collections::HashSet<String> = conn
        .prepare("PRAGMA table_info(pii_value_samples)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .flatten()
        .collect();
    for forbidden in ["value", "plaintext", "raw", "secret", "content"] {
        assert!(
            !cols.contains(forbidden),
            "落盘表不得含明文列 {forbidden}: {cols:?}"
        );
    }
    let keep_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pii_value_samples WHERE hash='keep'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(keep_rows, 1, "重复 flush 同复合键须合一行");
    let hits: i64 = conn
        .query_row(
            "SELECT hits FROM pii_value_samples WHERE hash='keep'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 2, "重复 flush hits 须累加不翻倍行数");
    drop(conn);
    purge_retention_blocking(&db).unwrap();
    let conn = open_wal(&db).unwrap();
    let kept: Vec<String> = conn
        .prepare("SELECT hash FROM pii_value_samples ORDER BY hash")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kept, vec!["keep"], "超 7 天行须滚动删除、窗口内保留");
    let mask: String = conn
        .query_row("SELECT mask FROM pii_value_samples", [], |r| r.get(0))
        .unwrap();
    assert!(!mask.contains("13812345678"), "落盘仅掩码不含明文");
    drop(conn);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn pii_value_sample_cross_day_buckets() {
    // P11/G4：同 hash 跨天按 day 复合键分桶不合并（TopN 各自独立）。
    use crate::service::metrics::sample::sampler_day;
    let db = tmp_db("pii-cross-day");
    let _ = std::fs::remove_file(&db);
    let d1 = sampler_day(86_400 * 10 + 100);
    let d2 = sampler_day(86_400 * 11 + 100);
    assert_ne!(d1, d2, "相邻两天 day 键须不同");
    let row = |day: &str, seen: i64| super::SampleRow {
        day: day.to_string(),
        upstream: "8878".to_string(),
        kind: "phone".to_string(),
        hash: "same-hash".to_string(),
        mask: "138****0000".to_string(),
        seen,
    };
    persist_sample_batch(&db, &[row(&d1, 100)]).unwrap();
    persist_sample_batch(&db, &[row(&d2, 200)]).unwrap();
    let conn = open_wal(&db).unwrap();
    let rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pii_value_samples WHERE hash='same-hash'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 2, "同 hash 跨天须分两行不合并");
    let days: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT day) FROM pii_value_samples",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(days, 2);
    drop(conn);
    let _ = std::fs::remove_file(&db);
}

#[test]
fn model_with_version_colon() {
    // G7/D7：冒号版本号模型进入模型分桶，不归 unknown_model（对照 redact_extra_test.py:194-208）。
    use super::super::aggregate::normalize_model;
    assert_eq!(normalize_model("gpt-4o:2024-08-06"), "gpt-4o:2024-08-06");
    assert_ne!(normalize_model("gpt-4o:2024-08-06"), "unknown_model");
    let store = MetricsStore::new(tmp_db("model-colon"));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "gpt-4o:2024-08-06",
        10,
        None,
        None,
        true,
        now(),
    ));
    let snap = store.snapshot();
    assert_eq!(snap.per_model.get("gpt-4o:2024-08-06"), Some(&1));
    assert!(
        !snap.per_model.contains_key("unknown_model"),
        "冒号版本不得归 unknown_model: {:?}",
        snap.per_model
    );
    // 既有归一不回退：空归 unknown_model、控制字符剔除。
    assert_eq!(normalize_model(""), "unknown_model");
    assert_eq!(normalize_model("a\u{0}b"), "ab");
}

#[tokio::test]
async fn flush_idempotent_window() {
    // G7/D7：批量驱动窗口不丢行、重复 flush 覆盖式 UPSERT 不翻倍（Rust 无 2s
    // 去抖，事件驱动批量等价）。
    let db = tmp_db("flush-idem-window");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    for i in 0..3 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "flush-m",
            12,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts + i,
        ));
    }
    store.flush().await.unwrap();
    let first = store.query_series("daily", None, None).await.unwrap();
    let reqs1: u64 = first.iter().map(|p| p.requests).sum();
    assert_eq!(reqs1, 3, "批量窗口须含全部三行不丢");
    store.flush().await.unwrap();
    let second = store.query_series("daily", None, None).await.unwrap();
    let reqs2: u64 = second.iter().map(|p| p.requests).sum();
    assert_eq!(reqs2, 3, "重复 flush 覆盖式不翻倍");
    assert_eq!(first.len(), second.len(), "窗口行数一致");
    let _ = std::fs::remove_file(&db);
}

#[test]
fn model_approximation_caliber_and_window_check() {
    assert!(super::super::aggregate::is_precise_for_window(3600, 100));
    assert!(super::super::aggregate::is_precise_for_window(86400, 1000));
    assert!(
        !super::super::aggregate::is_precise_for_window(3599, 100),
        "覆盖不足须标近似"
    );
    assert!(
        !super::super::aggregate::is_precise_for_window(3600, 99),
        "样本不足须标近似"
    );
    assert!(!super::super::aggregate::is_precise_for_window(0, 0));
}

#[tokio::test]
async fn window_cross_digit_ordering() {
    // OPS-8：retention 与 five_min 最新窗保留按整数序，字符串序在 d9/d10、m9/m10 进位处失真。
    let db = tmp_db("window-cross-digit");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    {
        let conn = open_wal(&db).unwrap();
        ensure_tables(&conn).unwrap();
        for i in 1..=40 {
            conn.execute(
                "INSERT INTO metrics_daily(window, protocol, requests) \
                 VALUES (?1, 'chat/completions', 1)",
                rusqlite::params![format!("d{i}")],
            )
            .unwrap();
        }
    }
    purge_retention_blocking(&db).unwrap();
    {
        let conn = open_wal(&db).unwrap();
        let windows: Vec<String> = conn
            .prepare("SELECT window FROM metrics_daily")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(windows.len(), 32, "daily retention 保留 32 窗: {windows:?}");
        for i in 9..=40 {
            assert!(
                windows.contains(&format!("d{i}")),
                "须按整数序保留最 d{i}: {windows:?}"
            );
        }
        assert!(!windows.contains(&"d8".to_string()), "最旧 d8 须被驱逐");
    }
    // five_min 只留最新：内存含 m10，库中另注 m9，flush 后应只留 m10。
    store.record_aux_counts(Protocol::Chat, 10 * 300, 0, 0, 1);
    {
        let conn = open_wal(&db).unwrap();
        conn.execute(
            "INSERT INTO metrics_five_min(window, protocol, requests) \
             VALUES ('m9', 'chat/completions', 1)",
            [],
        )
        .unwrap();
    }
    store.flush().await.unwrap();
    let pts = store.query_series("five_min", None, None).await.unwrap();
    assert_eq!(pts.len(), 1, "five_min 每协议只留最新窗口: {pts:?}");
    assert_eq!(
        pts[0].window, "m10",
        "跨位数最新窗口须为 m10（字符串 MAX 会错误保留 m9）"
    );
    let _ = std::fs::remove_file(&db);
}
