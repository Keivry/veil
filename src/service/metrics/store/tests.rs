#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../store.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "store.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "store/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
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
    // B5.1/B5.3：重复触发 flush 不翻倍（含附属列）；store 层无定时去抖，
    // 覆盖式 UPSERT 使多次触发效果等价一次（2s 节流锚在 SSE 层，见 sse.rs）。
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
