#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "aggregate.rs",
        include_str!("../aggregate.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "aggregate/tests.rs",
        include_str!("tests.rs"),
    );
}

use {
    super::{
        super::{
            store::MetricsStore,
            summarize::test_support::{chat_rec, ext_rec, now, tmp_db, usage},
        },
        *,
    },
    crate::service::llm_gateway::Protocol,
};

#[test]
fn latency_12_buckets_match_legacy_bounds() {
    assert_eq!(
        LATENCY_BOUNDS_MS,
        [10, 25, 50, 100, 200, 400, 800, 1500, 3000, 5000, 10000]
    );
    assert_eq!(LATENCY_BUCKETS, 12);
    assert_eq!(bucket_index(3), 0);
    assert_eq!(bucket_index(10_000), 10);
    assert_eq!(bucket_index(99_999), 11);
}

#[test]
fn p95_bucket_midpoint_approximation() {
    let mut buckets = [0u64; LATENCY_BUCKETS];
    for _ in 0..95 {
        buckets[bucket_index(8)] += 1;
    }
    for _ in 0..5 {
        buckets[bucket_index(9000)] += 1;
    }
    // 95% 落 [0,10] 桶，中位 5。
    assert_eq!(p95_approx(&buckets), 5);
    assert_eq!(p95_approx(&[0u64; LATENCY_BUCKETS]), 0);
    // [800,1500) 桶中位 (800+1500)/2=1150。
    let mut b2 = [0u64; LATENCY_BUCKETS];
    b2[bucket_index(1000)] = 100;
    assert_eq!(p95_approx(&b2), 1150);
}

#[test]
fn is_precise_requires_window_and_samples() {
    assert!(!is_precise_for_window(3600, 99));
    assert!(!is_precise_for_window(3599, 100));
    assert!(is_precise_for_window(3600, 100));
    let store = MetricsStore::new(tmp_db("precise"));
    // 少样本低覆盖一律近似（标≈）。
    store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
    assert!(!store.snapshot().is_precise);
    // 100 样本跨 3600s 全精确 → 精确。
    let base = now() - 4000;
    for i in 0..100 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            5,
            None,
            None,
            true,
            base + i * 40,
        ));
    }
    assert!(store.snapshot().is_precise);
    // 混入降级样本 → 近似。
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        5,
        None,
        None,
        false,
        base + 4100,
    ));
    assert!(!store.snapshot().is_precise);
}

#[test]
fn truncated_three_modes_split_by_label_invalid_ignored() {
    let store = MetricsStore::new(tmp_db("trunc"));
    store.record_chat(chat_rec(
        Protocol::Responses,
        "",
        5,
        None,
        Some("silent_discard"),
        true,
        now(),
    ));
    store.record_chat(chat_rec(
        Protocol::Responses,
        "",
        5,
        None,
        Some("open_ended"),
        true,
        now(),
    ));
    store.record_chat(chat_rec(
        Protocol::Responses,
        "",
        5,
        None,
        Some("synthesized_failed"),
        true,
        now(),
    ));
    store.record_chat(chat_rec(
        Protocol::Responses,
        "",
        5,
        None,
        Some("bogus_mode"),
        true,
        now(),
    ));
    let snap = store.snapshot();
    assert_eq!(snap.truncated_silent_discard, 1);
    assert_eq!(snap.truncated_open_ended, 1);
    assert_eq!(snap.truncated_synthesized_failed, 1);
    assert_eq!(snap.requests, 4);
}

#[test]
fn b5_model_at_sign_passthrough_and_edges() {
    // B5.2：`:@` 形态按普通字符保留通过；空归 unknown；超长截断；控制字符剥离。
    assert_eq!(normalize_model("org:proj@gpt-4o"), "org:proj@gpt-4o");
    assert_eq!(normalize_model("a:b@c"), "a:b@c");
    assert_eq!(normalize_model(""), "unknown_model");
    assert_eq!(
        normalize_model(&"m".repeat(200)).chars().count(),
        MODEL_MAX_CHARS
    );
    assert_eq!(normalize_model("\u{0}ab\n"), "ab");
    let store = MetricsStore::new(tmp_db("b5-atmodel"));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "org:proj@gpt-4o",
        5,
        None,
        None,
        true,
        now(),
    ));
    store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
    store.record_chat(chat_rec(
        Protocol::Chat,
        &"m".repeat(200),
        5,
        None,
        None,
        true,
        now(),
    ));
    let snap = store.snapshot();
    assert_eq!(snap.per_model.get("org:proj@gpt-4o"), Some(&1));
    assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
    assert_eq!(snap.requests, 3);
}

#[test]
fn record_chat_buckets_by_normalized_model() {
    // C13：`record_chat` 按归一化 model 分桶（截断128+去控制字符）；
    // 阻断体回显断言见 `block_inject` 单测。
    assert_eq!(normalize_model("gpt-4o"), "gpt-4o");
    assert_eq!(normalize_model(""), "unknown_model");
    assert_eq!(normalize_model("   "), "   ", "空白非控制字符，保留");
    assert_eq!(normalize_model("\u{0}ab\n"), "ab");
    assert_eq!(
        normalize_model(&"m".repeat(200)).chars().count(),
        MODEL_MAX_CHARS
    );
    let store = MetricsStore::new(tmp_db("model-bucket"));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "gpt-4o",
        5,
        None,
        None,
        true,
        now(),
    ));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "gpt-4o",
        5,
        None,
        None,
        true,
        now(),
    ));
    store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
    let snap = store.snapshot();
    assert_eq!(snap.per_model.get("gpt-4o"), Some(&2));
    assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
    assert_eq!(snap.requests, 3);
}

/// T9 可观测联动回补：model 分桶/协议联动/三粒度桶数与空桶稀疏/24h 近似口径/since 过滤。
mod observability_parity_tests {
    use {
        super::{ExtendedUsage, chat_rec, ext_rec, now, tmp_db, usage},
        crate::service::{llm_gateway::Protocol, metrics::MetricsStore},
    };

    #[test]
    fn t9_model_linkage_snapshot_buckets() {
        let store = MetricsStore::new(tmp_db("obs-model"));
        let ts = now();
        for _ in 0..2 {
            store.record_chat(chat_rec(
                Protocol::Chat,
                "gpt-4o",
                10,
                Some(&usage(10, 5, 15)),
                None,
                true,
                ts,
            ));
        }
        store.record_chat(chat_rec(
            Protocol::Chat,
            "gpt-4o-mini",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        let snap = store.snapshot();
        assert_eq!(snap.per_model.get("gpt-4o"), Some(&2));
        assert_eq!(snap.per_model.get("gpt-4o-mini"), Some(&1));
        assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
        assert_eq!(snap.per_protocol.get("chat/completions"), Some(&4));
        assert_eq!(snap.total_tokens, 15 * 2 + 2 + 2);
    }

    #[test]
    fn t9_protocol_linkage_series_rows_split() {
        let db = tmp_db("obs-proto");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        let ts = now();
        store.record_chat(chat_rec(
            Protocol::Chat,
            "m",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        store.record_chat(chat_rec(
            Protocol::Anthropic,
            "m",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        let snap = store.snapshot();
        assert_eq!(snap.per_protocol.get("chat/completions"), Some(&1));
        assert_eq!(snap.per_protocol.get("v1/messages"), Some(&1));
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn t9_three_granularities_exact_counts() {
        let db = tmp_db("obs-gran");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        let ts = now();
        for _ in 0..5 {
            store.record_chat(chat_rec(
                Protocol::Chat,
                "m",
                100,
                Some(&usage(10, 5, 15)),
                None,
                true,
                ts,
            ));
        }
        store.record_aux_counts(Protocol::Chat, ts, 1, 0, 0);
        store.flush().await.unwrap();
        for gran in ["daily", "hourly", "five_min"] {
            let pts = store
                .query_series(gran, None, Some("chat/completions".to_string()))
                .await
                .unwrap();
            let total: u64 = pts.iter().map(|p| p.requests).sum();
            assert_eq!(total, 5, "{gran} 粒度 requests 须精确求和");
            assert_eq!(pts.iter().map(|p| p.prompt_tokens).sum::<u64>(), 50);
            assert_eq!(pts.iter().map(|p| p.pii_hits).sum::<u64>(), 1);
        }
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn t9_empty_store_sparse_no_zero_fill() {
        let db = tmp_db("obs-empty");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        let pts = store.query_series("hourly", None, None).await.unwrap();
        assert!(pts.is_empty(), "空库稀疏无行（与原仓补零桶差异有意）");
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn t9_since_window_filters_old() {
        let db = tmp_db("obs-since");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        let ts = now();
        store.record_chat(chat_rec(
            Protocol::Chat,
            "m",
            10,
            Some(&usage(1, 1, 2)),
            None,
            true,
            ts,
        ));
        store.flush().await.unwrap();
        let all = store
            .query_series("daily", Some("d0".to_string()), None)
            .await
            .unwrap();
        assert!(!all.is_empty());
        let future = store
            .query_series("daily", Some("d999999999".to_string()), None)
            .await
            .unwrap();
        assert!(future.is_empty(), "未来 since 须过滤全部旧窗");
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn window_key_ordering() {
        // OPS-8：SQL 侧 since 过滤与排序改用整数序（字符串序在 d9/d10 进位处失真）。
        let db = tmp_db("window-key-ordering");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        store.record_aux_counts(Protocol::Chat, 9 * 86_400, 0, 0, 1);
        store.record_aux_counts(Protocol::Chat, 10 * 86_400, 0, 0, 1);
        store.flush().await.unwrap();
        let all = store.query_series("daily", None, None).await.unwrap();
        let windows: Vec<String> = all.iter().map(|p| p.window.clone()).collect();
        assert_eq!(
            windows,
            vec!["d9".to_string(), "d10".to_string()],
            "窗口须按整数序升序（字符串序会把 d10 排到 d9 之前）"
        );
        let since = store
            .query_series("daily", Some("d10".to_string()), None)
            .await
            .unwrap();
        let kept: Vec<String> = since.iter().map(|p| p.window.clone()).collect();
        assert_eq!(
            kept,
            vec!["d10".to_string()],
            "since=d10 须按整数序过滤掉 d9（字符串序会误留 d9）"
        );
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn t9_cached_columns_linkage() {
        let db = tmp_db("obs-cache");
        let _ = std::fs::remove_file(&db);
        let store = MetricsStore::new(db.clone());
        let ts = now();
        let ext = ExtendedUsage {
            prompt_tokens: 100,
            completion_tokens: 20,
            total_tokens: 120,
            cached_read: 30,
            cached_write: 0,
            ..Default::default()
        };
        store.record_chat_extended(ext_rec(Protocol::Chat, "m", 10, Some(&ext), None, true, ts));
        store.flush().await.unwrap();
        let pts = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert_eq!(pts.iter().map(|p| p.cached_read).sum::<u64>(), 30);
        let _ = std::fs::remove_file(&db);
    }
}

#[tokio::test]
async fn r5_18_negative_stored_counter_converges_no_sign_distortion() {
    use crate::fs_perm::open_wal;
    let db = tmp_db("negative-counter");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    store.flush().await.unwrap();
    {
        let conn = open_wal(&db).unwrap();
        conn.execute(
            "INSERT INTO metrics_daily(window, protocol, requests, buckets) \
             VALUES('d9001','chat/completions',-5,'0,0,0,0,0,0,0,0,0,0,0,0')",
            [],
        )
        .unwrap();
    }
    let before = corrupt_metric_reads_total();
    let pts = store.query_series("daily", None, None).await.unwrap();
    let row = pts
        .iter()
        .find(|p| p.window == "d9001")
        .expect("插入行须可读");
    assert_eq!(row.requests, 0, "负存储值须按 0 收敛，不得符号回绕为极大值");
    assert!(corrupt_metric_reads_total() > before, "须记脏数据计数");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn r5_18_corrupt_bucket_value_warns_and_counts() {
    use crate::fs_perm::open_wal;
    let db = tmp_db("corrupt-bucket");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    store.flush().await.unwrap();
    {
        let conn = open_wal(&db).unwrap();
        conn.execute(
            "INSERT INTO metrics_daily(window, protocol, buckets) \
             VALUES('d9002','chat/completions','bogus,1,0,0,0,0,0,0,0,0,0,0')",
            [],
        )
        .unwrap();
    }
    let before = corrupt_metric_reads_total();
    let n = store.backfill_from_sqlite().await.unwrap();
    assert!(n >= 1, "回填须读到行");
    {
        let aggs = store.aggs.lock().expect("聚合锁无毒");
        let agg = aggs
            .iter()
            .find(|(k, _)| k.window == "d9002")
            .map(|(_, v)| v)
            .expect("回填行");
        assert_eq!(agg.buckets[0], 0, "不可解析桶值按 0 有界收敛");
        assert_eq!(agg.buckets[1], 1, "合法桶值不受污染");
    }
    assert!(
        corrupt_metric_reads_total() > before,
        "不可解析桶值须记 warn 计数（不静默归零）"
    );
    let _ = std::fs::remove_file(&db);
}

#[test]
fn aggs_retention_eviction() {
    let store = MetricsStore::new(tmp_db("aggs-retention"));
    let base = 86_400 * 100;
    for i in 0..40 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "m",
            5,
            None,
            None,
            true,
            base + i * 86_400,
        ));
    }
    let aggs = store.aggs.lock().expect("聚合锁无毒");
    let daily = aggs
        .keys()
        .filter(|k| k.granularity == Granularity::Daily && k.protocol == "chat/completions")
        .count();
    assert!(daily >= 1, "保留窗内须有窗口");
    assert!(
        daily <= AGGS_DAILY_KEEP,
        "daily 须按 retention 驱逐至 {AGGS_DAILY_KEEP}: {daily}"
    );
    let five = aggs
        .keys()
        .filter(|k| k.granularity == Granularity::FiveMin)
        .count();
    assert!(
        five <= AGGS_FIVE_MIN_KEEP,
        "five_min 每协议只留最新: {five}"
    );
}

#[test]
fn aggs_hard_cap_lru() {
    let store = MetricsStore::new(tmp_db("aggs-cap"));
    {
        let mut aggs = store.aggs.lock().expect("聚合锁无毒");
        for i in 0..(AGGS_MAX_ENTRIES + 64) {
            let agg = WindowAgg {
                updated: i as u64,
                ..Default::default()
            };
            aggs.insert(
                AggKey {
                    granularity: Granularity::Daily,
                    window: "d1".to_string(),
                    protocol: format!("p{i}"),
                },
                agg,
            );
        }
        enforce_agg_bounds(&mut aggs, &store.aggs_evicted);
        assert!(
            aggs.len() <= AGGS_MAX_ENTRIES,
            "条目数不得超过硬上限: {}",
            aggs.len()
        );
        assert!(
            !aggs.contains_key(&AggKey {
                granularity: Granularity::Daily,
                window: "d1".to_string(),
                protocol: "p0".to_string(),
            }),
            "最久未更新窗口须被 LRU 驱逐"
        );
    }
    assert!(
        store.aggs_evicted_total() >= 64,
        "驱逐须计入可观测计数: {}",
        store.aggs_evicted_total()
    );
}

#[tokio::test]
async fn aggs_eviction_keeps_sqlite_recoverable() {
    let db = tmp_db("aggs-evict-recover");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    let ts = now();
    store.record_chat(chat_rec(
        Protocol::Chat,
        "m",
        5,
        Some(&usage(1, 1, 2)),
        None,
        true,
        ts,
    ));
    store.flush().await.unwrap();
    store.aggs.lock().expect("聚合锁无毒").clear();
    let restarted = MetricsStore::new(db.clone());
    let n = restarted.backfill_from_sqlite().await.unwrap();
    assert!(n >= 3, "三粒度至少各一窗: {n}");
    let pts = restarted
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(
        pts.iter().map(|p| p.requests).sum::<u64>(),
        1,
        "内存驱逐后重启回填仍恢复已刷盘窗口"
    );
    let _ = std::fs::remove_file(&db);
}
