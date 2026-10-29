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
fn latency_12_buckets_cover_long_tail() {
    assert_eq!(
        LATENCY_BOUNDS_MS,
        [
            50, 100, 200, 400, 800, 1500, 3000, 5000, 10000, 20000, 40000
        ]
    );
    assert_eq!(LATENCY_BUCKETS, 12);
    assert_eq!(bucket_index(3), 0);
    assert_eq!(bucket_index(40_000), 10);
    assert_eq!(bucket_index(120_000), 11);
}

#[test]
fn p95_interpolates_within_bucket() {
    let mut buckets = [0u64; LATENCY_BUCKETS];
    for _ in 0..90 {
        buckets[bucket_index(8)] += 1;
    }
    for _ in 0..10 {
        buckets[bucket_index(9000)] += 1;
    }
    // 阈值 95 落 [5000,10000) 桶内第 5 名：中点式
    // 5000 + 5000*(2*5-1)/(2*10) = 5000 + 2250 = 7250。
    assert_eq!(p95_approx(&buckets), 7250);
    assert!(!p95_saturated(&buckets));
    assert_eq!(p95_approx(&[0u64; LATENCY_BUCKETS]), 0);
    // 单桶 100 样本、阈值 95：[800,1500) 内 800 + 700*(2*95-1)/200 = 800 + 661 = 1461。
    let mut b2 = [0u64; LATENCY_BUCKETS];
    b2[bucket_index(1000)] = 100;
    assert_eq!(p95_approx(&b2), 1461);
}

#[test]
fn p95_single_sample_does_not_snap_to_upper_bound() {
    // 单样本桶 count=1/rank=1：旧式 `lower + span*rank/count` 恒返回上界（60ms 报 100ms），
    // 中点式给出区间半程 50 + 50*(2*1-1)/2 = 75。
    let mut single = [0u64; LATENCY_BUCKETS];
    single[bucket_index(60)] = 1;
    assert_eq!(p95_approx(&single), 75);
    assert_ne!(p95_approx(&single), 100, "单样本不得 snap 到桶上界");
    // 首桶同样不贴上界：0 + 50*(2*1-1)/2 = 25。
    let mut first = [0u64; LATENCY_BUCKETS];
    first[bucket_index(8)] = 1;
    assert_eq!(p95_approx(&first), 25);
}

#[test]
fn p95_overflow_reports_lower_bound_and_saturation() {
    let mut buckets = [0u64; LATENCY_BUCKETS];
    for _ in 0..100 {
        buckets[bucket_index(120_000)] += 1;
    }
    // 上溢桶只能给下界（最后一条边界），并显式标记饱和，不再伪装成精确值。
    assert_eq!(p95_approx(&buckets), 40_000);
    assert!(p95_saturated(&buckets));
    // 20s 样本不再落上溢桶（旧口径 10s 上界会把它钉在 10000）。
    let mut long_tail = [0u64; LATENCY_BUCKETS];
    long_tail[bucket_index(20_000)] = 100;
    // [10000,20000) 桶内 10000 + 10000*(2*95-1)/200 = 19450。
    assert_eq!(p95_approx(&long_tail), 19_450);
    assert!(!p95_saturated(&long_tail));
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
    // `:@` 形态按普通字符保留通过；空归 unknown；超长截断；控制字符剥离。
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
    // `record_chat` 按归一化 model 分桶（截断128+去控制字符）；
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

/// 可观测联动回补：model 分桶/协议联动/三粒度桶数与空桶稀疏/24h 近似口径/since 过滤。
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
        assert!(pts.is_empty(), "空库稀疏无行（补零桶差异有意）");
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
        // SQL 侧 since 过滤与排序改用整数序（字符串序在 d9/d10 进位处失真）。
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
fn five_min_memory_keeps_newest_13_by_window_ord() {
    let store = MetricsStore::new(tmp_db("five-min-mem-13"));
    let base = 300 * 1_000;
    for i in 0..14 {
        store.record_chat(chat_rec(
            Protocol::Chat,
            "m",
            5,
            None,
            None,
            true,
            base + i * 300,
        ));
    }
    let aggs = store.aggs.lock().expect("聚合锁无毒");
    let windows: Vec<String> = aggs
        .keys()
        .filter(|k| k.granularity == Granularity::FiveMin)
        .map(|k| k.window.clone())
        .collect();
    assert_eq!(
        windows.len(),
        AGGS_FIVE_MIN_KEEP,
        "内存每协议留 13 窗: {windows:?}"
    );
    let oldest = five_min_key(base);
    assert!(
        !windows.contains(&oldest),
        "最旧窗口须按 window_ord 驱逐: {windows:?}"
    );
    assert!(
        windows.contains(&five_min_key(base + 13 * 300)),
        "最新窗口须保留: {windows:?}"
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
async fn series_ts_start_is_ordinal_times_span() {
    // 三粒度 `ts_start` 均等于 window 序号 × 桶跨度，且对齐桶边界。
    let db = tmp_db("ts-start-spans");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    let ts = 86_400 * 40 + 3_600 * 5 + 123;
    store.record_chat(chat_rec(Protocol::Chat, "m", 5, None, None, true, ts));
    store.flush().await.unwrap();
    for (gran, span) in [
        ("daily", 86_400i64),
        ("hourly", 3_600),
        ("five_min", 300),
        ("5min", 300),
    ] {
        let pts = store
            .query_series(gran, None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert!(!pts.is_empty(), "{gran} 须有点");
        for p in &pts {
            let ord: i64 = p.window[1..].parse().expect("窗口序号可解析");
            assert_eq!(p.ts_start, ord * span, "{gran} ts_start 须为序号×跨度");
            assert_eq!(p.ts_start % span, 0, "{gran} ts_start 须对齐桶跨度");
        }
    }
    let _ = std::fs::remove_file(&db);
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
