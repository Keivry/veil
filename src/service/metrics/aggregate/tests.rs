#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../aggregate.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "aggregate.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "aggregate/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
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
