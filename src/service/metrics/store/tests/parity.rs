//! 指标口径对齐回归：旧库加列幂等、覆盖式 UPSERT 列完整性、快照总量。
//! 自 `store/tests.rs` 拆分以守 800 行红线。

use {
    super::super::{MetricsStore, ensure_tables},
    crate::{
        fs_perm::open_wal,
        service::{
            llm_gateway::Protocol,
            metrics::{
                aggregate::day_key,
                summarize::test_support::{chat_rec, now, tmp_db, usage},
            },
        },
    },
};

fn daily_columns(path: &std::path::Path) -> Vec<String> {
    let conn = open_wal(path).expect("库须可开");
    conn.prepare("PRAGMA table_info(metrics_daily)")
        .expect("查表结构")
        .query_map([], |r| r.get::<_, String>(1))
        .expect("取列名")
        .flatten()
        .collect()
}

/// 旧库缺 `pii_miss` 列时经 `ensure_tables` 幂等补列：既有列值不变、新列 DEFAULT 0，
/// 重复触发不得重复加列或清空既有值。
#[tokio::test]
async fn legacy_db_adds_pii_miss_idempotent_and_preserves_values() {
    let db = tmp_db("parity-legacy-pii-miss");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    {
        let conn = open_wal(&db).expect("旧库须可建");
        conn.execute_batch(&format!(
            "CREATE TABLE metrics_daily(
                window TEXT NOT NULL, protocol TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                cached_read INTEGER NOT NULL DEFAULT 0,
                cached_write INTEGER NOT NULL DEFAULT 0,
                unknown INTEGER NOT NULL DEFAULT 0,
                pii_hits INTEGER NOT NULL DEFAULT 0,
                cred_hits INTEGER NOT NULL DEFAULT 0,
                audit_blocks INTEGER NOT NULL DEFAULT 0,
                t_silent INTEGER NOT NULL DEFAULT 0,
                t_open INTEGER NOT NULL DEFAULT 0,
                t_synth INTEGER NOT NULL DEFAULT 0,
                t_upstream_error INTEGER NOT NULL DEFAULT 0,
                buckets TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(window, protocol));
             INSERT INTO metrics_daily(window, protocol, requests, pii_hits, cred_hits)
                VALUES('{}', 'chat/completions', 3, 5, 2);",
            day_key(ts),
        ))
        .expect("建旧库须成功");
    }
    assert!(
        !daily_columns(&db).iter().any(|n| n == "pii_miss"),
        "前置：旧库须缺 pii_miss"
    );
    let store = MetricsStore::new(db.clone());
    let first = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    let second = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(
        daily_columns(&db)
            .iter()
            .filter(|n| n.as_str() == "pii_miss")
            .count(),
        1,
        "重复触发须恰好一列 pii_miss"
    );
    assert_eq!(first[0].requests, 3, "既有列读取不变");
    assert_eq!(first[0].pii_hits, 5, "既有列读取不变");
    assert_eq!(first[0].cred_hits, 2, "既有列读取不变");
    assert_eq!(first[0].pii_miss, 0, "补列须 DEFAULT 0");
    assert_eq!(second[0].pii_hits, 5, "重复补列不得清零既有值");
    let _ = std::fs::remove_file(&db);
}

/// 覆盖式 UPSERT 逐列写入：flush 后每个非零列都能按列读回，无一被清空。
#[tokio::test]
async fn flush_writes_all_columns_no_zeroing() {
    let db = tmp_db("parity-col-complete");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    let ts = 86_400 * 20 + 123;
    store.record_chat(chat_rec(
        Protocol::Chat,
        "m",
        12,
        Some(&usage(4, 5, 9)),
        None,
        true,
        ts,
    ));
    assert!(store.record_aux_counts_extended(Protocol::Chat, ts, 7, 4, 3, 2));
    store.flush().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    let p = &pts[0];
    assert_eq!(
        (p.requests, p.total_tokens),
        (1, 9),
        "用量列不得被附属覆盖清零"
    );
    assert_eq!(
        (p.pii_hits, p.pii_miss, p.cred_hits, p.audit_blocks),
        (7, 4, 3, 2),
        "覆盖式 UPSERT 须逐列写入"
    );
    let _ = std::fs::remove_file(&db);
}

/// 快照总量按日粒度一次求和：三粒度扇出不得重复计数，且与 series 日粒度和一致。
#[tokio::test]
async fn snapshot_totals_match_daily_series_and_not_tripled() {
    let db = tmp_db("parity-snapshot-total");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    store.record_aux_counts_extended(Protocol::Chat, 86_400 * 30 + 10, 3, 2, 1, 0);
    store.record_aux_counts_extended(Protocol::Chat, 86_400 * 30 + 20, 4, 1, 0, 1);
    let snap = store.snapshot();
    assert_eq!(
        (snap.pii_hits, snap.pii_miss, snap.cred_hits),
        (7, 3, 1),
        "快照总量须为日粒度一次求和（三粒度不得重复计数）"
    );
    store.flush().await.unwrap();
    let pts = store.query_series("daily", None, None).await.unwrap();
    let series = pts.iter().fold((0u64, 0u64, 0u64), |(h, m, c), p| {
        (h + p.pii_hits, m + p.pii_miss, c + p.cred_hits)
    });
    assert_eq!(
        series,
        (snap.pii_hits, snap.pii_miss, snap.cred_hits),
        "快照总量须与 series 日粒度和一致"
    );
    let _ = std::fs::remove_file(&db);
}

/// `ensure_tables` 对全新库亦幂等：重复调用不报错、列集合稳定。
#[test]
fn ensure_tables_idempotent_on_fresh_db() {
    let db = tmp_db("parity-ensure-idempotent");
    let _ = std::fs::remove_file(&db);
    let conn = open_wal(&db).expect("新库须可建");
    ensure_tables(&conn).expect("首次建表");
    ensure_tables(&conn).expect("重复建表须幂等");
    drop(conn);
    let cols = daily_columns(&db);
    assert_eq!(
        cols.iter().filter(|n| n.as_str() == "pii_miss").count(),
        1,
        "重复建表不得重复加列: {cols:?}"
    );
}
