//! 加列式 schema 迁移回归：自 `store/tests.rs` 拆分以守 800 行红线（纯迁移）。

use {
    super::super::{
        super::{
            MetricsStore,
            aggregate::{
                LATENCY_BOUNDS_VERSION,
                LATENCY_BUCKETS,
                RangeSpec,
                hour_key,
                p95_approx,
                p95_saturated,
                stale_bucket_rows_total,
            },
            summarize::test_support::{chat_rec, now, tmp_db},
        },
        ensure_tables,
    },
    crate::{fs_perm::open_wal, service::llm_gateway::Protocol},
};

/// 对齐整点的固定 `now`：小时窗边界为整数，避免测试跨窗。
const NOW: i64 = 86_400 * 20_000;

/// 建一张只有 `bucket_bounds_version` 之前列形态的 `metrics_hourly` 旧表。
fn create_legacy_hourly(db: &std::path::Path) {
    let conn = open_wal(db).expect("旧库须可建");
    conn.execute_batch(
        "CREATE TABLE metrics_hourly(
            window TEXT NOT NULL, protocol TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cached_read INTEGER NOT NULL DEFAULT 0,
            cached_write INTEGER NOT NULL DEFAULT 0,
            unknown INTEGER NOT NULL DEFAULT 0,
            pii_hits INTEGER NOT NULL DEFAULT 0,
            pii_miss INTEGER NOT NULL DEFAULT 0,
            cred_hits INTEGER NOT NULL DEFAULT 0,
            audit_blocks INTEGER NOT NULL DEFAULT 0,
            t_silent INTEGER NOT NULL DEFAULT 0,
            t_open INTEGER NOT NULL DEFAULT 0,
            t_synth INTEGER NOT NULL DEFAULT 0,
            t_upstream_error INTEGER NOT NULL DEFAULT 0,
            buckets TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(window, protocol));",
    )
    .expect("建旧表须成功");
}

/// 桶串（12 个计数，`values` 之外的桶为 0）。
fn bucket_string(values: &[(usize, u64)]) -> String {
    let mut arr = [0u64; LATENCY_BUCKETS];
    for (index, count) in values {
        arr[*index] = *count;
    }
    arr.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// 插一行 `metrics_hourly`（显式带 `bucket_bounds_version`）。
fn insert_hourly_row(
    db: &std::path::Path,
    ts: i64,
    requests: i64,
    total_tokens: i64,
    buckets: &[(usize, u64)],
    version: i64,
) {
    let conn = open_wal(db).expect("库须可开");
    // 旧表先跑一次迁移（生产启动路径同样先 `ensure_tables` 再读写）。
    ensure_tables(&conn).expect("补列须成功");
    conn.execute(
        "INSERT INTO metrics_hourly(window, protocol, requests, total_tokens, buckets, \
         bucket_bounds_version) VALUES(?1, 'chat/completions', ?2, ?3, ?4, ?5)",
        rusqlite::params![
            hour_key(ts),
            requests,
            total_tokens,
            bucket_string(buckets),
            version
        ],
    )
    .expect("插行须成功");
}

/// 旧库缺 `t_upstream_error` 列时启动经 `ALTER TABLE ADD COLUMN ... DEFAULT 0`
/// 补列，既有列读取不变，新列经 UPSERT 可写可读。
#[tokio::test]
async fn legacy_db_missing_t_upstream_error_adds_column_default_zero() {
    let db = tmp_db("legacy-addcol");
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
                buckets TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(window, protocol));
             INSERT INTO metrics_daily(window, protocol, requests, t_synth)
                VALUES('{}', 'chat/completions', 2, 1);",
            super::super::super::aggregate::day_key(ts),
        ))
        .expect("建旧库须成功");
    }
    let column_info = |path: &std::path::Path| -> Vec<(String, i64, Option<String>)> {
        let conn = open_wal(path).unwrap();
        conn.prepare("PRAGMA table_info(metrics_daily)")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .flatten()
            .collect()
    };
    assert!(
        !column_info(&db)
            .iter()
            .any(|(n, ..)| n == "t_upstream_error"),
        "前置：旧库须缺 t_upstream_error"
    );
    // 启动读取触发 ensure_tables 补列；旧行读取不变、新列 DEFAULT 0。
    let store = MetricsStore::new(db.clone());
    store.backfill_from_sqlite().await.unwrap();
    let pts = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].requests, 2, "既有列读取不变");
    assert_eq!(pts[0].truncated_synthesized_failed, 1, "既有截断列不变");
    assert_eq!(pts[0].truncated_upstream_error, 0, "补列须 DEFAULT 0");
    let col = column_info(&db)
        .into_iter()
        .find(|(n, ..)| n == "t_upstream_error")
        .expect("补列须存在");
    assert_eq!(col.1, 1, "补列须 NOT NULL");
    assert_eq!(col.2.as_deref(), Some("0"), "补列须 DEFAULT 0");
    // 新列经 UPSERT 可写可读，且既有列不被清空。
    store.record_chat(chat_rec(
        Protocol::Chat,
        "",
        5,
        None,
        Some("upstream_error"),
        true,
        ts,
    ));
    store.flush().await.unwrap();
    let pts2 = store
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts2.len(), 1);
    assert_eq!(pts2[0].requests, 3, "回填后新记录须叠加于旧行");
    assert_eq!(pts2[0].truncated_synthesized_failed, 1, "既有截断列不丢");
    assert_eq!(pts2[0].truncated_upstream_error, 1, "补列须可写可读");
    let _ = std::fs::remove_file(&db);
}

/// 旧版本行（`bucket_bounds_version = 0`）的桶贡献为零，但请求数/token 照常计入。
#[tokio::test]
async fn legacy_bucket_version_rows_skip_buckets_keep_counts() {
    let db = tmp_db("migrate-stale-buckets");
    let _ = std::fs::remove_file(&db);
    create_legacy_hourly(&db);
    // 旧口径上溢桶（同下标 11）：若被误读成新口径即 ">40s"，p95 会虚假饱和。
    insert_hourly_row(&db, NOW - 60, 3, 9, &[(11, 5)], 0);
    let store = MetricsStore::new(db.clone());
    let before = stale_bucket_rows_total();
    store.backfill_from_sqlite().await.unwrap();
    assert!(
        stale_bucket_rows_total() > before,
        "跳过旧版本行须计入可观测计数（一次性 warn 依据）"
    );
    let snap = store.snapshot_in_range(RangeSpec::parse("24h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 3, "旧行请求数仍须计入");
    assert_eq!(snap.total_tokens, 9, "旧行 token 仍须计入");
    assert_eq!(
        snap.latency_buckets, [0u64; LATENCY_BUCKETS],
        "旧版本行的桶贡献须为零（不重解释旧桶）"
    );
    assert!(!snap.p95_saturated, "旧版本行不得让 p95 饱和");
    assert_eq!(snap.p95_ms, 0, "无当前版本桶时 p95 为 0");
    let _ = std::fs::remove_file(&db);
}

/// 两条当前版本行按桶正常求和。
#[tokio::test]
async fn current_version_rows_sum_buckets_normally() {
    let db = tmp_db("migrate-current-buckets");
    let _ = std::fs::remove_file(&db);
    let store = MetricsStore::new(db.clone());
    store.flush().await.unwrap();
    insert_hourly_row(
        &db,
        NOW - 7_260,
        1,
        2,
        &[(0, 1)],
        i64::from(LATENCY_BOUNDS_VERSION),
    );
    insert_hourly_row(
        &db,
        NOW - 60,
        1,
        4,
        &[(0, 1)],
        i64::from(LATENCY_BOUNDS_VERSION),
    );
    store.backfill_from_sqlite().await.unwrap();
    let snap = store.snapshot_in_range(RangeSpec::parse("24h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 2, "两行请求数须求和");
    assert_eq!(snap.total_tokens, 6, "两行 token 须求和");
    let mut expect = [0u64; LATENCY_BUCKETS];
    expect[0] = 2;
    assert_eq!(snap.latency_buckets, expect, "同版本行桶须正常求和");
    // 两样本全落 0-50ms 桶：阈值 ceil(2*0.95)=2 → rank 2/count 2，中点式
    // 0 + 50*(2*2-1)/4 = 37（不贴上界 50）。
    assert_eq!(p95_approx(&snap.latency_buckets), 37);
    assert!(!p95_saturated(&snap.latency_buckets));
    let _ = std::fs::remove_file(&db);
}

/// 版本不符的行即便全落上溢桶也不得产出 `p95_saturated = true`。
#[tokio::test]
async fn stale_rows_never_saturate_p95() {
    let db = tmp_db("migrate-stale-saturation");
    let _ = std::fs::remove_file(&db);
    create_legacy_hourly(&db);
    // 旧口径：100 个样本全在 >10s 上溢桶；新口径同下标是 >40s。
    insert_hourly_row(&db, NOW - 60, 100, 0, &[(11, 100)], 0);
    let store = MetricsStore::new(db.clone());
    store.backfill_from_sqlite().await.unwrap();
    let snap = store.snapshot_in_range(RangeSpec::parse("24h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 100);
    assert!(
        !snap.p95_saturated,
        "旧版本上溢桶不得被读成当前口径的上溢桶"
    );
    assert!(!p95_saturated(&snap.latency_buckets));
    assert_eq!(snap.p95_ms, 0, "旧版本桶不参与 p95");
    let _ = std::fs::remove_file(&db);
}

/// 旧窗口回填后同窗再记新样本：计数叠加、桶清零重算（不混入旧边界序列）。
#[tokio::test]
async fn recording_into_backfilled_stale_window_resets_buckets_only() {
    let db = tmp_db("migrate-stale-then-record");
    let _ = std::fs::remove_file(&db);
    create_legacy_hourly(&db);
    insert_hourly_row(&db, NOW - 60, 5, 15, &[(11, 5)], 0);
    let store = MetricsStore::new(db.clone());
    store.backfill_from_sqlite().await.unwrap();
    store.record_chat(chat_rec(Protocol::Chat, "m", 5, None, None, true, NOW - 60));
    let snap = store.snapshot_in_range(RangeSpec::parse("24h").unwrap(), NOW, None);
    assert_eq!(snap.requests, 6, "旧行计数与新样本须叠加");
    assert_eq!(snap.total_tokens, 15, "旧行 token 不丢");
    let mut expect = [0u64; LATENCY_BUCKETS];
    expect[0] = 1;
    assert_eq!(
        snap.latency_buckets, expect,
        "同窗新样本按当前边界落桶，旧桶不得残留"
    );
    let _ = std::fs::remove_file(&db);
}

/// `bucket_bounds_version` 补列幂等：列已存在时重复 `ensure_tables` 不重复加列、不清零值。
#[tokio::test]
async fn bucket_bounds_version_column_alter_idempotent() {
    let db = tmp_db("migrate-version-column");
    let _ = std::fs::remove_file(&db);
    create_legacy_hourly(&db);
    let columns = || -> Vec<(String, i64, Option<String>)> {
        let conn = open_wal(&db).unwrap();
        conn.prepare("PRAGMA table_info(metrics_hourly)")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap()
            .flatten()
            .collect()
    };
    assert!(
        !columns().iter().any(|(n, ..)| n == "bucket_bounds_version"),
        "前置：旧表须缺 bucket_bounds_version"
    );
    {
        let conn = open_wal(&db).unwrap();
        ensure_tables(&conn).expect("首次补列");
        ensure_tables(&conn).expect("重复补列须幂等");
    }
    let touched: Vec<(String, i64, Option<String>)> = columns()
        .into_iter()
        .filter(|(n, ..)| n == "bucket_bounds_version")
        .collect();
    assert_eq!(touched.len(), 1, "重复补列须恰好一列: {touched:?}");
    assert_eq!(touched[0].1, 1, "补列须 NOT NULL");
    assert_eq!(touched[0].2.as_deref(), Some("0"), "补列须 DEFAULT 0");
    let _ = std::fs::remove_file(&db);
}
