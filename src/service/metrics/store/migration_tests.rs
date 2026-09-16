//! N/10.2 加列式 schema 迁移回归：自 `store/tests.rs` 拆分以守 800 行红线（纯迁移）。

use {
    super::{
        super::summarize::test_support::{chat_rec, now, tmp_db},
        MetricsStore,
    },
    crate::{fs_perm::open_wal, service::llm_gateway::Protocol},
};

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
            super::super::aggregate::day_key(ts),
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
