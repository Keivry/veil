//! RUN-1 运行时可靠性回归：周期/关闭刷盘、重启保留、刷盘失败降级。

use {
    super::{
        super::summarize::test_support::{chat_rec, now, tmp_db, usage},
        METRICS_FLUSH_INTERVAL_SECS,
        MetricsStore,
    },
    crate::service::llm_gateway::Protocol,
    std::{sync::Arc, time::Duration},
};

#[tokio::test]
async fn metrics_periodic_flush_persists() {
    let db = tmp_db("periodic-flush");
    let _ = std::fs::remove_file(&db);
    let store = Arc::new(MetricsStore::new(db.clone()));
    store.record_chat(chat_rec(
        Protocol::Chat,
        "m",
        10,
        Some(&usage(1, 2, 3)),
        None,
        true,
        now(),
    ));
    let driver = store.spawn_flush_driver(Duration::from_millis(10));
    let mut persisted = false;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if let Ok(pts) = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            && !pts.is_empty()
        {
            persisted = true;
            break;
        }
    }
    driver.abort();
    assert!(persisted, "周期刷盘须在进程不退出时把窗口落盘");
    assert_eq!(METRICS_FLUSH_INTERVAL_SECS, 60);
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn metrics_restart_retains_flushed() {
    let db = tmp_db("restart-retain");
    let _ = std::fs::remove_file(&db);
    let ts = now();
    let store = MetricsStore::new(db.clone());
    store.record_chat(chat_rec(
        Protocol::Chat,
        "m",
        10,
        Some(&usage(2, 3, 5)),
        None,
        true,
        ts,
    ));
    store.flush().await.unwrap();
    let restarted = MetricsStore::new(db.clone());
    let n = restarted.backfill_from_sqlite().await.unwrap();
    assert!(n >= 3, "三粒度至少各一窗: {n}");
    let pts = restarted
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts.len(), 1);
    assert_eq!(pts[0].requests, 1, "已刷盘窗口重启后保留");
    assert_eq!(pts[0].total_tokens, 5, "数值不翻倍");
    restarted.flush().await.unwrap();
    let pts2 = restarted
        .query_series("daily", None, Some("chat/completions".to_string()))
        .await
        .unwrap();
    assert_eq!(pts2[0].requests, 1, "覆盖式回填后再刷不翻倍");
    let _ = std::fs::remove_file(&db);
}

#[tokio::test]
async fn metrics_flush_failure_warns_and_continues() {
    let db = tmp_db("flush-fail");
    let _ = std::fs::remove_file(&db);
    std::fs::create_dir_all(&db).ok();
    let store = Arc::new(MetricsStore::new(db.clone()));
    store.record_chat(chat_rec(Protocol::Chat, "m", 10, None, None, true, now()));
    assert!(
        store.flush().await.is_err(),
        "sqlite 不可写须返回 Err（驱动侧仅 warn）"
    );
    let driver = store.spawn_flush_driver(Duration::from_millis(5));
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!driver.is_finished(), "刷盘失败不得使驱动退出");
    driver.abort();
    store.record_chat(chat_rec(Protocol::Chat, "m", 10, None, None, true, now()));
    assert_eq!(store.snapshot().requests, 2, "服务继续且内存继续累计");
    let _ = std::fs::remove_dir_all(&db);
}
