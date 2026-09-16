//! `CRD-12` 旧哈希宽限通知去重回归（自 `approval/tests.rs` 拆出，保持 800 行红线内）。

use crate::{
    registry::HashChangeOutcome,
    service::credential::{AppStateParts, approve_hash_change, handle_credential, test_support::*},
};

#[tokio::test]
async fn grace_notification_dedup() {
    let sink = CountingSink::new();
    let state = cred_state_with_sink(&cred_env(&[]), sink.clone());
    state.notify.start();
    enrolled_with_entries(
        &state,
        "/s/grace-dedup.sh",
        "h1",
        entries_for("网易", &["授权码"]),
    )
    .await;
    approve_hash_change(
        &state,
        "/s/grace-dedup.sh",
        "h2",
        HashChangeOutcome::KeepAuto,
    )
    .await
    .unwrap();
    {
        let registry = state.registry.read().await;
        let entry = registry.lookup_by_path("/s/grace-dedup.sh").unwrap();
        assert!(entry.matches_old_hash("h1"), "前置：旧哈希须在宽限内");
        assert!(entry.old_hash_expires_at.is_some());
    }

    for _ in 0..3 {
        state.credential_hits().lock().await.clear();
        let out = handle_credential(
            &state,
            &headers("gethash", Some("s3cr3t")),
            &body("h1", "/s/grace-dedup.sh", None),
        )
        .await
        .unwrap();
        assert!(credential_value(&out).starts_with("__VG_CRED_"));
    }

    let grace_count = |sink: &CountingSink| {
        sink.texts()
            .iter()
            .filter(|t| t.contains("old_hash宽限内放行"))
            .count()
    };
    for _ in 0..200 {
        if grace_count(&sink) > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        grace_count(&sink),
        1,
        "同窗口宽限通知须去重为一次: {:?}",
        sink.texts()
    );
    state.notify.shutdown();
}

#[test]
fn grace_dedup_ttl_eviction() {
    // `CRD-12`/D6：满表先清扫过期、仍满逐出 `expires_at` 最小者、SHALL NOT 整表清空。
    use super::super::{GRACE_NOTIFY_DEDUP_MAX, first_grace_notification};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let prefix = format!("grace-ttl-{}", std::process::id());
    let key = |tag: &str, i: usize| format!("{prefix}-{tag}-{i}");
    let probe =
        |dedup_key: &str, expires_at: u64| first_grace_notification(dedup_key, expires_at, now);

    // ① 先清扫过期：过期条目不得挤占容量，也不得触发整表清空。
    let survivor = format!("{prefix}-survivor");
    assert!(probe(&survivor, now + 3600), "预热活键须首插成功");
    for i in 0..GRACE_NOTIFY_DEDUP_MAX {
        assert!(
            first_grace_notification(&key("expired", i), 0, 0),
            "过期条目首插须 true（i={i}）"
        );
    }
    assert!(
        probe(&format!("{prefix}-probe"), now + 600),
        "满表活键插入须成功"
    );
    assert!(
        !probe(&survivor, now + 3600),
        "清扫只淘汰过期条目，SHALL NOT 整表清空（既有活键须保留）"
    );
    assert!(
        first_grace_notification(&key("expired", 0), 0, 0),
        "过期条目须已被清扫（重插返回 true）"
    );

    // ② 仍满逐出 `expires_at` 最小者：升序活键溢出容量后，最小活键被逐、最大活键保留。
    for i in 0..(GRACE_NOTIFY_DEDUP_MAX + 16) {
        assert!(
            probe(&key("live", i), now + 1000 + i as u64),
            "活键首插须 true（i={i}）"
        );
    }
    let last = GRACE_NOTIFY_DEDUP_MAX - 1;
    assert!(
        !probe(&key("live", last), now + 1000 + last as u64),
        "最大 expires_at 键须保留（不清表）"
    );
    assert!(
        !probe(&survivor, now + 3600),
        "逐出单条而非整表清空（早期活键须保留）"
    );
    assert!(
        probe(&key("live", 0), now + 1000),
        "满表逐出须命中 expires_at 最小者（最小键被逐后重插返回 true）"
    );
}
