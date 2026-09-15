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
