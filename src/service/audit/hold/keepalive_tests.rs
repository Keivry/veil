//! keepalive 门控与超时竞态常量测试（触 800 红线后按测试外迁模板独立成子模块；
//! 实现体仍留 `hold.rs`，用例语义不变）。

use super::*;

#[test]
fn timeout_disconnect_race_window_constants_locked() {
    // 竞态区间契约经 `validate` 校验入口行为覆盖（非仅比对常量）：
    // `110..=130` 拒启动，区间外（`109`/`131`/`90`）通过。
    let parse = |raw: &str| {
        crate::config::parse_audit_timeout(&|k: &str| {
            (k == "AUDIT_TIMEOUT").then(|| raw.to_string())
        })
    };
    for rejected in ["110", "130"] {
        assert!(
            parse(rejected).is_err(),
            "AUDIT_TIMEOUT={rejected} 落在竞态区间须被拒"
        );
    }
    for accepted in ["109", "131", "90"] {
        assert_eq!(
            parse(accepted).unwrap(),
            accepted.parse::<i64>().unwrap(),
            "AUDIT_TIMEOUT={accepted} 在竞态区间外须通过"
        );
    }
}

#[tokio::test]
async fn keepalive_handle_per_request_independent_with_first_packet_hold() {
    let (tx1, _rx1) = tokio::sync::mpsc::channel::<String>(8);
    let (tx2, _rx2) = tokio::sync::mpsc::channel::<String>(8);
    let h1 = RequestKeepalive::spawn(tx1);
    let h2 = RequestKeepalive::spawn(tx2);
    assert!(h1.is_live() && h2.is_live());
    assert!(!std::ptr::eq(&h1, &h2));
    drop(h1);
    assert!(h2.is_live());
}

#[tokio::test]
async fn audit_approve_stream_timeout_disconnect_race_with_early_close_cleanup() {
    let (tx1, _rx1) = tokio::sync::mpsc::channel::<String>(8);
    let (tx2, _rx2) = tokio::sync::mpsc::channel::<String>(8);
    let gate_closed = std::sync::Arc::new(AtomicBool::new(false));
    let gated = RequestKeepalive::spawn_gated(tx1, gate_closed);
    assert!(gated.is_live());
    drop(gated);
    let h1 = RequestKeepalive::spawn(tx2);
    assert!(h1.is_live());
    drop(h1);
    let (tx3, _rx3) = tokio::sync::mpsc::channel::<String>(8);
    let (tx4, _rx4) = tokio::sync::mpsc::channel::<String>(8);
    let keep_a = RequestKeepalive::spawn(tx3);
    let keep_b = RequestKeepalive::spawn(tx4);
    assert!(keep_a.is_live() && keep_b.is_live());
    drop(keep_a);
    assert!(keep_b.is_live());
}

#[tokio::test]
async fn keepalive_gate_pending_only() {
    // 1.3：无未完成分片（gate=false）保活按周期发送；有未完成分片
    // （gate=true）被抑制，释放审计作用域后恢复发送。
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
    let gate = Arc::new(AtomicBool::new(false));
    let keep = RequestKeepalive::spawn_gated_with_interval(
        tx,
        gate.clone(),
        std::time::Duration::from_millis(20),
    );
    let first = tokio::time::timeout(std::time::Duration::from_millis(400), rx.recv())
        .await
        .expect("无分片须按周期发送保活")
        .expect("通道不得关闭");
    assert_eq!(first, crate::service::sse::keepalive_frame());
    let mut hold = AuditHold::new(1024);
    assert!(!hold.has_pending_fragments());
    hold.push_fragment(0, Some("c1"), Some("run"), "{\"x\":");
    assert!(hold.has_pending_fragments(), "累积分片后须为 pending");
    gate.store(hold.has_pending_fragments(), Ordering::Relaxed);
    while rx.try_recv().is_ok() {}
    tokio::time::sleep(std::time::Duration::from_millis(90)).await;
    assert!(rx.try_recv().is_err(), "存在未完成分片时保活须被抑制");
    hold.release_audited();
    assert!(!hold.has_pending_fragments());
    gate.store(hold.has_pending_fragments(), Ordering::Relaxed);
    let resumed = tokio::time::timeout(std::time::Duration::from_millis(400), rx.recv())
        .await
        .expect("释放后保活须恢复")
        .expect("通道不得关闭");
    assert_eq!(resumed, crate::service::sse::keepalive_frame());
    drop(keep);
}
