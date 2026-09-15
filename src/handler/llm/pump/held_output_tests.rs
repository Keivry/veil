//! D4/STP-4 持有输出抑制极性回归：`should_suppress_held_output` 实参须以
//! `emitted` 语义为准，调用点不得再传取反值 `!emitted`；三协议结论一致。

use {
    super::decide::should_suppress_held_output,
    crate::service::{audit::AuditHold, llm_gateway::Protocol},
};

#[test]
fn held_output_suppression_polarity() {
    // D4/STP-4：极性以 emitted 为准——本帧确有输出（emitted=true）才抑制；
    // emitted=false 不得抑制（旧调用点传 `!emitted` 为反转）。
    assert!(should_suppress_held_output(true, true, true, false));
    assert!(!should_suppress_held_output(true, true, false, false));
    // 调用点回归锁：`spawn/event_loop.rs` 不得出现 `!emitted`。
    const SRC: &str = include_str!("spawn/event_loop.rs");
    assert!(!SRC.contains("!emitted"), "调用点不得再传取反值 `!emitted`");
    assert!(
        SRC.contains("should_suppress_held_output"),
        "须保留持有抑制调用点"
    );
}

#[test]
fn held_output_three_protocols() {
    // D4：三协议 held 输出抑制极性一致——存在未完成分片时随 emitted 判定。
    use crate::service::audit::HoldVerdict;
    for protocol in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
        let mut hold = AuditHold::new(1024);
        if protocol == Protocol::Responses {
            let key = AuditHold::responses_key(Some("item-1"), 0);
            let _ = hold.push_responses_fragment(
                &key,
                0,
                Some(0),
                Some("item-1"),
                Some("run"),
                "{\"x\":",
            );
        } else {
            assert_eq!(
                hold.push_fragment(0, Some("c1"), Some("run"), "{\"x\":"),
                HoldVerdict::Approved
            );
        }
        let pending = hold.has_pending_fragments();
        assert!(pending, "{protocol:?} 未完成分片须 pending");
        assert!(
            should_suppress_held_output(true, pending, true, false),
            "{protocol:?} emitted=true 须抑制"
        );
        assert!(
            !should_suppress_held_output(true, pending, false, false),
            "{protocol:?} emitted=false 须放行"
        );
    }
}
