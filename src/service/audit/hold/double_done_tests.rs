//! R8-01 响应审计双投递字节去重与守恒测试（`hold/tests.rs` 触 800 红线后按
//! `keepalive_tests`/`zero_byte_tests` 模板独立成子模块；实现体仍留 `hold.rs`）。

use super::*;

/// 守恒量：`total_bytes` 的口径来源——`args_by_index` 各值长度之和 +
/// `responses_slots` 各槽 [`ResponsesSlot::held_bytes`] 之和
/// （`pending_bytes` 为独立维度，不计入）。
fn conserved_bytes(hold: &AuditHold) -> usize {
    hold.args_by_index.values().map(String::len).sum::<usize>()
        + hold
            .responses_slots
            .values()
            .map(ResponsesSlot::held_bytes)
            .sum::<usize>()
}

#[test]
fn responses_double_done_same_args_no_double_count_no_residual() {
    // Given：一个已完成槽（官方双投递候选）、一个未完成 pending 槽、一个 args_by_index 槽。
    let mut hold = AuditHold::new(4096);
    let a0 = "{\"a\":1}";
    let a1 = "{\"b\":22}";
    let a2 = "{\"c\":333}";
    let k0 = AuditHold::responses_key(Some("item-0"), 0);
    let k1 = AuditHold::responses_key(Some("item-1"), 1);
    hold.push_responses_fragment(&k0, 0, Some(0), Some("item-0"), Some("run"), a0);
    hold.push_responses_fragment(&k1, 1, Some(0), Some("item-1"), Some("run"), a1);
    hold.push_fragment(7, None, None, a2);
    assert_eq!(hold.total_bytes, a0.len() + a1.len() + a2.len());
    assert_eq!(hold.total_bytes, conserved_bytes(&hold));

    // When：第一次 `.done`（function_call_arguments.done）把分片转为完整参数，
    // 随后第二次 `.done`（output_item.done）携带同一完整参数。
    hold.mark_responses_done(&k0, Some(a0));
    let after_first = conserved_bytes(&hold);
    hold.mark_responses_done(&k0, Some(a0));

    // Then：双投递不二次累加，且任意变更后守恒不变量成立。
    assert_eq!(
        hold.total_bytes,
        a0.len() + a1.len() + a2.len(),
        "重复 .done 同参数不得二次累加"
    );
    assert_eq!(
        after_first,
        conserved_bytes(&hold),
        "首次 done 不得改变持有量"
    );
    assert_eq!(hold.total_bytes, conserved_bytes(&hold), "双投递后守恒");

    // When：审计释放。
    hold.release_audited();

    // Then：done 槽与 args_by_index 按同源口径恰好归还一次，仅余未完成槽。
    assert_eq!(hold.total_bytes, a1.len(), "仅 item-1 未完成分片仍在持");
    assert_eq!(hold.total_bytes, conserved_bytes(&hold), "释放后守恒");

    // When：pending 槽判毕并再次释放。
    hold.mark_responses_done(&k1, Some(a1));
    hold.release_audited();

    // Then：无残留、无 pending。
    assert_eq!(hold.total_bytes, 0, "释放后无残留");
    assert_eq!(conserved_bytes(&hold), 0);
    assert!(!hold.has_pending_fragments());
    assert!(!hold.is_rejected());
}

#[test]
fn responses_double_done_distinct_args_replaces_accounting_once() {
    // Given：槽先以短参数完成。
    let mut hold = AuditHold::new(4096);
    let short = "{\"a\":1}";
    let long = "{\"a\":12345}";
    let key = AuditHold::responses_key(Some("item-2"), 0);
    hold.push_responses_fragment(&key, 0, Some(0), Some("item-2"), Some("run"), short);
    hold.mark_responses_done(&key, Some(short));
    assert_eq!(hold.total_bytes, short.len());

    // When：第二次 `.done` 携带不同完整参数。
    hold.mark_responses_done(&key, Some(long));

    // Then：按新值替换记账（旧值经 `held_bytes()` 归还），不泄漏、不双计。
    assert_eq!(hold.total_bytes, long.len(), "替换后只计新完整参数");
    assert_eq!(hold.total_bytes, conserved_bytes(&hold));

    // When：释放。
    hold.release_audited();

    // Then：按新值恰好归还一次。
    assert_eq!(hold.total_bytes, 0);
    assert_eq!(conserved_bytes(&hold), 0);
}

#[test]
fn responses_double_done_dedup_still_fails_closed_on_real_overflow() {
    // R8-01「真实超限仍 fail-closed」：去重不削弱上限——同参数双投递不误判，
    // 替换为真实超限完整参数即拒绝清仓。
    let small = "{\"a\":1}";
    let big = "{\"a\":123456789}";
    assert!(big.len() > small.len());
    let mut hold = AuditHold::new(small.len());
    let key = AuditHold::responses_key(Some("item-cap"), 0);
    hold.push_responses_fragment(&key, 0, Some(0), Some("item-cap"), Some("run"), small);
    hold.mark_responses_done(&key, Some(small));
    hold.mark_responses_done(&key, Some(small));
    assert!(!hold.is_rejected(), "同参数双投递不得误判溢出");
    assert_eq!(hold.total_bytes, conserved_bytes(&hold));

    hold.mark_responses_done(&key, Some(big));

    assert!(hold.is_rejected(), "去重后真实超限仍须 fail-closed");
    assert_eq!(hold.total_bytes, 0, "拒绝须清仓归零");
    assert_eq!(conserved_bytes(&hold), 0);
}
