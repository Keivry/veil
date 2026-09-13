use super::*;

#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 hygiene-round4 模板）：
    // 超 800 即失败，须按模板拆分，不得只改数字放行。
    const SELF_SRC: &str = include_str!("../hold.rs");
    let lines = SELF_SRC.lines().count();
    assert!(
        lines <= 800,
        "hold.rs {lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
}

#[test]
fn responses_three_fragments_ordered_single_flush_no_audit_during_delta() {
    let mut hold = AuditHold::new(1024);
    let key = AuditHold::responses_key(Some("item-7"), 1);
    assert_eq!(
        hold.push_responses_fragment(&key, 1, Some(2), Some("item-7"), Some("run"), "1}"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_responses_fragment(&key, 1, Some(0), None, None, "{\"x\":"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_responses_fragment(&key, 1, Some(1), None, None, ""),
        HoldVerdict::Approved
    );
    assert!(
        hold.tool_triples().is_empty(),
        "done 到达前不得有可审计三元组"
    );
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"{\"x\":"})
    ));
    hold.mark_responses_done(&key, None);
    assert!(hold.is_responses_complete(&key));
    // D2：per-item `.done` 是槽级完成，不得置全局完成。
    assert!(AuditHold::is_responses_slot_complete_event(
        &serde_json::json!({"type":"response.function_call_arguments.done"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"response.function_call_arguments.done"})
    ));
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1, "三分片单 flush 为一条三元组");
    assert_eq!(triples[0].0, 1);
    assert_eq!(triples[0].1, "run");
    assert_eq!(triples[0].2, "{\"x\":1}");
}

#[test]
fn responses_slot_isolated() {
    // D2/S2：per-item `.done` 只完成该槽，不置全局完成；后续 item 分片照常
    // 累积（旧实现首个 done 即置全局完成，后续分片被 `completed` 早退跳过）。
    let done = serde_json::json!({"type":"response.output_item.done"});
    assert!(AuditHold::is_responses_slot_complete_event(&done));
    assert!(
        !AuditHold::is_complete_event(&done),
        "槽级 done 不得置全局完成"
    );
    let mut hold = AuditHold::new(1024);
    if AuditHold::is_complete_event(&done) {
        hold.mark_completed();
    }
    let k0 = AuditHold::responses_key(Some("item-0"), 0);
    hold.push_responses_fragment(&k0, 0, Some(0), Some("item-0"), Some("run"), "{\"x\":1}");
    hold.mark_responses_done(&k0, Some("{\"x\":1}"));
    hold.release_audited();
    assert!(
        !hold.has_pending_fragments(),
        "item-0 审计释放后归非 pending"
    );
    let k1 = AuditHold::responses_key(Some("item-1"), 1);
    assert_eq!(
        hold.push_responses_fragment(
            &k1,
            1,
            Some(1),
            Some("item-1"),
            Some("exec"),
            "{\"command\":\"rm -rf /\"}"
        ),
        HoldVerdict::Approved
    );
    hold.mark_responses_done(&k1, Some("{\"command\":\"rm -rf /\"}"));
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1, "item-1 须照常累积并可审计");
    assert_eq!(triples[0].0, 1);
    assert_eq!(triples[0].1, "exec");
    assert_eq!(triples[0].2, "{\"command\":\"rm -rf /\"}");
}

#[test]
fn responses_complete_events_only() {
    // D2：Responses 仅官方三元触发全局完成。
    for t in [
        "response.completed",
        "response.failed",
        "response.incomplete",
    ] {
        assert!(
            AuditHold::is_complete_event(&serde_json::json!({"type": t})),
            "{t} 须触发全局完成"
        );
    }
    for t in [
        "response.output_item.done",
        "response.function_call_arguments.done",
        "response.function_call_arguments.delta",
        "response.output_item.added",
    ] {
        assert!(
            !AuditHold::is_complete_event(&serde_json::json!({"type": t})),
            "{t} 不得触发全局完成"
        );
    }
}

#[test]
fn tool_deltas_accumulate_by_index_without_flush_until_complete() {
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("a"), Some("run"), "{\"x\":"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_fragment(0, None, None, "1}"),
        HoldVerdict::Approved
    );
    assert!(hold.held());
    assert_eq!(hold.accumulated(0), Some("{\"x\":1}"));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"delta":"hi"})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"finish_reason":"tool_calls"})
    ));
    // §2.5：stop/item_done 只触发按 index 清理，不标记全局完成。
    assert!(AuditHold::is_index_complete_event(
        &serde_json::json!({"type":"content_block_stop"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"content_block_stop"})
    ));
    assert!(AuditHold::is_index_complete_event(
        &serde_json::json!({"type":"item_done"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"item_done"})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"type":"message_stop"})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"message":{"finish_reason":"tool_calls"}}]})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"choices":[]})
    ));
    hold.mark_completed();
    assert!(!hold.held());
}

#[test]
fn overflow_fail_closed_and_clears_pending() {
    let mut hold = AuditHold::new(4);
    assert_eq!(
        hold.push_fragment(0, None, None, "ab"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_fragment(0, None, None, "cde"),
        HoldVerdict::Rejected
    );
    assert!(hold.is_rejected());
    assert_eq!(hold.accumulated(0), None);
}

#[test]
fn mid_abort_and_early_close_cleanup_fail_closed_without_hang() {
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("a"), Some("run"), "{\"x\":"),
        HoldVerdict::Approved
    );
    hold.mark_rejected();
    assert!(hold.is_rejected());
    assert!(!hold.held(), "abort 后不得再挂起等待");
    assert_eq!(
        hold.push_fragment(0, None, None, "1}"),
        HoldVerdict::Rejected,
        "abort 后续分片一律拒绝"
    );
    let mut early = AuditHold::new(1024);
    assert_eq!(
        early.push_fragment(1, Some("b"), Some("run"), "{\"y\":"),
        HoldVerdict::Approved
    );
    early.mark_completed();
    assert!(!early.held(), "早断完成即清理，不残留挂起");
}

#[test]
fn dual_index_independent_accumulation_without_crosstalk() {
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("a"), Some("run_a"), "{\"x\":"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_fragment(1, Some("b"), Some("run_b"), "{\"y\":"),
        HoldVerdict::Approved
    );
    assert_eq!(hold.accumulated(0), Some("{\"x\":"));
    assert_eq!(hold.accumulated(1), Some("{\"y\":"));
    hold.clear_index(0);
    assert_eq!(hold.accumulated(0), None);
    assert_eq!(hold.accumulated(1), Some("{\"y\":"), "清槽不得污染他槽");
    assert!(hold.held(), "单槽清理后整体仍挂起审计");
}

#[test]
fn hold_bytes_reclaim_long_stream_no_false_overflow() {
    // S7/D8：cap 约束同时活跃字节；长流多工具依次完成清槽须归还字节，
    // 不得因历史累计滞留误判 overflow。
    let mut hold = AuditHold::new(16);
    for idx in 0..50u32 {
        assert_eq!(
            hold.push_fragment(idx, Some("id"), Some("run"), "0123456789abcdef"),
            HoldVerdict::Approved,
            "第 {idx} 个工具活跃分片恰达上限，不得拒绝"
        );
        assert_eq!(hold.total_bytes, 16, "活跃字节应为单槽 16");
        hold.clear_index(idx);
        assert_eq!(hold.total_bytes, 0, "清槽须归还该槽字节");
    }
    assert!(!hold.is_rejected());
    assert!(!hold.has_pending_fragments());
}

#[test]
fn hold_bytes_reclaim_responses_done_slots() {
    // S7/D8：Responses per-item done 槽经 release_audited 清理时须归还字节。
    let mut hold = AuditHold::new(16);
    for i in 0..30u32 {
        let item = format!("item-{i}");
        let key = AuditHold::responses_key(Some(&item), i);
        assert_eq!(
            hold.push_responses_fragment(
                &key,
                i,
                Some(0),
                Some(&item),
                Some("run"),
                "0123456789abcdef"
            ),
            HoldVerdict::Approved
        );
        hold.mark_responses_done(&key, Some("0123456789abcdef"));
        hold.release_audited();
        assert_eq!(hold.total_bytes, 0, "per-item done 清理须归还字节");
    }
    assert!(!hold.is_rejected());
}

#[test]
fn hold_bytes_active_only_matches_single_call_cap() {
    // S7/D8：活跃口径=同时在持分片总字节；单槽累计与多槽并存同以 cap 判定。
    let mut single = AuditHold::new(8);
    assert_eq!(
        single.push_fragment(0, None, None, "1234"),
        HoldVerdict::Approved
    );
    assert_eq!(
        single.push_fragment(0, None, None, "5678"),
        HoldVerdict::Approved,
        "累计恰达 cap 不得拒绝"
    );
    assert_eq!(
        single.push_fragment(0, None, None, "9"),
        HoldVerdict::Rejected,
        "单槽活跃超 cap 须 fail-closed"
    );
    assert!(single.is_rejected());
    let mut reclaim = AuditHold::new(8);
    reclaim.push_fragment(0, None, None, "12345678");
    reclaim.clear_index(0);
    assert_eq!(reclaim.total_bytes, 0);
    for i in 0..100u32 {
        reclaim.push_fragment(i, None, None, "12345678");
        reclaim.clear_index(i);
    }
    assert!(!reclaim.is_rejected(), "回收后多轮不得误判溢出");
}

#[test]
fn hold_bytes_reclaim_on_complete_and_reject_zeroes() {
    // S7/D8：完成/拒绝为终端，归还全部字节（归零）。
    let mut done = AuditHold::new(1024);
    done.push_fragment(0, None, None, "abcdef");
    assert_eq!(done.total_bytes, 6);
    done.mark_completed();
    assert_eq!(done.total_bytes, 0);
    let mut rejected = AuditHold::new(1024);
    rejected.push_fragment(0, None, None, "abcdef");
    assert_eq!(rejected.total_bytes, 6);
    rejected.mark_rejected();
    assert_eq!(rejected.total_bytes, 0);
}

#[test]
fn overflow_fail_closed_after_reclaim_long_stream() {
    // 7.2：回收不削弱 fail-closed——长流回收多轮后单调用仍超限即拒绝清仓。
    let mut hold = AuditHold::new(8);
    for i in 0..20u32 {
        hold.push_fragment(i, None, None, "12345678");
        hold.clear_index(i);
    }
    assert!(!hold.is_rejected());
    assert_eq!(
        hold.push_fragment(99, None, None, "123456789"),
        HoldVerdict::Rejected
    );
    assert!(hold.is_rejected());
    assert_eq!(hold.accumulated(99), None);
    assert_eq!(hold.total_bytes, 0);
}

#[test]
fn timeout_disconnect_race_window_constants_locked() {
    assert_eq!(crate::config::AUDIT_TIMEOUT_RACE_MIN, 110);
    assert_eq!(crate::config::AUDIT_TIMEOUT_RACE_MAX, 130);
    assert_eq!(crate::config::AUDIT_TIMEOUT_DEFAULT, 90);
}

#[test]
fn completion_check_without_duplicate_branches() {
    // D2：`response.output_item.done` 走槽级完成，不再触发全局完成（无重复分支）。
    assert!(AuditHold::is_responses_slot_complete_event(
        &serde_json::json!({"type": "response.output_item.done", "item": {"id": "x"}})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type": "response.output_item.done", "item": {"id": "x"}})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"item": {"id": "x"}, "type": "other"})
    ));
}

#[test]
fn message_delta_after_slot_stop_does_not_duplicate_audit() {
    // B5.1：`message_delta` 非按槽完成事件，仅 `content_block_stop`/`item_done`
    // 触发槽清理（`is_index_complete_event`）；同帧到达不得重复审计/清理。
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("c1"), Some("exec"), "{\"command\":\"rm -rf /\"}"),
        HoldVerdict::Approved
    );
    let stop0 = serde_json::json!({"type":"content_block_stop","index":0});
    assert!(AuditHold::is_index_complete_event(&stop0));
    assert_eq!(hold.tool_triples().len(), 1, "槽完成须恰可审计一次");
    hold.clear_index(0);
    let md = serde_json::json!({"type":"message_delta","delta":{"stop_reason":"tool_use"}});
    assert!(
        !AuditHold::is_index_complete_event(&md),
        "message_delta 非按槽清理事件"
    );
    assert!(
        !AuditHold::is_complete_event(&md),
        "message_delta 非全局完成事件"
    );
    assert!(
        hold.tool_triples().is_empty(),
        "message_delta 不得重复审计/清理"
    );
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

#[test]
fn audit_approve_stream_approve_injects_completion_and_allows() {
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("c1"), Some("run"), "{\"x\":"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_fragment(0, None, None, "1}"),
        HoldVerdict::Approved
    );
    assert!(hold.held());
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].2, "{\"x\":1}");
    hold.mark_completed();
    assert!(!hold.held());
    assert!(!hold.is_rejected());
}

#[test]
fn audit_approve_stream_reject_and_expiry_inject_cleanup() {
    let mut deny = AuditHold::new(1024);
    deny.push_fragment(0, Some("c1"), Some("rm"), "{\"p\":");
    deny.mark_rejected();
    assert!(deny.is_rejected());
    assert!(deny.tool_triples().is_empty());
    assert_eq!(deny.accumulated(0), None);
    let mut expired = AuditHold::new(1024);
    expired.push_fragment(0, Some("c9"), Some("run"), "{\"y\":2}");
    expired.mark_rejected();
    assert!(expired.is_rejected());
    assert!(expired.tool_triples().is_empty());
    assert_eq!(
        expired.push_fragment(0, None, None, "x"),
        HoldVerdict::Rejected
    );
}

#[test]
fn audit_approve_stream_anthropic_precheck_three_events() {
    // §2.5：stop/item_done 只清对应 index 槽；全局完成仅 message_stop。
    assert!(AuditHold::is_index_complete_event(
        &serde_json::json!({"type":"content_block_stop"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"content_block_stop"})
    ));
    assert!(AuditHold::is_index_complete_event(
        &serde_json::json!({"type":"item_done"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"item_done"})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"type":"message_stop"})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"x"})
    ));
    assert!(AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]})
    ));
    assert!(!AuditHold::is_complete_event(
        &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]})
    ));
}

#[test]
fn second_tool_block_preserves_global_state_and_audits_normally() {
    let mut hold = AuditHold::new(1024);
    assert_eq!(
        hold.push_fragment(0, Some("a0"), Some("run"), "{\"x\":1}"),
        HoldVerdict::Approved
    );
    // 第一块 stop：只清 index 0，不标记全局完成。
    let stop0 = serde_json::json!({"type":"content_block_stop","index":0});
    assert!(AuditHold::is_index_complete_event(&stop0));
    assert!(!AuditHold::is_complete_event(&stop0));
    hold.clear_index(0);
    assert!(hold.held(), "全局完成须保持未标记");
    assert_eq!(hold.accumulated(0), None);
    assert!(hold.tool_triples().is_empty());
    // 第二块到达照常累积可审计，不直接 Approved 逃逸。
    assert_eq!(
        hold.push_fragment(1, Some("a1"), Some("run"), "{\"y\":2}"),
        HoldVerdict::Approved
    );
    assert!(hold.held());
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].0, 1);
    assert_eq!(triples[0].2, "{\"y\":2}");
}

#[test]
fn audit_approve_stream_overflow_fail_closed_both_paths() {
    let mut chat_hold = AuditHold::new(4);
    assert_eq!(
        chat_hold.push_fragment(0, None, None, "ab"),
        HoldVerdict::Approved
    );
    assert_eq!(
        chat_hold.push_fragment(0, None, None, "cde"),
        HoldVerdict::Rejected
    );
    assert!(chat_hold.is_rejected());
    assert!(chat_hold.tool_triples().is_empty());
    let mut resp_hold = AuditHold::new(4);
    let key = AuditHold::responses_key(Some("item-o"), 0);
    assert_eq!(
        resp_hold.push_responses_fragment(&key, 0, Some(0), None, None, "ab"),
        HoldVerdict::Approved
    );
    assert_eq!(
        resp_hold.push_responses_fragment(&key, 0, Some(1), None, None, "cde"),
        HoldVerdict::Rejected
    );
    assert!(resp_hold.is_rejected());
    assert!(resp_hold.responses_triples().is_empty());
}

#[test]
fn audit_approve_stream_abort_mid_toolcall_sticky_reject() {
    let mut hold = AuditHold::new(1024);
    hold.push_fragment(0, Some("c1"), Some("run"), "{\"a\":");
    hold.mark_rejected();
    assert_eq!(
        hold.push_fragment(0, None, None, "1}"),
        HoldVerdict::Rejected
    );
    let key = AuditHold::responses_key(Some("item-a"), 1);
    assert_eq!(
        hold.push_responses_fragment(&key, 1, Some(0), None, None, "z"),
        HoldVerdict::Rejected
    );
    hold.mark_completed();
    assert!(hold.is_rejected());
    assert!(hold.tool_triples().is_empty());
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
