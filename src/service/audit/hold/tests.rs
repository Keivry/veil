use super::*;

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("hold.rs", include_str!("../hold.rs"));
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
fn hold_preserves_sequence_order() {
    // RSP-5/2.29：并行 item 交错导致分片乱序到达时，同槽按 `sequence_number`
    // 升序缝合，放行结果不放乱相对次序。
    let mut hold = AuditHold::new(4096);
    let key = AuditHold::responses_key(Some("item-x"), 0);
    for (seq, frag) in [(2u64, "c"), (0u64, "a"), (1u64, "b")] {
        assert_eq!(
            hold.push_responses_fragment(&key, 0, Some(seq), Some("item-x"), Some("run"), frag),
            HoldVerdict::Approved
        );
    }
    hold.mark_responses_done(&key, None);
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].2, "abc", "须按 sequence_number 升序缝合");
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
    // RED-5：Chat `tool_calls` 为审计到期但非全局完成。
    assert!(AuditHold::is_audit_due_event(
        crate::service::llm_gateway::Protocol::Chat,
        &serde_json::json!({"finish_reason":"tool_calls"})
    ));
    assert!(!AuditHold::is_complete_event(
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
    for tc in [
        serde_json::json!({"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]}),
        serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]}),
        serde_json::json!({"choices":[{"message":{"finish_reason":"tool_calls"}}]}),
    ] {
        assert!(
            AuditHold::is_audit_due_event(crate::service::llm_gateway::Protocol::Chat, &tc),
            "Chat tool_calls 须审计到期"
        );
        assert!(
            !AuditHold::is_complete_event(&tc),
            "Chat tool_calls 不得置全局完成"
        );
    }
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
    // RED-5：Chat `tool_calls` 审计到期、非全局完成。
    let tc = serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]});
    assert!(AuditHold::is_audit_due_event(
        crate::service::llm_gateway::Protocol::Chat,
        &tc
    ));
    assert!(!AuditHold::is_complete_event(&tc));
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

#[test]
fn chat_tool_calls_still_audit_due() {
    // RED-5：Chat 任意非空 finish_reason（含 tool_calls）触发审计到期；
    // 空 finish_reason / 缺失 choices 不到期。
    use crate::service::llm_gateway::Protocol::Chat;
    for fr in ["tool_calls", "stop", "length", "content_filter"] {
        let v = serde_json::json!({"choices":[{"index":0,"finish_reason":fr}]});
        assert!(AuditHold::is_audit_due_event(Chat, &v), "{fr} 须审计到期");
        assert!(!AuditHold::is_complete_event(&v), "{fr} 不得置全局完成");
    }
    for v in [
        serde_json::json!({"finish_reason":"tool_calls"}),
        serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]}),
        serde_json::json!({"choices":[{"message":{"finish_reason":"tool_calls"}}]}),
    ] {
        assert!(AuditHold::is_audit_due_event(Chat, &v));
    }
    assert!(!AuditHold::is_audit_due_event(
        Chat,
        &serde_json::json!({"choices":[{"finish_reason":""}]})
    ));
    assert!(!AuditHold::is_audit_due_event(
        Chat,
        &serde_json::json!({"choices":[]})
    ));
}

#[test]
fn chat_tool_calls_not_global_complete() {
    // RED-5：仅 tool_calls 时全局完成未置位，后续分片照常累积入槽。
    let mut hold = AuditHold::new(1024);
    hold.push_fragment(0, Some("c0"), Some("run"), "{\"cmd\":\"echo ");
    let tc = serde_json::json!({"choices":[{"index":0,"finish_reason":"tool_calls"}]});
    if AuditHold::is_complete_event(&tc) {
        hold.mark_completed();
    }
    assert!(hold.held(), "tool_calls 不得置全局完成");
    assert_eq!(
        hold.push_fragment(0, None, None, "rm -rf /\"}"),
        HoldVerdict::Approved,
        "晚到分片须照常累积"
    );
    assert_eq!(hold.accumulated(0), Some("{\"cmd\":\"echo rm -rf /\"}"));
}

#[test]
fn responses_done_bytes_dedup() {
    // RED-6：`.done` 完整参数不得与已累积分片双计 `total_bytes`。
    let mut hold = AuditHold::new(16);
    let key = AuditHold::responses_key(Some("item-d"), 0);
    assert_eq!(
        hold.push_responses_fragment(&key, 0, None, Some("item-d"), Some("run"), "01234568"),
        HoldVerdict::Approved
    );
    assert_eq!(
        hold.push_responses_fragment(&key, 0, None, None, None, "9abcdef"),
        HoldVerdict::Approved
    );
    assert_eq!(hold.total_bytes, 15, "分片累计 15 字节");
    hold.mark_responses_done(&key, Some("012345689abcdef"));
    assert_eq!(hold.total_bytes, 15, "done 去重后仍只计一次");
    assert!(!hold.is_rejected(), "去重不得误判溢出");
}

#[test]
fn responses_dedup_keeps_audit_verdict() {
    // RED-6：去重不改变 `tool_triples` 参数文本与审计结论。
    let mut hold = AuditHold::new(1024);
    let key = AuditHold::responses_key(Some("i"), 0);
    hold.push_responses_fragment(&key, 0, None, Some("i"), Some("exec"), "{\"command\":\"rm ");
    hold.push_responses_fragment(&key, 0, None, None, None, "-rf /\"}");
    hold.mark_responses_done(&key, Some("{\"command\":\"rm -rf /\"}"));
    let triples = hold.tool_triples();
    assert_eq!(triples.len(), 1);
    assert_eq!(triples[0].1, "exec");
    assert_eq!(triples[0].2, "{\"command\":\"rm -rf /\"}");
}

#[test]
fn hold_zero_byte_flood_bounded() {
    // STP-5/D6：零字节分片洪泛（不同 index）不增 `total_bytes`，
    // 条目数维度须独立 fail-closed 清仓，使内存有界。
    let mut hold = AuditHold::new(1024);
    for idx in 0..AUDIT_HOLD_MAX_ENTRIES as u32 {
        assert_eq!(
            hold.push_fragment(idx, None, None, ""),
            HoldVerdict::Approved,
            "未达条目上限不得拒绝"
        );
    }
    assert!(!hold.is_rejected());
    assert_eq!(hold.total_bytes, 0, "零字节分片不增总字节");
    assert_eq!(
        hold.push_fragment(AUDIT_HOLD_MAX_ENTRIES as u32, None, None, ""),
        HoldVerdict::Rejected,
        "超条目上限须 fail-closed"
    );
    assert!(hold.is_rejected());
    assert!(hold.tool_triples().is_empty(), "清仓后无残留条目");
}

#[test]
fn hold_entry_cap_and_byte_cap() {
    // STP-5/D6：字节与条目两维度均触发有界策略（同 Rejected 语义、非 panic）。
    let mut bytes = AuditHold::new(4);
    assert_eq!(
        bytes.push_fragment(0, None, None, "ab"),
        HoldVerdict::Approved
    );
    assert_eq!(
        bytes.push_fragment(0, None, None, "cde"),
        HoldVerdict::Rejected
    );
    assert!(bytes.is_rejected());
    let mut entries = AuditHold::new(1024);
    let key = |i: u32| AuditHold::responses_key(Some(&format!("item-{i}")), i);
    for i in 0..AUDIT_HOLD_MAX_ENTRIES as u32 {
        assert_eq!(
            entries.push_responses_fragment(&key(i), i, Some(0), None, None, ""),
            HoldVerdict::Approved
        );
    }
    assert_eq!(
        entries.push_responses_fragment(
            &key(AUDIT_HOLD_MAX_ENTRIES as u32),
            AUDIT_HOLD_MAX_ENTRIES as u32,
            Some(0),
            None,
            None,
            ""
        ),
        HoldVerdict::Rejected,
        "Responses 零字节槽洪泛须受条目上限约束"
    );
    assert!(entries.is_rejected());
    assert!(entries.responses_triples().is_empty());
}
