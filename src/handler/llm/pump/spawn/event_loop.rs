//! ARC-1：流泵主循环与单事件处理（自 `spawn.rs` 拆出，纯搬移行为不变）。

use {
    super::{
        super::{
            decide::{self, ResponsesAction, StickyAction},
            event::{
                advance_responses_seq_cursor,
                extract_responses_seq,
                is_anthropic_opaque_event,
                is_anthropic_thinking_event,
                is_chat_error_terminal,
                is_minor_event,
                is_terminal_event,
                outer_event_index,
                parse_event_data,
                record_emitted_events,
                responses_error_object,
                responses_failed_incomplete,
                responses_synth_conv_id,
                sticky_terminal_event,
                stream_model_of,
            },
            fragments::extract_tool_fragments,
            synth_flush::flush_pre_terminal,
            toolbuf::take_pending_tool_inputs,
        },
        frame_feed::{drain_prefix_hold, feed_output_frame},
        restore_emit::{FrameSink, RestoredFrame, emit_restored_json_frame},
        setup::{PumpEnv, PumpLoopState},
        terminator::TerminalPlan,
    },
    crate::{
        approval::PendingRecord,
        config::AuditMode,
        handler::llm::protocol_header_value,
        service::{
            audit::{self, AuditHold},
            block_inject,
            llm_gateway,
            sse::{SseEvent, SseParser, TruncatedMode, data_frame, is_done_payload, set_truncated},
        },
    },
    serde_json::Value,
};

/// 单事件处理的控制流：`Next` 继续下一事件；`BreakFor` 因下游发送失败中止本块事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EventFlow {
    Next,
    BreakFor,
}

/// TRN-1：SSE 出口信封重建——在既有 `event:` 重放基础上补齐解析侧已保留的
/// `id:`（last-event-id，空值不透出）与合法整数 `retry:`，与 `data:` 同块写。
fn envelope_prefix(ev: &SseEvent) -> String {
    let mut prefix = String::new();
    if let Some(t) = ev.event_type.as_ref() {
        prefix.push_str(&format!("event: {t}\n"));
    }
    if let Some(id) = ev.id.as_deref().filter(|s| !s.is_empty()) {
        prefix.push_str(&format!("id: {id}\n"));
    }
    if let Some(r) = ev.retry {
        prefix.push_str(&format!("retry: {r}\n"));
    }
    prefix
}

/// ARC-1：主循环薄层——读取上游 chunk、喂入解析器并按事件驱动 [`handle_event`]。
/// 返回是否为传输错误（供收尾按断流终端策略处置）。
pub(super) async fn run_pump<F>(
    upstream: &mut reqwest::Response,
    parser: &mut SseParser,
    state: &mut PumpLoopState,
    env: &PumpEnv,
    boundary_spans: &F,
) -> bool
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    let mut received_bytes: usize = 0;
    let mut transport_error = false;
    // D3/ARH-1：下游断开（`handle_event` 发送失败返回 `BreakFor`）须中止上游读取
    // 并回收泵任务——外层循环以 `downstream_abort` 跳出，SHALL NOT 继续 `chunk()`。
    let mut downstream_abort = false;
    loop {
        let bytes = match upstream.chunk().await {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(e) => {
                transport_error = true;
                tracing::warn!(
                    forwarded = state.forwarded,
                    received_bytes,
                    error = %e,
                    "流式上游传输错误（chunk Err），按断流终端策略收尾"
                );
                break;
            }
        };
        received_bytes += bytes.len();
        if bytes.is_empty() {
            continue;
        }
        let events = parser.push_bytes(&bytes);
        let line_dropped = parser.take_truncated_line_dropped_bytes();
        if line_dropped > 0 {
            env.metrics
                .record_truncated_line_dropped_bytes(line_dropped);
        }
        for ev in events {
            if handle_event(state, &ev, env, line_dropped, boundary_spans).await
                == EventFlow::BreakFor
            {
                downstream_abort = true;
                break;
            }
        }
        if downstream_abort || state.terminator.terminated() {
            break;
        }
    }
    if downstream_abort {
        tracing::debug!(
            forwarded = state.forwarded,
            received_bytes,
            "客户端断开：中止上游读取并回收泵任务（不再拉取 chunk）"
        );
    }
    transport_error
}

/// C-3/D1（5.4）：fail-closed 阻断臂（`audit-policy-block` 与缓冲记账超限
/// `audit-hold-overflow` 共用）——置粘滞拒绝态、归还并清空 pending 缓冲（阻断
/// 非截断，不记截断计数）、恰一注入协议阻断帧；返回本帧是否属 tool/完成事件
/// （为真时调用方不再继续透出）。
async fn apply_reject_block(
    state: &mut PumpLoopState,
    env: &PumpEnv,
    v: &Value,
    reason: &str,
    is_tool_or_complete: bool,
) -> bool {
    state.terminator.note_sticky_rejected();
    state.agg.clear();
    state.boundary.clear();
    state.prefix_hold.clear();
    // P0-3.1：阻断丢弃缓冲（阻断非截断，不记截断计数）；记账同步归还。
    let released: usize = state
        .pending_tool_frames
        .iter()
        .map(|(_, p, d)| p.len() + d.len())
        .sum();
    state
        .hold
        .release_pending_frames(state.pending_tool_frames.len(), released);
    state.pending_tool_frames.clear();
    // 2.1 收敛：I-1 无 `add_sse_event`（BLOCKER-1 不得新增）；`plan_block` 的
    // `None` 门等价既有 `if !block_injected` 幂等守卫。
    let blocked_index = outer_event_index(env.protocol, v).unwrap_or(0);
    if let TerminalPlan::Frames { kind, frames, .. } = state.terminator.plan_block(
        env.protocol,
        reason,
        state.conv_id.as_deref(),
        blocked_index,
        state.responses_seq_cursor,
        Some(&env.metrics),
    ) {
        for f in frames {
            let _ = env.pump_tx.send(f).await;
        }
        state.terminator.commit(&mut state.meta, kind, true, true);
    }
    is_tool_or_complete
}

/// ARC-1：单事件处理（原 `spawn_stream_pump` 循环体搬移，分支/顺序/等待点不变）。
pub(super) async fn handle_event<F>(
    state: &mut PumpLoopState,
    ev: &SseEvent,
    env: &PumpEnv,
    line_dropped: u64,
    boundary_spans: &F,
) -> EventFlow
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    if ev.truncated {
        tracing::warn!(
            "SSE 超长行已截断（16KB），头部分发审计，尾部 {line_dropped} 字节已计数丢弃"
        );
    }
    if ev.is_comment_only {
        // E11/D6 空流守门：注释心跳透传但不置位 `any_frame_sent`
        //（非内容帧），纯心跳流仍走真空合成，不断链不悬空。
        let _ = env
            .pump_tx
            .send(format!(":{}\n\n", ev.comments.join("\n:")))
            .await;
        return EventFlow::Next;
    }
    // ARH-2（6.1/7.1）：每帧单次全量 JSON 解析（单点 `event::parse_event_data`），
    // 产物供本函数各判定复用；空帧/`[DONE]`/非法 JSON 为 `None`。
    let parsed: Option<Value> = parse_event_data(&ev.data);
    if let Some(v) = parsed.as_ref() {
        if let Some(id) = llm_gateway::extract_conv_id(v) {
            if state.stream_first_id.is_none() {
                state.stream_first_id = Some(id.clone());
            }
            let _ = env.resp_scope.record_response_id(env.protocol, &id);
            state.conv_id = Some(id);
        }
        if let Some(m) = stream_model_of(v).filter(|m| !m.is_empty()) {
            state.stream_model = Some(m.to_string());
            state.stream_model_from_resp = true;
        } else if !state.stream_model_from_resp && !env.req_model.is_empty() {
            state.stream_model = Some(env.req_model.clone());
        }
        llm_gateway::accumulate_usage(
            &mut state.stream_usage,
            llm_gateway::extract_usage_stream(env.protocol, v),
        );
        if env.protocol.is_chat() && AuditHold::chat_finish_reason_present(v) {
            state.chat_finish_seen = true;
        }
        // A-6/F-08：错误载荷帧即终端（顶层 `error` 且无 `choices`）——观测记
        // `upstream_error`（区别于 `open_ended`）；本帧仍作终端帧透出，其后数据帧
        // 由终端守卫丢弃，流末不再补 `[DONE]`。
        if is_chat_error_terminal(env.protocol, v) && !state.terminator.terminal_sent() {
            let _ = set_truncated(
                &mut state.meta,
                env.protocol,
                TruncatedMode::UpstreamError,
                Some(&env.metrics),
            );
        }
    }
    // A-2/F-02：Responses 序号游标——每帧解析后、任何分流前推进（次要帧/被 hold
    // 缓冲帧/被替换的 error 帧同样参与），取已见上游序号上界；缺序号不推进、
    // 回退忽略。
    if env.protocol.is_responses()
        && let Some(v) = parsed.as_ref()
    {
        advance_responses_seq_cursor(&mut state.responses_seq_cursor, v);
    }
    env.hold_gate.store(
        !matches!(env.audit_mode, AuditMode::Off) && state.hold.has_pending_fragments(),
        std::sync::atomic::Ordering::Relaxed,
    );
    if state.terminator.rejected_sticky() {
        // 纯函数决策；短路求值与 metrics 副作用留调用点：
        // 仅非空非 DONE 才解析/记 terminal_fallback（原语义不变）。
        let data_empty = ev.data.is_empty();
        let is_done = is_done_payload(&ev.data);
        let is_terminal = !data_empty
            && !is_done
            && sticky_terminal_event(env.protocol, parsed.as_ref(), &ev.data, &env.metrics);
        let is_tool_or_complete = parsed.as_ref().is_some_and(|v| {
            !extract_tool_fragments(env.protocol, v).is_empty()
                || AuditHold::is_audit_due_event(env.protocol, v)
        });
        if decide::sticky_suppress_action(
            state.terminator.rejected_sticky(),
            data_empty,
            is_done,
            is_terminal,
            is_tool_or_complete,
        ) == StickyAction::Drop
        {
            return EventFlow::Next;
        }
    }
    if env.protocol.is_responses() && !ev.data.is_empty() {
        // N1 守卫（T1/D1）：决策交纯函数 `responses_control_action`；
        // 已发终端时保持原语义不解析（terminal_fallback 计数不漂移）。
        let (is_failed, is_error) = if state.terminator.terminal_sent() {
            (false, false)
        } else {
            let (f, _, e) = responses_failed_incomplete(parsed.as_ref(), &ev.data, &env.metrics);
            (f, e)
        };
        match decide::responses_control_action(
            state.terminator.terminal_sent(),
            state.terminator.responses_failed_seen(),
            is_error,
            is_failed,
        ) {
            ResponsesAction::Ignore => return EventFlow::Next,
            ResponsesAction::SynthesizeFailed => {
                // P4/D4：`error` 仅合成单帧 `response.failed`
                //（`response.error.message` 携带上游 error 文案），不注入
                // `output_index` 序列；`incomplete` 不在此列——原样透传并作为
                // 唯一终端（保留 `incomplete_details`，由 `is_terminal_event` 置位）。
                state.terminator.note_responses_failed();
                let fid = responses_synth_conv_id(
                    state.stream_first_id.as_deref(),
                    state.conv_id.as_deref(),
                    &env.metrics,
                );
                let err_obj = responses_error_object(parsed.as_ref());
                // D3/S3：合成终端前先 flush 边界滞留帧，保证末段增量先下行。
                drain_prefix_hold(
                    &mut state.prefix_hold,
                    &mut state.boundary,
                    &boundary_spans,
                    &mut state.agg,
                );
                if flush_pre_terminal(
                    &mut state.boundary,
                    &mut state.agg,
                    &env.pump_tx,
                    &env.metrics,
                )
                .await
                {
                    state.forwarded += 1;
                    state.terminator.note_frame_sent();
                }
                // 3.2 收敛：`responses_failed_frame` 构造迁入 `plan_responses_error`；
                // I-5 逐帧成功下行记 `add_sse_event`（BLOCKER-1，不得增删）。
                // D9/S9：合成 failed 帧 send 成功才置位终端，下游早断不撒谎。
                let mut terminal_ok = false;
                if let TerminalPlan::Frames { kind, frames, .. } =
                    state.terminator.plan_responses_error(
                        &fid,
                        err_obj.as_ref().map(|(v, _)| v),
                        err_obj.as_ref().and_then(|(_, s)| *s),
                    )
                {
                    for f in frames {
                        if env.pump_tx.send(f).await.is_err() {
                            break;
                        }
                        env.metrics.add_sse_event();
                        state.forwarded += 1;
                        state.terminator.note_frame_sent();
                        terminal_ok = true;
                    }
                    // BLOCKER-3：传实际 `terminal_ok`，不得硬编码 `true`
                    //（`send` 失败即不置终端帧位、不落 `terminal_injected`）。
                    state
                        .terminator
                        .commit(&mut state.meta, kind, terminal_ok, terminal_ok);
                }
                // BLOCKER-3：无帧也可终止循环（对齐旧 `event_loop.rs:341` 无条件置
                // `terminated`）；`ResponsesAction::DuplicateFailed` 仅调本方法。
                state.terminator.mark_loop_terminated();
                return EventFlow::Next;
            }
            ResponsesAction::DuplicateFailed => {
                state.terminator.mark_loop_terminated();
                return EventFlow::Next;
            }
            ResponsesAction::Passthrough => {
                if is_failed {
                    state.terminator.note_responses_failed();
                }
            }
        }
    }
    if !ev.data.is_empty() && !is_done_payload(&ev.data) {
        if let Some(v) = parsed.as_ref() {
            // 终端后不再透出任何数据帧：恰一终止帧且其后无内容。
            if state.terminator.terminal_sent() {
                return EventFlow::Next;
            }
            let event_terminal =
                is_terminal_event(env.protocol, v) || is_chat_error_terminal(env.protocol, v);
            let frags = extract_tool_fragments(env.protocol, v);
            let is_tool_event = !frags.is_empty();
            let minor = !is_tool_event && is_minor_event(env.protocol, v);
            if state.terminator.rejected_sticky() && is_tool_event {
                return EventFlow::Next;
            }
            // F3/D3：Responses 槽完成（`response.output_item.done`/
            // `response.function_call_arguments.done`）视同按槽完成——既触发
            // 该槽缓冲分片重放，又使本帧不被缓冲（其审计/释放由
            // `responses_slot_complete` 承载）。
            let responses_slot_complete = AuditHold::is_responses_slot_complete_event(v);
            let is_index_complete =
                AuditHold::is_index_complete_event(v) || responses_slot_complete;
            // P0-3.1：完成事件先放行此前缓冲的残缺分片（到达序重放进
            // 边界 hold，保证缝合时序），再处理本帧；全局完成全放行，
            // 按槽完成只放行对应槽（他槽残缺继续缓冲）。F3/D3：Responses
            // 工具分片纳入 hold（先审后放），未完成分片缓冲至槽 `.done`。
            let audit_hold_on =
                !matches!(env.audit_mode, AuditMode::Off) && env.protocol.is_dialog();
            let mut reject_reason: Option<String> = None;
            let mut approve_held = false;
            if audit_hold_on {
                let slot = decide::tool_replay_slot(
                    env.protocol,
                    v,
                    AuditHold::is_audit_due_event(env.protocol, v),
                    is_index_complete,
                );
                if let Some(slot) = slot {
                    // D5/STP-1/RSP-2：全局完成（`slot == None`）时对仍缺 per-item
                    // `.done` 的 Responses 槽「先审后放」——按已累积参数执行与逐-item
                    // done 相同判定，Block 则整槽筛除不重放；SHALL NOT 因缺 `.done`
                    // 绕过审计直接重放（与 `terminal.rs` 终审同 verdict）。
                    if env.protocol.is_responses()
                        && slot.is_none()
                        && !matches!(env.audit_mode, AuditMode::Off)
                        && !state.hold.is_rejected()
                    {
                        for (idx, name, args) in state.hold.responses_pending_triples() {
                            match env
                                .audit_sink
                                .evaluate_and_record(
                                    env.audit_mode,
                                    &name,
                                    &args,
                                    &env.audit_policy,
                                    &env.approval_whitelist,
                                    Some(protocol_header_value(env.protocol)),
                                )
                                .await
                            {
                                audit::AuditVerdict::Block { .. } => {
                                    state.hold.mark_rejected();
                                    reject_reason = Some("audit-policy-block".to_string());
                                    break;
                                }
                                audit::AuditVerdict::NeedApproval { reason, summary } => {
                                    env.audit_pending.insert(PendingRecord::new(
                                        &format!("audit-hold-{idx}-{name}"),
                                        &format!("{reason}: {summary}"),
                                    ));
                                    approve_held = true;
                                }
                                audit::AuditVerdict::Allow => {}
                            }
                        }
                    }
                    if reject_reason.is_none() {
                        let taken = take_pending_tool_inputs(&mut state.pending_tool_frames, slot);
                        // C-3/D1（5.4）：缓冲帧按槽取出即归还记账，长流多轮 drain 不误判溢出。
                        let released_bytes: usize =
                            taken.iter().map(|(p, d)| p.len() + d.len()).sum();
                        state
                            .hold
                            .release_pending_frames(taken.len(), released_bytes);
                        for (b_prefix, b_data) in taken {
                            feed_output_frame(
                                &mut state.prefix_hold,
                                &mut state.boundary,
                                &env.resp_detector,
                                &env.resp_vault,
                                &boundary_spans,
                                &mut state.agg,
                                (b_prefix, b_data),
                            )
                            .await;
                        }
                    }
                }
            }
            // P0-3.1：未完成 tool 分片缓冲不转发（hold-until-complete）；
            // 本帧槽号组取自各分片桶号（到达序 flush 时保序）。
            let buffer_tool_frame = decide::should_buffer_tool_frame(
                audit_hold_on,
                is_tool_event,
                AuditHold::is_audit_due_event(env.protocol, v),
                is_index_complete,
            );
            let tool_buckets: Vec<u32> = frags.iter().map(|f| f.0).collect();
            if minor {
                // 次要事件透传且审计声明放行：不进 hold、不审计。
            } else if env.protocol.is_responses() {
                let slot_complete = AuditHold::is_responses_slot_complete_event(v);
                for frag in &frags {
                    let key = AuditHold::responses_key(frag.1.as_deref(), frag.0);
                    if slot_complete {
                        // RED-6：`.done` 完整参数经 `mark_responses_done`
                        // 记账（去重），不以分片重复计入 `total_bytes`；
                        // 空分片仅登记名/id。
                        let _ = state.hold.push_responses_fragment(
                            &key,
                            frag.0,
                            None,
                            frag.1.as_deref(),
                            frag.2.as_deref(),
                            "",
                        );
                        state.hold.mark_responses_done(&key, Some(&frag.3));
                        if state.hold.is_rejected() {
                            reject_reason = Some("audit-hold-overflow".to_string());
                            break;
                        }
                        continue;
                    }
                    let seq = extract_responses_seq(v);
                    let verdict = state.hold.push_responses_fragment(
                        &key,
                        frag.0,
                        seq,
                        frag.1.as_deref(),
                        frag.2.as_deref(),
                        &frag.3,
                    );
                    if verdict == crate::service::audit::HoldVerdict::Rejected {
                        reject_reason = Some("audit-hold-overflow".to_string());
                        break;
                    }
                }
            } else {
                for frag in &frags {
                    if state.hold.push_fragment(
                        frag.0,
                        frag.1.as_deref(),
                        frag.2.as_deref(),
                        &frag.3,
                    ) == crate::service::audit::HoldVerdict::Rejected
                    {
                        reject_reason = Some("audit-hold-overflow".to_string());
                        break;
                    }
                }
            }
            // D2：Responses per-item `.done` 走槽级审计，与全局完成解耦。
            if reject_reason.is_none()
                && !state.hold.is_rejected()
                && (AuditHold::is_audit_due_event(env.protocol, v) || responses_slot_complete)
                && !matches!(env.audit_mode, AuditMode::Off)
            {
                for (idx, name, args) in state.hold.tool_triples() {
                    match env
                        .audit_sink
                        .evaluate_and_record(
                            env.audit_mode,
                            &name,
                            &args,
                            &env.audit_policy,
                            &env.approval_whitelist,
                            Some(protocol_header_value(env.protocol)),
                        )
                        .await
                    {
                        audit::AuditVerdict::Block { .. } => {
                            state.hold.mark_rejected();
                            reject_reason = Some("audit-policy-block".to_string());
                            break;
                        }
                        audit::AuditVerdict::NeedApproval { reason, summary } => {
                            env.audit_pending.insert(PendingRecord::new(
                                &format!("audit-hold-{idx}-{name}"),
                                &format!("{reason}: {summary}"),
                            ));
                            approve_held = true;
                        }
                        audit::AuditVerdict::Allow => {}
                    }
                }
            }
            // §2.5 前置：stop/item_done 只审计并清理对应 index 的槽
            //（外层序号），不得标记全局完成，后续块照常审计；
            // 命中阻断落 reject_reason，走下方统一阻断臂注入。
            if reject_reason.is_none()
                && !state.hold.is_rejected()
                && !matches!(env.audit_mode, AuditMode::Off)
                && AuditHold::is_index_complete_event(v)
                && let Some(idx) = outer_event_index(env.protocol, v)
            {
                for (_, name, args) in state
                    .hold
                    .tool_triples()
                    .into_iter()
                    .filter(|(i, ..)| *i == idx)
                {
                    match env
                        .audit_sink
                        .evaluate_and_record(
                            env.audit_mode,
                            &name,
                            &args,
                            &env.audit_policy,
                            &env.approval_whitelist,
                            Some(protocol_header_value(env.protocol)),
                        )
                        .await
                    {
                        audit::AuditVerdict::Block { .. } => {
                            state.hold.mark_rejected();
                            reject_reason = Some("audit-policy-block".to_string());
                            break;
                        }
                        audit::AuditVerdict::NeedApproval { reason, summary } => {
                            env.audit_pending.insert(PendingRecord::new(
                                &format!("audit-hold-{idx}-{name}"),
                                &format!("{reason}: {summary}"),
                            ));
                        }
                        audit::AuditVerdict::Allow => {}
                    }
                }
                state.hold.clear_index(idx);
            }
            // D1：完成事件审计（Allow/NeedApproval 均算已判定）后释放
            // 作用域出抑制集，后续帧据此恢复逐帧增量；拒绝态已清理。
            if reject_reason.is_none()
                && !state.hold.is_rejected()
                && (AuditHold::is_audit_due_event(env.protocol, v) || responses_slot_complete)
            {
                state.hold.release_audited();
            }
            if let Some(reason) = &reject_reason {
                if apply_reject_block(
                    state,
                    env,
                    v,
                    reason,
                    is_tool_event
                        || AuditHold::is_audit_due_event(env.protocol, v)
                        || AuditHold::is_index_complete_event(v),
                )
                .await
                {
                    return EventFlow::Next;
                }
            } else if AuditHold::is_complete_event(v) && !approve_held {
                state.hold.mark_completed();
            }
            // D/Q5/B-2：正常帧两臂（opaque 与常规）与残余帧共用
            // `emit_restored_json_frame`——先守卫（失败回退占位符帧），再按
            // 是否缓冲决定立即喂出或暂存守卫产物。
            let prefix = envelope_prefix(ev);
            if event_terminal {
                state.terminator.mark_upstream_terminal();
            }
            let (restored_data, emitted) = if env.protocol.is_anthropic()
                && is_anthropic_opaque_event(v)
                && !is_anthropic_thinking_event(v)
            {
                // M3/D6：opaque（signature/redacted/thinking+signature）帧跳过
                // 响应侧新 PII 扫描与 `json_aware_line` 重序列化，仅做字节级还原
                //（JSON 转义变体保证不破帧）；审计 hold/次要判定维持现状。
                let (restored, _spans) = env
                    .resp_scope
                    .restore_response_with_spans_json(&env.resp_vault, &ev.data);
                emit_restored_json_frame(
                    &mut FrameSink {
                        prefix_hold: &mut state.prefix_hold,
                        boundary: &mut state.boundary,
                        detector: &env.resp_detector,
                        vault: &env.resp_vault,
                        boundary_spans,
                        agg: &mut state.agg,
                    },
                    RestoredFrame {
                        prefix: &prefix,
                        restored,
                        placeholder: &ev.data,
                        placeholder_parsed: parsed.as_ref(),
                        json_aware: false,
                        feed: !buffer_tool_frame,
                    },
                    &env.metrics,
                )
                .await
            } else {
                // MSP-4/2.28：thinking 明文 opaque 增量与其他文本同路——接入
                // `TokenCarry` 做跨帧缝合，不绕过携带。
                let cleaned = state.carry.prepare(&ev.data);
                let (restored, spans) = env
                    .resp_scope
                    .restore_response_with_spans_json(&env.resp_vault, &cleaned);
                let scanned = env
                    .resp_scope
                    .redact_response_new_pii_with_skip(
                        &env.resp_vault,
                        &env.resp_detector,
                        &restored,
                        &spans,
                    )
                    .await;
                let parsed_opt = (cleaned == ev.data).then_some(parsed.as_ref()).flatten();
                emit_restored_json_frame(
                    &mut FrameSink {
                        prefix_hold: &mut state.prefix_hold,
                        boundary: &mut state.boundary,
                        detector: &env.resp_detector,
                        vault: &env.resp_vault,
                        boundary_spans,
                        agg: &mut state.agg,
                    },
                    RestoredFrame {
                        prefix: &prefix,
                        restored: scanned,
                        placeholder: &cleaned,
                        placeholder_parsed: parsed_opt,
                        json_aware: true,
                        feed: !buffer_tool_frame,
                    },
                    &env.metrics,
                )
                .await
            };
            // P0-3.1：未完成 tool 分片不进边界 hold、不进 `agg`
            // （hold-until-complete），直接缓冲还原后输入；完成帧走
            // 正常透传（此前缓冲已在本帧前重放进边界 hold）。
            if buffer_tool_frame {
                // C-3/D1（5.4）：入缓冲前先记账——同一 index 零字节分片不增聚合
                // 条目/字节（聚合维度看不见该洪泛），独立计数器超限即 fail-closed
                // 走阻断臂（不静默丢弃，被清参数已由 hold 内终审评估）。
                let pending_bytes = prefix.len() + restored_data.len();
                if state.hold.account_pending_frame(pending_bytes)
                    == crate::service::audit::HoldVerdict::Rejected
                {
                    let _ = apply_reject_block(state, env, v, "audit-hold-overflow", true).await;
                    return EventFlow::Next;
                }
                state
                    .pending_tool_frames
                    .push((tool_buckets, prefix, restored_data));
                return EventFlow::Next;
            }
            if decide::should_suppress_held_output(
                audit_hold_on,
                state.hold.has_pending_fragments(),
                emitted,
                minor,
            ) {
                return EventFlow::Next;
            }
        } else {
            // 非 JSON 文本同样走 span 跳过还原，终端后不再透出。
            if state.terminator.terminal_sent() {
                return EventFlow::Next;
            }
            let (restored, spans) = env
                .resp_scope
                .restore_response_with_spans(&env.resp_vault, &ev.data);
            let scanned = env
                .resp_scope
                .redact_response_new_pii_with_skip(
                    &env.resp_vault,
                    &env.resp_detector,
                    &restored,
                    &spans,
                )
                .await;
            let prefix = envelope_prefix(ev);
            feed_output_frame(
                &mut state.prefix_hold,
                &mut state.boundary,
                &env.resp_detector,
                &env.resp_vault,
                &boundary_spans,
                &mut state.agg,
                (prefix, scanned),
            )
            .await;
        }
    } else if ev.data.is_empty() {
        // L17：空 `data:` 心跳帧丢弃不透传（不计数、不参与终端判定；
        // 真空流保持 open-ended，见 C8）。
        return EventFlow::Next;
    } else {
        // `[DONE]`（含 BOM 前缀）：恰一终止帧，多余去重。
        // 滞留帧先于终止帧放行（保序：滞留内容属于终止前的数据）。
        if state.terminator.terminal_sent() {
            return EventFlow::Next;
        }
        state.terminator.mark_upstream_terminal();
        drain_prefix_hold(
            &mut state.prefix_hold,
            &mut state.boundary,
            &boundary_spans,
            &mut state.agg,
        );
        if let Some((fp, fd)) = state.boundary.flush() {
            state.agg.push_str(&data_frame(&fp, &fd));
        }
        let prefix = envelope_prefix(ev);
        state.agg.push_str(&prefix);
        state.agg.push_str(&block_inject::chat_done_frame());
    }
    if let Some(out) = crate::service::sse::select_emit(&mut state.agg, env.speed) {
        record_emitted_events(&env.metrics, &out);
        state.forwarded += 1;
        state.terminator.note_frame_sent();
        if env.pump_tx.send(out).await.is_err() {
            return EventFlow::BreakFor;
        }
    }
    EventFlow::Next
}
