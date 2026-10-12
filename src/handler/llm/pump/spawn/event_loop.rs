//! 流泵主循环与单事件处理（自 `spawn.rs` 拆出，纯搬移行为不变）。

use {
    super::{
        super::{
            decide,
            event::{
                advance_responses_seq_cursor,
                extract_responses_seq,
                is_anthropic_message_start,
                is_anthropic_opaque_event,
                is_anthropic_thinking_event,
                is_chat_error_terminal,
                is_minor_event,
                is_normal_end_event,
                is_terminal_event,
                is_upstream_error_terminal,
                outer_event_index,
                parse_event_data,
                record_emitted_events,
                stream_model_of,
            },
            toolbuf::take_pending_tool_inputs,
        },
        frames,
        release::{self, ReleaseCtx},
        setup::{PumpEnv, PumpLoopState},
    },
    crate::{
        approval::PendingRecord,
        config::AuditMode,
        handler::llm::protocol_header_value,
        service::{
            audit::{self, AuditHold},
            block_inject,
            llm_gateway::{self, tool::extract_tool_calls_with},
            sse::{SseEvent, SseParser, TruncatedMode, is_done_payload, set_truncated},
        },
    },
    serde_json::Value,
};

mod guards;
mod reject;

use {guards::apply_pre_emit_guards, reject::apply_reject_block};

#[cfg(test)]
mod tests;

/// 单事件处理的控制流：`Next` 继续下一事件；`BreakFor` 因下游发送失败中止本块事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EventFlow {
    Next,
    BreakFor,
}

/// SSE 出口信封重建——在既有 `event:` 重放基础上补齐解析侧已保留的
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

/// 正常结束前 fail-open 回吐 carry 残段：合成协议最小增量帧并入 `agg` 保序放行。
/// 无 pending 或协议无法合成时零动作。
async fn release_carry_residual(state: &mut PumpLoopState, env: &PumpEnv) {
    let residuals = state.carry.drain();
    if residuals.is_empty() {
        return;
    }
    let ctx = ReleaseCtx {
        protocol: env.protocol,
        id: state.conv_id.as_deref(),
        model: state.stream_model.as_deref(),
    };
    for residual in &residuals {
        if let Some((prefix, data)) =
            release::release_frame(&ctx, &residual.path, &residual.literal)
        {
            // fix 3：残段为部分前缀（carry 单测锁定），无完整 token 形态时逐字节
            // 回吐（fail-open 零字符丢失，与既有实现一致）；仅当载荷含完整 token
            // 形态时经响应还原管线（本次铸造凭据/PII → 明文）。
            let restored = if crate::service::redaction::leaf::scan_token_forms(&data).is_empty() {
                data.clone()
            } else {
                env.resp_scope
                    .restore_response_with_spans_json(&env.resp_vault, &data)
                    .0
            };
            let _ = frames::emit_restored_json_frame(
                &mut frames::FrameSink {
                    agg: &mut state.agg,
                },
                frames::RestoredFrame {
                    prefix: &prefix,
                    restored,
                    placeholder: &data,
                    placeholder_parsed: None,
                    json_aware: true,
                    feed: true,
                },
                &env.metrics,
            )
            .await;
        }
    }
}

/// 主循环薄层——读取上游 chunk、喂入解析器并按事件驱动 [`handle_event`]。
/// 返回是否为传输错误（供收尾按断流终端策略处置）。
pub(super) async fn run_pump(
    upstream: &mut reqwest::Response,
    parser: &mut SseParser,
    state: &mut PumpLoopState,
    env: &PumpEnv,
) -> bool {
    let mut received_bytes: usize = 0;
    let mut transport_error = false;
    // 下游断开（`handle_event` 发送失败返回 `BreakFor`）须中止上游读取
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
        let oversize_bytes = parser.take_oversize_bytes();
        let oversize_frames = parser.take_oversize_frames();
        if oversize_frames > 0 || oversize_bytes > 0 {
            env.metrics
                .record_oversize_frames(oversize_frames, oversize_bytes);
        }
        for ev in events {
            if handle_event(state, &ev, env).await == EventFlow::BreakFor {
                downstream_abort = true;
                break;
            }
        }
        let carry_overflow = state.carry.take_over_limit_dropped();
        if carry_overflow > 0 {
            env.metrics.record_carry_over_limit_dropped(carry_overflow);
        }
        if downstream_abort || state.terminator.terminated() {
            break;
        }
        // 超硬限 fail-closed：停止解析，交既有收尾路径按协议合成正确终止帧
        //（复用 `OpenEnded`/`SynthesizedFailed` 观测），不交付半帧、不无界累积。
        if parser.carry_fatal() {
            transport_error = true;
            tracing::warn!(
                forwarded = state.forwarded,
                received_bytes,
                "SSE 单行/未终结行尾超硬上限（SSE_FRAME_HARD_BYTES），fail-closed 收尾（不交付半帧）"
            );
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

/// 单事件处理（原 `spawn_stream_pump` 循环体搬移，分支/顺序/等待点不变）。
pub(super) async fn handle_event(
    state: &mut PumpLoopState,
    ev: &SseEvent,
    env: &PumpEnv,
) -> EventFlow {
    if ev.oversize {
        tracing::warn!("SSE 事件超软限（1MiB），已完整交付并由 oversize 计数观测（未截断）");
    }
    if ev.is_comment_only {
        // 空流守门：注释心跳透传但不置位 `any_frame_sent`
        //（非内容帧），纯心跳流仍走真空合成，不断链不悬空。
        let _ = env
            .pump_tx
            .send(format!(":{}\n\n", ev.comments.join("\n:")))
            .await;
        return EventFlow::Next;
    }
    // 每帧单次全量 JSON 解析（单点 `event::parse_event_data`），
    // 产物供本函数各判定复用；空帧/`[DONE]`/非法 JSON 为 `None`。
    let parsed: Option<Value> = parse_event_data(&ev.data);
    if let Some(v) = parsed.as_ref() {
        let response_id = llm_gateway::extract_conv_id(v);
        let wrote = response_id
            .as_deref()
            .is_some_and(|id| env.resp_scope.record_response_id(env.protocol, id));
        // 写回失败仅「响应 id 缺失/为空」计一次；无写回上下文（`request`
        // 模式/键未推导）与非 Responses 协议门控 MUST NOT 计入。计数点取 Responses
        // 官方终端帧且本流从未见过 id，保证一次响应恰一次（不回退为逐帧误计）。
        if !wrote
            && env.protocol.is_responses()
            && response_id.is_none()
            && env.resp_scope.has_conversation()
            && state.conv_id.is_none()
            && is_terminal_event(env.protocol, v)
        {
            env.metrics.record_conversation_writeback_miss();
        }
        if let Some(id) = response_id {
            if state.stream_first_id.is_none() {
                state.stream_first_id = Some(id.clone());
            }
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
        // 上游错误即终端（Chat 顶层 `error` 无 `choices`；Anthropic
        // `type:"error"`）——观测记 `upstream_error`（区别于 `open_ended`）；本帧仍作
        // 终端帧透出，其后数据帧由终端守卫丢弃，流末不再补合成终端。
        if is_upstream_error_terminal(env.protocol, v) && !state.terminator.terminal_sent() {
            let _ = set_truncated(
                &mut state.meta,
                env.protocol,
                TruncatedMode::UpstreamError,
                Some(&env.metrics),
            );
        }
    }
    // Responses 序号游标——每帧解析后、任何分流前推进（次要帧/被 hold
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
    if apply_pre_emit_guards(state, env, ev, parsed.as_ref()).await {
        return EventFlow::Next;
    }
    if !ev.data.is_empty() && !is_done_payload(&ev.data) {
        if let Some(v) = parsed.as_ref() {
            // 终端后不再透出任何数据帧：恰一终止帧且其后无内容。
            if state.terminator.terminal_sent() {
                return EventFlow::Next;
            }
            let event_terminal =
                is_terminal_event(env.protocol, v) || is_chat_error_terminal(env.protocol, v);
            let frags = extract_tool_calls_with(false, env.protocol, v);
            let is_tool_event = !frags.is_empty();
            let minor = !is_tool_event && is_minor_event(env.protocol, v);
            if state.terminator.rejected_sticky() && is_tool_event {
                return EventFlow::Next;
            }
            // Responses 槽完成（`response.output_item.done`/
            // `response.function_call_arguments.done`）视同按槽完成——既触发
            // 该槽缓冲分片重放，又使本帧不被缓冲（其审计/释放由
            // `responses_slot_complete` 承载）。
            let responses_slot_complete = AuditHold::is_responses_slot_complete_event(v);
            let is_index_complete =
                AuditHold::is_index_complete_event(v) || responses_slot_complete;
            // 完成事件先放行此前缓冲的残缺分片（按到达序重放进
            // `agg`，保证时序），再处理本帧；全局完成全放行，
            // 按槽完成只放行对应槽（他槽残缺继续缓冲）。Responses
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
                    // 全局完成（`slot == None`）时对仍缺 per-item
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
                        // pending 槽经完整 verdict 通道评估后释放（Allow 与
                        // NeedApproval 均算已判定），使终端 pending 循环自然 no-op、
                        // 同一槽 SHALL NOT 被二次审计；Block 早退已由 `mark_rejected()`
                        // 清仓，无需释放。
                        if reject_reason.is_none() {
                            state.hold.release_pending_audited();
                        }
                    }
                    if reject_reason.is_none() {
                        let taken = take_pending_tool_inputs(&mut state.pending_tool_frames, slot);
                        // 缓冲帧按槽取出即归还记账，长流多轮 drain 不误判溢出。
                        let released_bytes: usize =
                            taken.iter().map(|(p, d)| p.len() + d.len()).sum();
                        state
                            .hold
                            .release_pending_frames(taken.len(), released_bytes);
                        for (b_prefix, b_data) in taken {
                            frames::feed_output_frame(&mut state.agg, &b_prefix, &b_data);
                        }
                    }
                }
            }
            // 未完成 tool 分片缓冲不转发（hold-until-complete）；
            // 本帧槽号组取自各分片桶号（到达序 flush 时保序）。
            let buffer_tool_frame = decide::should_buffer_tool_frame(
                audit_hold_on,
                is_tool_event,
                AuditHold::is_audit_due_event(env.protocol, v),
                is_index_complete,
            );
            let tool_buckets: Vec<u32> = frags.iter().map(|c| c.index).collect();
            if minor {
                // 次要事件透传且审计声明放行：不进 hold、不审计。
            } else if env.protocol.is_responses() {
                let slot_complete = AuditHold::is_responses_slot_complete_event(v);
                for frag in &frags {
                    let key = AuditHold::responses_key(Some(frag.id.as_str()), frag.index);
                    if slot_complete {
                        // `.done` 完整参数经 `mark_responses_done`
                        // 记账（去重），不以分片重复计入 `total_bytes`；
                        // 空分片仅登记名/id。
                        let _ = state.hold.push_responses_fragment(
                            &key,
                            frag.index,
                            None,
                            Some(frag.id.as_str()),
                            frag.name.as_deref(),
                            "",
                        );
                        state.hold.mark_responses_done(&key, Some(&frag.args));
                        if state.hold.is_rejected() {
                            reject_reason = Some("audit-hold-overflow".to_string());
                            break;
                        }
                        continue;
                    }
                    let seq = extract_responses_seq(v);
                    let verdict = state.hold.push_responses_fragment(
                        &key,
                        frag.index,
                        seq,
                        Some(frag.id.as_str()),
                        frag.name.as_deref(),
                        &frag.args,
                    );
                    if verdict == crate::service::audit::HoldVerdict::Rejected {
                        reject_reason = Some("audit-hold-overflow".to_string());
                        break;
                    }
                }
            } else {
                for frag in &frags {
                    if state.hold.push_fragment(
                        frag.index,
                        Some(frag.id.as_str()),
                        frag.name.as_deref(),
                        &frag.args,
                    ) == crate::service::audit::HoldVerdict::Rejected
                    {
                        reject_reason = Some("audit-hold-overflow".to_string());
                        break;
                    }
                }
            }
            // Responses per-item `.done` 走槽级审计，与全局完成解耦。
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
            // 前置：stop/item_done 只审计并清理对应 index 的槽
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
            // 完成事件审计（Allow/NeedApproval 均算已判定）后释放
            // 作用域出抑制集，后续帧据此恢复逐帧增量；拒绝态已清理。
            if reject_reason.is_none()
                && !state.hold.is_rejected()
                && (AuditHold::is_audit_due_event(env.protocol, v) || responses_slot_complete)
            {
                state.hold.release_audited();
            }
            if let Some(reason) = &reject_reason {
                // 拒绝即消费——阻断入口恒消费触发帧，调用点无条件早返回，
                // 不落正常还原/放行路径（structurally 保证，不依赖 reject_reason 门控）。
                apply_reject_block(state, env, v, reason).await;
                return EventFlow::Next;
            } else if AuditHold::is_complete_event(v) && !approve_held {
                state.hold.mark_completed();
            }
            // 正常帧两臂（opaque 与常规）与残余帧共用
            // `emit_restored_json_frame`——先守卫（失败回退占位符帧），再按
            // 是否缓冲决定立即喂出或暂存守卫产物。
            let prefix = envelope_prefix(ev);
            if event_terminal {
                state.terminator.mark_upstream_terminal();
            }
            // 正常结束（Anthropic message_stop / Responses response.completed）
            // 前 fail-open 回吐 carry 残段，保证残段先于终止帧下行。终止帧本身
            // 仅走 stitch-only（`prepare_terminal`），SHALL NOT 建立新 pending。
            let normal_end = is_normal_end_event(env.protocol, v);
            if normal_end {
                release_carry_residual(state, env).await;
            }
            let (restored_data, emitted) = if env.protocol.is_anthropic()
                && is_anthropic_opaque_event(v)
                && !is_anthropic_thinking_event(v)
            {
                // opaque（signature/redacted/thinking+signature）帧跳过
                // `json_aware_line` 重序列化，仅做字节级还原
                //（JSON 转义变体保证不破帧）；审计 hold/次要判定维持现状。
                let (restored, _spans) = env
                    .resp_scope
                    .restore_response_with_spans_json(&env.resp_vault, &ev.data);
                frames::emit_restored_json_frame(
                    &mut frames::FrameSink {
                        agg: &mut state.agg,
                    },
                    frames::RestoredFrame {
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
                // thinking 明文 opaque 增量与其他文本同路——接入
                // `TokenCarry` 做跨帧缝合，不绕过携带。终止帧（Anthropic
                // message_stop / Responses response.completed）只补全既有 carry，
                // 不从终止帧自身吸收新 pending。
                let cleaned = if normal_end {
                    state.carry.prepare_terminal(&ev.data, v)
                } else {
                    state.carry.prepare(&ev.data, v)
                };
                let (restored, _spans) = env
                    .resp_scope
                    .restore_response_with_spans_json(&env.resp_vault, &cleaned);
                let parsed_opt = (cleaned == ev.data).then_some(parsed.as_ref()).flatten();
                frames::emit_restored_json_frame(
                    &mut frames::FrameSink {
                        agg: &mut state.agg,
                    },
                    frames::RestoredFrame {
                        prefix: &prefix,
                        restored,
                        placeholder: &cleaned,
                        placeholder_parsed: parsed_opt,
                        json_aware: true,
                        feed: !buffer_tool_frame,
                    },
                    &env.metrics,
                )
                .await
            };
            // 未完成 tool 分片不进 `agg`（hold-until-complete），
            // 直接缓冲还原后输入；完成帧走正常透传（此前缓冲已在本帧前重放进 `agg`）。
            if buffer_tool_frame {
                // 入缓冲前先记账——同一 index 零字节分片不增聚合
                // 条目/字节（聚合维度看不见该洪泛），独立计数器超限即 fail-closed
                // 走阻断臂（不静默丢弃，被清参数已由 hold 内终审评估）。
                let pending_bytes = prefix.len() + restored_data.len();
                if state.hold.account_pending_frame(pending_bytes)
                    == crate::service::audit::HoldVerdict::Rejected
                {
                    apply_reject_block(state, env, v, "audit-hold-overflow").await;
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
            let (restored, _spans) = env
                .resp_scope
                .restore_response_with_spans(&env.resp_vault, &ev.data);
            let prefix = envelope_prefix(ev);
            frames::feed_output_frame(&mut state.agg, &prefix, &restored);
        }
    } else if ev.data.is_empty() {
        // 空 `data:` 心跳帧丢弃不透传（不计数、不参与终端判定；
        // 真空流保持 open-ended）。
        return EventFlow::Next;
    } else {
        // `data: [DONE]` 仅 Chat 为终端标记（`spec().done_terminator`）；非 Chat
        // 视为**非事件**——不置终端、不透出，交既有中途断流/真空流合成产出协议正确的
        // 恰一终端（下游不再出现 `[DONE]`，`add_sse_event` 不再计该帧，属已声明变更）。
        if env.protocol.spec().done_terminator.is_none() {
            return EventFlow::Next;
        }
        // Chat：恰一终止帧，多余去重。
        // 滞留帧先于终止帧放行（保序：滞留内容属于终止前的数据）。
        if state.terminator.terminal_sent() {
            return EventFlow::Next;
        }
        state.terminator.mark_upstream_terminal();
        // `[DONE]` 为 Chat 正常结束：先 fail-open 回吐 carry 残段再下发终止帧。
        release_carry_residual(state, env).await;
        let prefix = envelope_prefix(ev);
        state.agg.push_str(&prefix);
        state.agg.push_str(&block_inject::chat_done_frame());
    }
    if let Some(out) = crate::service::sse::select_emit(&mut state.agg, env.speed) {
        record_emitted_events(&env.metrics, &out);
        state.forwarded += 1;
        state.terminator.note_frame_sent();
        if env.protocol.is_anthropic() && parsed.as_ref().is_some_and(is_anthropic_message_start) {
            state.terminator.note_stream_head_sent();
        }
        if env.pump_tx.send(out).await.is_err() {
            return EventFlow::BreakFor;
        }
    }
    EventFlow::Next
}
