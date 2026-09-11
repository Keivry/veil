//! 流泵主循环（D2 自 `pump.rs` 拆出）：字节泵 + hold 四分支装配 + 终止闭合。

use {
    super::{
        super::protocol_header_value,
        PumpOutcome,
        StreamPumpCtx,
        decide::{self, ResponsesAction, StickyAction},
        event::{
            chat_finish_reason_seen,
            extract_responses_seq,
            is_anthropic_opaque_event,
            is_minor_event,
            is_terminal_event,
            now_secs,
            outer_event_index,
            responses_error_object,
            responses_failed_incomplete,
            responses_synth_conv_id,
            should_synthesize_empty_stream,
            sticky_terminal_event,
        },
        fragments::extract_tool_fragments,
        toolbuf::{clamp_pump_limits, take_pending_tool_inputs},
    },
    crate::{
        approval::PendingRecord,
        config::AuditMode,
        service::{
            audit::{self, AuditHold, AuditPolicy, RequestKeepalive},
            block_inject,
            json_walk::strip_bom,
            llm_gateway::{self, GatewayMetrics, Protocol},
            metrics::ChatRecord,
            redaction::{BoundaryHold, marker_cross_spans},
            sse::{Speed, SseParser, classify_residue, is_done_payload, set_truncated},
        },
    },
    serde_json::Value,
    std::sync::Arc,
};

/// H2/D1 兜底回退：还原后帧 `jloads` 校验（BOM 感知）；失败时回退**还原前占位符帧**
/// （fail-closed，token 形态保留、不破帧），记 warn + `restore_fallback` 计数，
/// 对齐非流 `retry_stripped` 回退语义（`nonstream.rs::retry_stripped`）。
pub(crate) fn guard_restored_frame(
    restored: String,
    placeholder_frame: &str,
    metrics: &GatewayMetrics,
) -> String {
    if serde_json::from_str::<Value>(strip_bom(&restored)).is_ok() {
        return restored;
    }
    tracing::warn!("流式还原后 JSON 校验失败，已回退还原前占位符帧（fail-closed）");
    metrics.record_restore_fallback();
    placeholder_frame.to_string()
}

/// 2.3 `spawn_stream_pump`：把上游字节流泵为下游 SSE 帧流，保证终止闭合；
/// 阻断或合成终止时注入终止标记。`upstream` 所有权移入 task，不解析业务语义之外的状态。
pub fn spawn_stream_pump(
    upstream: reqwest::Response,
    tx: tokio::sync::mpsc::Sender<String>,
    ctx: StreamPumpCtx,
) -> tokio::task::JoinHandle<PumpOutcome> {
    tokio::spawn(async move {
        let StreamPumpCtx {
            protocol,
            scope: resp_scope,
            vault: resp_vault,
            detector: resp_detector,
            audit_mode,
            audit_policy_file,
            approval_whitelist,
            hold_max,
            gateway_metrics: metrics,
            admin_metrics,
            sqlite_precise,
            req_start,
            pending: audit_pending,
            init_conv,
            normalized_out: _,
            pii_boundary_chars,
        } = ctx;
        // P0-4.1：泵入口钳位非法配置（0→默认+warn，超 8MB→截断+warn），
        // 永不导致未定义行为。
        let (hold_max, pii_boundary_chars) = clamp_pump_limits(hold_max, pii_boundary_chars);
        let mut boundary = BoundaryHold::new(pii_boundary_chars);
        let boundary_spans = |window: &str, seam: usize| {
            let cred_map = resp_vault.p2t_snapshot();
            let mut spans: Vec<(usize, usize)> = resp_detector
                .scan_spans_sync(window, cred_map.map())
                .into_iter()
                .map(|(_, _, s, e)| (s, e))
                .collect();
            spans.extend(marker_cross_spans(window, seam));
            spans
        };
        let mut conv_id = init_conv;
        // E9：流内首见 `id`（合成截断帧优先采用，下游可关联）。
        let mut stream_first_id: Option<String> = conv_id.clone();
        let hold_gate = Arc::new(std::sync::atomic::AtomicBool::new(!matches!(
            audit_mode,
            AuditMode::Off
        )));
        let keepalive = RequestKeepalive::spawn_gated(tx.clone(), hold_gate.clone());
        let audit_policy = match audit_policy_file.clone() {
            Some(path) => match AuditPolicy::load_from_file(Some(path.as_path())) {
                Ok(policy) => policy,
                Err(err) => {
                    tracing::warn!("审计策略文件加载失败，使用默认策略: {err}");
                    AuditPolicy::default_policy()
                }
            },
            None => AuditPolicy::default_policy(),
        };
        let mut upstream = upstream;
        let pump_tx = tx.clone();
        let speed = if matches!(audit_mode, AuditMode::Off) {
            Speed::Fast
        } else {
            Speed::Slow
        };
        let _keep = keepalive;
        let _gate = hold_gate;
        let mut parser = SseParser::new();
        let mut hold = AuditHold::new(hold_max);
        let mut meta = crate::service::sse::StreamMeta::default();
        let mut forwarded: usize = 0;
        // D4：已发任意帧状态位（残余/合成 `send` 即记位）：空流合成守门以
        // `terminal_sent/any_frame_sent` 为准，不依赖 `forwarded` 计数器
        //（计数器与实际发送位可分叉，残余已发但计数未增时误触发二次空流帧）。
        let mut any_frame_sent = false;
        let mut agg = String::new();
        let mut terminated = false;
        let mut rejected_sticky = false;
        let mut block_injected = false;
        // 审计驱动的阻断（策略阻断/超限 fail-closed），与空流/截断合成区分口径。
        let mut audit_blocked = false;
        // 终端去重（§2.6 流式等价）：每协议恰一终止帧，多余 `[DONE]/message_stop/completed` 丢弃。
        let mut terminal_sent = false;
        // B3/P2-2：Chat 已见非 null `finish_reason`（soft-terminal）但流末缺 `[DONE]`。
        let mut saw_finish_reason = false;
        let mut stream_usage: Option<llm_gateway::Usage> = None;
        // C13 模型分桶：跟踪上游回显 `model`（首见为准，缺失归
        // `unknown_model`），随 `record_chat` 落快照。
        let mut stream_model: Option<String> = None;
        // Responses 终端去重旗：上游 `failed` 直接透传、`incomplete`/`error`
        // 合成为单个 `response.failed`，恒恰其一。
        let mut responses_failed_sent = false;
        // P0-3.1/TSS-03：未完成 tool 分片缓冲（hold-until-complete）：审计开启时
        // chat/anthropic 非终止 tool 事件帧先缓冲不转发，`done`/stop 到达才放行；
        // 流截断时丢弃并记 `truncated_tool_dropped`（对标 Python
        // `tool_calls_pending_events`）。条目为（分桶槽号组，帧前缀，边界输入），
        // 缓冲点在边界 hold 上游，重放时缝合时序不变，保到达序。
        // E10/D5 方案 B 分工声明（双缓冲并存）：`AuditHold` 管审计判定持有
        //（tool 三元组聚合 + verdict 判定 + 完成标记），`pending_tool_frames` 管
        // Chat/Anthropic 完成前重放排序（hold-until-complete，到达序经
        // `take_pending_tool_inputs` 按槽取出、重放进边界 hold）；两者无双重持有，
        // 去向以本注释与取出函数文档为准，单测 `dual_buffer_slot_handoff_e10` 锁定。
        let mut pending_tool_frames: Vec<(Vec<u32>, String, String)> = Vec::new();
        while let Ok(chunk) = upstream.chunk().await {
            let bytes = match chunk {
                Some(b) => b,
                None => break,
            };
            if bytes.is_empty() {
                continue;
            }
            // C11：超长行尾部字节排入 metrics；截断事件打 warn 标记审计可见。
            let events = parser.push_bytes(&bytes);
            let line_dropped = parser.take_truncated_line_dropped_bytes();
            if line_dropped > 0 {
                metrics.record_truncated_line_dropped_bytes(line_dropped);
            }
            for ev in events {
                if ev.truncated {
                    tracing::warn!(
                        "SSE 超长行已截断（16KB），头部分发审计，尾部 {line_dropped} 字节已计数丢弃"
                    );
                }
                if ev.is_comment_only {
                    // E11/D6 空流守门：注释心跳透传但不置位 `any_frame_sent`
                    //（非内容帧），纯心跳流仍走真空合成，不断链不悬空。
                    let _ = pump_tx
                        .send(format!(":{}\n\n", ev.comments.join("\n:")))
                        .await;
                    continue;
                }
                if !ev.data.is_empty()
                    && !is_done_payload(&ev.data)
                    && let Ok(v) = serde_json::from_str::<Value>(strip_bom(&ev.data))
                {
                    if protocol == Protocol::Chat && chat_finish_reason_seen(&v) {
                        saw_finish_reason = true;
                    }
                    if let Some(id) = llm_gateway::extract_conv_id(&v) {
                        if stream_first_id.is_none() {
                            stream_first_id = Some(id.clone());
                        }
                        conv_id = Some(id);
                    }
                    if stream_model.is_none()
                        && let Some(m) = v.get("model").and_then(|m| m.as_str())
                    {
                        stream_model = Some(m.to_string());
                    }
                    llm_gateway::accumulate_usage(
                        &mut stream_usage,
                        llm_gateway::extract_usage_stream(protocol, &v),
                    );
                }
                _gate.store(
                    hold.held() && !matches!(audit_mode, AuditMode::Off),
                    std::sync::atomic::Ordering::Relaxed,
                );
                if rejected_sticky {
                    // 纯函数决策；短路求值与 metrics 副作用留调用点：
                    // 仅非空非 DONE 才解析/记 terminal_fallback（原语义不变）。
                    let data_empty = ev.data.is_empty();
                    let is_done = is_done_payload(&ev.data);
                    let is_terminal = !data_empty
                        && !is_done
                        && sticky_terminal_event(protocol, &ev.data, &metrics);
                    let is_tool_or_complete = !data_empty
                        && !is_done
                        && serde_json::from_str::<Value>(strip_bom(&ev.data)).is_ok_and(|v| {
                            !extract_tool_fragments(protocol, &v).is_empty()
                                || AuditHold::is_complete_event(&v)
                        });
                    if decide::sticky_suppress_action(
                        rejected_sticky,
                        data_empty,
                        is_done,
                        is_terminal,
                        is_tool_or_complete,
                    ) == StickyAction::Drop
                    {
                        continue;
                    }
                }
                if protocol == Protocol::Responses && !ev.data.is_empty() {
                    // N1 守卫（T1/D1）：决策交纯函数 `responses_control_action`；
                    // 已发终端时保持原语义不解析（terminal_fallback 计数不漂移）。
                    let (is_failed, is_error) = if terminal_sent {
                        (false, false)
                    } else {
                        let (f, _, e) = responses_failed_incomplete(&ev.data, &metrics);
                        (f, e)
                    };
                    match decide::responses_control_action(
                        terminal_sent,
                        responses_failed_sent,
                        is_error,
                        is_failed,
                    ) {
                        ResponsesAction::Ignore => continue,
                        ResponsesAction::SynthesizeFailed => {
                            // P4/D4：`error` 仅合成单帧 `response.failed`
                            //（`response.error.message` 携带上游 error 文案），不注入
                            // `output_index` 序列；`incomplete` 不在此列——原样透传并作为
                            // 唯一终端（保留 `incomplete_details`，由 `is_terminal_event` 置位）。
                            responses_failed_sent = true;
                            terminal_sent = true;
                            let fid = responses_synth_conv_id(
                                stream_first_id.as_deref(),
                                conv_id.as_deref(),
                                &metrics,
                            );
                            let err_obj = responses_error_object(&ev.data);
                            for f in block_inject::ensure_event_lines(vec![
                                block_inject::responses_failed_frame(&fid, err_obj.as_ref()),
                            ]) {
                                metrics.add_sse_event();
                                forwarded += 1;
                                any_frame_sent = true;
                                if pump_tx.send(f).await.is_err() {
                                    break;
                                }
                            }
                            block_inject::mark_terminal(&mut meta);
                            terminated = true;
                            continue;
                        }
                        ResponsesAction::DuplicateFailed => {
                            terminated = true;
                            continue;
                        }
                        ResponsesAction::Passthrough => {
                            if is_failed {
                                responses_failed_sent = true;
                            }
                        }
                    }
                }
                if !ev.data.is_empty() && !is_done_payload(&ev.data) {
                    if let Ok(v) = serde_json::from_str::<Value>(strip_bom(&ev.data)) {
                        // 终端后不再透出任何数据帧：恰一终止帧且其后无内容。
                        if terminal_sent {
                            continue;
                        }
                        let event_terminal = is_terminal_event(protocol, &v);
                        let frags = extract_tool_fragments(protocol, &v);
                        let is_tool_event = !frags.is_empty();
                        let minor = !is_tool_event && is_minor_event(protocol, &v);
                        if rejected_sticky && is_tool_event {
                            continue;
                        }
                        // P0-3.1：完成事件先放行此前缓冲的残缺分片（到达序重放进
                        // 边界 hold，保证缝合时序），再处理本帧；全局完成全放行，
                        // 按槽完成只放行对应槽（他槽残缺继续缓冲）。
                        let audit_hold_on = !matches!(audit_mode, AuditMode::Off)
                            && matches!(protocol, Protocol::Chat | Protocol::Anthropic);
                        if audit_hold_on {
                            let slot = decide::tool_replay_slot(
                                protocol,
                                &v,
                                AuditHold::is_complete_event(&v),
                                AuditHold::is_index_complete_event(&v),
                            );
                            if let Some(slot) = slot {
                                for (b_prefix, b_data) in
                                    take_pending_tool_inputs(&mut pending_tool_frames, slot)
                                {
                                    let (op, od) = boundary.push(b_prefix, b_data, boundary_spans);
                                    if !od.is_empty() || !boundary.has_held() {
                                        agg.push_str(&op);
                                        agg.push_str(&format!("data: {od}\n\n"));
                                    }
                                }
                            }
                        }
                        // P0-3.1：未完成 tool 分片缓冲不转发（hold-until-complete）；
                        // 本帧槽号组取自各分片桶号（到达序 flush 时保序）。
                        let buffer_tool_frame = decide::should_buffer_tool_frame(
                            audit_hold_on,
                            is_tool_event,
                            AuditHold::is_complete_event(&v),
                            AuditHold::is_index_complete_event(&v),
                        );
                        let tool_buckets: Vec<u32> = frags.iter().map(|f| f.0).collect();
                        let mut reject_reason: Option<String> = None;
                        if minor {
                            // 次要事件透传且审计声明放行：不进 hold、不审计。
                        } else if protocol == Protocol::Responses {
                            for frag in &frags {
                                let key = AuditHold::responses_key(frag.1.as_deref(), frag.0);
                                let seq = extract_responses_seq(&v);
                                let verdict = hold.push_responses_fragment(
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
                                if AuditHold::is_complete_event(&v) {
                                    hold.mark_responses_done(&key, Some(&frag.3));
                                }
                            }
                        } else {
                            for frag in &frags {
                                if hold.push_fragment(
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
                        let mut approve_held = false;
                        if reject_reason.is_none()
                            && !hold.is_rejected()
                            && AuditHold::is_complete_event(&v)
                            && !matches!(audit_mode, AuditMode::Off)
                        {
                            for (idx, name, args) in hold.tool_triples() {
                                match audit::evaluate_with_whitelist(
                                    audit_mode,
                                    &name,
                                    &args,
                                    &audit_policy,
                                    &approval_whitelist,
                                ) {
                                    audit::AuditVerdict::Block { .. } => {
                                        hold.mark_rejected();
                                        reject_reason = Some("audit-policy-block".to_string());
                                        break;
                                    }
                                    audit::AuditVerdict::NeedApproval { reason, summary } => {
                                        audit_pending.insert(PendingRecord::new(
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
                            && !hold.is_rejected()
                            && !matches!(audit_mode, AuditMode::Off)
                            && AuditHold::is_index_complete_event(&v)
                            && let Some(idx) = outer_event_index(protocol, &v)
                        {
                            for (_, name, args) in
                                hold.tool_triples().into_iter().filter(|(i, ..)| *i == idx)
                            {
                                match audit::evaluate_with_whitelist(
                                    audit_mode,
                                    &name,
                                    &args,
                                    &audit_policy,
                                    &approval_whitelist,
                                ) {
                                    audit::AuditVerdict::Block { .. } => {
                                        hold.mark_rejected();
                                        reject_reason = Some("audit-policy-block".to_string());
                                        break;
                                    }
                                    audit::AuditVerdict::NeedApproval { reason, summary } => {
                                        audit_pending.insert(PendingRecord::new(
                                            &format!("audit-hold-{idx}-{name}"),
                                            &format!("{reason}: {summary}"),
                                        ));
                                    }
                                    audit::AuditVerdict::Allow => {}
                                }
                            }
                            hold.clear_index(idx);
                        }
                        if let Some(reason) = reject_reason {
                            rejected_sticky = true;
                            audit_blocked = true;
                            terminal_sent = true;
                            agg.clear();
                            boundary.clear();
                            // P0-3.1：阻断丢弃缓冲（阻断非截断，不记截断计数）。
                            pending_tool_frames.clear();
                            if !block_injected {
                                block_injected = true;
                                for f in block_inject::ensure_event_lines(match protocol {
                                    Protocol::Chat => block_inject::chat_block_frames(&reason),
                                    Protocol::Anthropic => {
                                        block_inject::anthropic_block_frames(&reason)
                                    }
                                    Protocol::Responses => {
                                        let bid = conv_id.clone().unwrap_or_else(|| {
                                            llm_gateway::resolve_conv_id(
                                                None,
                                                &serde_json::Value::Null,
                                                Some(&metrics),
                                                "block",
                                            )
                                            .0
                                        });
                                        block_inject::responses_block_frames(&bid)
                                    }
                                    Protocol::NonDialog => vec![],
                                }) {
                                    let _ = pump_tx.send(f).await;
                                }
                                block_inject::mark_terminal(&mut meta);
                            }
                            if is_tool_event
                                || AuditHold::is_complete_event(&v)
                                || AuditHold::is_index_complete_event(&v)
                            {
                                continue;
                            }
                        } else if AuditHold::is_complete_event(&v) && !approve_held {
                            hold.mark_completed();
                        }
                        let restored_data =
                            if protocol == Protocol::Anthropic && is_anthropic_opaque_event(&v) {
                                // M3/D6：opaque（signature/redacted/thinking）帧跳过响应侧
                                // 新 PII 扫描与 `json_aware_line` 重序列化，仅做字节级还原
                                //（JSON 转义变体保证不破帧）；审计 hold/次要判定维持现状。
                                let (restored, _spans) = resp_scope
                                    .restore_response_with_spans_json(&resp_vault, &ev.data);
                                guard_restored_frame(restored, &ev.data, &metrics)
                            } else {
                                let (restored, spans) = resp_scope
                                    .restore_response_with_spans_json(&resp_vault, &ev.data);
                                let scanned = resp_scope
                                    .redact_response_new_pii_with_skip(
                                        &resp_vault,
                                        &resp_detector,
                                        &restored,
                                        &spans,
                                    )
                                    .await;
                                guard_restored_frame(
                                    crate::service::sse::json_aware_line(&scanned, |s| s),
                                    &ev.data,
                                    &metrics,
                                )
                            };
                        let prefix = ev
                            .event_type
                            .as_ref()
                            .map(|t| format!("event: {t}\n"))
                            .unwrap_or_default();
                        if event_terminal {
                            terminal_sent = true;
                        }
                        // P0-3.1：未完成 tool 分片不进边界 hold、不进 `agg`
                        // （hold-until-complete），直接缓冲还原后输入；完成帧走
                        // 正常透传（此前缓冲已在本帧前重放进边界 hold）。
                        if buffer_tool_frame {
                            pending_tool_frames.push((tool_buckets, prefix, restored_data));
                            continue;
                        }
                        let (out_prefix, out_data) =
                            boundary.push(prefix, restored_data, boundary_spans);
                        if !out_data.is_empty() || !boundary.has_held() {
                            agg.push_str(&out_prefix);
                            agg.push_str(&format!("data: {out_data}\n\n"));
                        }
                        if decide::should_suppress_held_output(
                            minor,
                            hold.held(),
                            !out_data.is_empty(),
                        ) {
                            continue;
                        }
                    } else {
                        // 非 JSON 文本同样走 span 跳过还原，终端后不再透出。
                        if terminal_sent {
                            continue;
                        }
                        let (restored, spans) =
                            resp_scope.restore_response_with_spans(&resp_vault, &ev.data);
                        let scanned = resp_scope
                            .redact_response_new_pii_with_skip(
                                &resp_vault,
                                &resp_detector,
                                &restored,
                                &spans,
                            )
                            .await;
                        let prefix = ev
                            .event_type
                            .as_ref()
                            .map(|t| format!("event: {t}\n"))
                            .unwrap_or_default();
                        let (out_prefix, out_data) = boundary.push(prefix, scanned, boundary_spans);
                        if !out_data.is_empty() || !boundary.has_held() {
                            agg.push_str(&out_prefix);
                            agg.push_str(&format!("data: {out_data}\n\n"));
                        }
                    }
                } else if ev.data.is_empty() {
                    // L17：空 `data:` 心跳帧丢弃不透传（不计数、不参与终端判定；
                    // 真空流保持 open-ended，见 C8）。
                    continue;
                } else {
                    // `[DONE]`（含 BOM 前缀）：恰一终止帧，多余去重。
                    // 滞留帧先于终止帧放行（保序：滞留内容属于终止前的数据）。
                    if terminal_sent {
                        continue;
                    }
                    terminal_sent = true;
                    if let Some((fp, fd)) = boundary.flush() {
                        agg.push_str(&fp);
                        agg.push_str(&format!("data: {fd}\n\n"));
                    }
                    let prefix = ev
                        .event_type
                        .as_ref()
                        .map(|t| format!("event: {t}\n"))
                        .unwrap_or_default();
                    agg.push_str(&format!("{prefix}data: [DONE]\n\n"));
                }
                if let Some(out) = crate::service::sse::select_emit(&mut agg, speed) {
                    metrics.add_sse_event();
                    forwarded += 1;
                    any_frame_sent = true;
                    if pump_tx.send(out).await.is_err() {
                        break;
                    }
                }
            }
            if terminated {
                break;
            }
        }
        // P0-3.1/TSS-03：截断丢弃未完成 tool 分片（对标 Python `_synthesize_truncation`
        // TSS-03 分支）：缓冲帧永不透传下游，记 `truncated_tool_dropped` 并 warn；
        // 置 `terminal_sent` 跳过空流二次合成（open-ended，以已透传块收尾）。
        if !pending_tool_frames.is_empty() {
            let dropped = pending_tool_frames.len() as u64;
            pending_tool_frames.clear();
            metrics.record_truncated_tool_dropped(dropped);
            tracing::warn!("LLM 截断丢弃残缺 tool 分片: {dropped} 帧");
            // P0-3.2：截断合成（responses 出 failed，chat/anthropic open-ended
            // 空实现）；与 C8 空流合成联动：此处已置 `terminal_sent`，下游空流
            // 守门不再二次合成，恒恰一终止语义。
            let tid = conv_id.clone().unwrap_or_else(|| {
                llm_gateway::resolve_conv_id(
                    None,
                    &serde_json::Value::Null,
                    Some(&metrics),
                    "truncated",
                )
                .0
            });
            for f in block_inject::ensure_event_lines(block_inject::synthesize_truncation(
                protocol, &tid,
            )) {
                metrics.add_sse_event();
                forwarded += 1;
                any_frame_sent = true;
                if pump_tx.send(f).await.is_err() {
                    break;
                }
            }
            terminal_sent = true;
            let _ = crate::service::sse::set_truncated(
                &mut meta,
                protocol,
                if protocol == Protocol::Responses {
                    crate::service::sse::TruncatedMode::SynthesizedFailed
                } else {
                    crate::service::sse::TruncatedMode::OpenEnded
                },
                Some(&metrics),
            );
        }
        if let Some((fp, fd)) = boundary.flush() {
            agg.push_str(&fp);
            agg.push_str(&format!("data: {fd}\n\n"));
        }
        if !agg.is_empty() {
            metrics.add_sse_event();
            let _ = pump_tx.send(std::mem::take(&mut agg)).await;
            forwarded += 1;
            any_frame_sent = true;
        }
        let residual = parser.residual_json_aware();
        // 残余分类（§2.6）：None 直接丢弃，不得 `data:` 直发；
        // BOM/`[DONE]`/空白同样归入丢弃，终端去重已处理。
        if let Some(classified) = classify_residue(&residual) {
            let (restored, spans) =
                resp_scope.restore_response_with_spans(&resp_vault, &classified);
            let scanned = resp_scope
                .redact_response_new_pii_with_skip(&resp_vault, &resp_detector, &restored, &spans)
                .await;
            if !scanned.is_empty() {
                let (op, od) = boundary.push(String::new(), scanned, boundary_spans);
                let _ = op;
                if !od.is_empty() {
                    let _ = pump_tx.send(format!("data: {od}\n\n")).await;
                    any_frame_sent = true;
                }
                if let Some((fp, fd)) = boundary.flush() {
                    let _ = pump_tx.send(format!("{fp}data: {fd}\n\n")).await;
                    any_frame_sent = true;
                }
            }
        }
        // P1/D2：Chat 已见非 null `finish_reason` 却未收到 `[DONE]`（上游异常收尾）：
        // flush 边界后补发恰一 `data: [DONE]` 并置终端；`finish_reason` 后的 usage
        // 尾帧此前已透传，不提前截断。`truncated_mode=open_ended` 观测保留
        //（如实描述上游截断形态，不新增枚举）。置于空流守门前：补发后
        // `terminal_sent` 已置位，守门自然跳过，恒恰一终端。
        if decide::should_backfill_chat_done(
            protocol,
            terminal_sent,
            saw_finish_reason,
            meta.truncated_mode.is_some(),
        ) {
            if let Some((fp, fd)) = boundary.flush() {
                agg.push_str(&fp);
                agg.push_str(&format!("data: {fd}\n\n"));
            }
            agg.push_str(&block_inject::chat_done_frame());
            if !agg.is_empty() {
                metrics.add_sse_event();
                forwarded += 1;
                any_frame_sent = true;
                let _ = pump_tx.send(std::mem::take(&mut agg)).await;
            }
            terminal_sent = true;
            block_inject::mark_terminal(&mut meta);
            let _ = set_truncated(
                &mut meta,
                protocol,
                crate::service::sse::TruncatedMode::OpenEnded,
                Some(&metrics),
            );
            tracing::warn!(
                "Chat 流已见 finish_reason 但缺 [DONE]，已补发 [DONE] 收尾（open-ended 观测保留）"
            );
        }
        // D4：空流合成守门以终端/任意帧状态位为准（残余 `send` 即记位），
        // 不依赖 `forwarded` 计数器；真空流（三位全假）仍合成三协议恰一终端帧。
        if should_synthesize_empty_stream(terminal_sent, any_frame_sent, block_injected) {
            let proto_name = protocol_header_value(protocol);
            let tid = conv_id.clone().unwrap_or_else(|| {
                llm_gateway::resolve_conv_id(
                    None,
                    &serde_json::Value::Null,
                    Some(&metrics),
                    "truncated",
                )
                .0
            });
            // C8 open-ended：真空流 chat/anthropic 为空帧集（不伪造成功终止，
            // 仅记 open-ended 可观测，不置 block_injected）；Responses 合成 failed。
            // 与 P0-3.2 截断合成共用 `terminal_sent` 守门：此处仅真空（终端未发、
            // 无帧、无阻断）才进入，恒恰一语义不变。
            let frames = block_inject::ensure_event_lines(block_inject::empty_stream_frames(
                proto_name, &tid,
            ));
            if frames.is_empty() {
                let _ = set_truncated(
                    &mut meta,
                    protocol,
                    crate::service::sse::TruncatedMode::OpenEnded,
                    Some(&metrics),
                );
            } else {
                block_injected = true;
                for f in frames {
                    let _ = pump_tx.send(f).await;
                }
                let _ = set_truncated(
                    &mut meta,
                    protocol,
                    if protocol == Protocol::Responses {
                        crate::service::sse::TruncatedMode::SynthesizedFailed
                    } else {
                        crate::service::sse::TruncatedMode::OpenEnded
                    },
                    Some(&metrics),
                );
                block_inject::mark_terminal(&mut meta);
            }
            terminated = true;
        }
        let _ = terminated;
        _gate.store(false, std::sync::atomic::Ordering::Relaxed);
        admin_metrics.record_chat(ChatRecord {
            protocol,
            model: stream_model.as_deref().unwrap_or(""),
            latency_ms: req_start.elapsed().as_millis() as u64,
            usage: stream_usage.as_ref(),
            truncated_mode: meta.truncated_mode.as_ref().map(|m| m.as_str()),
            is_precise: sqlite_precise,
            ts_secs: now_secs(),
        });
        admin_metrics.record_aux_counts(protocol, now_secs(), 0, 0, u64::from(audit_blocked));
        PumpOutcome {
            forwarded,
            block_injected,
            terminal_injected: meta.terminal_injected,
        }
    })
}
