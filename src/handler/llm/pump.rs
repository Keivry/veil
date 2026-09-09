//! 流泵单元（2.3）：上游字节流泵为下游 SSE 帧流，保证终止闭合。

use {
    super::protocol_header_value,
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
        service::{
            audit::{self, AuditPolicy},
            audit_hold::{AuditHold, RequestKeepalive},
            block_inject,
            credential_vault::CredentialVault,
            json_walk::strip_bom,
            llm_gateway::{self, GatewayMetrics, Protocol},
            metrics::{ChatRecord, MetricsStore},
            pii::PiiDetector,
            redaction::{BoundaryHold, Scope, marker_cross_spans},
            sse::{Speed, SseParser, classify_residue, is_done_payload, set_truncated},
        },
    },
    axum::{
        body::Body,
        http::{StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::Value,
    std::{path::PathBuf, sync::Arc, time::Instant},
};

/// 2.3 `stream_pump` 字节泵的上下文：全 `Arc`，`spawn` 闭包全 `Arc move`。
pub struct StreamPumpCtx {
    pub protocol: Protocol,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub audit_mode: AuditMode,
    pub audit_policy_file: Option<PathBuf>,
    pub approval_whitelist: Vec<String>,
    pub hold_max: usize,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub pending: Arc<PendingApprovals>,
    pub init_conv: Option<String>,
    pub normalized_out: bool,
    /// PII 边界 hold 窗（字符数，`PII_HOLD_MAX` 口径；0 = 响应侧关闭，直通）。
    pub pii_boundary_chars: usize,
}

/// 流泵结束时的可观测结果（单测断言用）。
pub struct PumpOutcome {
    /// 转发出的 SSE 帧数（含最终 flush）。
    pub forwarded: usize,
    /// 是否注入过阻断帧。
    pub block_injected: bool,
    /// 终止标记是否落到 `StreamMeta`（`terminal_injected`）。
    pub terminal_injected: bool,
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
            let cred_map = resp_vault.snapshot_p2t();
            let mut spans: Vec<(usize, usize)> = resp_detector
                .scan_spans_sync(window, &cred_map)
                .into_iter()
                .map(|(_, _, s, e)| (s, e))
                .collect();
            spans.extend(marker_cross_spans(window, seam));
            spans
        };
        let mut conv_id = init_conv;
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
                    let _ = pump_tx
                        .send(format!(":{}\n\n", ev.comments.join("\n:")))
                        .await;
                    continue;
                }
                if !ev.data.is_empty()
                    && !is_done_payload(&ev.data)
                    && let Ok(v) = serde_json::from_str::<Value>(strip_bom(&ev.data))
                {
                    if let Some(id) = llm_gateway::extract_conv_id(&v) {
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
                    if is_done_payload(&ev.data) {
                        continue;
                    }
                    if !ev.data.is_empty() {
                        let terminal = match protocol {
                            Protocol::Anthropic => {
                                ev.data.contains("content_block_stop")
                                    || ev.data.contains("message_delta")
                                    || ev.data.contains("message_stop")
                            }
                            Protocol::Responses => {
                                ev.data.contains("response.completed")
                                    || ev.data.contains("response.failed")
                                    || ev.data.contains("response.incomplete")
                                    || ev.data.contains("\"type\":\"error\"")
                                    || ev.data.contains("\"type\": \"error\"")
                            }
                            _ => false,
                        };
                        if terminal {
                            continue;
                        }
                    }
                    if !ev.data.is_empty()
                        && !is_done_payload(&ev.data)
                        && let Ok(v) = serde_json::from_str::<Value>(strip_bom(&ev.data))
                        && (!extract_tool_fragments(protocol, &v).is_empty()
                            || AuditHold::is_complete_event(&v))
                    {
                        continue;
                    }
                }
                if protocol == Protocol::Responses && !ev.data.is_empty() {
                    let is_failed = ev.data.contains("response.failed");
                    let is_incomplete = ev.data.contains("response.incomplete");
                    let is_error = ev.data.contains("\"type\":\"error\"")
                        || ev.data.contains("\"type\": \"error\"");
                    if is_incomplete || is_error {
                        if !responses_failed_sent {
                            responses_failed_sent = true;
                            terminal_sent = true;
                            let fid = conv_id.clone().unwrap_or_else(|| {
                                llm_gateway::resolve_conv_id(
                                    None,
                                    &serde_json::Value::Null,
                                    Some(&metrics),
                                    "failed",
                                )
                                .0
                            });
                            for f in block_inject::ensure_event_lines(
                                block_inject::responses_truncated_frames(&fid),
                            ) {
                                metrics.add_sse_event();
                                forwarded += 1;
                                any_frame_sent = true;
                                if pump_tx.send(f).await.is_err() {
                                    break;
                                }
                            }
                            block_inject::mark_terminal(&mut meta);
                        }
                        terminated = true;
                        continue;
                    }
                    if is_failed {
                        if responses_failed_sent {
                            terminated = true;
                            continue;
                        }
                        responses_failed_sent = true;
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
                            let slot: Option<Option<u32>> = if AuditHold::is_complete_event(&v) {
                                Some(None)
                            } else if AuditHold::is_index_complete_event(&v) {
                                outer_event_index(protocol, &v).map(Some)
                            } else {
                                None
                            };
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
                        let buffer_tool_frame = audit_hold_on
                            && is_tool_event
                            && !AuditHold::is_complete_event(&v)
                            && !AuditHold::is_index_complete_event(&v);
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
                                if verdict == crate::service::audit_hold::HoldVerdict::Rejected {
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
                                ) == crate::service::audit_hold::HoldVerdict::Rejected
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
                        let restored_data = crate::service::sse::json_aware_line(&scanned, |s| s);
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
                        if !minor && hold.held() && !out_data.is_empty() {
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

/// 2.3 `build_sse_response`：把泵出的帧通道装成下游 SSE 响应，保留
/// `x-veil-normalized` 声明与 `X-Accel-Buffering: no`。
pub fn build_sse_response(
    rx: tokio::sync::mpsc::Receiver<String>,
    normalized_out: bool,
) -> Response {
    use bytes::Bytes;
    let stream = async_stream::stream! {
        let mut rx = rx;
        while let Some(msg) = rx.recv().await {
            yield Ok::<_, anyhow::Error>(Bytes::from(msg));
        }
    };
    let mut stream_builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache");
    if normalized_out {
        stream_builder = stream_builder.header("x-veil-normalized", "json-whitespace");
    }
    stream_builder
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "stream").into_response())
}

pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 空流合成守门（D4）：以是否已发终端/任意帧为准，不依赖 `forwarded` 计数器。
pub(crate) fn should_synthesize_empty_stream(
    terminal_sent: bool,
    any_frame_sent: bool,
    block_injected: bool,
) -> bool {
    !terminal_sent && !any_frame_sent && !block_injected
}

/// 流式终端事件判定（§2.6 去重用）：chat 以 `[DONE]` 为准（非 JSON 分支处理，
/// 此处恒 false）；anthropic 仅 `message_stop`；responses 仅 `completed/failed`
/// （`incomplete/error` 已提前映射为单个 `failed`）。
fn is_terminal_event(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => v
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "message_stop"),
        P::Responses => v
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "response.completed" || t == "response.failed"),
        _ => false,
    }
}

/// 外层事件序号（§2.5/§2.4）：anthropic 取事件级 `index`
/// （`content_block_start/delta.index`），responses 取 `output_index`；
/// 缺失返回 None（调用方跳过按槽清理，不误清）。
/// TSS-03 缓冲取出（P0-3.1）：按到达序取出与 `slot` 相交的缓冲输入；
/// `slot` 为 `None` 时全取（全局完成），否则只取含该槽号的帧（按槽完成）。
/// 取出的是边界 hold 上游输入（还原/脱敏后、边界缝合前），调用方须按序
/// 重放进 `BoundaryHold::push` 再转发，保证缝合状态机时序不变。
fn take_pending_tool_inputs(
    pending: &mut Vec<(Vec<u32>, String, String)>,
    slot: Option<u32>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut kept = Vec::new();
    for (buckets, prefix, data) in std::mem::take(pending) {
        if slot.is_none_or(|s| buckets.contains(&s)) {
            out.push((prefix, data));
        } else {
            kept.push((buckets, prefix, data));
        }
    }
    *pending = kept;
    out
}

/// 泵入口限值钳位（P0-4.1）：`hold_max == 0 → 1MB 默认并 warn`，超
/// `AUDIT_SUBLIMIT_CEILING` 截断至上限并 warn；
/// `pii_boundary_chars == 0` 为响应侧关闭直通信号（`StreamPumpCtx` 调用方契约，
/// 见字段注释与 `handler::llm` 接线），保留不钳位。
pub(crate) fn clamp_pump_limits(hold_max: usize, pii_boundary_chars: usize) -> (usize, usize) {
    let hold_max = if hold_max == 0 {
        tracing::warn!("hold_max 非法 ({hold_max})，已回退 1MB 默认");
        crate::config::AUDIT_HOLD_MAX_BYTES_DEFAULT as usize
    } else if hold_max > crate::config::AUDIT_SUBLIMIT_CEILING_BYTES {
        tracing::warn!("hold_max 超限 ({hold_max})，已截断至 8MB 上限");
        crate::config::AUDIT_SUBLIMIT_CEILING_BYTES
    } else {
        hold_max
    };
    (hold_max, pii_boundary_chars)
}

fn outer_event_index(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> Option<u32> {
    use crate::service::llm_gateway::Protocol as P;
    let n = match protocol {
        P::Anthropic => v.get("index")?.as_u64()?,
        P::Responses => v.get("output_index").or_else(|| v.get("index"))?.as_u64()?,
        _ => return None,
    };
    Some(n as u32)
}

fn extract_responses_seq(v: &Value) -> Option<u64> {
    v.get("sequence_number").and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

fn is_minor_event(protocol: crate::service::llm_gateway::Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            t.contains("thinking")
                || t.contains("signature")
                || t.contains("redacted")
                || t.contains("citation")
                || v.get("delta")
                    .and_then(|d| d.get("type"))
                    .and_then(|x| x.as_str())
                    .is_some_and(|dt| {
                        dt.contains("thinking")
                            || dt.contains("signature")
                            || dt.contains("citation")
                    })
        }
        P::Responses => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            // C10：`file_search/web_search` 计 tool（与非流一致），不再列为
            // 次要事件；其余检索外围（reasoning/mcp/code_interpreter/image_gen）
            // 仍透传不审计。
            ["reasoning", "mcp", "code_interpreter", "image_gen"]
                .iter()
                .any(|k| t.contains(k))
        }
        P::Chat => v
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|choices| {
                choices.iter().any(|ch| {
                    ["delta", "message"]
                        .iter()
                        .any(|k| ch.get(k).and_then(|c| c.get("refusal")).is_some())
                })
            }),
        P::NonDialog => false,
    }
}

fn extract_tool_fragments(
    protocol: crate::service::llm_gateway::Protocol,
    v: &Value,
) -> Vec<(u32, Option<String>, Option<String>, String)> {
    use crate::service::llm_gateway::Protocol as P;
    let mut out = Vec::new();
    match protocol {
        P::Chat => {
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
            if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
                    for key in ["delta", "message"] {
                        let Some(container) = ch.get(key) else {
                            continue;
                        };
                        if let Some(calls) = container.get("tool_calls").and_then(|c| c.as_array())
                        {
                            for (i, call) in calls.iter().enumerate() {
                                let idx = call
                                    .get("index")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(i as u64)
                                    as u32;
                                let id = synth(idx, call.get("id").and_then(|x| x.as_str()));
                                let name = call
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let args = norm_args(
                                    call.get("function").and_then(|f| f.get("arguments")),
                                );
                                out.push((idx, Some(id), name, args));
                            }
                        }
                        for legacy_key in ["function_call", "custom_tool_call"] {
                            let Some(legacy) = container.get(legacy_key) else {
                                continue;
                            };
                            let items: Vec<&Value> = match legacy {
                                Value::Array(a) => a.iter().collect(),
                                Value::Object(_) => vec![legacy],
                                _ => vec![],
                            };
                            for (i, item) in items.iter().enumerate() {
                                let Some(obj) = item.as_object() else {
                                    continue;
                                };
                                if legacy_key == "function_call" {
                                    let idx = ci as u32;
                                    let name = obj
                                        .get("name")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = norm_args(obj.get("arguments"));
                                    out.push((idx, Some(synth(idx, None)), name, args));
                                } else {
                                    let idx = i as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    if name.is_some() || !args.is_empty() || id_raw.is_some() {
                                        out.push((idx, Some(synth(idx, id_raw)), name, args));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        P::Anthropic => {
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
            let mut blocks: Vec<&Value> = Vec::new();
            for key in ["content_block", "delta"] {
                if let Some(b) = v.get(key) {
                    blocks.push(b);
                }
            }
            // §2.4/P0-2.2：分桶复用共享 `anthropic_bucket_index`
            // （外层事件序号优先，内层回退，与非流单实现）。
            let outer_index = v.get("index").and_then(|x| x.as_u64()).map(|n| n as u32);
            if let Some(arr) = v.get("content").and_then(|c| c.as_array()) {
                blocks.extend(arr.iter());
            }
            if let Some(msg) = v.get("message").and_then(|m| m.get("content")) {
                if let Some(arr) = msg.as_array() {
                    blocks.extend(arr.iter());
                } else if msg.is_object() {
                    blocks.push(msg);
                }
            }
            for (i, b) in blocks.iter().enumerate() {
                let idx = llm_gateway::anthropic_bucket_index(outer_index, b, i as u32);
                if let Some(fc) = b.get("function_call").and_then(|x| x.as_object()) {
                    let name = fc
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let args = norm_args(fc.get("arguments"));
                    out.push((idx, Some(synth(idx, None)), name, args));
                    continue;
                }
                if let Some(cc) = b.get("custom_tool_call") {
                    match cc {
                        Value::Object(obj) => {
                            let id_raw = obj
                                .get("id")
                                .or_else(|| obj.get("call_id"))
                                .or_else(|| obj.get("tool_call_id"))
                                .and_then(|x| x.as_str());
                            let name = obj
                                .get("name")
                                .or_else(|| obj.get("tool_name"))
                                .and_then(|x| x.as_str())
                                .or_else(|| {
                                    obj.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|x| x.as_str())
                                })
                                .map(|s| s.to_string());
                            let args = norm_args(
                                obj.get("arguments")
                                    .or_else(|| obj.get("input"))
                                    .or_else(|| obj.get("args")),
                            );
                            out.push((idx, Some(synth(idx, id_raw)), name, args));
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    let jdx = j as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    out.push((jdx, Some(synth(jdx, id_raw)), name, args));
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let is_tool = b.get("type").and_then(|x| x.as_str()).is_some_and(|t| {
                    t.contains("tool_use") || t.contains("function") || t.contains("custom")
                }) || b.get("name").is_some()
                    || b.get("partial_json").is_some()
                    || b.get("input").is_some()
                    || b.get("function_call").is_some()
                    || b.get("custom_tool_call").is_some();
                if !is_tool {
                    continue;
                }
                let id_raw = b.get("id").and_then(|x| x.as_str());
                let name = b
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let args = norm_args(
                    b.get("partial_json")
                        .or_else(|| b.get("input"))
                        .or_else(|| b.get("arguments")),
                );
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                out.push((idx, Some(synth(idx, id_raw)), name, args));
            }
        }
        P::Responses => {
            let ev_type = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = v
                        .get("delta")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !delta.is_empty() || name.is_some() {
                        out.push((idx, id, name, delta));
                    }
                } else if ev_type.ends_with(".done") {
                    let args = v
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !args.is_empty() || name.is_some() {
                        out.push((idx, id, name, args));
                    }
                }
                return out;
            }
            // C10 检索事件计 tool（与非流一致）：名按类型派生，参按
            // queries 回退；中间态同样建槽审计，误报优于漏审。
            if let Some(rname) = llm_gateway::retrieval_tool_name(ev_type) {
                let idx = v
                    .get("output_index")
                    .or_else(|| v.get("index"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u32;
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some(rname.to_string()));
                let mut args = v
                    .as_object()
                    .map(llm_gateway::retrieval_args)
                    .unwrap_or_default();
                if args.is_empty()
                    && let Some(d) = v.get("delta").and_then(|x| x.as_str())
                {
                    args = d.to_string();
                }
                out.push((idx, id, name, args));
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = v.get("item")
                && let Some(type_str) = item.get("type").and_then(|x| x.as_str())
                && (type_str == "function_call"
                    || llm_gateway::retrieval_tool_name(type_str).is_some())
            {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let mut args = item
                    .get("arguments")
                    .map(|a| {
                        if let Some(s) = a.as_str() {
                            s.to_string()
                        } else {
                            a.to_string()
                        }
                    })
                    .unwrap_or_default();
                if args.is_empty()
                    && let Some(obj) = item.as_object()
                {
                    args = llm_gateway::retrieval_args(obj);
                }
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| llm_gateway::retrieval_tool_name(type_str).map(|s| s.to_string()));
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                if !args.is_empty() || name.is_some() {
                    out.push((idx, id, name, args));
                }
                return out;
            }
            if ev_type == "response.output_item.added"
                && let Some(item) = v.get("item")
            {
                // C9 起始事件建槽（与非流同形）：`added` 携带 function_call
                // 名/id（尚无 arguments），产出空参数分片经既有
                // `push_responses_fragment` 建槽，复用按槽缓冲；
                // C10 检索起始同样建槽（名按类型派生）；非 tool 形态直返。
                let type_str = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                let is_tool = type_str.contains("function_call")
                    || type_str.contains("custom_tool_call")
                    || type_str.contains("tool")
                    || llm_gateway::retrieval_tool_name(type_str).is_some()
                    || item.get("name").is_some();
                if !is_tool {
                    return out;
                }
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| llm_gateway::retrieval_tool_name(type_str).map(|s| s.to_string()));
                out.push((idx, id, name, String::new()));
                return out;
            }
            if v.get("item").is_some() {
                return out;
            }
            if let Some(output) = v.get("output").and_then(|o| o.as_array()) {
                // C9：复用非流 `custom_obj_to_call` 取字段优先级
                //（`id/call_id/tool_call_id`、`name/tool_name/function.name`、
                // `arguments/input/args`），流/非流同调用同结论。
                let custom_parts =
                    |obj: &serde_json::Map<String, Value>| -> (Option<String>, Option<String>, String) {
                        let cid = obj
                            .get("id")
                            .or_else(|| obj.get("call_id"))
                            .or_else(|| obj.get("tool_call_id"))
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string());
                        let cname = obj
                            .get("name")
                            .or_else(|| obj.get("tool_name"))
                            .and_then(|x| x.as_str())
                            .or_else(|| {
                                obj.get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                            })
                            .map(|s| s.to_string());
                        let cargs = obj
                            .get("arguments")
                            .or_else(|| obj.get("input"))
                            .or_else(|| obj.get("args"))
                            .map(|a| {
                                if let Some(s) = a.as_str() {
                                    s.to_string()
                                } else if a.is_null() {
                                    String::new()
                                } else {
                                    a.to_string()
                                }
                            })
                            .unwrap_or_default();
                        (cid, cname, cargs)
                    };
                for (i, item) in output.iter().enumerate() {
                    // 非流同形 `is_tool` 前置门：非 tool 项直接跳过，不得建槽。
                    let item_type = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    let is_tool = item_type.contains("function_call")
                        || item_type.contains("custom_tool_call")
                        || item_type.contains("tool")
                        || llm_gateway::retrieval_tool_name(item_type).is_some()
                        || item.get("name").is_some()
                        || item.get("arguments").is_some()
                        || item.get("input").is_some();
                    if !is_tool {
                        continue;
                    }
                    // C10 检索调用直建分片（与非流同形：名派生+queries 回退）。
                    if let Some(obj) = item.as_object()
                        && let Some(rname) = llm_gateway::retrieval_tool_name(item_type)
                    {
                        let cid = obj
                            .get("id")
                            .and_then(|x| x.as_str())
                            .or_else(|| obj.get("call_id").and_then(|x| x.as_str()))
                            .map(|s| s.to_string());
                        let cname = obj
                            .get("name")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| Some(rname.to_string()));
                        out.push((i as u32, cid, cname, llm_gateway::retrieval_args(obj)));
                        continue;
                    }
                    if let Some(obj) = item.as_object() {
                        if let Some(Value::Object(inner)) = obj.get("custom_tool_call") {
                            let (cid, cname, cargs) = custom_parts(inner);
                            out.push((i as u32, cid, cname, cargs));
                            continue;
                        }
                        let (cid, cname, cargs) = custom_parts(obj);
                        if cname.is_some() || !cargs.is_empty() || cid.is_some() {
                            out.push((i as u32, cid, cname, cargs));
                            continue;
                        }
                    }
                    let args = item
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let name = item
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let id = item
                        .get("id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    if !args.is_empty() || name.is_some() {
                        out.push((i as u32, id, name, args));
                    }
                }
            }
        }
        P::NonDialog => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_legacy_function_call_matches_nonstream() {
        use crate::service::llm_gateway::Protocol as P;
        let stream_delta = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags = extract_tool_fragments(P::Chat, &stream_delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 0);
        assert_eq!(frags[0].1.as_deref(), Some("call_stable_0"));
        assert_eq!(frags[0].2.as_deref(), Some("old"));
        assert_eq!(frags[0].3, "{\"x\":1}");
        let non_stream = serde_json::json!({"choices":[{"message":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags2 = extract_tool_fragments(P::Chat, &non_stream);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("old"));
        assert_eq!(frags2[0].1.as_deref(), Some("call_stable_0"));
        let legacy_arr = serde_json::json!({"choices":[{"delta":{"function_call":[{"name":"a","arguments":"{}"}]}}]});
        let frags3 = extract_tool_fragments(P::Chat, &legacy_arr);
        assert!(frags3.is_empty() || frags3.len() == 1);
    }

    #[test]
    fn dual_tool_calls_accumulate_independently_by_index() {
        use crate::service::llm_gateway::Protocol as P;
        let two = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"call_a","type":"function","function":{"name":"exec_a","arguments":"{\"x\":1}"}},
            {"index":1,"id":"call_b","type":"function","function":{"name":"exec_b","arguments":"{\"y\":2}"}}
        ]}}]});
        let frags = extract_tool_fragments(P::Chat, &two);
        assert_eq!(frags.len(), 2, "双路须各一条: {frags:?}");
        assert_eq!(frags[0].0, 0);
        assert_eq!(frags[1].0, 1);
        assert_eq!(frags[0].2.as_deref(), Some("exec_a"));
        assert_eq!(frags[1].2.as_deref(), Some("exec_b"));
        assert!(frags[0].3.contains("\"x\":1") && !frags[0].3.contains("\"y\""));
        assert!(frags[1].3.contains("\"y\":2") && !frags[1].3.contains("\"x\""));
    }

    #[test]
    fn anthropic_array_content_aligns_with_gateway() {
        use crate::service::llm_gateway::Protocol as P;
        let content_arr = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}]});
        let frags = extract_tool_fragments(P::Anthropic, &content_arr);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].1.as_deref(), Some("a1"));
        assert_eq!(frags[0].2.as_deref(), Some("bash"));
        assert_eq!(frags[0].3, r#"{"cmd":"ls"}"#);
        let msg_content = serde_json::json!({"message":{"content":[{"type":"tool_use","id":"m1","name":"run","input":{"p":2}}]}});
        let frags2 = extract_tool_fragments(P::Anthropic, &msg_content);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].1.as_deref(), Some("m1"));
        let delta =
            serde_json::json!({"delta":{"type":"tool_use","name":"t","partial_json":"{\"a\":"}});
        let frags3 = extract_tool_fragments(P::Anthropic, &delta);
        assert_eq!(frags3.len(), 1);
        assert_eq!(frags3[0].1.as_deref(), Some("call_stable_0"));
        let text_only = serde_json::json!({"delta":{"type":"text","text":"hi"}});
        assert!(extract_tool_fragments(P::Anthropic, &text_only).is_empty());
    }

    #[test]
    fn anthropic_buckets_by_event_index_not_position() {
        use crate::service::llm_gateway::Protocol as P;
        let first = serde_json::json!({"content_block":{"type":"tool_use","index":4,"id":"a4","name":"t","input":{}}});
        let frags = extract_tool_fragments(P::Anthropic, &first);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 4);
        let second =
            serde_json::json!({"delta":{"type":"input_json_delta","index":4,"partial_json":"{}"}});
        let frags2 = extract_tool_fragments(P::Anthropic, &second);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].0, 4);
        assert_eq!(frags2[0].3, "{}");
    }

    #[test]
    fn responses_delta_carries_sequence_and_done_is_full() {
        use crate::service::llm_gateway::Protocol as P;
        let delta = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"it1","sequence_number":3,"delta":"{\"a\":"});
        let frags = extract_tool_fragments(P::Responses, &delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(extract_responses_seq(&delta), Some(3));
        assert!(!AuditHold::is_complete_event(&delta));
        let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"it1","sequence_number":4,"name":"run","arguments":"{\"a\":1}"});
        let frags2 = extract_tool_fragments(P::Responses, &done);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("run"));
        assert!(AuditHold::is_complete_event(&done));
    }

    #[test]
    fn minor_events_passthrough_without_audit() {
        use crate::service::llm_gateway::Protocol as P;
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"type":"thinking_delta","thinking":"hmm"})
        ));
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"delta":{"type":"signature_delta","signature":"s"}})
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.reasoning.delta","delta":"x"})
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.mcp_call.in_progress"})
        ));
        assert!(is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"delta":{"refusal":"no"}}]})
        ));
        assert!(!is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"delta":{"content":"hi"}}]})
        ));
        assert!(!is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"x"})
        ));
    }

    #[test]
    fn responses_added_builds_slot_so_truncation_stays_auditable() {
        // C9 起始截断漏审回归：仅 `added` 到达（`.done` 前截断）时槽须已建，
        // 名/id 保留至审计三元组；非 tool 起始不建槽。
        use crate::service::llm_gateway::Protocol as P;
        let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
        let frags = extract_tool_fragments(P::Responses, &added);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 2);
        assert_eq!(frags[0].1.as_deref(), Some("call-9"));
        assert_eq!(frags[0].2.as_deref(), Some("run"));
        assert!(frags[0].3.is_empty());
        // 复用既有按槽缓冲建槽：空参分片入槽后，即使零参数到达完成点，
        // 审计仍可见起始名（截断前可审计，不断链漏审）。
        let mut hold = AuditHold::new(1_048_576);
        for (idx, id, name, args) in &frags {
            let key = AuditHold::responses_key(id.as_deref(), *idx);
            hold.push_responses_fragment(&key, *idx, None, id.as_deref(), name.as_deref(), args);
            hold.mark_responses_done(&key, None);
        }
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0, 2);
        assert_eq!(triples[0].1, "run");
        let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
        assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
    }

    #[test]
    fn responses_custom_tool_call_stream_matches_nonstream() {
        // C9 流式 custom 覆盖：同调用在流/非流须同结论（名/参/id 一致）。
        use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
        let nested = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
        let frags = extract_tool_fragments(P::Responses, &nested);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].2.as_deref(), Some("ct"));
        assert_eq!(frags[0].3, "{}");
        let calls = extract_tool_calls(P::Responses, &nested);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), frags[0].2.as_deref());
        assert_eq!(calls[0].args, frags[0].3);
        // 裸回退形态（`tool_name`+`input` 别名）双向同解。
        let bare =
            serde_json::json!({"output":[{"type":"tool","tool_name":"grep","input":{"p":1}}]});
        let frags2 = extract_tool_fragments(P::Responses, &bare);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("grep"));
        assert_eq!(frags2[0].3, r#"{"p":1}"#);
        let calls2 = extract_tool_calls(P::Responses, &bare);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].name.as_deref(), Some("grep"));
        assert_eq!(calls2[0].args, r#"{"p":1}"#);
        // 纯消息项双向皆不建槽。
        let msg = serde_json::json!({"output":[{"type":"message","id":"m1","content":[]}]});
        assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
        assert!(extract_tool_calls(P::Responses, &msg).is_empty());
    }

    #[test]
    fn retrieval_calls_reach_identical_verdicts_across_modes() {
        // C10 同调用同结论：同一检索调用经流/非流须得同一审计结论。
        use crate::{
            config::AuditMode,
            service::{
                audit::{AuditPolicy, evaluate},
                llm_gateway::{Protocol as P, extract_tool_calls},
            },
        };
        let policy = AuditPolicy::default_policy();
        let nonstream = serde_json::json!({"output":[{"type":"file_search_call","id":"fs1","queries":["rm -rf /"]}]});
        let calls = extract_tool_calls(P::Responses, &nonstream);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), Some("file_search"));
        assert!(calls[0].args.contains("rm -rf /"));
        let stream = serde_json::json!({"type":"response.file_search_call.completed","output_index":0,"item_id":"fs1","queries":["rm -rf /"]});
        let frags = extract_tool_fragments(P::Responses, &stream);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].2.as_deref(), Some("file_search"));
        assert!(frags[0].3.contains("rm -rf /"));
        assert!(
            !is_minor_event(P::Responses, &stream),
            "检索事件不再列为次要"
        );
        let v_stream = evaluate(
            AuditMode::Block,
            frags[0].2.as_deref().unwrap_or(""),
            &frags[0].3,
            &policy,
        );
        let v_nonstream = evaluate(
            AuditMode::Block,
            calls[0].name.as_deref().unwrap_or(""),
            &calls[0].args,
            &policy,
        );
        assert!(
            matches!(v_stream, crate::service::audit::AuditVerdict::Block { .. }),
            "流式危险检索须阻断"
        );
        assert!(
            matches!(
                v_nonstream,
                crate::service::audit::AuditVerdict::Block { .. }
            ),
            "非流危险检索须阻断"
        );
        // 良性检索双向同放行；检索外围仍透传不审计。
        let benign_ns = serde_json::json!({"output":[{"type":"web_search_call","id":"w1","queries":["hello"]}]});
        let benign_calls = extract_tool_calls(P::Responses, &benign_ns);
        assert_eq!(benign_calls[0].name.as_deref(), Some("web_search"));
        let benign_s = serde_json::json!({"type":"response.web_search_call.completed","output_index":0,"item_id":"w1","queries":["hello"]});
        let benign_frags = extract_tool_fragments(P::Responses, &benign_s);
        assert_eq!(benign_frags[0].2.as_deref(), Some("web_search"));
        assert!(matches!(
            evaluate(AuditMode::Block, "web_search", &benign_frags[0].3, &policy),
            crate::service::audit::AuditVerdict::Allow
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.reasoning.delta"})
        ));
    }

    #[test]
    fn stream_interleaved_outer_index_matches_nonstream_slot() {
        // P0-2.3 回归：流式分桶与非流同槽（外层 0/1 胜过内层 3/5）。
        use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
        let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
        let frags = extract_tool_fragments(P::Anthropic, &start0);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 0, "流式外层 0 须胜过内层 3");
        let calls = extract_tool_calls(P::Anthropic, &start0);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, frags[0].0, "流/非流同槽");
        let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
        let frags1 = extract_tool_fragments(P::Anthropic, &d1);
        assert_eq!(frags1.len(), 1);
        assert_eq!(frags1[0].0, 1, "流式外层 1 须胜过内层 5");
        let calls1 = extract_tool_calls(P::Anthropic, &d1);
        assert_eq!(calls1.len(), 1);
        assert_eq!(calls1[0].index, frags1[0].0, "流/非流同槽");
    }

    #[test]
    fn pump_entry_clamps_hold_limits() {
        // P0-4.1：0→1MB 默认，超 8MB→截断；pii 0（关闭直通）保留。
        use crate::config::{AUDIT_HOLD_MAX_BYTES_DEFAULT, AUDIT_SUBLIMIT_CEILING_BYTES};
        assert_eq!(
            clamp_pump_limits(0, 64),
            (AUDIT_HOLD_MAX_BYTES_DEFAULT as usize, 64)
        );
        assert_eq!(clamp_pump_limits(1_048_576, 64), (1_048_576, 64));
        assert_eq!(
            clamp_pump_limits(16 * 1024 * 1024, 64),
            (AUDIT_SUBLIMIT_CEILING_BYTES, 64)
        );
        assert_eq!(
            clamp_pump_limits(1_048_576, 0),
            (1_048_576, 0),
            "pii 0 为关闭直通信号，须保留"
        );
    }

    #[test]
    fn pending_tool_buffer_drains_by_slot_preserving_order() {
        // P0-3.1：缓冲按槽取出保到达序；全局完成全取，按槽完成只取对应槽。
        let mut pending: Vec<(Vec<u32>, String, String)> = vec![
            (vec![0], "e0".to_string(), "d0".to_string()),
            (vec![1], "e1".to_string(), "d1".to_string()),
            (vec![0, 1], "e2".to_string(), "d2".to_string()),
        ];
        let slot0 = take_pending_tool_inputs(&mut pending, Some(0));
        assert_eq!(slot0.len(), 2, "含槽 0 的两帧须取出");
        assert_eq!(pending.len(), 1, "纯槽 1 帧须保留");
        let rest = take_pending_tool_inputs(&mut pending, None);
        assert_eq!(rest.len(), 1, "全局完成取空剩余");
        assert!(pending.is_empty());
    }

    #[test]
    fn refusal_message_shape_passthrough_as_minor() {
        use crate::service::llm_gateway::Protocol as P;
        assert!(is_minor_event(
            P::Chat,
            &serde_json::json!({"choices":[{"message":{"refusal":"no"}}]})
        ));
        assert!(is_minor_event(
            P::Anthropic,
            &serde_json::json!({"type":"redacted_thinking","redacted_data":"x"})
        ));
        assert!(!is_minor_event(
            P::NonDialog,
            &serde_json::json!({"refusal":"no"})
        ));
    }
}
