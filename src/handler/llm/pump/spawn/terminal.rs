//! 流泵终止收尾（H5/D5 自 `spawn.rs` 拆出）：截断丢弃、残余分类、D6 断流终端
//! 与真空流最小终止合成。帧循环主体留在 `spawn.rs`，此处仅收尾，行为不变。

use {
    super::{
        super::{
            super::protocol_header_value,
            carry::TokenCarry,
            decide,
            event::{record_emitted_events, should_synthesize_empty_stream},
            synth_flush::{MidstreamInput, midstream_terminal},
        },
        frame_feed::{drain_prefix_hold, residual_frame_payload},
        restore_emit::{FrameSink, RestoredFrame, emit_restored_json_frame},
    },
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
        service::{
            audit::{self, AuditHold, AuditPolicy, AuditSink},
            block_inject,
            credential_vault::CredentialVault,
            llm_gateway::{self, GatewayMetrics, Protocol},
            pii::PiiDetector,
            redaction::{BoundaryHold, PrefixHold, Scope},
            sse::{SseParser, StreamMeta, TruncatedMode, data_frame, set_truncated},
        },
    },
};

/// 收尾上下文：帧循环可变状态与只读依赖经借用传入，避免跨模块可变借用 churn。
pub(super) struct TerminalCtx<'a, F>
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    pub protocol: Protocol,
    pub conv_id: &'a Option<String>,
    pub transport_error: bool,
    pub terminal_sent: bool,
    /// CHC-5/2.24：Chat 干净收尾（已见非空 `finish_reason`），断流终端不记 open_ended。
    pub chat_finish_seen: bool,
    /// A-2/F-02：Responses 上游序号上界游标（阻断 7 帧序列与截断单帧的 base 来源）。
    pub responses_seq_cursor: Option<u64>,
    pub any_frame_sent: bool,
    pub forwarded: &'a mut usize,
    pub block_injected: &'a mut bool,
    pub pending_tool_frames: &'a mut Vec<(Vec<u32>, String, String)>,
    pub metrics: &'a GatewayMetrics,
    pub prefix_hold: &'a mut PrefixHold,
    pub boundary: &'a mut BoundaryHold,
    pub boundary_spans: &'a F,
    pub agg: &'a mut String,
    pub pump_tx: &'a tokio::sync::mpsc::Sender<String>,
    pub resp_scope: &'a Scope,
    pub resp_vault: &'a CredentialVault,
    pub resp_detector: &'a PiiDetector,
    pub parser: &'a mut SseParser,
    pub meta: &'a mut StreamMeta,
    pub carry: &'a mut TokenCarry,
    /// RED-5：终端最终审计的持仓（清除前对未判定 tool 参数恰一次幂等审计）。
    pub hold: &'a mut AuditHold,
    pub audit_sink: &'a AuditSink,
    pub audit_mode: AuditMode,
    pub audit_policy: &'a AuditPolicy,
    pub approval_whitelist: &'a [String],
    pub audit_pending: &'a PendingApprovals,
}

pub(super) async fn finalize<F>(ctx: TerminalCtx<'_, F>)
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    let TerminalCtx {
        protocol,
        conv_id,
        transport_error,
        terminal_sent: terminal_sent_in,
        chat_finish_seen,
        responses_seq_cursor,
        any_frame_sent: any_frame_sent_in,
        forwarded,
        block_injected,
        pending_tool_frames,
        metrics,
        prefix_hold,
        boundary,
        boundary_spans,
        agg,
        pump_tx,
        resp_scope,
        resp_vault,
        resp_detector,
        parser,
        meta,
        carry,
        hold,
        audit_sink,
        audit_mode,
        audit_policy,
        approval_whitelist,
        audit_pending,
    } = ctx;
    let mut terminal_sent = terminal_sent_in;
    let mut any_frame_sent = any_frame_sent_in;

    // RED-8：截断未完成 tool 分片信息（清除前捕获，供审计/告警；不含参数明文）。
    let truncated_tool_dropped = !pending_tool_frames.is_empty();
    let truncated_count = pending_tool_frames.len() as u64;
    let truncated_slots: Vec<u32> = {
        let mut v: Vec<u32> = pending_tool_frames
            .iter()
            .flat_map(|(b, ..)| b.iter().copied())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };

    // RED-5：终端最终审计（恰一次幂等）——清除持仓/收尾前对未判定 tool 参数
    // 执行评估：截断/未完成或晚到分片在此被审且 `block` 模式阻断；已判定参数
    // 已由流内 `release_audited` 移出持仓，空持仓天然 no-op，不重复评估。
    let mut blocked_index: Option<u32> = None;
    if !matches!(audit_mode, AuditMode::Off) && !hold.is_rejected() {
        let mut blocked = false;
        for (idx, name, args) in hold.tool_triples() {
            match audit_sink
                .evaluate_and_record(
                    audit_mode,
                    &name,
                    &args,
                    audit_policy,
                    approval_whitelist,
                    Some(protocol_header_value(protocol)),
                )
                .await
            {
                audit::AuditVerdict::Block { .. } => {
                    hold.mark_rejected();
                    blocked_index = Some(idx);
                    blocked = true;
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
        if blocked {
            terminal_sent = true;
            agg.clear();
            boundary.clear();
            prefix_hold.clear();
            pending_tool_frames.clear();
            if !*block_injected {
                *block_injected = true;
                let reason = "audit-policy-block".to_string();
                for f in block_inject::ensure_event_lines(block_inject::protocol_block_frames(
                    protocol,
                    &reason,
                    conv_id.as_deref(),
                    blocked_index.unwrap_or(0),
                    None,
                    responses_seq_cursor,
                )) {
                    let _ = pump_tx.send(f).await;
                }
                block_inject::mark_terminal(meta);
            }
        } else {
            hold.release_audited();
        }
    }

    // P0-3.1/TSS-03 + RED-8：截断丢弃未完成 tool 分片（缓冲帧永不透传下游），
    // 记 `truncated_tool_dropped` + warn（含槽号/分片数，不含参数明文）并经审计
    // sink 记录「截断未完成」事件；终端策略统一交下方 D6 收尾路径。
    if truncated_tool_dropped {
        pending_tool_frames.clear();
        metrics.record_truncated_tool_dropped(truncated_count);
        tracing::warn!(
            slots = ?truncated_slots,
            frames = truncated_count,
            "LLM 截断丢弃残缺 tool 分片（不含参数明文）"
        );
        audit_sink.admin().push_event(
            "audit",
            &format!(
                "truncated unfinished tool: slots={truncated_slots:?} frames={truncated_count}"
            ),
            Some(protocol_header_value(protocol).to_string()),
        );
    }
    let stream_truncated = transport_error || truncated_tool_dropped;
    drain_prefix_hold(prefix_hold, boundary, boundary_spans, agg);
    if let Some((fp, fd)) = boundary.flush() {
        agg.push_str(&data_frame(&fp, &fd));
    }
    if !agg.is_empty() {
        record_emitted_events(metrics, agg);
        let _ = pump_tx.send(std::mem::take(agg)).await;
        *forwarded += 1;
        any_frame_sent = true;
    }
    let residual = parser.residual_json_aware();
    // CHC-2/D7：残余分类（§2.6）+ 半帧丢弃——BOM/`[DONE]`/空白/半帧/非 JSON 一律
    // 丢弃；仅完整 JSON 载荷（已剥 `data:` 前缀）才放行，杜绝二次加前缀转发。
    if let Some(payload) = residual_frame_payload(&residual) {
        // B1/A-9：残余帧由 `residual_frame_payload` 保证为完整 JSON，还原须走
        // `_json` 变体（按深度转义）——明文含 `"`/`\`/控制字符时仍为合法 JSON，
        // 与正常帧（`event_loop.rs` 两处）同口径；逐字插入变体会破帧。
        let (restored, spans) = resp_scope.restore_response_with_spans_json(resp_vault, &payload);
        let scanned = resp_scope
            .redact_response_new_pii_with_skip(resp_vault, resp_detector, &restored, &spans)
            .await;
        if !scanned.is_empty() {
            // D/B-2：残余帧与正常帧共用 `emit_restored_json_frame`（守卫失败
            // 回退占位符帧），消除残余路径缺守卫的回退缺口。
            let _ = emit_restored_json_frame(
                &mut FrameSink {
                    prefix_hold: &mut *prefix_hold,
                    boundary: &mut *boundary,
                    detector: resp_detector,
                    vault: resp_vault,
                    boundary_spans,
                    agg: &mut *agg,
                },
                RestoredFrame {
                    prefix: "",
                    restored: scanned,
                    placeholder: &payload,
                    placeholder_parsed: None,
                    json_aware: true,
                    feed: true,
                },
                metrics,
            )
            .await;
            drain_prefix_hold(prefix_hold, boundary, boundary_spans, agg);
            if let Some((fp, fd)) = boundary.flush() {
                agg.push_str(&data_frame(&fp, &fd));
            }
            if !agg.is_empty() {
                let _ = pump_tx.send(std::mem::take(agg)).await;
                any_frame_sent = true;
            }
        }
    }
    // D6/S11：统一断流终端收尾（合并既有 `finish_reason` 补发与截断合成，
    // 消除 `truncated_mode_set` 条件竞态）：未终端、未阻断且已发帧时按协议注入；
    // 真空流（零帧零残余）交下方空流守门补最小终止。
    if decide::should_apply_midstream_terminal(
        protocol,
        terminal_sent,
        *block_injected,
        any_frame_sent,
        stream_truncated,
    ) {
        let mid = midstream_terminal(
            protocol,
            MidstreamInput {
                conv_id: conv_id.as_deref(),
                clean_close: protocol.is_chat() && chat_finish_seen,
                seq_cursor: responses_seq_cursor,
            },
            boundary,
            agg,
            pump_tx,
            metrics,
            meta,
        )
        .await;
        *forwarded += mid.forwarded as usize;
        any_frame_sent |= mid.forwarded > 0;
        // D9/S9：仅合成终端实际下行才置位；全失败时保持未终端，守门如实。
        terminal_sent = mid.terminal_sent;
    }
    // D4：空流合成守门以终端/任意帧状态位为准（残余 `send` 即记位），
    // 不依赖 `forwarded` 计数器；真空流（三位全假）仍合成三协议恰一终端帧。
    if should_synthesize_empty_stream(terminal_sent, any_frame_sent, *block_injected) {
        let proto_name = protocol_header_value(protocol);
        let tid = conv_id.clone().unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(None, &serde_json::Value::Null, Some(metrics), "truncated")
                .0
        });
        // C8 open-ended：真空流 chat/anthropic 为空帧集（不伪造成功终止，
        // 仅记 open-ended 可观测，不置 block_injected）；Responses 合成 failed。
        let frames =
            block_inject::ensure_event_lines(block_inject::empty_stream_frames(proto_name, &tid));
        if frames.is_empty() {
            let _ = set_truncated(meta, protocol, TruncatedMode::OpenEnded, Some(metrics));
        } else {
            *block_injected = true;
            for f in frames {
                let _ = pump_tx.send(f).await;
            }
            let _ = set_truncated(
                meta,
                protocol,
                if protocol.is_responses() {
                    TruncatedMode::SynthesizedFailed
                } else {
                    TruncatedMode::OpenEnded
                },
                Some(metrics),
            );
            block_inject::mark_terminal(meta);
        }
    }
    carry.finish();
}

#[cfg(test)]
mod residual_tests {
    use {
        super::*,
        crate::handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
    };

    #[tokio::test]
    async fn residual_frame_json_escape_restore() {
        // B1/A-9：残余帧还原走 `_json` 变体——明文含 `"`/`\` 时仍为合法 JSON
        // （逐字插入变体会破帧），还原值精确、下游无解析错误。
        // B3 授权前提：token 须由本请求脱敏实际产出（minted-set）方可还原——
        // 先注册再经请求侧脱敏产出（其返回值经残缺清理剥离 token，不消费）；
        // 未产出 token 会被按未授权剥离，本用例即无从还原。
        let (scope, vault, detector) = fresh_arcs();
        let secret = "a\"b\\c";
        let token = vault.register(secret).expect("注册恒成功");
        let _ = scope.redact_request_plain(&vault, &detector, secret).await;
        let body =
            format!("data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{token}\"}}")
                .into_bytes();
        let (url, server) = loopback_server(200, "text/event-stream", body).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
        ctx.pii_boundary_chars = 0;
        let (_outcome, frames) = collect_pump(upstream, ctx).await;
        server.abort();
        let payload = frames
            .iter()
            .flat_map(|f| f.lines())
            .filter_map(|l| l.strip_prefix("data: "))
            .find(|p| p.contains("output_text.delta"))
            .expect("残余帧须送达下游");
        let v: serde_json::Value = serde_json::from_str(payload).expect("残余还原后须为合法 JSON");
        assert_eq!(v["delta"], secret, "明文须按 JSON 转义精确还原: {payload}");
    }
}
