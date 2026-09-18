//! 流泵终止收尾（H5/D5 自 `spawn.rs` 拆出）：截断丢弃、残余分类、D6 断流终端
//! 与真空流最小终止合成。帧循环主体留在 `spawn.rs`，此处仅收尾，行为不变。

use {
    super::{
        super::{
            super::protocol_header_value,
            carry::TokenCarry,
            decide,
            event::{record_emitted_events, should_synthesize_empty_stream},
            synth_flush::midstream_terminal,
        },
        frame_feed::{drain_prefix_hold, residual_frame_payload},
        restore_emit::{FrameSink, RestoredFrame, emit_restored_json_frame},
        terminator::{StreamTerminator, TerminalPlan},
    },
    crate::{
        approval::{PendingApprovals, PendingRecord},
        config::AuditMode,
        service::{
            audit::{self, AuditHold, AuditPolicy, AuditSink},
            credential_vault::CredentialVault,
            llm_gateway::{self, GatewayMetrics, Protocol},
            pii::PiiDetector,
            redaction::{BoundaryHold, PrefixHold, Scope},
            sse::{SseParser, StreamMeta, data_frame, set_truncated},
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
    /// R5-39：流式回显模型（阻断/截断/真空合成帧回显，缺失归 `unknown_model`）。
    pub stream_model: Option<&'a str>,
    pub transport_error: bool,
    /// CHC-5/2.24：Chat 干净收尾（已见非空 `finish_reason`），断流终端不记 open_ended。
    pub chat_finish_seen: bool,
    /// A-2/F-02：Responses 上游序号上界游标（阻断 7 帧序列与截断单帧的 base 来源）。
    pub responses_seq_cursor: Option<u64>,
    /// 1.2/2.2：终端状态机（取代 `terminal_sent`/`block_injected`/`any_frame_sent` 借用字段）。
    pub terminator: &'a mut StreamTerminator,
    pub forwarded: &'a mut usize,
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

pub(super) async fn finalize<F>(ctx: TerminalCtx<'_, F>) -> Option<u32>
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    let TerminalCtx {
        protocol,
        conv_id,
        stream_model,
        transport_error,
        chat_finish_seen,
        responses_seq_cursor,
        terminator,
        forwarded,
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
        // R7-01/D1：pending 槽终端最终审计（done 槽在前、pending 槽在后）——
        // 门控 `protocol.is_responses() && !hold.is_rejected()`；verdict 处置与
        // 上方 done 循环逐字一致（`blocked_index` 取该 triple 自身 `output_index`）。
        // 无截断的清理完成流已在全局完成臂 `release_pending_audited()` 释放，此处
        // 集合为空天然 no-op，同一槽 SHALL NOT 被二次审计。
        if !blocked && protocol.is_responses() && !hold.is_rejected() {
            for (idx, name, args) in hold.responses_pending_triples() {
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
        }
        if blocked {
            agg.clear();
            boundary.clear();
            prefix_hold.clear();
            pending_tool_frames.clear();
            // 2.2 收敛：`metrics` 保持现状 `None`；I-2 计数无 `add_sse_event`（BLOCKER-1）；
            // Block commit 无条件置终端/阻断位并回填 `mark_terminal`（现状 :153/:171）。
            if let TerminalPlan::Frames { kind, frames, .. } = terminator.plan_block(
                protocol,
                "audit-policy-block",
                conv_id.as_deref(),
                stream_model.unwrap_or(""),
                blocked_index.unwrap_or(0),
                responses_seq_cursor,
                None,
            ) {
                for f in frames {
                    let _ = pump_tx.send(f).await;
                }
                terminator.commit(meta, kind, true, true);
            } else {
                // R5-35/D3：已终端后收尾审计命中 Block——不注入第二终端，但保留
                // 阻断语义与观测（warn 不含明文/token；audit_blocks 经 audit_blocked）。
                terminator.note_terminal_reject_block();
                tracing::warn!(
                    protocol = protocol_header_value(protocol),
                    "已终端流收尾审计命中 Block，不注入第二终端（保留阻断语义与计数）"
                );
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
        terminator.note_frame_sent();
    }
    let residual = parser.residual_json_aware();
    let residual_payload = residual_frame_payload(&residual);
    // CHC-2/D7：残余分类（§2.6）+ 半帧丢弃——BOM/`[DONE]`/空白/半帧/非 JSON 一律
    // 丢弃；仅完整 JSON 载荷（已剥 `data:` 前缀）才放行，杜绝二次加前缀转发。
    // R8-02/D1：任一终端（上游终端/阻断）已发出后，残余帧恒丢弃——终端之后
    // SHALL NOT 下发任何数据帧；本守卫不影响上方 `drain_prefix_hold`/`boundary.flush`
    // 的终端前滞留送达通道，也不改正常 EOF（无终端）的残余放行语义。
    if !terminator.terminal_sent()
        && !terminator.block_injected()
        && let Some(payload) = residual_payload
    {
        // B1/A-9：残余帧由 `residual_frame_payload` 保证为完整 JSON，还原须走
        // `_json` 变体（按深度转义）——明文含 `"`/`\`/控制字符时仍为合法 JSON，
        // 与正常帧（`event_loop.rs` 两处）同口径；逐字插入变体会破帧。
        let (restored, spans) = resp_scope.restore_response_with_spans_json(resp_vault, &payload);
        let scanned = resp_scope
            .redact_response_new_pii_with_skip(resp_vault, resp_detector, &restored, &spans)
            .await;
        // R5-14/D5：脱敏链 fail-closed——本帧若触发熵源/内部故障，`scanned` 仍可能
        // 含未能 token 化的明文，MUST NOT 下发（与 `event_loop.rs` 主循环帧同口径）。
        // 此处上下文无 `apply_reject_block`，改为经唯一所有者 `StreamTerminator`
        // 注入协议阻断终端并提交；后续 D6 收尾因已终端而不再合成第二终端。
        if resp_scope.pii_unavailable() {
            tracing::warn!(
                protocol = protocol_header_value(protocol),
                "残余帧脱敏失败（PII 不可用），改注入协议阻断终端（不含明文）"
            );
            if let TerminalPlan::Frames { kind, frames, .. } = terminator.plan_block(
                protocol,
                "pii-unavailable",
                conv_id.as_deref(),
                stream_model.unwrap_or(""),
                blocked_index.unwrap_or(0),
                responses_seq_cursor,
                None,
            ) {
                for f in frames {
                    let _ = pump_tx.send(f).await;
                }
                terminator.commit(meta, kind, true, true);
            } else {
                // 已终端/已阻断：不注入第二终端，仅保留阻断语义与观测。
                terminator.note_terminal_reject_block();
            }
        } else if !scanned.is_empty() {
            // D/B-2：残余帧与正常帧共用 `emit_restored_json_frame`（守卫失败
            // 回退占位符帧），消除残余路径缺守卫的回退缺口。
            let _ = emit_restored_json_frame(
                &mut FrameSink {
                    prefix_hold: &mut *prefix_hold,
                    boundary: &mut *boundary,
                    detector: resp_detector,
                    vault: resp_vault,
                    scope: resp_scope,
                    boundary_spans,
                    agg: &mut *agg,
                },
                RestoredFrame {
                    prefix: "",
                    restored: scanned,
                    placeholder: &payload,
                    placeholder_parsed: None,
                    json_aware: true,
                    mask_fallback: true,
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
                terminator.note_frame_sent();
            }
        }
    }
    // D6/S11：统一断流终端收尾（合并既有 `finish_reason` 补发与截断合成，
    // 消除 `truncated_mode_set` 条件竞态）：未终端、未阻断且已发帧时按协议注入；
    // 真空流（零帧零残余）交下方空流守门补最小终止。
    if decide::should_apply_midstream_terminal(
        protocol,
        terminator.terminal_sent(),
        terminator.block_injected(),
        terminator.any_frame_sent(),
        stream_truncated,
    ) {
        // 3.1 收敛：终端帧选择迁入 `plan_midstream`（MAJOR-5 的 `metrics` 供 Responses
        // 归档回退计数）；`None` 即未开放/已终端（幂等，调用点零动作）。
        if let TerminalPlan::Frames {
            kind,
            frames,
            truncated,
        } = terminator.plan_midstream(
            protocol,
            conv_id.as_deref(),
            stream_model.unwrap_or(""),
            protocol.is_chat() && chat_finish_seen,
            responses_seq_cursor,
            Some(metrics),
        ) {
            let mid = midstream_terminal(
                protocol, &frames, truncated, boundary, agg, pump_tx, metrics,
            )
            .await;
            *forwarded += mid.forwarded as usize;
            if mid.forwarded > 0 {
                terminator.note_frame_sent();
            }
            // 调用点按 plan 携带的观测落 `set_truncated`（口径不变）。
            if let Some(mode) = truncated {
                let _ = set_truncated(meta, protocol, mode, Some(metrics));
            }
            // D9/S9：仅合成终端实际下行/收尾成立才置位（Chat/Responses 送成即标，
            // Anthropic 零合成帧按收尾成立计；下游早断 `frames_sent=false` 不置位）。
            // `delivered` 须以终端帧集非空为准，不用 `mid.forwarded`（其含
            // `flush_pre_terminal` 滞留帧，非终端帧）。
            let delivered = !frames.is_empty() && mid.terminal_sent;
            terminator.commit(meta, kind, mid.terminal_sent, delivered);
        }
    }
    // D4：空流合成守门以终端/任意帧状态位为准（残余 `send` 即记位），
    // 不依赖 `forwarded` 计数器；真空流（三位全假）仍合成三协议恰一终端帧。
    if should_synthesize_empty_stream(
        terminator.terminal_sent(),
        terminator.any_frame_sent(),
        terminator.block_injected(),
    ) {
        let proto_name = protocol_header_value(protocol);
        let tid = conv_id.clone().unwrap_or_else(|| {
            llm_gateway::resolve_conv_id(None, &serde_json::Value::Null, Some(metrics), "truncated")
                .0
        });
        // 3.2 收敛：真空流帧集与截断观测交 `plan_empty_stream`；I-4 无 `add_sse_event`
        // （BLOCKER-1，不得新增）。空帧集（未知/非对话协议）仅落 `set_truncated`；
        // 非空帧集先 `commit` 再落对应 truncation。
        if let TerminalPlan::Frames {
            kind,
            frames,
            truncated,
        } = terminator.plan_empty_stream(proto_name, &tid, stream_model.unwrap_or(""))
        {
            if frames.is_empty() {
                if let Some(mode) = truncated {
                    let _ = set_truncated(meta, protocol, mode, Some(metrics));
                }
            } else {
                for f in frames {
                    let _ = pump_tx.send(f).await;
                }
                terminator.commit(meta, kind, true, true);
                if let Some(mode) = truncated {
                    let _ = set_truncated(meta, protocol, mode, Some(metrics));
                }
            }
        }
    }
    carry.finish();
    blocked_index
}

#[cfg(test)]
mod residual_tests {
    use {
        super::*,
        crate::{
            handler::llm::stream_tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
            service::block_inject,
        },
    };

    #[tokio::test]
    async fn residual_after_upstream_terminal_is_dropped() {
        // R8-02/D1：上游终端帧后无空行收尾的完整 JSON 残余恒丢弃——
        // 终端后零数据帧、恰一终端。
        let body = b"event: response.completed\ndata: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"r1\",\"status\":\"completed\"}}\n\ndata: {\"type\":\"response.output_text.delta\",\"sequence_number\":2,\"delta\":\"late-residual\"}".to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", body).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
        ctx.pii_boundary_chars = 0;
        let (outcome, frames) = collect_pump(upstream, ctx).await;
        server.abort();
        let joined = frames.join("");
        assert!(
            joined.contains("response.completed"),
            "上游终端须送达: {joined}"
        );
        assert!(
            !joined.contains("late-residual"),
            "终端后残余须丢弃（零数据帧）: {joined}"
        );
        assert_eq!(
            block_inject::terminal_count(&frames, "responses"),
            1,
            "终端恰一: {joined}"
        );
        assert!(!outcome.block_injected, "正常终端非阻断: {joined}");
    }

    #[tokio::test]
    async fn residual_without_terminal_still_passes() {
        // R8-02/D1 对照：正常 EOF 且尚无任何终端时，残余放行语义与修复前一致。
        let body =
            b"data: {\"type\":\"response.output_text.delta\",\"sequence_number\":1,\"delta\":\"tail-kept\"}"
                .to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", body).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
        ctx.pii_boundary_chars = 0;
        let (_outcome, frames) = collect_pump(upstream, ctx).await;
        server.abort();
        let joined = frames.join("");
        assert!(joined.contains("tail-kept"), "无终端时残余须放行: {joined}");
    }

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

    #[tokio::test]
    async fn residual_frame_pii_unavailable_fails_closed_without_plaintext() {
        // R5-14/D5：残余帧触发脱敏链故障（熵源不可用）时 MUST NOT 下发明文，
        // 改经 StreamTerminator 注入协议阻断终端并保留阻断语义。
        let (scope, vault, detector) = fresh_arcs();
        scope.pii_scope().force_entropy_failure(true);
        let phone = "13812345678";
        let body =
            format!("data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{phone}\"}}")
                .into_bytes();
        let (url, server) = loopback_server(200, "text/event-stream", body).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let probe = scope.clone();
        let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
        ctx.pii_boundary_chars = 0;
        let (outcome, frames) = collect_pump(upstream, ctx).await;
        server.abort();
        let joined = frames.join("");
        assert!(probe.pii_unavailable(), "熵源故障须置位 pii_unavailable");
        assert!(!joined.contains(phone), "MUST NOT 下发未脱敏明文: {joined}");
        assert!(outcome.block_injected, "残余帧故障须保留阻断语义: {joined}");
    }
}
