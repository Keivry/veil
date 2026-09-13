//! 流泵终止收尾（H5/D5 自 `spawn.rs` 拆出）：截断丢弃、残余分类、D6 断流终端
//! 与真空流最小终止合成。帧循环主体留在 `spawn.rs`，此处仅收尾，行为不变。

use {
    super::{
        super::{
            super::protocol_header_value,
            carry::TokenCarry,
            decide,
            event::should_synthesize_empty_stream,
            synth_flush::midstream_terminal,
        },
        frame_feed::{drain_prefix_hold, feed_output_frame},
    },
    crate::service::{
        block_inject,
        credential_vault::CredentialVault,
        llm_gateway::{self, GatewayMetrics, Protocol},
        pii::PiiDetector,
        redaction::{BoundaryHold, PrefixHold, Scope},
        sse::{SseParser, StreamMeta, TruncatedMode, classify_residue, set_truncated},
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
    } = ctx;
    let mut terminal_sent = terminal_sent_in;
    let mut any_frame_sent = any_frame_sent_in;

    // P0-3.1/TSS-03：截断丢弃未完成 tool 分片（缓冲帧永不透传下游），记
    // `truncated_tool_dropped` 并 warn；终端策略统一交下方 D6 收尾路径。
    let truncated_tool_dropped = !pending_tool_frames.is_empty();
    if truncated_tool_dropped {
        let dropped = pending_tool_frames.len() as u64;
        pending_tool_frames.clear();
        metrics.record_truncated_tool_dropped(dropped);
        tracing::warn!("LLM 截断丢弃残缺 tool 分片: {dropped} 帧");
    }
    let stream_truncated = transport_error || truncated_tool_dropped;
    drain_prefix_hold(prefix_hold, boundary, boundary_spans, agg);
    if let Some((fp, fd)) = boundary.flush() {
        agg.push_str(&fp);
        agg.push_str(&format!("data: {fd}\n\n"));
    }
    if !agg.is_empty() {
        metrics.add_sse_event();
        let _ = pump_tx.send(std::mem::take(agg)).await;
        *forwarded += 1;
        any_frame_sent = true;
    }
    let residual = parser.residual_json_aware();
    // 残余分类（§2.6）：None 直接丢弃，不得 `data:` 直发；
    // BOM/`[DONE]`/空白同样归入丢弃，终端去重已处理。
    if let Some(classified) = classify_residue(&residual) {
        let (restored, spans) = resp_scope.restore_response_with_spans(resp_vault, &classified);
        let scanned = resp_scope
            .redact_response_new_pii_with_skip(resp_vault, resp_detector, &restored, &spans)
            .await;
        if !scanned.is_empty() {
            feed_output_frame(
                prefix_hold,
                boundary,
                resp_detector,
                resp_vault,
                boundary_spans,
                agg,
                (String::new(), scanned),
            )
            .await;
            drain_prefix_hold(prefix_hold, boundary, boundary_spans, agg);
            if let Some((fp, fd)) = boundary.flush() {
                agg.push_str(&fp);
                agg.push_str(&format!("data: {fd}\n\n"));
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
            conv_id.as_deref(),
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
                if protocol == Protocol::Responses {
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
