//! 流泵收尾——`terminal::finalize` 调用 + 指标记录 + `PumpOutcome`。

use {
    super::{
        super::{PumpOutcome, event::now_secs},
        setup::{PumpEnv, PumpLoopState},
        terminal::{self, TerminalCtx},
    },
    crate::service::{metrics::ChatRecord, sse::SseParser},
    std::sync::atomic::Ordering,
};

/// 收尾薄层——终结合成、指标记录与 `PumpOutcome` 组装（行为不变）。
pub(super) async fn finish(
    env: &PumpEnv,
    mut state: PumpLoopState,
    parser: &mut SseParser,
    transport_error: bool,
) -> PumpOutcome {
    let blocked_index = terminal::finalize(TerminalCtx {
        protocol: env.protocol,
        conv_id: &state.conv_id,
        stream_model: state.stream_model.as_deref(),
        transport_error,
        chat_finish_seen: state.chat_finish_seen,
        responses_seq_cursor: state.responses_seq_cursor,
        terminator: &mut state.terminator,
        forwarded: &mut state.forwarded,
        pending_tool_frames: &mut state.pending_tool_frames,
        metrics: &env.metrics,
        agg: &mut state.agg,
        pump_tx: &env.pump_tx,
        resp_scope: &env.resp_scope,
        resp_vault: &env.resp_vault,
        parser,
        meta: &mut state.meta,
        carry: &mut state.carry,
        hold: &mut state.hold,
        audit_sink: env.audit_sink.as_ref(),
        audit_mode: env.audit_mode,
        audit_policy: env.audit_policy.as_ref(),
        approval_whitelist: env.approval_whitelist.as_slice(),
        audit_pending: &env.audit_pending,
    })
    .await;
    env.hold_gate.store(false, Ordering::Relaxed);
    env.admin_metrics.record_chat(ChatRecord {
        protocol: env.protocol,
        model: state.stream_model.as_deref().unwrap_or(""),
        latency_ms: env.req_start.elapsed().as_millis() as u64,
        usage: state.stream_usage.as_ref(),
        truncated_mode: state.meta.truncated_mode.as_ref().map(|m| m.as_str()),
        is_precise: env.sqlite_precise,
        ts_secs: now_secs(),
    });
    let tally = env.redaction_tally;
    env.admin_metrics.record_aux_counts_extended(
        env.protocol,
        now_secs(),
        tally.pii_hits,
        tally.pii_miss,
        tally.cred_hits,
        u64::from(state.terminator.audit_blocked()),
    );
    PumpOutcome {
        forwarded: state.forwarded,
        block_injected: state.terminator.block_injected(),
        terminal_injected: state.meta.terminal_injected,
        blocked_index,
    }
}
