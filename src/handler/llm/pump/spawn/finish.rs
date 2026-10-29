//! 流泵收尾——`terminal::finalize` 调用 + 指标记录 + `PumpOutcome`。

use {
    super::{
        super::{PumpOutcome, event::now_secs},
        setup::{PumpEnv, PumpLoopState},
        terminal::{self, TerminalCtx},
    },
    crate::service::{
        metrics::ChatRecord,
        request_log::StreamOutcome,
        sse::{SseParser, TruncatedMode},
    },
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
        ttft: &env.ttft,
    })
    .await;
    env.hold_gate.store(false, Ordering::Relaxed);
    let counted = env.admin_metrics.record_chat(ChatRecord {
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
    record_request_row(env, &state, counted);
    PumpOutcome {
        forwarded: state.forwarded,
        block_injected: state.terminator.block_injected(),
        terminal_injected: state.meta.terminal_injected,
        blocked_index,
    }
}

/// 流式请求的「恰好一行」落点（design §1.2）：真实上游状态 + 终态字段一次补全，
/// 由 [`StreamGuard::finish`] 取走待写行后交 `RequestLog::record`（幂等，只写一行）。
/// `counted` 取 `record_chat` 返回值——与 KPI `requests` 按构造同集合（design §2）。
fn record_request_row(env: &PumpEnv, state: &PumpLoopState, counted: bool) {
    let Some(log) = env.stream_log.as_ref() else {
        return;
    };
    // 审计 hold 缓冲超限是「阻断非截断」：`truncated_mode` 保持 `None`（不污染
    // 截断指标），改由 `error_kind` 让该失败在 `/_admin/requests` 可见。
    // 上游 4xx/5xx 的真实状态分类优先（那才是根因）。
    let overflow_kind = state.audit_hold_overflow.then_some("audit_hold_overflow");
    let outcome = StreamOutcome {
        status: Some(log.upstream_status),
        error_kind: (log.upstream_status >= 400)
            .then_some("upstream_status")
            .or(overflow_kind),
        upstream_id: state.stream_first_id.as_deref(),
        finish_reason: state.stream_finish_reason.as_deref(),
        truncated_mode: state
            .meta
            .truncated_mode
            .as_ref()
            .map(TruncatedMode::as_str),
        usage: state.stream_usage.as_ref(),
        latency_ms: Some(env.req_start.elapsed().as_millis() as u64),
        ttft_ms: env.ttft.first_ms(),
        counted_metrics: Some(counted),
    };
    if let Some(row) = log.guard.finish(&outcome) {
        log.request_log.record(row);
    }
}
