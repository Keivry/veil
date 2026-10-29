//! fail-closed 阻断臂——「拒绝即消费」结构化入口。
//!
//! `apply_reject_block` 恒消费触发帧（返回 `()`，调用点无条件早返回），SHALL NOT
//! 依赖各 `reject_reason` 设置点的隐式门控；阻断非截断，不记截断计数。

use {
    crate::handler::llm::pump::{
        AUDIT_HOLD_OVERFLOW_REASON,
        event::outer_event_index,
        spawn::{
            setup::{PumpEnv, PumpLoopState},
            terminator::TerminalPlan,
        },
    },
    serde_json::Value,
};

/// fail-closed 阻断臂（`audit-policy-block` 与缓冲记账超限
/// `audit-hold-overflow` 共用）——置粘滞拒绝态、归还并清空 pending 缓冲（阻断
/// 非截断，不记截断计数）、恰一注入协议阻断帧。返回 `()`，由调用点
/// 无条件消费触发帧（不落正常还原/放行路径）。
pub(super) async fn apply_reject_block(
    state: &mut PumpLoopState,
    env: &PumpEnv,
    v: &Value,
    reason: &str,
) {
    state.terminator.note_sticky_rejected();
    // 缓冲超限是「阻断非截断」的一种：不写 `truncated_mode`、不记截断计数，
    // 只在请求行落 `error_kind`（见 `spawn/finish.rs`）。策略拒绝
    // （`audit-policy-block`）不走此标记，语义不变。
    if reason == AUDIT_HOLD_OVERFLOW_REASON {
        state.audit_hold_overflow = true;
        // 单点告警：所有超限来源（缓冲帧数/零载荷/载荷字节/信封字节/聚合槽）
        // 都经本函数收敛，故在此发唯一一条 warn（不含参数明文）。数字取
        // `HoldRejectStats`——清仓已把实时计数器归零，只有该快照还留着现场值。
        let slots: Vec<u32> = state
            .pending_tool_frames
            .iter()
            .flat_map(|frame| frame.buckets.iter().copied())
            .collect();
        let stats = state.hold.last_reject_stats().unwrap_or_default();
        tracing::warn!(
            slots = ?slots,
            frames = stats.pending_frames,
            payload_bytes = stats.pending_payload_bytes,
            envelope_bytes = stats.pending_envelope_bytes,
            held_payload_bytes = stats.held_payload_bytes,
            "审计 hold 超限，已 fail-closed 阻断（不含参数明文）"
        );
    }
    state.agg.clear();
    // 阻断丢弃缓冲（阻断非截断，不记截断计数）；记账同步归还。
    // 归还口径与入账同源：直接取帧上保存的两块字节，零载荷帧数一并归还。
    let released: usize = state
        .pending_tool_frames
        .iter()
        .map(|frame| frame.payload_bytes)
        .sum();
    let released_envelope: usize = state
        .pending_tool_frames
        .iter()
        .map(|frame| frame.envelope_bytes)
        .sum();
    let released_zero: usize = state
        .pending_tool_frames
        .iter()
        .filter(|frame| frame.payload_bytes == 0)
        .count();
    state.hold.release_pending_frames(
        state.pending_tool_frames.len(),
        released,
        released_envelope,
        released_zero,
    );
    state.pending_tool_frames.clear();
    // 收敛：无 `add_sse_event`（不得新增）；`plan_block` 的
    // `None` 门等价既有 `if !block_injected` 幂等守卫。
    let blocked_index = outer_event_index(env.protocol, v).unwrap_or(0);
    if let TerminalPlan::Frames { kind, frames, .. } = state.terminator.plan_block(
        env.protocol,
        reason,
        state.conv_id.as_deref(),
        state.stream_model.as_deref().unwrap_or(""),
        blocked_index,
        state.responses_seq_cursor,
        Some(&env.metrics),
    ) {
        for f in frames {
            let _ = env.pump_tx.send(f).await;
        }
        state.terminator.commit(&mut state.meta, kind, true, true);
    }
}
