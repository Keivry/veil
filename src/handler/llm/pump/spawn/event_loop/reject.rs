//! C-3/D1（5.4）+ R5-26（5.3）：fail-closed 阻断臂——「拒绝即消费」结构化入口。
//!
//! `apply_reject_block` 恒消费触发帧（返回 `()`，调用点无条件早返回），SHALL NOT
//! 依赖各 `reject_reason` 设置点的隐式门控；阻断非截断，不记截断计数。

use {
    crate::handler::llm::pump::{
        event::outer_event_index,
        spawn::{
            setup::{PumpEnv, PumpLoopState},
            terminator::TerminalPlan,
        },
    },
    serde_json::Value,
};

/// C-3/D1（5.4）：fail-closed 阻断臂（`audit-policy-block` 与缓冲记账超限
/// `audit-hold-overflow` 共用）——置粘滞拒绝态、归还并清空 pending 缓冲（阻断
/// 非截断，不记截断计数）、恰一注入协议阻断帧。R5-26：返回 `()`，由调用点
/// 无条件消费触发帧（不落正常还原/放行路径）。
pub(super) async fn apply_reject_block(
    state: &mut PumpLoopState,
    env: &PumpEnv,
    v: &Value,
    reason: &str,
) {
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
    // R8-07/D3：阻断帧提交后立即终止泵读取循环（`Frames` 与幂等 `None` 两分支
    // 统一）——下游 mpsc 随泵任务结束而关闭，SHALL NOT 保持连接等待上游 EOF；
    // 阻断前已累计的 usage/观测保留，R7-01 的 `finalize` pending 终审仍恰一次。
    state.terminator.mark_loop_terminated();
}
