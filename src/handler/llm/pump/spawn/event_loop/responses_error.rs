//! Responses 上游 `error` 帧的失败终端合成臂（自 `event_loop.rs` 拆出，纯搬移
//! 行为不变）。

use {
    super::EventFlow,
    crate::{
        handler::llm::pump::{
            event::{responses_error_object, responses_synth_conv_id},
            spawn::{
                frame_feed::drain_prefix_hold,
                setup::{PumpEnv, PumpLoopState},
                terminator::TerminalPlan,
            },
            synth_flush::flush_pre_terminal,
        },
        service::sse::set_truncated,
    },
    serde_json::Value,
};

/// P4/D4：`error` 仅合成单帧 `response.failed`
/// （`response.error.message` 携带上游 error 文案），不注入
/// `output_index` 序列；`incomplete` 不在此列——原样透传并作为
/// 唯一终端（保留 `incomplete_details`，由 `is_terminal_event` 置位）。
pub(super) async fn synthesize_responses_failed<F>(
    state: &mut PumpLoopState,
    env: &PumpEnv,
    parsed: Option<&Value>,
    boundary_spans: &F,
) -> EventFlow
where
    F: Fn(&str, usize) -> Vec<(usize, usize)>,
{
    state.terminator.note_responses_failed();
    let fid = responses_synth_conv_id(
        state.stream_first_id.as_deref(),
        state.conv_id.as_deref(),
        &env.metrics,
    );
    let err_obj = responses_error_object(parsed);
    // D3/S3：合成终端前先 flush 边界滞留帧，保证末段增量先下行。
    drain_prefix_hold(
        &mut state.prefix_hold,
        &mut state.boundary,
        boundary_spans,
        &mut state.agg,
    );
    if flush_pre_terminal(
        &mut state.boundary,
        &mut state.agg,
        &env.pump_tx,
        &env.metrics,
    )
    .await
    {
        state.forwarded += 1;
        state.terminator.note_frame_sent();
    }
    // 3.2 收敛：`responses_failed_frame` 构造迁入 `plan_responses_error`；
    // I-5 逐帧成功下行记 `add_sse_event`（BLOCKER-1，不得增删）。
    // D9/S9：合成 failed 帧 send 成功才置位终端，下游早断不撒谎。
    let mut terminal_ok = false;
    if let TerminalPlan::Frames {
        kind,
        frames,
        truncated,
    } = state.terminator.plan_responses_error(
        &fid,
        err_obj.as_ref().map(|(v, _)| v),
        err_obj.as_ref().and_then(|(_, s)| *s),
        state.stream_model.as_deref().unwrap_or(""),
    ) {
        for f in frames {
            if env.pump_tx.send(f).await.is_err() {
                break;
            }
            env.metrics.add_sse_event();
            state.forwarded += 1;
            state.terminator.note_frame_sent();
            terminal_ok = true;
        }
        // BLOCKER-3：传实际 `terminal_ok`，不得硬编码 `true`
        //（`send` 失败即不置终端帧位、不落 `terminal_injected`）。
        state
            .terminator
            .commit(&mut state.meta, kind, terminal_ok, terminal_ok);
        // R7-03/D3：观测与终端帧位解耦——`commit` 后无条件落截断观测
        //（下游早断时观测仍落，不低于一次）；`set_truncated` 自带
        // Responses-only 守卫，调用点不重复协议门控。
        if let Some(mode) = truncated {
            let _ = set_truncated(&mut state.meta, env.protocol, mode, Some(&env.metrics));
        }
    }
    // BLOCKER-3：无帧也可终止循环（对齐旧 `event_loop.rs:341` 无条件置
    // `terminated`）；`ResponsesAction::DuplicateFailed` 仅调本方法。
    state.terminator.mark_loop_terminated();
    EventFlow::Next
}
