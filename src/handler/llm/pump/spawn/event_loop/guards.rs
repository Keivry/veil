//! 帧级准入守卫（自 `event_loop.rs` 主处理搬移，分支/顺序/等待点不变）：
//! 粘滞拒绝抑制与 Responses 控制动作（error→failed 合成、重复去重、透传）。

use {
    crate::{
        handler::llm::pump::{
            decide::{self, ResponsesAction, StickyAction},
            event::{
                responses_error_object,
                responses_failed_incomplete,
                responses_synth_conv_id,
                sticky_terminal_event,
            },
            spawn::{
                setup::{PumpEnv, PumpLoopState},
                terminator::TerminalPlan,
            },
            synth_flush::flush_pre_terminal,
        },
        service::{
            audit::AuditHold,
            llm_gateway::tool::extract_tool_calls_with,
            sse::{SseEvent, is_done_payload, set_truncated},
        },
    },
    serde_json::Value,
};

/// 前置守卫：粘滞拒绝态抑制 + Responses 控制动作。返回 `true` 表示调用点应立即以
/// `EventFlow::Next` 消费本帧（不再透出）；`false` 继续常规数据帧处理。
pub(super) async fn apply_pre_emit_guards(
    state: &mut PumpLoopState,
    env: &PumpEnv,
    ev: &SseEvent,
    parsed: Option<&Value>,
) -> bool {
    if state.terminator.rejected_sticky() {
        // 纯函数决策；短路求值与 metrics 副作用留调用点：
        // 仅非空非 DONE 才解析/记 terminal_fallback（原语义不变）。
        let data_empty = ev.data.is_empty();
        let is_done = is_done_payload(&ev.data);
        let is_terminal = !data_empty
            && !is_done
            && sticky_terminal_event(env.protocol, parsed, &ev.data, &env.metrics);
        let is_tool_or_complete = parsed.is_some_and(|v| {
            !extract_tool_calls_with(false, env.protocol, v).is_empty()
                || AuditHold::is_audit_due_event(env.protocol, v)
        });
        if decide::sticky_suppress_action(
            state.terminator.rejected_sticky(),
            data_empty,
            is_done,
            is_terminal,
            is_tool_or_complete,
        ) == StickyAction::Drop
        {
            return true;
        }
    }
    if env.protocol.is_responses() && !ev.data.is_empty() {
        // 守卫：决策交纯函数 `responses_control_action`；
        // 已发终端时保持原语义不解析（terminal_fallback 计数不漂移）。
        let (is_failed, is_error) = if state.terminator.terminal_sent() {
            (false, false)
        } else {
            let (f, _, e) = responses_failed_incomplete(parsed, &ev.data, &env.metrics);
            (f, e)
        };
        match decide::responses_control_action(
            state.terminator.terminal_sent(),
            state.terminator.responses_failed_seen(),
            is_error,
            is_failed,
        ) {
            ResponsesAction::Ignore => return true,
            ResponsesAction::SynthesizeFailed => {
                // `error` 仅合成单帧 `response.failed`
                //（`response.error.message` 携带上游 error 文案），不注入
                // `output_index` 序列；`incomplete` 不在此列——原样透传并作为
                // 唯一终端（保留 `incomplete_details`，由 `is_terminal_event` 置位）。
                state.terminator.note_responses_failed();
                let fid = responses_synth_conv_id(
                    state.stream_first_id.as_deref(),
                    state.conv_id.as_deref(),
                    &env.metrics,
                );
                let err_obj = responses_error_object(parsed);
                // 合成终端前先 flush 待发帧，保证末段增量先下行。
                if flush_pre_terminal(&mut state.agg, &env.pump_tx, &env.metrics, &env.ttft).await {
                    state.forwarded += 1;
                    state.terminator.note_frame_sent();
                }
                // 收敛：`responses_failed_frame` 构造迁入 `plan_responses_error`；
                // 逐帧成功下行记 `add_sse_event`（不得增删）。
                // 合成 failed 帧 send 成功才置位终端，下游早断不撒谎。
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
                    // 传实际 `terminal_ok`，不得硬编码 `true`
                    //（`send` 失败即不置终端帧位、不落 `terminal_injected`）。
                    state
                        .terminator
                        .commit(&mut state.meta, kind, terminal_ok, terminal_ok);
                    // 观测与终端帧位解耦——`commit` 后无条件落截断观测
                    //（下游早断时观测仍落，不低于一次）；`set_truncated` 自带
                    // Responses-only 守卫，调用点不重复协议门控。
                    if let Some(mode) = truncated {
                        let _ =
                            set_truncated(&mut state.meta, env.protocol, mode, Some(&env.metrics));
                    }
                }
                // 无帧也可终止循环（无条件置 `terminated`）；
                // `ResponsesAction::DuplicateFailed` 仅调本方法。
                state.terminator.mark_loop_terminated();
                return true;
            }
            ResponsesAction::DuplicateFailed => {
                state.terminator.mark_loop_terminated();
                return true;
            }
            ResponsesAction::Passthrough => {
                if is_failed {
                    state.terminator.note_responses_failed();
                }
            }
        }
    }
    false
}
