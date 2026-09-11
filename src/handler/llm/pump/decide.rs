//! 流泵主循环纯决策函数（`veil-test-coverage-fill` T1/D1）：把 `spawn.rs`
//! 内联布尔判定抽为无 async/无 IO 纯函数，供真值表直接断言。metrics 计数
//! 与状态突变一律留在调用点（可观测计数不漂移），本模块只承载布尔/枚举
//! 决策，抽取为等价重构（既有 `stream_tests`/`proto_closeout_tests`/
//! `http_e2e_truncation_matrix` 全绿为锁定条件）。

use {super::event::outer_event_index, crate::service::llm_gateway::Protocol, serde_json::Value};

/// Responses 控制帧动作（N1 守卫 + error/failed 分类，对应 `spawn.rs` 原
/// 「terminal_sent 先于解析」语义；调用点决定副作用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponsesAction {
    /// 已发终端（N1 守卫）：后续控制帧一律忽略，不解析、不合成。
    Ignore,
    /// 未终端的 `type:"error"`：合成恰一 `response.failed` 终端。
    SynthesizeFailed,
    /// 重复 `failed`（`responses_failed_sent` 已置）：置终止并忽略。
    DuplicateFailed,
    /// 首见 `failed`（调用点置 `responses_failed_sent`）或非控制帧：透传。
    Passthrough,
}

/// N1 守卫/Responses 控制帧决策：`terminal_sent` 优先于一切（恒恰一终端）；
/// `error` 优先于 `failed`（分类互斥，纯函数仍显式定序）。
pub(super) fn responses_control_action(
    terminal_sent: bool,
    responses_failed_sent: bool,
    is_error: bool,
    is_failed: bool,
) -> ResponsesAction {
    if terminal_sent {
        return ResponsesAction::Ignore;
    }
    if is_error {
        return ResponsesAction::SynthesizeFailed;
    }
    if is_failed && responses_failed_sent {
        return ResponsesAction::DuplicateFailed;
    }
    ResponsesAction::Passthrough
}

/// rejected_sticky 抑制动作（粘滞阻断后帧处置）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StickyAction {
    /// 透传（普通文本帧交由后续终端守卫处理）。
    Pass,
    /// 丢弃（空数据/DONE/终端/tool/完成事件）。
    Drop,
}

/// 阻断粘滞后的帧抑制：仅「已粘滞且属 DONE/终端/tool/完成事件/空数据」为
/// Drop，普通文本帧 Pass。终端判定与解析副作用留调用点（短路求值不变）。
pub(super) fn sticky_suppress_action(
    rejected_sticky: bool,
    data_empty: bool,
    is_done: bool,
    is_terminal: bool,
    is_tool_or_complete: bool,
) -> StickyAction {
    if rejected_sticky && (data_empty || is_done || is_terminal || is_tool_or_complete) {
        StickyAction::Drop
    } else {
        StickyAction::Pass
    }
}

/// P1 补 DONE 四条件：Chat 且未终端且见 `finish_reason` 且未置截断观测。
pub(super) fn should_backfill_chat_done(
    protocol: Protocol,
    terminal_sent: bool,
    saw_finish_reason: bool,
    truncated_mode_set: bool,
) -> bool {
    protocol == Protocol::Chat && !terminal_sent && saw_finish_reason && !truncated_mode_set
}

/// tool hold-until-complete 缓冲判定：审计开启且 tool 事件且非完成且非
/// 按槽完成（完成帧走重放/透传，不缓冲）。
pub(super) fn should_buffer_tool_frame(
    audit_hold_on: bool,
    is_tool_event: bool,
    is_complete: bool,
    is_index_complete: bool,
) -> bool {
    audit_hold_on && is_tool_event && !is_complete && !is_index_complete
}

/// 完成帧重放槽（包装 `outer_event_index`）：全局完成 `Some(None)`、
/// 按槽完成 `Some(Some(idx))`（缺失外层序号返回 `None`，不误清）、
/// 非完成 `None`。
pub(super) fn tool_replay_slot(
    protocol: Protocol,
    v: &Value,
    is_complete: bool,
    is_index_complete: bool,
) -> Option<Option<u32>> {
    if is_complete {
        Some(None)
    } else if is_index_complete {
        outer_event_index(protocol, v).map(Some)
    } else {
        None
    }
}

/// 边界 hold 抑制：非次要事件且 hold 有滞留且本帧有输出。
pub(super) fn should_suppress_held_output(
    minor: bool,
    hold_held: bool,
    out_data_nonempty: bool,
) -> bool {
    !minor && hold_held && out_data_nonempty
}
