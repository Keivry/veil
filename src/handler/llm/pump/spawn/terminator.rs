//! 流式「恰一终端」状态机（`veil-stream-terminator-convergence` 1.1）：
//! `StreamTerminator` 是终端位与阻断/终止帧注入的**唯一所有者**。
//!
//! 设计依据：本 change `design.md` §2.1（状态/接口/逐 kind `commit` 语义）；
//! §2.3 的迁移窗口 `dead_code` 登记已于 3.3 移除（全部 `plan_*` 消费者落位）。
//! 本模块只承载**状态与帧选择**，不发送、
//! 不计数——`plan_*` 返回纯数据 [`TerminalPlan`]，调用点循环 `send`、按站点既有
//! 口径记账（BLOCKER-1：计数逐点保持不迁入本模块），随后 `commit` 回填终端位。
//!
//! 可见性：类型与 impl 声明 `pub(in crate::handler::llm::pump)`（MAJOR-4 选项 (a)）
//! ——测试模块 `pump::terminator_tests` 是 `spawn` 的**兄弟**，`pub(super)` 无法命名；
//! 测试保持在 `src/handler/llm/pump/terminator_tests.rs`。

use crate::service::{
    block_inject,
    llm_gateway::{GatewayMetrics, Protocol, resolve_conv_id},
    sse::{StreamMeta, TruncatedMode},
};

/// 「恰一终端」的内部状态：`Open` 为唯一可注入态，迁移到任一终态后无反向迁移。
/// `terminal_sent`（`Synthesized`/`UpstreamTerminal`/`ResponsesError`、及 `Blocked`）
/// 与 `block_injected`（`Blocked`/`EmptyStream`）是**两条独立语义位**——I-1/I-2 两者
/// 兼置、I-4 仅置阻断位、I-3/I-5 仅置终端位，故 `state` 必须保留该区分，不压成
/// 单一「已终止」布尔。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalState {
    Open,
    /// I-1/I-2 阻断帧注入（`terminal_sent`/`block_injected` 兼置）。
    Blocked,
    /// I-3 中途断流合成终端（`terminal_sent`）。
    Synthesized,
    /// I-4 真空流最小终止（`block_injected`）。
    EmptyStream,
    /// 上游终端（`event_terminal`/`[DONE]`，`terminal_sent`）。
    UpstreamTerminal,
    /// I-5 Responses `error` 合成 `response.failed`（`terminal_sent`）。
    ResponsesError,
}

/// 终端帧注入族（`commit` 的逐 kind 回填语义见 [`StreamTerminator::commit`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::handler::llm::pump) enum TerminalKind {
    Block,
    Midstream,
    EmptyStream,
    ResponsesError,
}

/// 注入计划（纯数据）。MAJOR-6：`None` 严格保留给「未开放 / 已终端」（幂等拒绝，
/// 调用点零动作）；**按设计零合成帧**（Anthropic 中途断流）用 `Frames` + 空
/// `frames` 表达，不得混用。`truncated` 由 plan 携带，调用点据此落 `set_truncated`
/// （观测口径不变）。
#[derive(Debug)]
pub(in crate::handler::llm::pump) enum TerminalPlan {
    None,
    Frames {
        kind: TerminalKind,
        frames: Vec<String>,
        truncated: Option<TruncatedMode>,
    },
}

/// 流式「恰一终端」状态机。字段**全私有**，仅经访问器（读）与变更器/`commit`（写）
/// 交互；持有状态取代 `PumpLoopState` 的 7 枚终端相关 bool。
pub(in crate::handler::llm::pump) struct StreamTerminator {
    /// 终端推进态（`terminal_sent`/`block_injected` 的位保留语义）。
    state: TerminalState,
    /// 取代 `terminated`：`run_pump` 循环跳出（仅 Responses error/DuplicateFailed 置位）。
    loop_terminated: bool,
    /// 取代 `rejected_sticky`：I-1 粘滞拒绝（I-2 不置）。
    rejected_sticky: bool,
    /// 取代 `audit_blocked`：I-1 阻断命中（`finish` 的 `record_aux_counts` 读取）。
    audit_blocked: bool,
    /// R5-35/D3：已终端后收尾审计命中 `Block`——独立于终端帧位的阻断语义位，
    /// 其置位 SHALL NOT 触发 `mark_terminal`/`terminal_injected`。
    terminal_block_sticky: bool,
    /// 取代 `responses_failed_sent`：上游 failed 分类（非终端位）。
    responses_failed_seen: bool,
    /// 帧发送事实（[`Self::note_frame_sent`] 唯一写点）。
    any_frame_sent: bool,
}

impl StreamTerminator {
    /// 初始态：`Open`，所有位清零。
    pub(in crate::handler::llm::pump) fn new() -> Self {
        Self {
            state: TerminalState::Open,
            loop_terminated: false,
            rejected_sticky: false,
            audit_blocked: false,
            terminal_block_sticky: false,
            responses_failed_seen: false,
            any_frame_sent: false,
        }
    }

    // ---- 读取访问器（覆盖 design §1.2 全部读点）----

    /// `state == Open`（供 `decide`/`event` 纯谓词）。
    pub(in crate::handler::llm::pump) fn is_open(&self) -> bool {
        matches!(self.state, TerminalState::Open)
    }

    /// `terminal_sent` 语义（I-1/I-2/I-3/I-5 与上游终端）。
    pub(in crate::handler::llm::pump) fn terminal_sent(&self) -> bool {
        matches!(
            self.state,
            TerminalState::Blocked
                | TerminalState::Synthesized
                | TerminalState::UpstreamTerminal
                | TerminalState::ResponsesError
        )
    }

    /// `block_injected` 语义（I-1/I-2/I-4 + R5-35 已终端后收尾阻断；`decide` + `PumpOutcome`）。
    pub(in crate::handler::llm::pump) fn block_injected(&self) -> bool {
        self.terminal_block_sticky
            || matches!(
                self.state,
                TerminalState::Blocked | TerminalState::EmptyStream
            )
    }

    /// `loop_terminated`（`run_pump` 循环跳出）。
    pub(in crate::handler::llm::pump) fn terminated(&self) -> bool { self.loop_terminated }

    /// 是否已发过任一帧（`decide.rs`/`event.rs` 纯谓词）。
    pub(in crate::handler::llm::pump) fn any_frame_sent(&self) -> bool { self.any_frame_sent }

    /// I-1 粘滞拒绝态。
    pub(in crate::handler::llm::pump) fn rejected_sticky(&self) -> bool { self.rejected_sticky }

    /// I-1 阻断命中（`record_aux_counts` 读取）。
    pub(in crate::handler::llm::pump) fn audit_blocked(&self) -> bool { self.audit_blocked }

    /// 上游 Responses failed 分类（非终端位）。
    pub(in crate::handler::llm::pump) fn responses_failed_seen(&self) -> bool {
        self.responses_failed_seen
    }

    // ---- 变更器（终端位唯一写点族）----

    /// `any_frame_sent` 唯一写点。
    pub(in crate::handler::llm::pump) fn note_frame_sent(&mut self) { self.any_frame_sent = true; }

    /// 上游终端（`event_terminal` / `[DONE]`）：置 `terminal_sent` 语义位。
    /// 幂等；仅在 `Open` 时推进（已阻断/已终态不回退 `block_injected` 位）。
    pub(in crate::handler::llm::pump) fn mark_upstream_terminal(&mut self) {
        if self.is_open() {
            self.state = TerminalState::UpstreamTerminal;
        }
    }

    /// I-1 粘滞拒绝：置 `rejected_sticky` + `audit_blocked`（两者同点写，保持既有语义）。
    pub(in crate::handler::llm::pump) fn note_sticky_rejected(&mut self) {
        self.rejected_sticky = true;
        self.audit_blocked = true;
    }

    /// R5-35/D3：已终端后收尾审计命中 `Block`——置独立阻断语义位（不触发
    /// `mark_terminal`/`terminal_injected`），并显式经 [`Self::note_sticky_rejected`]
    /// 计入 `audit_blocked`（`finish` 的 `record_aux_counts` 读取）。
    pub(in crate::handler::llm::pump) fn note_terminal_reject_block(&mut self) {
        self.terminal_block_sticky = true;
        self.note_sticky_rejected();
    }

    /// `responses_failed_seen` 写点（`event_loop` Responses 分类）。
    pub(in crate::handler::llm::pump) fn note_responses_failed(&mut self) {
        self.responses_failed_seen = true;
    }

    /// 仅置 `loop_terminated`（BLOCKER-3：无帧也可终止循环）。
    pub(in crate::handler::llm::pump) fn mark_loop_terminated(&mut self) {
        self.loop_terminated = true;
    }

    // ---- 注入计划（`!is_open()` 时一律返回 `TerminalPlan::None`）----

    /// I-1/I-2 协议阻断帧计划；`metrics` 仅参与 Responses 归档回退计数；
    /// `model` 为流式回显模型（缺失归 `unknown_model`，R5-39）。
    // R5-39：`model` 入参使参数数超 clippy 默认阈值；聚合结构会加大调用点 churn，故就地允许。
    #[allow(clippy::too_many_arguments)]
    pub(in crate::handler::llm::pump) fn plan_block(
        &self,
        protocol: Protocol,
        reason: &str,
        conv_id: Option<&str>,
        model: &str,
        blocked_index: u32,
        seq_cursor: Option<u64>,
        metrics: Option<&GatewayMetrics>,
    ) -> TerminalPlan {
        if !self.is_open() {
            return TerminalPlan::None;
        }
        TerminalPlan::Frames {
            kind: TerminalKind::Block,
            frames: block_inject::ensure_event_lines(block_inject::protocol_block_frames_modeled(
                protocol,
                reason,
                conv_id,
                model,
                blocked_index,
                metrics,
                seq_cursor,
            )),
            truncated: None,
        }
    }

    /// I-3 中途断流终端帧计划（MAJOR-5：`metrics` 供 Responses 臂
    /// `resolve_conv_id(None, &Value::Null, Some(metrics), "truncated")` 记
    /// `record_conv_missing` 并取归档回退 id）。
    ///
    /// Anthropic 返回 `Frames { frames: vec![], truncated: Some(OpenEnded) }`——**零合成帧
    /// 但仍是合法终止**（不伪造 `message_stop`）；Chat 补恰一 `[DONE]`（`clean_close`
    /// 时不记 `open_ended`）；Responses 合成恰一 `response.failed` 并记
    /// `synthesized_failed`。3.1 起由 `terminal::finalize` 消费。
    pub(in crate::handler::llm::pump) fn plan_midstream(
        &self,
        protocol: Protocol,
        conv_id: Option<&str>,
        model: &str,
        clean_close: bool,
        seq_cursor: Option<u64>,
        metrics: Option<&GatewayMetrics>,
    ) -> TerminalPlan {
        if !self.is_open() {
            return TerminalPlan::None;
        }
        match protocol {
            Protocol::Chat => TerminalPlan::Frames {
                kind: TerminalKind::Midstream,
                frames: vec![block_inject::chat_done_frame()],
                truncated: if clean_close {
                    None
                } else {
                    Some(TruncatedMode::OpenEnded)
                },
            },
            Protocol::Anthropic => TerminalPlan::Frames {
                kind: TerminalKind::Midstream,
                frames: Vec::new(),
                truncated: Some(TruncatedMode::OpenEnded),
            },
            Protocol::Responses => {
                let tid = conv_id.map(str::to_string).unwrap_or_else(|| {
                    resolve_conv_id(None, &serde_json::Value::Null, metrics, "truncated").0
                });
                TerminalPlan::Frames {
                    kind: TerminalKind::Midstream,
                    frames: block_inject::ensure_event_lines(
                        block_inject::synthesize_truncation_modeled(
                            protocol, &tid, seq_cursor, model,
                        ),
                    ),
                    truncated: Some(TruncatedMode::SynthesizedFailed),
                }
            }
            // 非对话不合成终端（现状 `midstream_terminal` NonDialog 臂返回
            // `terminal_sent=false`，调用点据 `frames.is_empty()` 不置位）。
            Protocol::NonDialog => TerminalPlan::Frames {
                kind: TerminalKind::Midstream,
                frames: Vec::new(),
                truncated: None,
            },
        }
    }

    /// I-4 真空流最小终止计划；空帧集（未知/非对话协议）仍返回 `Frames` 以
    /// 携带 `OpenEnded` 观测，调用点判 `frames.is_empty()` 决定是否 `commit`。
    /// 3.2 起由 `terminal::finalize` 消费。
    pub(in crate::handler::llm::pump) fn plan_empty_stream(
        &self,
        protocol_name: &str,
        conv_id: &str,
        model: &str,
    ) -> TerminalPlan {
        if !self.is_open() {
            return TerminalPlan::None;
        }
        let frames = block_inject::ensure_event_lines(block_inject::empty_stream_frames_modeled(
            protocol_name,
            conv_id,
            model,
        ));
        let truncated = if protocol_name == "responses" {
            TruncatedMode::SynthesizedFailed
        } else {
            TruncatedMode::OpenEnded
        };
        TerminalPlan::Frames {
            kind: TerminalKind::EmptyStream,
            frames,
            truncated: Some(truncated),
        }
    }

    /// I-5 Responses `type:"error"` 单帧 `response.failed` 计划；`R7-03`：计划携带
    /// `truncated: Some(SynthesizedFailed)`，调用点解构后在 `commit` 后无条件落观测。
    /// 3.2 起由 `event_loop::handle_event` 消费。
    pub(in crate::handler::llm::pump) fn plan_responses_error(
        &self,
        fid: &str,
        error: Option<&serde_json::Value>,
        sequence_number: Option<u64>,
        model: &str,
    ) -> TerminalPlan {
        if !self.is_open() {
            return TerminalPlan::None;
        }
        TerminalPlan::Frames {
            kind: TerminalKind::ResponsesError,
            frames: block_inject::ensure_event_lines(vec![
                block_inject::responses_failed_frame_modeled(fid, error, sequence_number, model),
            ]),
            truncated: Some(TruncatedMode::SynthesizedFailed),
        }
    }

    /// BLOCKER-3：终端帧位与 `StreamMeta.terminal_injected` 的**唯一回填点**，
    /// 逐 kind 镜像现状（见 design §2.1 表）：
    /// - `Block` → `terminal_sent=true`、`block_injected=true`、`mark_terminal` （I-1/I-2
    ///   无条件，`frames_sent`/`terminal_frame_delivered` 仅记录）；
    /// - `Midstream` → `terminal_sent=frames_sent`；`mark_terminal` 仅当 `frames_sent &&
    ///   terminal_frame_delivered`（Chat/Responses 终端帧实际下行才标； Anthropic
    ///   零合成帧收尾成立但**不置** `terminal_injected`）；
    /// - `EmptyStream` → `block_injected=true`、`mark_terminal`（调用点仅在非空帧集
    ///   落此路；空帧集只由调用点落 `set_truncated`）；
    /// - `ResponsesError` → `terminal_sent=frames_sent`、`mark_terminal` 仅当
    ///   `terminal_frame_delivered`（下游早断不撒谎）。
    ///
    /// `frames_sent` = 收尾是否成立；`terminal_frame_delivered` = 终端帧是否实际下行
    /// （决定 `terminal_injected`）；二者 SHALL NOT 合并。
    ///
    /// `loop_terminated` **不由 commit 置位**：Responses error 臂在 commit 后另调
    /// [`Self::mark_loop_terminated`]，`DuplicateFailed` 仅调 `mark_loop_terminated`。
    /// 终态后为 no-op（幂等；`plan_*` 已挡住重复注入）。
    pub(in crate::handler::llm::pump) fn commit(
        &mut self,
        meta: &mut StreamMeta,
        kind: TerminalKind,
        frames_sent: bool,
        terminal_frame_delivered: bool,
    ) {
        if !self.is_open() {
            return;
        }
        match kind {
            TerminalKind::Block => {
                self.state = TerminalState::Blocked;
                block_inject::mark_terminal(meta);
            }
            TerminalKind::Midstream => {
                if frames_sent {
                    self.state = TerminalState::Synthesized;
                    // 仅在实际有合成终端帧下行时回填；Anthropic 零合成帧收尾成立但不置位
                    // （veil-stream-fidelity-fix D9/S9：该位＝终端帧已实际下行，不得撒谎）。
                    if terminal_frame_delivered {
                        block_inject::mark_terminal(meta);
                    }
                }
            }
            TerminalKind::EmptyStream => {
                self.state = TerminalState::EmptyStream;
                block_inject::mark_terminal(meta);
            }
            TerminalKind::ResponsesError => {
                if frames_sent {
                    self.state = TerminalState::ResponsesError;
                    if terminal_frame_delivered {
                        block_inject::mark_terminal(meta);
                    }
                }
            }
        }
    }
}

/// 1.1 内联最小单测：为 `cfg(test)` 构建标记 `plan_midstream`/`plan_empty_stream`/
/// `plan_responses_error` 与 `Frames` 的 `kind`/`truncated` 字段已被消费（迁出
/// `dead_code` 中间态）；完整矩阵测试见 4.2 `pump::terminator_tests`。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_idempotent_after_commit() {
        let mut t = StreamTerminator::new();
        let mut meta = StreamMeta::default();
        assert!(t.is_open(), "初始须为 Open");
        let TerminalPlan::Frames {
            kind,
            frames,
            truncated,
        } = t.plan_block(
            Protocol::Chat,
            "audit-policy-block",
            None,
            "",
            0,
            None,
            None,
        )
        else {
            panic!("Open 态 plan_block 须产出 Frames");
        };
        assert_eq!(kind, TerminalKind::Block);
        assert!(!frames.is_empty(), "Chat 阻断须产出帧");
        assert!(truncated.is_none(), "阻断不携带截断观测");
        t.commit(&mut meta, kind, true, true);
        assert!(!t.is_open() && t.terminal_sent() && t.block_injected());
        assert!(meta.terminal_injected, "commit 须回填 terminal_injected");
        // MAJOR-6 幂等：已终端后各 plan 一律 None。
        assert!(matches!(
            t.plan_block(Protocol::Chat, "r", None, "", 0, None, None),
            TerminalPlan::None
        ));
        assert!(matches!(
            t.plan_midstream(Protocol::Chat, None, "", false, None, None),
            TerminalPlan::None
        ));
        assert!(matches!(
            t.plan_empty_stream("chat", "c", ""),
            TerminalPlan::None
        ));
        assert!(matches!(
            t.plan_responses_error("r", None, None, ""),
            TerminalPlan::None
        ));
    }

    #[test]
    fn plan_responses_error_carries_synthesized_failed() {
        // R7-03/D3：error 终端计划携带 `synthesized_failed` 观测，调用点解构后
        // 在 commit 后无条件落 `set_truncated`（下游早断不丢观测）。
        let t = StreamTerminator::new();
        let TerminalPlan::Frames {
            kind,
            frames,
            truncated,
        } = t.plan_responses_error("r1", None, None, "")
        else {
            panic!("Open 态 plan_responses_error 须产出 Frames");
        };
        assert_eq!(kind, TerminalKind::ResponsesError);
        assert_eq!(frames.len(), 1, "恰一 response.failed 帧");
        assert_eq!(truncated, Some(TruncatedMode::SynthesizedFailed));
    }

    #[test]
    fn anthropic_midstream_zero_frames_is_frames_not_none() {
        let t = StreamTerminator::new();
        // MAJOR-6：零合成帧不得用 None 表达。
        let TerminalPlan::Frames {
            kind,
            frames,
            truncated,
        } = t.plan_midstream(Protocol::Anthropic, None, "", false, None, None)
        else {
            panic!("Anthropic 中途断流须为 Frames");
        };
        assert_eq!(kind, TerminalKind::Midstream);
        assert!(frames.is_empty());
        assert_eq!(truncated, Some(TruncatedMode::OpenEnded));
        let plan = t.plan_empty_stream("chat", "c", "");
        assert!(matches!(
            plan,
            TerminalPlan::Frames {
                kind: TerminalKind::EmptyStream,
                ..
            }
        ));
    }

    #[test]
    fn midstream_zero_frames_closes_without_marking_injected() {
        // D9/S9：Anthropic 中途断流 `frames_sent=true`（收尾成立）但零合成帧
        //（`terminal_frame_delivered=false`）——须闭合且不置 `terminal_injected`。
        let mut t = StreamTerminator::new();
        let mut meta = StreamMeta::default();
        t.commit(&mut meta, TerminalKind::Midstream, true, false);
        assert!(
            !t.is_open() && t.terminal_sent(),
            "零合成帧收尾仍须闭合终端位"
        );
        assert!(!meta.terminal_injected, "零合成帧不得置 terminal_injected");
    }

    #[test]
    fn terminal_sticky_block_keeps_semantics_without_second_terminal() {
        // R5-35/D3：已终端后收尾审计命中 Block——不注入第二终端，但 block_injected/
        // audit_blocked 为真、terminal_injected 保持不变。
        let mut t = StreamTerminator::new();
        let meta = StreamMeta::default();
        t.mark_upstream_terminal();
        assert!(t.terminal_sent() && !t.block_injected(), "上游终端初始态");
        assert!(
            matches!(
                t.plan_block(
                    Protocol::Chat,
                    "audit-policy-block",
                    None,
                    "",
                    0,
                    None,
                    None
                ),
                TerminalPlan::None
            ),
            "已终端后 plan_block 须 None（不注入第二终端）"
        );
        t.note_terminal_reject_block();
        assert!(t.block_injected(), "block_injected 须为 true");
        assert!(
            t.audit_blocked(),
            "audit_blocked 须置位（audit_blocks 计数）"
        );
        assert!(t.rejected_sticky(), "须显式走 note_sticky_rejected 语义");
        assert!(t.terminal_sent(), "终端帧位须保持");
        assert!(!meta.terminal_injected, "不得置 terminal_injected");
    }
}
