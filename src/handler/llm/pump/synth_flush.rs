//! D3/S3：合成终端前的边界滞留帧 flush（保序）。
//!
//! `SynthesizeFailed`（`type:"error"` → `response.failed`）与截断合成路径在发送
//! 合成终端帧前，须先把 [`BoundaryHold`] 中滞留的内容帧按原序并入 `agg` 下发，
//! 避免终端帧越过尚未落下的末尾增量；阻断路径不适用（显式 `clear`，不释放危险内容）。
//!
//! D6/S11：断流终端策略统一收尾（[`midstream_terminal`]），合并既有 Chat
//! `finish_reason` 补发与截断合成到同一路径，消除 `truncated_mode_set` 条件竞态。
//!
//! 3.1 收敛后的职责边界（`veil-stream-terminator-convergence` design §2.1/§2.2）：
//! - **帧选择**（协议 × 中途断流的终端帧集与截断观测）迁入
//!   `terminator.plan_midstream`；本模块不再出现 `match protocol` 的终端帧构造。
//! - **发送与计数**留在调用点链路：本模块按 `plan` 产物逐协议下发并执行**既有口径**
//!   的帧级计数（BLOCKER-1：I-3 既有 `add_sse_event` 一处不增、一处不减）， 绝不把计数迁入
//!   `StreamTerminator`（其只持有状态、不发送、不计数）。
//! - **截断观测**（`set_truncated`）由调用点 `terminal::finalize` 据 `plan.truncated`
//!   落位；本模块仅在日志层面区分 Chat 的干净收尾与异常截断，不写 `StreamMeta`。
//! - **终端回填**（`commit`）由调用点完成；本模块只回报「发送是否成功/收尾是否成立」
//!   （[`MidstreamTerminalOutcome`]），保持 D9/S9「下游早断不置位」的语义。
//!
//! 三协议发送口径（与收敛前逐点一致）：
//! - Chat：把恰一 `data: [DONE]` 并入 `agg` 后单次 `send`，成功即按 `data:` 行数 记
//!   `add_sse_event`；干净收尾（已见非空 `finish_reason`）不记截断，异常截断记
//!   `open_ended`（观测在调用点落）。
//! - Anthropic：**不合成任何终端帧**（不伪造 `message_stop`），零帧可失败，
//!   收尾按观测成立计（`terminal_sent=true`）。
//! - Responses：逐帧下发 `synthesize_truncation` 产物（恰一 `response.failed`）， 逐帧成功即记
//!   `add_sse_event`；任一帧失败即中止且不置终端位。
//! - NonDialog：不合成终端（零帧），`terminal_sent=false`，调用点不 `commit`。

use {
    super::event::data_event_count,
    crate::service::{
        llm_gateway::{GatewayMetrics, Protocol},
        redaction::BoundaryHold,
        sse::{TruncatedMode, data_frame},
    },
};

/// 合成终端前把边界滞留帧并入 `agg` 并优先下发；返回本次是否实际下发成功
/// （D9/S9：`send` 失败即未下行，不下发计数、不置位，调用方据此更新
/// `forwarded`/`any_frame_sent`）。
pub(super) async fn flush_pre_terminal(
    boundary: &mut BoundaryHold,
    agg: &mut String,
    pump_tx: &tokio::sync::mpsc::Sender<String>,
    metrics: &GatewayMetrics,
) -> bool {
    if let Some((fp, fd)) = boundary.flush() {
        agg.push_str(&data_frame(&fp, &fd));
    }
    if agg.is_empty() {
        return false;
    }
    let events = data_event_count(agg);
    let sent = pump_tx.send(std::mem::take(agg)).await.is_ok();
    if sent {
        for _ in 0..events {
            metrics.add_sse_event();
        }
    }
    sent
}

/// D6/S9 断流终端注入结果：`forwarded` 为实际成功下发的帧数（失败不计数），
/// `terminal_sent` 为终端收尾是否成立——Chat/Responses 以合成帧 `send` 成功
/// 为准；Anthropic 无合成帧，按观测收尾成立计（不伪造成功终止）。
///
/// 该结构是调用点与 `commit` 之间的**唯一回报通道**：`terminal_sent` 直接作为
/// `commit(TerminalKind::Midstream, terminal_sent)` 的 `frames_sent` 入参，
/// 从而保证「send 失败 ⇒ 不置终端位」在收敛后仍成立（BLOCKER-3 的 I-3 侧）。
/// `forwarded` 由调用点累加进 `PumpOutcome.forwarded` 并在 >0 时 `note_frame_sent`，
/// 与收敛前 `any_frame_sent |= mid.forwarded > 0` 的语义逐点一致。
pub(super) struct MidstreamTerminalOutcome {
    pub forwarded: u64,
    pub terminal_sent: bool,
}

/// 3.1/D6/S11：中途断流终端策略的**发送执行器**（仅在已发帧、未终端、未阻断时由
/// 调用方进入）。终端帧集与截断观测由 `terminator.plan_midstream` 产出，本函数只做
/// 「flush 保序 + 按协议既有发送口径下发 + 按站点既有计数（BLOCKER-1 不得增删）」；
/// `truncated` 仅用于区分 Chat 干净收尾/异常截断的日志，实际 `set_truncated` 由调用点落。
///
/// 参数契约：`frames` 为 `plan` 携带的终端帧集（Anthropic/NonDialog 为空——**零合成帧
/// 是合法终止**，不得用 `None` 语义替代）；`truncated` 由 plan 透传，仅影响日志分支。
/// 本函数不触碰 `StreamMeta`、不调用 `mark_terminal`、不调 `commit`——终端位的唯一回填
/// 由调用点在拿到 [`MidstreamTerminalOutcome`] 后完成。
///
/// Chat 补恰一 `data: [DONE]`（传输层终止标记；异常截断记 `open_ended`，干净收尾不计）；
/// Anthropic 不合成 `message_stop`（零合成帧，不伪造成功终止，仅观测收尾）；
/// Responses 合成恰一 `response.failed`（失败语义）并记 `synthesized_failed`。
/// 真空流（零帧零残余）不走本函数，由空流守门补最小终止。
/// D9/S9：`terminal_sent` 仅在实际下发成功时置位；下游早断（`send` 失败）时
/// 不置位，空流守门不被掩盖，`PumpOutcome` 如实反映未注入终端。
pub(super) async fn midstream_terminal(
    protocol: Protocol,
    frames: &[String],
    truncated: Option<TruncatedMode>,
    boundary: &mut BoundaryHold,
    agg: &mut String,
    pump_tx: &tokio::sync::mpsc::Sender<String>,
    metrics: &GatewayMetrics,
) -> MidstreamTerminalOutcome {
    // D3/S3：合成终端前先 flush 边界滞留帧，保证末段增量先于终端帧下行。
    let flush_ok = flush_pre_terminal(boundary, agg, pump_tx, metrics).await;
    let mut forwarded = u64::from(flush_ok);
    let terminal_sent = match protocol {
        Protocol::Chat => {
            // A-6/F-08：错误载荷帧已在流内置终端（`upstream_error` 观测），
            // `should_apply_midstream_terminal` 随即短路——本臂不再为其补 `[DONE]`、
            // 不记 `open_ended`；此处仅承载无终端信号的异常断流与干净收尾。
            for f in frames {
                agg.push_str(f);
            }
            let events = data_event_count(agg);
            let ok = pump_tx.send(std::mem::take(agg)).await.is_ok();
            if ok {
                for _ in 0..events {
                    metrics.add_sse_event();
                }
                forwarded += frames.len() as u64;
            }
            if truncated.is_some() {
                tracing::warn!("Chat 流中途断流，按恰一 [DONE] 收尾（open_ended 观测）");
            } else {
                // CHC-5/2.24：已见非空 `finish_reason` 的干净 EOF，仅补线级 [DONE]，
                // 不记 `open_ended`（仅异常截断才记）。
                tracing::debug!("Chat 流干净完成，补恰一 [DONE]（不计截断）");
            }
            ok
        }
        Protocol::Anthropic => {
            // 不伪造成功终止：仅观测收尾，不发送 `message_stop`；无合成帧可失败。
            tracing::warn!("Anthropic 流中途断流，不合成 message_stop（open_ended 观测）");
            true
        }
        Protocol::Responses => {
            // 逐帧下发 `synthesize_truncation` 产物（单帧 `response.failed`），
            // 逐帧成功即 `add_sse_event`（I-3 既有口径，不得增删）。
            let mut ok = false;
            for f in frames {
                if pump_tx.send(f.clone()).await.is_err() {
                    ok = false;
                    break;
                }
                metrics.add_sse_event();
                forwarded += 1;
                ok = true;
            }
            tracing::warn!(
                "Responses 流中途断流，按恰一 response.failed 收尾（synthesized_failed 观测）"
            );
            ok
        }
        Protocol::NonDialog => false,
    };
    MidstreamTerminalOutcome {
        forwarded,
        terminal_sent,
    }
}
