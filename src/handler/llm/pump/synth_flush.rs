//! D3/S3：合成终端前的边界滞留帧 flush（保序）。
//!
//! `SynthesizeFailed`（`type:"error"` → `response.failed`）与截断合成路径在发送
//! 合成终端帧前，须先把 [`BoundaryHold`] 中滞留的内容帧按原序并入 `agg` 下发，
//! 避免终端帧越过尚未落下的末尾增量；阻断路径不适用（显式 `clear`，不释放危险内容）。
//!
//! D6/S11：断流终端策略统一收尾（[`midstream_terminal`]），合并既有 Chat
//! `finish_reason` 补发与截断合成到同一路径，消除 `truncated_mode_set` 条件竞态。

use {
    super::event::data_event_count,
    crate::service::{
        block_inject,
        llm_gateway::{self, GatewayMetrics, Protocol},
        redaction::BoundaryHold,
        sse::{StreamMeta, TruncatedMode, set_truncated},
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
        agg.push_str(&fp);
        agg.push_str(&format!("data: {fd}\n\n"));
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
pub(super) struct MidstreamTerminalOutcome {
    pub forwarded: u64,
    pub terminal_sent: bool,
}

/// D6/S11 + CHC-5/2.24：断流终端输入（conv 与干净收尾标志合并，控制参数数）。
pub(super) struct MidstreamInput<'a> {
    pub conv_id: Option<&'a str>,
    /// 已见非空 `finish_reason` 的干净 EOF（Chat 不记 `open_ended`）。
    pub clean_close: bool,
}

/// D6/S11：中途断流终端策略（仅在已发帧、未终端、未阻断时由调用方进入）。
/// Chat 补恰一 `data: [DONE]`（传输层终止标记）；异常截断记 `truncated_mode=open_ended`，
/// `clean_close`（已见非空 `finish_reason` 的干净 EOF）则不计该观测（CHC-5/2.24）；
/// Anthropic 不合成 `message_stop`（不伪造成功终止），仅记 `open_ended` 观测；
/// Responses 合成恰一 `response.failed`（失败语义）并记 `synthesized_failed`。
///
/// 真空流（零帧零残余）不走本函数，由空流守门补最小终止。
/// D9/S9：`terminal_sent` 仅在实际下发成功时置位；下游早断（`send` 失败）时
/// 不置位，空流守门不被掩盖，`PumpOutcome` 如实反映未注入终端。
pub(super) async fn midstream_terminal(
    protocol: Protocol,
    input: MidstreamInput<'_>,
    boundary: &mut BoundaryHold,
    agg: &mut String,
    pump_tx: &tokio::sync::mpsc::Sender<String>,
    metrics: &GatewayMetrics,
    meta: &mut StreamMeta,
) -> MidstreamTerminalOutcome {
    let MidstreamInput {
        conv_id,
        clean_close,
    } = input;
    // D3/S3：合成终端前先 flush 边界滞留帧，保证末段增量先于终端帧下行。
    let flush_ok = flush_pre_terminal(boundary, agg, pump_tx, metrics).await;
    let mut forwarded = u64::from(flush_ok);
    let terminal_sent = match protocol {
        Protocol::Chat => {
            agg.push_str(&block_inject::chat_done_frame());
            let events = data_event_count(agg);
            let ok = pump_tx.send(std::mem::take(agg)).await.is_ok();
            if ok {
                for _ in 0..events {
                    metrics.add_sse_event();
                }
                forwarded += 1;
                block_inject::mark_terminal(meta);
            }
            if clean_close {
                // CHC-5/2.24：已见非空 `finish_reason` 的干净 EOF，仅补线级 [DONE]，
                // 不记 `open_ended`（仅异常截断才记）。
                tracing::debug!("Chat 流干净完成，补恰一 [DONE]（不计截断）");
            } else {
                let _ = set_truncated(meta, protocol, TruncatedMode::OpenEnded, Some(metrics));
                tracing::warn!("Chat 流中途断流，按恰一 [DONE] 收尾（open_ended 观测）");
            }
            ok
        }
        Protocol::Anthropic => {
            // 不伪造成功终止：仅观测，不发送 `message_stop`；无合成帧可失败。
            let _ = set_truncated(meta, protocol, TruncatedMode::OpenEnded, Some(metrics));
            tracing::warn!("Anthropic 流中途断流，不合成 message_stop（open_ended 观测）");
            true
        }
        Protocol::Responses => {
            let tid = conv_id.map(str::to_string).unwrap_or_else(|| {
                llm_gateway::resolve_conv_id(
                    None,
                    &serde_json::Value::Null,
                    Some(metrics),
                    "truncated",
                )
                .0
            });
            let mut ok = false;
            for f in block_inject::ensure_event_lines(block_inject::synthesize_truncation(
                protocol, &tid,
            )) {
                if pump_tx.send(f).await.is_err() {
                    ok = false;
                    break;
                }
                metrics.add_sse_event();
                forwarded += 1;
                ok = true;
            }
            if ok {
                block_inject::mark_terminal(meta);
            }
            let _ = set_truncated(
                meta,
                protocol,
                TruncatedMode::SynthesizedFailed,
                Some(metrics),
            );
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
