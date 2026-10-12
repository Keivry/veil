//! 流泵帧出口（自 `spawn.rs` 拆出）：还原守卫、残余帧归一化，与还原后帧统一
//! 出口。残余帧（`terminal.rs`）与正常帧（`event_loop.rs` 两臂）共用
//! `emit_restored_json_frame`，杜绝任一路径裸喂未守卫载荷；
//! 不落 `service/redaction/restore_guard.rs`（保持其零 axum 依赖边界）。

use {
    crate::service::{
        json_walk::{jloads, strip_bom},
        llm_gateway::GatewayMetrics,
        redaction::restore_guard::restore_guard_ok,
        sse::{classify_residue, data_frame, json_aware_line},
    },
    serde_json::Value,
};

/// 截断残余帧归一化——「丢弃残余」：
/// 先剥 BOM 与已存在的 `data:` 前缀，再要求载荷为**完整 JSON 容器**；半帧
/// （如 `data: {"a": 1`）、CR-only 半帧与非 JSON 残余一律返回 `None` 丢弃，
/// 杜绝把裸残余二次加 `data:` 前缀转发（下游 `JSONDecodeError`）。
pub(super) fn residual_frame_payload(raw: &str) -> Option<String> {
    let classified = classify_residue(raw)?;
    let trimmed = strip_bom(classified.trim()).trim();
    let payload = trimmed
        .strip_prefix("data:")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    if (payload.starts_with('{') || payload.starts_with('[')) && jloads(payload).is_ok() {
        Some(payload.to_string())
    } else {
        None
    }
}

/// 兜底回退：还原后帧 `jloads` 校验（BOM 感知）；失败时回退**还原前占位符帧**
/// （fail-closed，token 形态保留、不破帧），记 warn + `restore_fallback` 计数，
/// 对齐非流 `retry_stripped` 回退语义（`nonstream.rs::retry_stripped`）。
/// 外层合法时进一步校验字符串值内的 stringified JSON 结构有效性——
/// 外层合法会掩盖内层破损，内层破损须回退而非静默透传。
#[cfg(test)]
pub(crate) fn guard_restored_frame(
    restored: String,
    placeholder_frame: &str,
    metrics: &GatewayMetrics,
) -> String {
    guard_restored_frame_parsed(restored, placeholder_frame, None, metrics)
}

/// 调用方已持有占位符帧的解析产物时复用，避免同帧二次解析。
pub(crate) fn guard_restored_frame_parsed(
    restored: String,
    placeholder_frame: &str,
    placeholder_parsed: Option<&Value>,
    metrics: &GatewayMetrics,
) -> String {
    if restore_guard_ok(&restored, placeholder_frame, placeholder_parsed) {
        return restored;
    }
    tracing::warn!("流式还原后 JSON 校验失败，已回退还原前占位符帧（fail-closed）");
    metrics.record_restore_fallback();
    placeholder_frame.to_string()
}

/// 把一帧并入下游聚合 `agg`（`data:` 信封重建）；返回本帧是否有非空数据放行
/// （供审计 pending 抑制判定）。
pub(super) fn feed_output_frame(agg: &mut String, prefix: &str, data: &str) -> bool {
    agg.push_str(&data_frame(prefix, data));
    !data.is_empty()
}

/// 帧出口目的地（借用聚合，规避 `too_many_arguments`）。
pub(super) struct FrameSink<'a> {
    pub agg: &'a mut String,
}

/// 还原后帧输入：`prefix` 信封前缀（残余帧为空串）；`restored` 为还原/脱敏后
/// 载荷；`placeholder` 为还原前占位符帧（守卫失败回退目标）；`placeholder_parsed`
/// 为占位符帧解析产物（复用避免二次解析）；`json_aware` 为是否经
/// `json_aware_line` 复核（opaque 帧按跳过）；`feed` 为是否立即送入出口
/// （tool 分片缓冲路径先取守卫产物、稍后重放，故不即时喂出）。
pub(super) struct RestoredFrame<'a> {
    pub prefix: &'a str,
    pub restored: String,
    pub placeholder: &'a str,
    pub placeholder_parsed: Option<&'a Value>,
    pub json_aware: bool,
    pub feed: bool,
}

/// 还原后帧统一守卫出口：
/// 1. `json_aware` 为真时经 `json_aware_line` 复核（合法 JSON 原样返回，不二次
///    `loads→walk→dumps`）；
/// 2. `guard_restored_frame_parsed`（含 metrics + warn）——还原后 JSON 破损 fail-closed
///    回退**占位符帧**，绝不把非法 JSON 送下游；
/// 3. `feed` 为真时经 `feed_output_frame` 送入出口。
///
/// 返回（守卫后载荷，本帧是否有非空数据放行）。tool 分片缓冲路径以返回值复用
/// 同一守卫产物（`feed == false` 时 `emitted` 恒为假）。
pub(super) async fn emit_restored_json_frame(
    sink: &mut FrameSink<'_>,
    frame: RestoredFrame<'_>,
    metrics: &GatewayMetrics,
) -> (String, bool) {
    let restored = if frame.json_aware {
        json_aware_line(&frame.restored, |s| s)
    } else {
        frame.restored
    };
    let guarded = guard_restored_frame_parsed(
        restored,
        frame.placeholder,
        frame.placeholder_parsed,
        metrics,
    );
    if !frame.feed {
        return (guarded, false);
    }
    let emitted = feed_output_frame(sink.agg, frame.prefix, &guarded);
    (guarded, emitted)
}

#[cfg(test)]
mod tests;
