//! SSE 截断元数据（H1.1 一切：常量归属见门面重导出）。
//!
//! - `TruncatedMode` 四态 + `StreamMeta` 随流标记；`set_truncated` 唯一写入口 （`SynthesizedFailed`
//!   仅 Responses 可置位，其余协议返回 `false` 拒绝）。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

use crate::service::llm_gateway::{GatewayMetrics, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncatedMode {
    SilentDiscard,
    OpenEnded,
    SynthesizedFailed,
    /// A-6/F-08：上游错误载荷帧即终端（带顶层 `error` 且无 `choices`），
    /// 与中途截断的 `open_ended` 区分。
    UpstreamError,
}

impl TruncatedMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SilentDiscard => "silent_discard",
            Self::OpenEnded => "open_ended",
            Self::SynthesizedFailed => "synthesized_failed",
            Self::UpstreamError => "upstream_error",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StreamMeta {
    pub truncated_mode: Option<TruncatedMode>,
    pub terminal_injected: bool,
}

pub fn set_truncated(
    meta: &mut StreamMeta,
    protocol: Protocol,
    mode: TruncatedMode,
    metrics: Option<&GatewayMetrics>,
) -> bool {
    if mode == TruncatedMode::SynthesizedFailed && !protocol.is_responses() {
        return false;
    }
    meta.truncated_mode = Some(mode);
    if let Some(m) = metrics {
        m.record_truncated(mode.as_str());
    }
    true
}
