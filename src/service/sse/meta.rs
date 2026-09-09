//! SSE 截断元数据（H1.1 一切：常量归属见门面重导出）。
//!
//! - `TruncatedMode` 三态 + `StreamMeta` 随流标记；`set_truncated` 唯一写入口 （`SynthesizedFailed`
//!   仅 Responses 可置位，其余协议返回 `false` 拒绝）。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

use crate::service::llm_gateway::{GatewayMetrics, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncatedMode {
    SilentDiscard,
    OpenEnded,
    SynthesizedFailed,
}

impl TruncatedMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SilentDiscard => "silent_discard",
            Self::OpenEnded => "open_ended",
            Self::SynthesizedFailed => "synthesized_failed",
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
    if mode == TruncatedMode::SynthesizedFailed && protocol != Protocol::Responses {
        return false;
    }
    meta.truncated_mode = Some(mode);
    if let Some(m) = metrics {
        m.record_truncated(mode.as_str());
    }
    true
}
