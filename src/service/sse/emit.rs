//! SSE 保活帧 + 快慢径发送（H1.1 三切）。
//!
//! - `keepalive_frame` 流内保活唯一帧形态（`: keepalive`，注释帧，不计事件）。
//! - `Speed::Slow` 见文即吐，`Speed::Fast` 攒至标点边界或 4KB 阈值再吐（T4）。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

pub fn keepalive_frame() -> String { ": keepalive\n\n".to_string() }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Fast,
}

/// Fast 径攒批阈值（字节）：攒至标点边界或该阈值即吐出（T4）。
/// 硬编码理由：经验值平衡首字延迟与 SSE 帧数，调整须同步复核续跑测试。
pub const FAST_EMIT_THRESHOLD_BYTES: usize = 4096;

pub fn is_punct_boundary(text: &str) -> bool {
    text.chars().last().is_some_and(|c| {
        matches!(
            c,
            '。' | '！' | '？' | '.' | '!' | '?' | ',' | '，' | ';' | '；' | ':' | '：' | '\n'
        )
    })
}

pub fn select_emit(buffer: &mut String, speed: Speed) -> Option<String> {
    match speed {
        Speed::Slow => {
            if buffer.is_empty() {
                None
            } else {
                Some(std::mem::take(buffer))
            }
        }
        Speed::Fast => {
            if buffer.is_empty() {
                None
            } else if is_punct_boundary(buffer) || buffer.len() >= FAST_EMIT_THRESHOLD_BYTES {
                Some(std::mem::take(buffer))
            } else {
                None
            }
        }
    }
}
