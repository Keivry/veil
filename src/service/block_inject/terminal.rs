//! 终端去重与计数（H1.2 二切：去重终结）。
//!
//! - `dedupe_terminal_frames` 按协议去重终端（chat 归一恰一 `[DONE]`， anthropic 恰一
//!   `message_stop`，responses 恰一 `completed/failed`）。
//! - `terminal_count`/`count_done` 恰一约束的计数口径（D6 帧级/行级）。
//! - `mark_terminal` 落 `StreamMeta.terminal_injected`，泵据此停泵。
//! - 对外路径不变：经 `super`（`service::block_inject`）重导出，调用方零改。

use {
    super::frames::{chat_done_frame, ensure_event_lines, is_done_frame},
    crate::service::sse::StreamMeta,
};

pub fn mark_terminal(meta: &mut StreamMeta) { meta.terminal_injected = true; }

pub fn has_chat_terminal(frames: &[String]) -> bool { frames.iter().any(|f| is_done_frame(f)) }

pub fn normalize_chat_done(frames: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = frames.into_iter().filter(|f| !is_done_frame(f)).collect();
    kept = ensure_event_lines(kept);
    kept.push(chat_done_frame());
    kept
}

pub fn dedupe_terminal_frames(frames: Vec<String>, protocol: &str) -> Vec<String> {
    match protocol {
        "chat" => normalize_chat_done(frames),
        "anthropic" => {
            let mut seen_stop = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_stop = f.contains("message_stop");
                if is_stop {
                    if seen_stop {
                        continue;
                    }
                    seen_stop = true;
                }
                out.push(f);
            }
            out
        }
        _ => {
            let mut seen_term = false;
            let mut out = Vec::new();
            for f in ensure_event_lines(frames) {
                let is_term = f.contains("response.completed") || f.contains("response.failed");
                if is_term {
                    if seen_term {
                        continue;
                    }
                    seen_term = true;
                }
                out.push(f);
            }
            out
        }
    }
}

pub fn should_discard_after_terminal(terminated: bool) -> bool { terminated }

/// 协议级终端计数（D6 帧级）：chat 数 `[DONE]` 帧、anthropic 数 `message_stop`、
/// responses 数 `completed/failed`；恰一约束的计数口径。
pub fn terminal_count(frames: &[String], protocol: &str) -> usize {
    match protocol {
        "chat" => count_done(frames),
        "anthropic" => frames.iter().filter(|f| f.contains("message_stop")).count(),
        _ => frames
            .iter()
            .filter(|f| f.contains("response.completed") || f.contains("response.failed"))
            .count(),
    }
}

/// DONE 行级计数（D6 行级）：逐帧按行精确匹配裸终止行（载荷内同串不误计）。
pub fn count_done(frames: &[String]) -> usize { frames.iter().filter(|f| is_done_frame(f)).count() }
