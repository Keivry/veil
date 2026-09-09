//! SSE 切行解析 + 截断（H1.1 二切：行切分/超长行截断/残余分类）。
//!
//! - `Utf8ByteBuffer` 按字节累积、按有效 UTF-8 边界吐文本（分片中文不碎字）。
//! - `SseParser` WHATWG 行切分（`\n`/`\r\n`/`\r`）+ 块分发（`event:/data:/id:/retry:`）
//!   + C11 超长行截断（头 16KB 保留分发审计、尾部计数、事件带 `truncated` 标记）。
//! - `is_done_payload`/`classify_residue`/`json_aware_line` 残余与载荷判定（§2.6）。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

use {
    crate::{
        config::{EVENT_IDLE_TIMEOUT, LINE_LIMIT_BYTES},
        service::{json_walk, redaction},
    },
    std::time::Instant,
};

#[derive(Debug, Default)]
pub struct Utf8ByteBuffer {
    buf: Vec<u8>,
}

impl Utf8ByteBuffer {
    pub fn new() -> Self { Self::default() }

    /// D6：仅单测使用，降级为测试可见（生产经 `SseParser` 只用 `push`/`flush_text`）。
    #[cfg(test)]
    pub fn pending_len(&self) -> usize { self.buf.len() }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.buf.extend_from_slice(chunk);
        let valid_up_to = match std::str::from_utf8(&self.buf) {
            Ok(_) => self.buf.len(),
            Err(e) => {
                let valid = e.valid_up_to();
                if e.error_len().is_none() {
                    valid
                } else {
                    match std::str::from_utf8(&self.buf[..valid]) {
                        Ok(_) => valid,
                        Err(_) => 0,
                    }
                }
            }
        };
        let out = String::from_utf8_lossy(&self.buf[..valid_up_to]).into_owned();
        self.buf.drain(..valid_up_to);
        out
    }

    pub fn flush_text(&mut self) -> String {
        let out = String::from_utf8_lossy(&self.buf).into_owned();
        self.buf.clear();
        redaction::strip_partials(&out)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
    pub id: Option<String>,
    pub retry: Option<u64>,
    pub comments: Vec<String>,
    pub is_comment_only: bool,
    /// C11 截断标记：本事件含被截断的超长行（头 16KB 已分发审计，
    /// 尾部记 `truncated_line_dropped_bytes`），下游不得视为完整帧。
    pub truncated: bool,
}

#[derive(Debug)]
pub struct SseParser {
    byte_buf: Utf8ByteBuffer,
    text_carry: String,
    block_lines: Vec<String>,
    block_comments: Vec<String>,
    line_bytes: usize,
    event_start: Option<Instant>,
    pub sse_event_count: u64,
    pub line_overflow: bool,
    /// C11：超长行截断丢弃的尾部字节累计（调用方经
    /// [`SseParser::take_truncated_line_dropped_bytes`] 排入 metrics）。
    truncated_line_dropped_bytes: u64,
    /// C11：当前块是否含截断行（分发时落到 [`SseEvent::truncated`] 后复位）。
    block_truncated: bool,
}

impl Default for SseParser {
    fn default() -> Self { Self::new() }
}

impl SseParser {
    pub fn new() -> Self {
        Self {
            byte_buf: Utf8ByteBuffer::new(),
            text_carry: String::new(),
            block_lines: Vec::new(),
            block_comments: Vec::new(),
            line_bytes: 0,
            event_start: None,
            sse_event_count: 0,
            line_overflow: false,
            truncated_line_dropped_bytes: 0,
            block_truncated: false,
        }
    }

    /// 取出并清零超长行丢弃字节累计（泵按块排入 metrics）。
    pub fn take_truncated_line_dropped_bytes(&mut self) -> u64 {
        std::mem::take(&mut self.truncated_line_dropped_bytes)
    }

    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let text = self.byte_buf.push(chunk);
        self.push_text(&text)
    }

    fn push_text(&mut self, text: &str) -> Vec<SseEvent> {
        self.text_carry.push_str(text);
        let mut events = Vec::new();
        let mut lines: Vec<String> = Vec::new();
        let rest: String;
        {
            let s = &self.text_carry;
            let bytes = s.as_bytes();
            let mut start = 0usize;
            let mut i = 0usize;
            while i < bytes.len() {
                if bytes[i] == b'\r' {
                    lines.push(s[start..i].to_string());
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                        i += 2;
                    } else {
                        i += 1;
                    }
                    start = i;
                } else if bytes[i] == b'\n' {
                    lines.push(s[start..i].to_string());
                    i += 1;
                    start = i;
                } else {
                    i += 1;
                }
            }
            rest = s[start..].to_string();
        }
        self.text_carry = rest;
        for line in lines {
            if let Some(ev) = self.feed_line(&line) {
                events.push(ev);
            }
        }
        if self.event_idle_exceeded() {
            self.block_lines.clear();
            self.block_comments.clear();
            self.block_truncated = false;
            self.line_bytes = 0;
            self.event_start = None;
        }
        events
    }

    fn feed_line(&mut self, line: &str) -> Option<SseEvent> {
        if self.event_start.is_none() {
            self.event_start = Some(Instant::now());
        }
        // C12：行内 BOM 先剥离再解析（复用 `json_walk::strip_bom`，
        // 删除归 `veil-arch-hygiene-round4` R1，此处只路由新/改调用点）。
        let line = json_walk::strip_bom(line);
        // C11 超长行截断标记化：超 16KB 时保留界内头部随块分发审计，
        // 尾部记字节计数，不静默整块丢；块满后同块余行全计数丢弃。
        if !line.is_empty() && self.line_bytes >= LINE_LIMIT_BYTES {
            self.truncated_line_dropped_bytes += line.len() as u64;
            self.line_overflow = true;
            self.block_truncated = true;
            return None;
        }
        let truncated_head: Option<String> = if self.line_bytes + line.len() > LINE_LIMIT_BYTES {
            let keep = LINE_LIMIT_BYTES - self.line_bytes;
            let boundary = line.floor_char_boundary(keep.min(line.len()));
            self.truncated_line_dropped_bytes += (line.len() - boundary) as u64;
            self.line_overflow = true;
            self.block_truncated = true;
            Some(line[..boundary].to_string())
        } else {
            None
        };
        let effective: &str = truncated_head.as_deref().unwrap_or(line);
        self.line_bytes += effective.len();
        let line = effective;
        if line.is_empty() {
            return self.dispatch_block();
        }
        if let Some(comment) = line.strip_prefix(':') {
            self.block_comments.push(comment.to_string());
            if self.block_lines.is_empty() && self.block_comments.len() == 1 {
                let ev = SseEvent {
                    comments: std::mem::take(&mut self.block_comments),
                    is_comment_only: true,
                    truncated: std::mem::take(&mut self.block_truncated),
                    ..Default::default()
                };
                self.line_bytes = 0;
                self.event_start = None;
                return Some(ev);
            }
            return None;
        }
        self.block_lines.push(line.to_string());
        None
    }

    fn dispatch_block(&mut self) -> Option<SseEvent> {
        if self.block_lines.is_empty() && self.block_comments.is_empty() {
            self.line_bytes = 0;
            self.event_start = None;
            return None;
        }
        let mut ev = SseEvent {
            comments: std::mem::take(&mut self.block_comments),
            truncated: std::mem::take(&mut self.block_truncated),
            ..Default::default()
        };
        let mut data_parts: Vec<String> = Vec::new();
        for raw in std::mem::take(&mut self.block_lines) {
            if let Some(v) = raw.strip_prefix("event:") {
                ev.event_type = Some(v.strip_prefix(' ').unwrap_or(v).to_string());
            } else if let Some(v) = raw.strip_prefix("data:") {
                data_parts.push(v.strip_prefix(' ').unwrap_or(v).to_string());
            } else if let Some(v) = raw.strip_prefix("id:") {
                ev.id = Some(v.strip_prefix(' ').unwrap_or(v).to_string());
            } else if let Some(v) = raw.strip_prefix("retry:") {
                let t = v.trim();
                if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
                    ev.retry = t.parse::<u64>().ok();
                }
            }
        }
        ev.data = data_parts.join("\n");
        self.line_bytes = 0;
        self.event_start = None;
        if ev.event_type.is_none() && ev.data.is_empty() && ev.id.is_none() && ev.retry.is_none() {
            return None;
        }
        self.sse_event_count += 1;
        Some(ev)
    }

    fn event_idle_exceeded(&self) -> bool {
        self.event_start
            .is_some_and(|t| t.elapsed() >= EVENT_IDLE_TIMEOUT)
    }

    pub fn residual_json_aware(&mut self) -> String {
        let mut tail = self.byte_buf.flush_text();
        tail.push_str(&std::mem::take(&mut self.text_carry));
        // §2.6：BOM 剥离后判空与 DONE；残余 DONE 丢弃（终端已由正常事件
        // 处理，此处再 `data:` 直发会造成重复终止帧），不做 `data:` 转发。
        let stripped = json_walk::strip_bom(&tail);
        if stripped.trim().is_empty() {
            return String::new();
        }
        if is_done_payload(stripped) {
            return String::new();
        }
        json_aware_line(stripped, |s| s)
    }
}

/// DONE 载荷判定（§2.6/D6 载荷级）：BOM 剥离后 trim 等于 `[DONE]` 即终端；
/// 兼容残余路径的 `data:` 前缀形态（`data: [DONE]`/`data:[DONE]`，含 BOM）；
/// chat 裸帧恒为 `data: [DONE]`，不得补 `event:`。
/// R1：BOM 唯一来源为 `json_walk::strip_bom`（`strip_sse_bom` 已删，同体函数）。
pub fn is_done_payload(data: &str) -> bool {
    let t = json_walk::strip_bom(data).trim();
    if t == "[DONE]" {
        return true;
    }
    t.strip_prefix("data:")
        .is_some_and(|rest| json_walk::strip_bom(rest).trim() == "[DONE]")
}

/// 残余分类（§2.6）：`None` 必须丢弃，不得 `data:` 直发；
/// - 空/空白 → 丢弃；
/// - `[DONE]`（含 BOM 前缀）→ 丢弃（终端去重已处理，避免重复终止）；
/// - 其余 → `Some` 还原后文本（调用方经还原/脱敏后按正常帧发送； 纯垃圾残余的彻底丢弃由 handler
///   接线方按需收紧，见接线说明）。
pub fn classify_residue(tail: &str) -> Option<String> {
    let stripped = json_walk::strip_bom(tail);
    if stripped.trim().is_empty() {
        return None;
    }
    if is_done_payload(stripped) {
        return None;
    }
    Some(json_aware_line(stripped, |s| s))
}

pub fn json_aware_line(line: &str, restore: impl Fn(String) -> String) -> String {
    // §2.6：BOM 剥离后判 JSON（BOM+JSON 不得当残余转发）。
    let trimmed = json_walk::strip_bom(line).trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed)
        && matches!(
            v,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        let owned_restore = restore;
        return json_walk::process_text(trimmed, &mut |s| owned_restore(s), json_walk::DEPTH_LIMIT);
    }
    restore(line.to_string())
}
