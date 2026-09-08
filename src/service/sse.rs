use {
    super::llm_gateway::{GatewayMetrics, Protocol},
    std::time::{Duration, Instant},
};

pub const LINE_LIMIT_BYTES: usize = 16 * 1024;
pub const EVENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

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

#[derive(Debug, Default)]
pub struct Utf8ByteBuffer {
    buf: Vec<u8>,
}

impl Utf8ByteBuffer {
    pub fn new() -> Self { Self::default() }

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
        super::redaction::strip_partials(&out)
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
}

pub fn keepalive_frame() -> String { ": keepalive\n\n".to_string() }

#[derive(Debug)]
pub struct KeepaliveTracker {
    last_emit: Instant,
}

impl KeepaliveTracker {
    pub fn new() -> Self {
        Self {
            last_emit: Instant::now(),
        }
    }

    pub fn should_emit(&self) -> bool { self.last_emit.elapsed() >= KEEPALIVE_INTERVAL }

    pub fn mark_emitted(&mut self) { self.last_emit = Instant::now(); }
}

impl Default for KeepaliveTracker {
    fn default() -> Self { Self::new() }
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
        }
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
            self.line_bytes = 0;
            self.event_start = None;
        }
        events
    }

    fn feed_line(&mut self, line: &str) -> Option<SseEvent> {
        if self.event_start.is_none() {
            self.event_start = Some(Instant::now());
        }
        self.line_bytes += line.len();
        if self.line_bytes > LINE_LIMIT_BYTES {
            self.line_overflow = true;
            self.block_lines.clear();
            self.block_comments.clear();
            self.line_bytes = 0;
            self.event_start = None;
            return None;
        }
        if line.is_empty() {
            return self.dispatch_block();
        }
        if let Some(comment) = line.strip_prefix(':') {
            self.block_comments.push(comment.to_string());
            if self.block_lines.is_empty() && self.block_comments.len() == 1 {
                let ev = SseEvent {
                    comments: std::mem::take(&mut self.block_comments),
                    is_comment_only: true,
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
        if tail.trim().is_empty() {
            return String::new();
        }
        json_aware_line(&tail, |s| s)
    }
}

pub fn json_aware_line(line: &str, restore: impl Fn(String) -> String) -> String {
    let trimmed = line.trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed)
        && matches!(
            v,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        let owned_restore = restore;
        return super::json_walk::process_text(
            trimmed,
            &mut |s| owned_restore(s),
            super::json_walk::DEPTH_LIMIT,
        );
    }
    restore(line.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    Slow,
    Fast,
}

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
            } else if is_punct_boundary(buffer) || buffer.len() >= 4096 {
                Some(std::mem::take(buffer))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatwg切行与注释透传() {
        let mut p = SseParser::new();
        let evs = p.push_bytes(b"event: message\ndata: {\"a\":1}\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_type.as_deref(), Some("message"));
        assert_eq!(evs[0].data, "{\"a\":1}");
        let crlf = p.push_bytes(b"data: x\r\ndata: y\r\n\n");
        assert_eq!(crlf[0].data, "x\ny");
        let cr = p.push_bytes(b"data: z\r\r");
        assert_eq!(cr[0].data, "z");
        let comment = p.push_bytes(b": ping\n\n");
        assert!(comment[0].is_comment_only);
        let before = p.sse_event_count;
        let _ = p.push_bytes(b": keepalive\n\n");
        assert_eq!(p.sse_event_count, before);
    }

    #[test]
    fn retry全数字与data单空格剥离() {
        let mut p = SseParser::new();
        let evs = p.push_bytes(b"retry: 3000\ndata:  hello\n\n");
        assert_eq!(evs[0].retry, Some(3000));
        assert_eq!(evs[0].data, " hello");
        let bad = p.push_bytes(b"retry: 3x\ndata: v\n\n");
        assert_eq!(bad[0].retry, None);
    }

    #[test]
    fn utf8按字节缓冲不逐chunk解码() {
        let mut buf = Utf8ByteBuffer::new();
        let ch = "中".as_bytes();
        let first = buf.push(&ch[..1]);
        assert_eq!(first, "");
        assert_eq!(buf.pending_len(), 1);
        let second = buf.push(&ch[1..]);
        assert_eq!(second, "中");
        assert_eq!(buf.pending_len(), 0);
        let mut p = SseParser::new();
        let a = "data: ".as_bytes();
        let b = "中文".as_bytes();
        let mut evs = p.push_bytes(a);
        assert!(evs.is_empty());
        evs = p.push_bytes(&b[..2]);
        assert!(evs.is_empty());
        evs = p.push_bytes(&b[2..]);
        assert!(evs.is_empty());
        evs = p.push_bytes(b"\n\n");
        assert_eq!(evs[0].data, "中文");
    }

    #[test]
    fn 行缓冲16kb兜底不崩() {
        let mut p = SseParser::new();
        let big = vec![b'x'; LINE_LIMIT_BYTES + 10];
        let mut frame = b"data: ".to_vec();
        frame.extend_from_slice(&big);
        frame.extend_from_slice(b"\n\n");
        let evs = p.push_bytes(&frame);
        assert!(evs.is_empty());
        assert!(p.line_overflow);
        let ok = p.push_bytes(b"data: fine\n\n");
        assert_eq!(ok[0].data, "fine");
    }

    #[test]
    fn keepalive对齐且不计事件() {
        let p = SseParser::new();
        assert_eq!(p.sse_event_count, 0);
        let f = keepalive_frame();
        assert_eq!(f, ": keepalive\n\n");
        let mut slow = KeepaliveTracker::new();
        let mut fast = KeepaliveTracker::new();
        assert!(!slow.should_emit() && !fast.should_emit());
        slow.last_emit -= KEEPALIVE_INTERVAL;
        fast.last_emit -= KEEPALIVE_INTERVAL;
        assert!(slow.should_emit() && fast.should_emit());
    }

    #[test]
    fn 截断三态与responses限定() {
        let mut meta = StreamMeta::default();
        assert!(set_truncated(
            &mut meta,
            Protocol::Responses,
            TruncatedMode::SynthesizedFailed,
            None
        ));
        assert_eq!(meta.truncated_mode, Some(TruncatedMode::SynthesizedFailed));
        let mut m2 = StreamMeta::default();
        assert!(!set_truncated(
            &mut m2,
            Protocol::Chat,
            TruncatedMode::SynthesizedFailed,
            None
        ));
        assert!(set_truncated(
            &mut m2,
            Protocol::Chat,
            TruncatedMode::SilentDiscard,
            None
        ));
        assert!(set_truncated(
            &mut m2,
            Protocol::Anthropic,
            TruncatedMode::OpenEnded,
            None
        ));
        let gm = GatewayMetrics::default();
        let mut m3 = StreamMeta::default();
        assert!(set_truncated(
            &mut m3,
            Protocol::Responses,
            TruncatedMode::OpenEnded,
            Some(&gm)
        ));
        assert_eq!(gm.truncated_count("open_ended"), 1);
    }

    #[test]
    fn slow_fast分发语义() {
        let mut buf = "hello。".to_string();
        assert!(select_emit(&mut buf, Speed::Slow).is_some());
        let mut buf2 = "hello".to_string();
        assert!(select_emit(&mut buf2, Speed::Fast).is_none());
        buf2.push('。');
        assert!(select_emit(&mut buf2, Speed::Fast).is_some());
    }

    #[test]
    fn truncation_真实数据_utf8分片重组与终止唯一() {
        let mut buf = Utf8ByteBuffer::new();
        let raw = "data: {\"content\":\"中文回复。\"}\n\n".as_bytes();
        let mut text = String::new();
        for chunk in raw.chunks(3) {
            text.push_str(&buf.push(chunk));
        }
        text.push_str(&buf.flush_text());
        assert!(text.contains("中文回复"));
        let mut p = SseParser::new();
        let mut evs = Vec::new();
        for chunk in raw.chunks(5) {
            evs.extend(p.push_bytes(chunk));
        }
        assert_eq!(evs.len(), 1);
        assert!(evs[0].data.contains("中文回复"));
        let mut meta = StreamMeta::default();
        assert!(set_truncated(
            &mut meta,
            Protocol::Chat,
            TruncatedMode::OpenEnded,
            None
        ));
        assert_eq!(meta.truncated_mode, Some(TruncatedMode::OpenEnded));
    }

    #[test]
    fn data行级json_aware还原() {
        let out = json_aware_line("{\"a\": \"v1\"}", |s| s.replace("v1", "v2"));
        assert!(out.contains("v2"));
        let plain = json_aware_line("plain token", |s| s.to_uppercase());
        assert_eq!(plain, "PLAIN TOKEN");
    }

    #[test]
    fn fast去抖累积至标点或阈值才吐() {
        let mut agg = String::new();
        agg.push_str("hello");
        assert!(select_emit(&mut agg, Speed::Fast).is_none());
        agg.push_str(" world");
        assert!(select_emit(&mut agg, Speed::Fast).is_none());
        assert_eq!(agg, "hello world");
        agg.push('。');
        assert_eq!(
            select_emit(&mut agg, Speed::Fast).as_deref(),
            Some("hello world。")
        );
        assert!(agg.is_empty());
        // 空缓冲恒 None，两档一致。
        assert!(select_emit(&mut agg, Speed::Fast).is_none());
        assert!(select_emit(&mut agg, Speed::Slow).is_none());
        // 4KB 阈值无标点也吐（长文本不饿死）。
        agg.push_str(&"x".repeat(4096));
        assert_eq!(select_emit(&mut agg, Speed::Fast).unwrap().len(), 4096);
        // 阈值差一字节仍缓冲。
        agg.push_str(&"y".repeat(4095));
        assert!(select_emit(&mut agg, Speed::Fast).is_none());
    }

    #[test]
    fn 多行data按序透传且事件名保留() {
        let mut p = SseParser::new();
        let evs = p.push_bytes("event: message\ndata: 第一行\ndata: 第二行\n\n".as_bytes());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].event_type.as_deref(), Some("message"));
        assert_eq!(evs[0].data, "第一行\n第二行");
        // 多行中文分包到达仍完整组装。
        let mut q = SseParser::new();
        assert!(q.push_bytes("data: 甲".as_bytes()).is_empty());
        assert!(q.push_bytes("乙\n".as_bytes()).is_empty());
        let evs = q.push_bytes("data: 丙\n\n".as_bytes());
        assert_eq!(evs[0].data, "甲乙\n丙");
    }
}
