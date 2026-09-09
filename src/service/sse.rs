use {
    super::llm_gateway::{GatewayMetrics, Protocol},
    std::time::Instant,
};

/// SSE 三常量唯一定义归属 `config`（D5 下沉，只搬不改值），此处原位转发防外部引用断裂。
pub use crate::config::{EVENT_IDLE_TIMEOUT, KEEPALIVE_INTERVAL, LINE_LIMIT_BYTES};
/// D5：`KeepaliveTracker`（时间戳自检形态，生产零接线）已删除，保活唯一实现为
/// `RequestKeepalive`（`pump.rs` 经 `spawn_gated` 接线，间隔消费 `KEEPALIVE_INTERVAL` 10s）。

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
    /// C11 截断标记：本事件含被截断的超长行（头 16KB 已分发审计，
    /// 尾部记 `truncated_line_dropped_bytes`），下游不得视为完整帧。
    pub truncated: bool,
}

pub fn keepalive_frame() -> String { ": keepalive\n\n".to_string() }

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
        let line = super::json_walk::strip_bom(line);
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
        let stripped = super::json_walk::strip_bom(&tail);
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
    let t = super::json_walk::strip_bom(data).trim();
    if t == "[DONE]" {
        return true;
    }
    t.strip_prefix("data:")
        .is_some_and(|rest| super::json_walk::strip_bom(rest).trim() == "[DONE]")
}

/// 残余分类（§2.6）：`None` 必须丢弃，不得 `data:` 直发；
/// - 空/空白 → 丢弃；
/// - `[DONE]`（含 BOM 前缀）→ 丢弃（终端去重已处理，避免重复终止）；
/// - 其余 → `Some` 还原后文本（调用方经还原/脱敏后按正常帧发送； 纯垃圾残余的彻底丢弃由 handler
///   接线方按需收紧，见接线说明）。
pub fn classify_residue(tail: &str) -> Option<String> {
    let stripped = super::json_walk::strip_bom(tail);
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
    let trimmed = super::json_walk::strip_bom(line).trim();
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
    fn whatwg_line_splitting_with_comment_passthrough() {
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
    fn retry_all_digits_and_data_single_space_stripped() {
        let mut p = SseParser::new();
        let evs = p.push_bytes(b"retry: 3000\ndata:  hello\n\n");
        assert_eq!(evs[0].retry, Some(3000));
        assert_eq!(evs[0].data, " hello");
        let bad = p.push_bytes(b"retry: 3x\ndata: v\n\n");
        assert_eq!(bad[0].retry, None);
    }

    #[test]
    fn double_space_data_json_parses() {
        let mut p = SseParser::new();
        let evs = p.push_bytes(b"data:  {\"a\":1}\n\n");
        assert_eq!(evs.len(), 1);
        let v: serde_json::Value =
            serde_json::from_str(&evs[0].data).expect("双空格残留须被 serde_json 容忍");
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn utf8_byte_buffered_without_per_chunk_decoding() {
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
    fn line_buffer_16kb_truncates_with_counter_and_mark() {
        // C11：超长行改丢弃为截断——头 16KB 保留分发审计，尾部计数，
        // 事件带截断标记；后续正常帧不受影响。
        let mut p = SseParser::new();
        let big = "x".repeat(LINE_LIMIT_BYTES + 10);
        let mut frame = b"data: ".to_vec();
        frame.extend_from_slice(big.as_bytes());
        frame.extend_from_slice(b"\n\n");
        let evs = p.push_bytes(&frame);
        assert_eq!(evs.len(), 1, "截断头须分发，不得静默整块丢");
        assert!(evs[0].truncated, "截断事件须带标记");
        assert!(p.line_overflow);
        assert_eq!(
            evs[0].data.len(),
            LINE_LIMIT_BYTES - "data: ".len(),
            "头 16KB（含前缀）保留"
        );
        assert_eq!(
            p.take_truncated_line_dropped_bytes(),
            (big.len() + "data: ".len() - LINE_LIMIT_BYTES) as u64,
            "尾部字节须计数"
        );
        assert_eq!(p.take_truncated_line_dropped_bytes(), 0, "取出后清零");
        let ok = p.push_bytes(b"data: fine\n\n");
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].data, "fine");
        assert!(!ok[0].truncated, "正常帧不得带截断标记");
    }

    #[test]
    fn overlong_tool_fragment_stays_auditable_with_mark() {
        // C11 超长 tool 分片：20KB 工具参数头截断后仍分发（审计可见），
        // 尾部字节计数，标记随事件。
        let mut p = SseParser::new();
        let args = "y".repeat(20 * 1024);
        let payload = format!("{{\"type\":\"tool_use\",\"partial_json\":\"{args}\"}}");
        let frame = format!("data: {payload}\n\n");
        let evs = p.push_bytes(frame.as_bytes());
        assert_eq!(evs.len(), 1);
        assert!(evs[0].truncated);
        assert!(
            evs[0].data.starts_with("{\"type\":\"tool_use\""),
            "头部须保留可审计"
        );
        assert!(evs[0].data.len() < payload.len(), "尾部须被截断");
        assert!(p.take_truncated_line_dropped_bytes() > 0);
    }

    #[test]
    fn keepalive_aligned_without_counting_events() {
        let p = SseParser::new();
        assert_eq!(p.sse_event_count, 0);
        let f = keepalive_frame();
        assert_eq!(f, ": keepalive\n\n");
    }

    #[test]
    fn truncation_three_states_with_responses_restriction() {
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
    fn slow_fast_dispatch_semantics() {
        let mut buf = "hello。".to_string();
        assert!(select_emit(&mut buf, Speed::Slow).is_some());
        let mut buf2 = "hello".to_string();
        assert!(select_emit(&mut buf2, Speed::Fast).is_none());
        buf2.push('。');
        assert!(select_emit(&mut buf2, Speed::Fast).is_some());
    }

    #[test]
    fn truncation_real_data_utf8_fragments_reassembled_single_terminal() {
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
    fn data_line_level_json_aware_restore() {
        let out = json_aware_line("{\"a\": \"v1\"}", |s| s.replace("v1", "v2"));
        assert!(out.contains("v2"));
        let plain = json_aware_line("plain token", |s| s.to_uppercase());
        assert_eq!(plain, "PLAIN TOKEN");
    }

    #[test]
    fn fast_debounce_accumulates_until_punctuation_or_threshold() {
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
    fn bom_done_residue_discarded_single_terminal() {
        assert!(is_done_payload("\u{feff}[DONE]"));
        assert!(is_done_payload("  [DONE]  "));
        assert!(is_done_payload("data: [DONE]"));
        assert!(is_done_payload("data:[DONE]"));
        assert!(is_done_payload("\u{feff}data: [DONE]"));
        assert!(!is_done_payload("[DONE] extra"));
        assert!(!is_done_payload("{\"a\":1}"));
        assert!(classify_residue("").is_none());
        assert!(classify_residue("   ").is_none());
        assert!(classify_residue("\u{feff}data: [DONE]").is_none());
        assert!(classify_residue("\u{feff}[DONE]").is_none());
        // JSON 残余保留还原（断连半帧不断链）。
        let kept = classify_residue("data: {\"a\": 1").expect("半帧残余须保留");
        assert!(kept.contains("\"a\""));
        // BOM+JSON 正常解析，不当残余转发。
        let out = json_aware_line("\u{feff}{\"a\": \"v1\"}", |s| s.replace("v1", "v2"));
        assert!(out.contains("v2"));
        // 残余 DONE 经 parser 直接丢弃，不 data: 转发。
        let mut q = SseParser::new();
        let _ = q.push_bytes("\u{feff}[DONE]".as_bytes());
        assert!(q.residual_json_aware().is_empty());
        // BOM 流经终端去重后恰一终止帧。
        let frames = super::super::block_inject::dedupe_terminal_frames(
            vec![
                "event: message\ndata: {\"a\":1}\n\n".to_string(),
                "data: [DONE]\n\n".to_string(),
                "\u{feff}data: [DONE]\n\n".to_string(),
            ],
            "chat",
        );
        assert_eq!(
            super::super::block_inject::count_done(&frames),
            1,
            "BOM+重复 DONE 去重后恰一终止"
        );
        assert!(
            frames
                .last()
                .is_some_and(|f| super::super::block_inject::is_done_frame(f))
        );
    }

    #[test]
    fn multiline_data_ordered_passthrough_preserving_event_name() {
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

    #[test]
    fn empty_retry_and_comment_lines_ignored_without_event_count() {
        let mut p = SseParser::new();
        let before = p.sse_event_count;
        let evs = p.push_bytes(b"retry:\ndata: v\n\n");
        assert_eq!(evs[0].retry, None, "空 retry 不得解析出数值");
        assert_eq!(evs[0].data, "v");
        let c1 = p.push_bytes(b": comment-a\n\n");
        assert!(c1[0].is_comment_only);
        let c2 = p.push_bytes(b": comment-b\n\n");
        assert!(c2[0].is_comment_only);
        assert_eq!(
            p.sse_event_count,
            before + 1,
            "纯注释帧透传但不计入事件（comment 不计）"
        );
    }

    #[test]
    fn refusal_three_fragments_reassembled_single_event() {
        let mut p = SseParser::new();
        let full = "data: {\"choices\":[{\"delta\":{\"refusal\":\"合成拒绝文\"}}]}\n\n";
        let a = full.floor_char_boundary(full.len() / 3);
        let b = full.floor_char_boundary(2 * full.len() / 3);
        assert!(p.push_bytes(&full.as_bytes()[..a]).is_empty());
        assert!(p.push_bytes(&full.as_bytes()[a..b]).is_empty());
        let evs = p.push_bytes(&full.as_bytes()[b..]);
        assert_eq!(evs.len(), 1, "三片段须重组为单事件单次还原");
        assert!(evs[0].data.contains("合成拒绝文"));
        assert_eq!(p.sse_event_count, 1, "幂等哨兵：单事件只计一次");
    }

    #[test]
    fn flush_text_idempotent_without_double_restore() {
        let mut buf = Utf8ByteBuffer::new();
        assert_eq!(buf.push("甲".as_bytes()), "甲");
        let first = buf.flush_text();
        assert!(first.is_empty(), "无残余时 flush 为空");
        let second = buf.flush_text();
        assert!(second.is_empty(), "重复 flush 不得二次产出（无双还原）");
        let mut p = SseParser::new();
        assert!(p.push_bytes(b"data: {\"a\":1}\n").is_empty());
        let evs = p.push_bytes(b"\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "{\"a\":1}");
    }

    #[test]
    fn bom_prefixed_frames_parse_like_non_bom() {
        // C12：行内 BOM 先剥离再解析——BOM 前缀帧与非 BOM 等价分发。
        // R1：经 `json_walk::strip_bom` 唯一来源断言（`strip_sse_bom` 已删）。
        assert_eq!(
            super::super::json_walk::strip_bom("\u{feff}data: x"),
            "data: x"
        );
        assert_eq!(
            super::super::json_walk::strip_bom("\u{feff}\u{feff}data: x"),
            "data: x"
        );
        let mut p = SseParser::new();
        let evs = p.push_bytes("\u{feff}data: {\"b\":2}\n\n".as_bytes());
        assert_eq!(evs.len(), 1, "BOM 数据行须产出事件");
        assert_eq!(evs[0].data, "{\"b\":2}");
        assert!(!evs[0].truncated);
        let mut q = SseParser::new();
        let evs_q = q.push_bytes("data: {\"b\":2}\n\n".as_bytes());
        assert_eq!(evs_q[0].data, evs[0].data, "BOM 与非 BOM 等价");
        // BOM 事件名前缀同样识别；BOM 终止帧照常为 `[DONE]` 数据。
        let mut r = SseParser::new();
        let evs_r = r.push_bytes("\u{feff}event: message\n\u{feff}data: {\"b\":3}\n\n".as_bytes());
        assert_eq!(evs_r.len(), 1);
        assert_eq!(evs_r[0].event_type.as_deref(), Some("message"));
        assert_eq!(evs_r[0].data, "{\"b\":3}");
        let mut d = SseParser::new();
        let evs_d = d.push_bytes("\u{feff}data: [DONE]\n\n".as_bytes());
        assert_eq!(evs_d.len(), 1);
        assert!(is_done_payload(&evs_d[0].data));
        // 纯注释帧仍透传。
        let c = p.push_bytes(b": note\n\n");
        assert_eq!(c.len(), 1, "注释帧须透传");
        assert!(c[0].is_comment_only);
    }
}

/// T4 快慢径/delta 切分回补：`select_emit` 两档语义 + 解析器分包等价。
#[cfg(test)]
mod speed_split_parity_tests {
    use super::{Speed, SseParser, is_punct_boundary, select_emit};

    #[test]
    fn t4_slow_emits_immediately_fast_holds() {
        let mut slow = "hello".to_string();
        assert_eq!(
            select_emit(&mut slow, Speed::Slow).as_deref(),
            Some("hello")
        );
        assert!(slow.is_empty());
        let mut fast = "hello".to_string();
        assert!(select_emit(&mut fast, Speed::Fast).is_none());
        assert_eq!(fast, "hello");
    }

    #[test]
    fn t4_fast_slow_converge_on_punctuation() {
        for tail in ["。", ".", "!", "?", ",", "，", ";", "：", "\n"] {
            assert!(is_punct_boundary(&format!("x{tail}")), "{tail:?}");
            let mut buf = format!("text{tail}");
            assert_eq!(
                select_emit(&mut buf, Speed::Fast).as_deref(),
                Some(format!("text{tail}").as_str())
            );
        }
        assert!(!is_punct_boundary("hello"));
        assert!(!is_punct_boundary(""));
    }

    #[test]
    fn t4_fast_slow_final_output_identical() {
        let full = "第一句。第二句！第三句？尾";
        let mut slow_out = String::new();
        let mut buf = String::new();
        for ch in full.chars() {
            buf.push(ch);
            if let Some(chunk) = select_emit(&mut buf, Speed::Slow) {
                slow_out.push_str(&chunk);
            }
        }
        slow_out.push_str(&buf);
        let mut fast_out = String::new();
        let mut buf = String::new();
        for ch in full.chars() {
            buf.push(ch);
            if let Some(chunk) = select_emit(&mut buf, Speed::Fast) {
                fast_out.push_str(&chunk);
            }
        }
        fast_out.push_str(&buf);
        assert_eq!(slow_out, full);
        assert_eq!(fast_out, full);
    }

    #[test]
    fn t4_delta_byte_splits_reassemble_identically() {
        let raw =
            "data: {\"choices\":[{\"delta\":{\"content\":\"你好世界\"}}]}\n\ndata: [DONE]\n\n";
        let whole: Vec<String> = {
            let mut p = SseParser::new();
            p.push_bytes(raw.as_bytes())
                .iter()
                .map(|e| e.data.clone())
                .collect()
        };
        for at in [1usize, 7, 13, 29, 53] {
            let at = raw.floor_char_boundary(at.min(raw.len()));
            let mut p = SseParser::new();
            let mut got = Vec::new();
            got.extend(
                p.push_bytes(&raw.as_bytes()[..at])
                    .iter()
                    .map(|e| e.data.clone()),
            );
            got.extend(
                p.push_bytes(&raw.as_bytes()[at..])
                    .iter()
                    .map(|e| e.data.clone()),
            );
            assert_eq!(got, whole, "切分点 {at} 须与整体等价");
        }
    }

    #[test]
    fn t4_delta_char_streaming_single_event() {
        let raw = "data: {\"delta\":{\"content\":\"abc\"}}\n\n";
        let mut p = SseParser::new();
        let mut events = 0;
        for chunk in raw.as_bytes().chunks(3) {
            events += p.push_bytes(chunk).len();
        }
        assert_eq!(events, 1, "逐片投喂须重组为单事件");
    }

    #[test]
    fn t4_fast_threshold_bytes_not_chars() {
        let mut buf = "中".repeat(1366);
        assert!(
            select_emit(&mut buf, Speed::Fast).is_some(),
            "4098 字节≥阈值应吐"
        );
        let mut buf2 = "x".repeat(4095);
        assert!(select_emit(&mut buf2, Speed::Fast).is_none());
    }

    #[test]
    fn t9_sse_event_count_per_block() {
        let mut p = SseParser::new();
        assert_eq!(p.sse_event_count, 0);
        let evs = p.push_bytes(b"data: a\n\ndata: b\n\ndata: c\n\n");
        assert_eq!(evs.len(), 3);
        assert_eq!(p.sse_event_count, 3, "每数据块计一次");
        let comments = p.push_bytes(b": note\n\n");
        assert_eq!(comments.len(), 1);
        assert!(comments[0].is_comment_only);
        assert_eq!(p.sse_event_count, 3, "纯注释块不计入事件");
    }
}
