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
    std::{collections::VecDeque, time::Instant},
};

/// D2/STP-2：`text_carry`（未终结行尾）总字节上限——与单行上限同源，防止无行
/// 终止的畸形流（含持续无效 UTF-8）在 `feed_line` 生效前无界累积；超限丢弃尾部
/// 并计入 `truncated_line_dropped_bytes`（与行截断同口径）。
const TEXT_CARRY_MAX_BYTES: usize = LINE_LIMIT_BYTES;

/// D2/TRN-1：跨块 `event:` FIFO 暂存硬上限——仅发信封不发 `data` 的畸形流
/// 超限时丢**最旧**并计入 `pending_events_dropped`（每流首次丢弃 warn），
/// 防无界累积；`pending_retry` 为单值，无需上限。
const PENDING_EVENTS_MAX: usize = 8;

#[derive(Debug, Default)]
pub struct Utf8ByteBuffer {
    buf: Vec<u8>,
}

impl Utf8ByteBuffer {
    pub fn new() -> Self { Self::default() }

    /// D6：仅单测使用，降级为测试可见（生产经 `SseParser` 只用 `push`/`flush_text`）。
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { self.buf.len() }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.buf.extend_from_slice(chunk);
        // D2/STP-2：逐序列推进直至整块消费完——真无效序列（`error_len().is_some()`）
        // 连同该序列一并按替换语义消费（对齐 Python `errors='replace'`），仅合法但
        // 不完整的前缀（`error_len().is_none()`）保留至下一块拼接。旧实现单轮只返回
        // `valid_up_to` 且对真无效字节不前进，导致解析器卡死、缓冲无界增长。
        let mut out = String::new();
        let mut consumed = 0usize;
        while consumed < self.buf.len() {
            match std::str::from_utf8(&self.buf[consumed..]) {
                Ok(_) => {
                    out.push_str(&String::from_utf8_lossy(&self.buf[consumed..]));
                    consumed = self.buf.len();
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    if valid > 0 {
                        out.push_str(&String::from_utf8_lossy(
                            &self.buf[consumed..consumed + valid],
                        ));
                    }
                    match e.error_len() {
                        Some(len) => {
                            let end = consumed + valid + len;
                            out.push_str(&String::from_utf8_lossy(
                                &self.buf[consumed + valid..end],
                            ));
                            consumed = end;
                        }
                        None => {
                            consumed += valid;
                            break;
                        }
                    }
                }
            }
        }
        self.buf.drain(..consumed);
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
    /// STP-10：统一事件计数口径——解析出的数据事件与经
    /// [`SseParser::record_injected_event`] 纳入的注入合成帧（审计阻断/截断收尾等）
    /// 共用本计数，与生产指标 `GatewayMetrics::add_sse_event()` 逐一致；纯注释块与
    /// 纯信封块不计入。生产注入点 SHALL 经 `record_injected_event` 计数。
    pub sse_event_count: u64,
    pub line_overflow: bool,
    /// C11：超长行截断丢弃的尾部字节累计（调用方经
    /// [`SseParser::take_truncated_line_dropped_bytes`] 排入 metrics）。
    truncated_line_dropped_bytes: u64,
    /// C11：当前块是否含截断行（分发时落到 [`SseEvent::truncated`] 后复位）。
    block_truncated: bool,
    /// N3：上一块以孤立 `\r` 结尾，下一块首字节为 `\n` 时按 `\r\n`
    /// 合并吞掉，不产生空行/提前分发。
    swallow_lf: bool,
    /// TRN-1：跨块暂存——「有 `event` 无 `data`」块的 `event` 按 FIFO 待配对
    /// 下一含 `data` 块，出口同块重建，不产生孤立 `event:` 块。
    pending_events: VecDeque<String>,
    /// D2：`pending_events` 超上限丢最旧的累计（经
    /// [`SseParser::take_pending_events_dropped`] 排入观测）。
    pending_events_dropped: u64,
    /// D2：每流仅首次丢弃 warn 一次（防日志洪泛）。
    pending_events_drop_warned: bool,
    /// TRN-1：无 `data` 块暂存的 `retry`，随下一含 `data` 块同块透出。
    pending_retry: Option<u64>,
    /// TRN-1：WHATWG last-event-id——最近一次出现的 `id`（空值重置）对后续
    /// 无 `id` 事件持续有效。
    last_event_id: Option<String>,
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
            swallow_lf: false,
            pending_events: VecDeque::new(),
            pending_events_dropped: 0,
            pending_events_drop_warned: false,
            pending_retry: None,
            last_event_id: None,
        }
    }

    /// 取出并清零超长行丢弃字节累计（泵按块排入 metrics）。
    pub fn take_truncated_line_dropped_bytes(&mut self) -> u64 {
        std::mem::take(&mut self.truncated_line_dropped_bytes)
    }

    /// D2：取出并清零跨块 `event:` 暂存丢弃累计（泵按块排入观测，仿
    /// [`SseParser::take_truncated_line_dropped_bytes`]；不新增导出指标）。
    pub fn take_pending_events_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.pending_events_dropped)
    }

    /// STP-10：把注入的合成帧并入统一事件计数（与解析事件同源），
    /// 使 `sse_event_count` 与生产指标 `GatewayMetrics::add_sse_event()` 一致。
    #[cfg(test)]
    pub(crate) fn record_injected_event(&mut self) { self.sse_event_count += 1; }

    /// D2/STP-2：仅单测使用，暴露未终结行尾缓冲长度以断言有界。
    #[cfg(test)]
    pub fn text_carry_len(&self) -> usize { self.text_carry.len() }

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
            // N3/D5：上一块以孤立 `\r` 收尾时，本块首字节若为 `\n` 则按单个
            // `\r\n` 行终止吞掉，不产生空行提前分发；否则按孤立 `\r` 处理。
            if self.swallow_lf && !bytes.is_empty() {
                if bytes[0] == b'\n' {
                    i = 1;
                    start = 1;
                }
                self.swallow_lf = false;
            }
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
            // 缓冲区以 `\r` 收尾（已按孤立 `\r` 终止行）：CRLF 判定暂存到下一块。
            self.swallow_lf = bytes.last() == Some(&b'\r');
            rest = s[start..].to_string();
        }
        // D2/STP-2：未终结行尾总上限——超限按字符边界截断尾部并计数，防止
        // 无行终止的畸形流在 `feed_line` 生效前无界累积。
        let rest = if rest.len() > TEXT_CARRY_MAX_BYTES {
            let boundary = rest.floor_char_boundary(TEXT_CARRY_MAX_BYTES);
            self.truncated_line_dropped_bytes += (rest.len() - boundary) as u64;
            self.line_overflow = true;
            self.block_truncated = true;
            rest[..boundary].to_string()
        } else {
            rest
        };
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
            // STP-7：块内注释一律累积到本块，待块终止时随块聚合分发——首注释不再
            // 被提前拆为独立事件，同块多注释合为恰一注释事件；含数据块的注释经
            // `SseEvent::comments` 保真，不丢失、不额外多事件。
            self.block_comments.push(comment.to_string());
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
            } else if raw == "data" {
                // P11/D9：无冒号 `data` 行按空值字段处理（WHATWG），参与
                // 多 `data:` 行 `\n` 合并；其他无冒号行维持忽略。
                data_parts.push(String::new());
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
        // TRN-1：维护 last-event-id（空值按 WHATWG 重置）。
        match ev.id.as_deref() {
            Some("") => {
                self.last_event_id = None;
                ev.id = None;
            }
            Some(id) => self.last_event_id = Some(id.to_string()),
            None => {}
        }
        // TRN-1：无 `data` 的纯信封块不产出事件、不计事件数——`event` 入 FIFO、
        // `retry` 暂存，待下一含 `data` 块同块重建（计数与出口帧数保真）。
        if ev.data.is_empty() {
            if ev.event_type.is_some() || ev.retry.is_some() {
                if let Some(t) = ev.event_type.take() {
                    // D2：超上限丢最旧（消费语义不变——存活窗口内仍按 FIFO 配对）。
                    if self.pending_events.len() >= PENDING_EVENTS_MAX {
                        self.pending_events.pop_front();
                        self.pending_events_dropped += 1;
                        if !self.pending_events_drop_warned {
                            self.pending_events_drop_warned = true;
                            tracing::warn!(
                                cap = PENDING_EVENTS_MAX,
                                "SSE 跨块 event 暂存超上限，丢弃最旧（计数经 take_pending_events_dropped 观测）"
                            );
                        }
                    }
                    self.pending_events.push_back(t);
                }
                if ev.retry.is_some() {
                    self.pending_retry = ev.retry.take();
                }
            }
            // STP-7：纯注释块按块聚合为恰一注释事件（不计入 `sse_event_count`），
            // 不再逐行拆分；同块多注释合并为同一事件。
            if !ev.comments.is_empty() {
                ev.is_comment_only = true;
                return Some(ev);
            }
            return None;
        }
        if ev.event_type.is_none() {
            ev.event_type = self.pending_events.pop_front();
        }
        if ev.retry.is_none() {
            ev.retry = self.pending_retry.take();
        }
        if ev.id.is_none() {
            ev.id = self.last_event_id.clone();
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
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
    {
        // H1/D2：JSON 合法即返回输入（仅保留校验），不再二次 `loads→walk→dumps`。
        // Leaf 还原/脱敏已由调用方（scope 层）先行完成；二次序列化会重排
        // 键序/数字表示/空白（如 `1e3`→`1000.0`），与字节保真契约相悖。
        return line.to_string();
    }
    restore(line.to_string())
}
