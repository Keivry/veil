//! SSE 切行解析 + 有界超长行处理（行切分/超软限观测/超硬限 fail-closed/残余分类）。
//!
//! - `Utf8ByteBuffer` 按字节累积、按有效 UTF-8 边界吐文本（分片中文不碎字）。
//! - `SseParser` WHATWG 行切分（`\n`/`\r\n`/`\r`）+ 块分发（`event:/data:/id:/retry:`）
//!   + 超软限完整交付观测（`oversize` 标记 + `oversize_frame_bytes`/`oversize_frames`）
//!   + 超硬限 fail-closed（`carry_fatal`，不截断交付、不无界累积）。
//! - `is_done_payload`/`classify_residue`/`json_aware_line` 残余与载荷判定。
//! - 对外路径不变：经 `super`（`service::sse`）重导出，调用方零改。

use {
    crate::{
        config::{EVENT_IDLE_TIMEOUT, SSE_FRAME_HARD_BYTES, SSE_FRAME_SOFT_BYTES},
        service::{json_walk, redaction},
    },
    std::{collections::VecDeque, time::Instant},
};

/// `text_carry`（未终结行尾）总字节上限**默认值**——与配置默认同源：无行终止的
/// 畸形流（含持续无效 UTF-8）累积超限即置 `carry_fatal` fail-closed，丢弃整条未终结行
/// （SHALL NOT 截断尾部后先行交付），缓冲有界。运行时经配置
/// `SSE_FRAME_HARD_BYTES`（env/TOML）覆盖，注入点为 [`SseParser::with_hard_bytes`]。
const TEXT_CARRY_MAX_BYTES: usize = SSE_FRAME_HARD_BYTES;

/// 跨块 `event:` FIFO 暂存硬上限——仅发信封不发 `data` 的畸形流
/// 超限时**清空整队**并计入 `pending_events_dropped`（fail-safe：宁缺信封不错标，
/// 每流首次丢弃 warn），防无界累积；`pending_retry` 为单值，无需上限。
const PENDING_EVENTS_MAX: usize = 8;

#[derive(Debug, Default)]
pub struct Utf8ByteBuffer {
    buf: Vec<u8>,
}

impl Utf8ByteBuffer {
    pub fn new() -> Self { Self::default() }

    /// 仅单测使用，降级为测试可见（生产经 `SseParser` 只用 `push`/`flush_text`）。
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { self.buf.len() }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        self.buf.extend_from_slice(chunk);
        // 逐序列推进直至整块消费完——真无效序列（`error_len().is_some()`）
        // 连同该序列一并按替换语义消费，仅合法但
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
    /// 超软限标记：本事件超过软限（1MiB）但已**完整交付**（未截断）。
    /// 语义取代旧 `truncated`（旧口径为「被截断、下游不得视为完整帧」）。
    pub oversize: bool,
}

#[derive(Debug)]
pub struct SseParser {
    byte_buf: Utf8ByteBuffer,
    text_carry: String,
    block_lines: Vec<String>,
    block_comments: Vec<String>,
    line_bytes: usize,
    /// 运行时硬上限（配置 `SSE_FRAME_HARD_BYTES` 注入；默认 [`TEXT_CARRY_MAX_BYTES`]）：
    /// 单行/单事件与未终结行尾两条超限路径同源消费本值。
    sse_frame_hard_bytes: usize,
    event_start: Option<Instant>,
    /// 统一事件计数口径——解析出的数据事件与经
    /// `SseParser::record_injected_event` 纳入的注入合成帧（审计阻断/截断收尾等）
    /// 共用本计数，与生产指标 `GatewayMetrics::add_sse_event()` 逐一致；纯注释块与
    /// 纯信封块不计入。生产注入点 SHALL 经 `record_injected_event` 计数。
    pub sse_event_count: u64,
    pub line_overflow: bool,
    /// 超长行丢弃字节累计（旧截断口径，生产恒 0；调用方经
    /// [`SseParser::take_truncated_line_dropped_bytes`] 排入 metrics，字段保留兼容）。
    truncated_line_dropped_bytes: u64,
    /// 超软限完整交付的帧字节/帧数累计（经 `take_oversize_*` 排入 metrics）。
    oversize_frame_bytes: u64,
    oversize_frames: u64,
    /// 当前块是否超软限（分发时落到 [`SseEvent::oversize`] 后复位）。
    block_oversize: bool,
    /// 超硬限 fail-closed 粘滞位：置位后不再解析/交付任何后续字节，
    /// 由泵侧合成协议正确终止帧收尾（残余与未终结行尾一律不交付）。
    carry_fatal: bool,
    /// 上一块以孤立 `\r` 结尾，下一块首字节为 `\n` 时按 `\r\n`
    /// 合并吞掉，不产生空行/提前分发。
    swallow_lf: bool,
    /// 跨块暂存——「有 `event` 无 `data`」块的 `event` 按 FIFO 待配对
    /// 下一含 `data` 块，出口同块重建，不产生孤立 `event:` 块。
    pending_events: VecDeque<String>,
    /// `pending_events` 超上限清空整队丢弃的累计（已暂存项 + 触发事件，
    /// 经 [`SseParser::take_pending_events_dropped`] 排入观测）。
    pending_events_dropped: u64,
    /// 每流仅首次丢弃 warn 一次（防日志洪泛）。
    pending_events_drop_warned: bool,
    /// 无 `data` 块暂存的 `retry`，随下一含 `data` 块同块透出。
    pending_retry: Option<u64>,
    /// WHATWG last-event-id——最近一次出现的 `id`（空值重置）对后续
    /// 无 `id` 事件持续有效。
    last_event_id: Option<String>,
}

impl Default for SseParser {
    fn default() -> Self { Self::new() }
}

impl SseParser {
    /// 默认硬上限构造（等价 [`SseParser::with_hard_bytes`] 传 `TEXT_CARRY_MAX_BYTES`）。
    pub fn new() -> Self { Self::with_hard_bytes(TEXT_CARRY_MAX_BYTES) }

    /// 以配置层（env/TOML `SSE_FRAME_HARD_BYTES`）解析出的运行时硬上限构造：
    /// 未终结行尾（`text_carry`）与单行/单事件超限路径同源消费本值。
    pub fn with_hard_bytes(sse_frame_hard_bytes: usize) -> Self {
        Self {
            byte_buf: Utf8ByteBuffer::new(),
            text_carry: String::new(),
            block_lines: Vec::new(),
            block_comments: Vec::new(),
            line_bytes: 0,
            sse_frame_hard_bytes,
            event_start: None,
            sse_event_count: 0,
            line_overflow: false,
            truncated_line_dropped_bytes: 0,
            oversize_frame_bytes: 0,
            oversize_frames: 0,
            block_oversize: false,
            carry_fatal: false,
            swallow_lf: false,
            pending_events: VecDeque::new(),
            pending_events_dropped: 0,
            pending_events_drop_warned: false,
            pending_retry: None,
            last_event_id: None,
        }
    }

    /// 取出并清零旧口径超长行丢弃字节累计（生产恒 0；保留兼容）。
    pub fn take_truncated_line_dropped_bytes(&mut self) -> u64 {
        std::mem::take(&mut self.truncated_line_dropped_bytes)
    }

    /// 取出并清零超软限完整交付帧的字节累计（泵按块排入 metrics）。
    pub fn take_oversize_bytes(&mut self) -> u64 { std::mem::take(&mut self.oversize_frame_bytes) }

    /// 取出并清零超软限完整交付帧的帧数累计（泵按块排入 metrics）。
    pub fn take_oversize_frames(&mut self) -> u64 { std::mem::take(&mut self.oversize_frames) }

    /// 超硬限 fail-closed 粘滞位（泵据此以协议正确终止帧收尾）。
    pub fn carry_fatal(&self) -> bool { self.carry_fatal }

    /// 取出并清零跨块 `event:` 暂存丢弃累计（泵按块排入观测，仿
    /// [`SseParser::take_truncated_line_dropped_bytes`]；不新增导出指标）。
    pub fn take_pending_events_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.pending_events_dropped)
    }

    /// 把注入的合成帧并入统一事件计数（与解析事件同源），
    /// 使 `sse_event_count` 与生产指标 `GatewayMetrics::add_sse_event()` 一致。
    #[cfg(test)]
    pub(crate) fn record_injected_event(&mut self) { self.sse_event_count += 1; }

    /// 仅单测使用，暴露未终结行尾缓冲长度以断言有界。
    #[cfg(test)]
    pub fn text_carry_len(&self) -> usize { self.text_carry.len() }

    pub fn push_bytes(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let text = self.byte_buf.push(chunk);
        self.push_text(&text)
    }

    fn push_text(&mut self, text: &str) -> Vec<SseEvent> {
        if self.carry_fatal {
            return Vec::new();
        }
        self.text_carry.push_str(text);
        let mut events = Vec::new();
        let mut lines: Vec<String> = Vec::new();
        let rest: String;
        {
            let s = &self.text_carry;
            let bytes = s.as_bytes();
            let mut start = 0usize;
            let mut i = 0usize;
            // 上一块以孤立 `\r` 收尾时，本块首字节若为 `\n` 则按单个
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
        // 未终结行尾超硬限 → fail-closed：丢弃整条未终结行（SHALL NOT 截断尾部先行交付），
        // 置粘滞位并计数，缓冲有界；后续字节一律不解析。
        if rest.len() > self.sse_frame_hard_bytes {
            self.fail_closed_oversize(rest.len() as u64);
            return Vec::new();
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
            self.block_oversize = false;
            self.line_bytes = 0;
            self.event_start = None;
        }
        events
    }

    /// 超硬上限统一 fail-closed 收尾：置粘滞位、计入 `oversize` 观测、清空未终结
    /// 行尾与当前块缓冲。未终结行尾路径与块级累计路径同源消费本方法，语义一致。
    fn fail_closed_oversize(&mut self, bytes: u64) {
        self.carry_fatal = true;
        self.line_overflow = true;
        self.oversize_frames += 1;
        self.oversize_frame_bytes += bytes;
        self.text_carry.clear();
        self.block_lines.clear();
        self.block_comments.clear();
        self.block_oversize = false;
        self.line_bytes = 0;
        self.event_start = None;
    }

    fn feed_line(&mut self, line: &str) -> Option<SseEvent> {
        // 同批已置 fail-closed 时，后续行一律不再进入块（不交付半帧）。
        if self.carry_fatal {
            return None;
        }
        if self.event_start.is_none() {
            self.event_start = Some(Instant::now());
        }
        // 行内 BOM 先剥离再解析（复用 `json_walk::strip_bom`，
        // 旧实现已删除，此处只路由新/改调用点）。
        let line = json_walk::strip_bom(line);
        // 超软限仅观测：完整缓冲、原样分发，超限置块级标记待分发时计数。
        if !line.is_empty() {
            self.line_bytes += line.len();
            if self.line_bytes > SSE_FRAME_SOFT_BYTES {
                self.line_overflow = true;
                self.block_oversize = true;
            }
            // 块级硬上限（单行或同块多行累计超限）→ fail-closed：一次 `push_bytes`
            // 内带换行到达的完整超硬限行/块不得完整交付，与未终结行尾路径同源收尾，
            // 关闭「小行累计成巨型块」的无界累积面。
            if self.line_bytes > self.sse_frame_hard_bytes {
                self.fail_closed_oversize(self.line_bytes as u64);
                return None;
            }
        }
        if line.is_empty() {
            return self.dispatch_block();
        }
        if let Some(comment) = line.strip_prefix(':') {
            // 块内注释一律累积到本块，待块终止时随块聚合分发——首注释不再
            // 被提前拆为独立事件，同块多注释合为恰一注释事件；含数据块的注释经
            // `SseEvent::comments` 保真，不丢失、不额外多事件。
            self.block_comments.push(comment.to_string());
            return None;
        }
        self.block_lines.push(line.to_string());
        None
    }

    fn dispatch_block(&mut self) -> Option<SseEvent> {
        let block_oversize = std::mem::take(&mut self.block_oversize);
        let block_bytes = self.line_bytes;
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
            } else if raw == "data" {
                // 无冒号 `data` 行按空值字段处理（WHATWG），参与
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
        if block_oversize && !ev.data.is_empty() {
            ev.oversize = true;
            self.oversize_frames += 1;
            self.oversize_frame_bytes += block_bytes as u64;
        }
        self.line_bytes = 0;
        self.event_start = None;
        // 维护 last-event-id（空值按 WHATWG 重置）。
        match ev.id.as_deref() {
            Some("") => {
                self.last_event_id = None;
                ev.id = None;
            }
            Some(id) => self.last_event_id = Some(id.to_string()),
            None => {}
        }
        // 无 `data` 的纯信封块不产出事件、不计事件数——`event` 入 FIFO、
        // `retry` 暂存，待下一含 `data` 块同块重建（计数与出口帧数保真）。
        if ev.data.is_empty() {
            if ev.event_type.is_some() || ev.retry.is_some() {
                if let Some(t) = ev.event_type.take() {
                    // 超上限**清空整队**（fail-safe：宁缺信封不错标）——已
                    // 暂存事件与本次触发事件一并丢弃，避免部分保留使后续 data 帧的
                    // `event:` 名错配；消费语义不变（未溢出窗口内仍按 FIFO 配对）。
                    if self.pending_events.len() >= PENDING_EVENTS_MAX {
                        let dropped = self.pending_events.len() as u64 + 1;
                        self.pending_events.clear();
                        self.pending_events_dropped += dropped;
                        if !self.pending_events_drop_warned {
                            self.pending_events_drop_warned = true;
                            tracing::warn!(
                                cap = PENDING_EVENTS_MAX,
                                dropped,
                                "SSE 跨块 event 暂存超上限，清空整队（计数经 take_pending_events_dropped 观测）"
                            );
                        }
                    } else {
                        self.pending_events.push_back(t);
                    }
                }
                if ev.retry.is_some() {
                    self.pending_retry = ev.retry.take();
                }
            }
            // 纯注释块按块聚合为恰一注释事件（不计入 `sse_event_count`），
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
        // fail-closed 后不交付任何残余（含未终结行尾），避免半帧泄漏。
        if self.carry_fatal {
            return String::new();
        }
        let mut tail = self.byte_buf.flush_text();
        tail.push_str(&std::mem::take(&mut self.text_carry));
        // BOM 剥离后判空与 DONE；残余 DONE 丢弃（终端已由正常事件
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

/// DONE 载荷判定（载荷级）：BOM 剥离后 trim 等于 `[DONE]` 即终端；
/// 兼容残余路径的 `data:` 前缀形态（`data: [DONE]`/`data:[DONE]`，含 BOM）；
/// chat 裸帧恒为 `data: [DONE]`，不得补 `event:`。
/// BOM 唯一来源为 `json_walk::strip_bom`（`strip_sse_bom` 已删，同体函数）。
pub fn is_done_payload(data: &str) -> bool {
    let t = json_walk::strip_bom(data).trim();
    if t == "[DONE]" {
        return true;
    }
    t.strip_prefix("data:")
        .is_some_and(|rest| json_walk::strip_bom(rest).trim() == "[DONE]")
}

/// 残余分类：`None` 必须丢弃，不得 `data:` 直发；
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
    // BOM 剥离后判 JSON（BOM+JSON 不得当残余转发）。
    let trimmed = json_walk::strip_bom(line).trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && json_walk::jloads(trimmed).is_ok()
    {
        // JSON 合法即返回输入（仅保留校验），不再二次 `loads→walk→dumps`。
        // Leaf 还原/脱敏已由调用方（scope 层）先行完成；二次序列化会重排
        // 键序/数字表示/空白（如 `1e3`→`1000.0`），与字节保真契约相悖。
        return line.to_string();
    }
    restore(line.to_string())
}
