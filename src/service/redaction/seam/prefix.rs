//! P1/D2 自定义规则跨帧前缀 hold（自 `seam.rs` 拆出）：半截字面量滞留与跨帧掩码。

use super::{filter_window, map_filtered_span, mask_span_bytes};

/// P1/D2 自定义规则跨帧前缀 hold：滞留帧尾（过滤后解码空间）为任一 hint 前缀的帧，
/// 防半截敏感字面量先泄出；拼接后跨帧完整命中按 hint 掩码（复用 [`mask_span_bytes`]）。
/// 与 [`BoundaryHold`] 正交：本结构独立于 `PII_HOLD_MAX` 缝窗（窗口 0 时仍生效），
/// 仅受 hint 长度与 [`PREFIX_HOLD_MAX_CHARS`] 兜底约束；无 hint 时直通（零开销）。
///
/// 退化声明（design Open Questions 定稿）：无可提取字面前缀的复杂自定义正则不产生
/// hint，该规则仅由逐帧扫描与缝窗保护覆盖。
pub struct PrefixHold {
    hints: Vec<String>,
    decoded: String,
    extra_spans: Vec<(usize, usize)>,
    frames: Vec<HeldFrame>,
}

/// 滞留帧累计过滤文本上限（字符）：防「帧尾恒为某 hint 前缀」的对抗流无限滞留，
/// 超限强制放行（半截泄漏风险优于内存无界增长）。
pub const PREFIX_HOLD_MAX_CHARS: usize = 256;

struct HeldFrame {
    prefix: String,
    data: String,
    map: Vec<(usize, usize)>,
    decoded_start: usize,
    decoded_len: usize,
}

impl PrefixHold {
    /// 由 hint 集（长度降序去重，见 `PiiDetector::partial_prefix_hints`）构造。
    pub fn new(hints: Vec<String>) -> Self {
        Self {
            hints,
            decoded: String::new(),
            extra_spans: Vec::new(),
            frames: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool { self.hints.is_empty() }

    pub fn has_held(&self) -> bool { !self.frames.is_empty() }

    /// 预览滞留 + 下一帧的过滤后解码文本（不改变状态；供调用方做异步自定义扫描）。
    pub fn preview(&self, data: &str) -> String {
        let mut s = self.decoded.clone();
        s.push_str(&filter_window(data, false, false).0);
        s
    }

    /// 推入一帧（事件前缀 + 数据），返回本轮可放行的帧（可能不止一帧）。
    /// `extra_spans` 为合并解码空间的额外命中区间（如自定义正则完整匹配），
    /// 仅其跨帧部分被掩码；完全落在单帧内的命中已由逐帧路径处理，不重复掩码。
    /// 帧尾为 hint 前缀时滞留至下一帧判定；帧尾不再是前缀或触发上限时放行。
    pub fn push(
        &mut self,
        prefix: String,
        data: String,
        extra_spans: &[(usize, usize)],
    ) -> Vec<(String, String)> {
        if self.hints.is_empty() {
            return vec![(prefix, data)];
        }
        let (decoded, map) = filter_window(&data, false, false);
        let decoded_start = self.decoded.len();
        let decoded_len = decoded.len();
        self.decoded.push_str(&decoded);
        self.frames.push(HeldFrame {
            prefix,
            data,
            map,
            decoded_start,
            decoded_len,
        });
        self.extra_spans.extend_from_slice(extra_spans);
        let over_bound = self.decoded.chars().count() > PREFIX_HOLD_MAX_CHARS;
        if !over_bound && trailing_hint_prefix_len(&self.decoded, &self.hints) > 0 {
            return Vec::new();
        }
        self.take_frames()
    }

    /// 终止 flush：放行全部滞留帧（不丢内容；与 [`BoundaryHold::flush`] 同语义）。
    pub fn flush(&mut self) -> Vec<(String, String)> { self.take_frames() }

    /// 阻断：丢弃滞留帧（与 [`BoundaryHold::clear`] 同语义，不再透出）。
    pub fn clear(&mut self) {
        self.decoded.clear();
        self.extra_spans.clear();
        self.frames.clear();
    }

    fn take_frames(&mut self) -> Vec<(String, String)> {
        let spans = self.cross_frame_spans();
        mask_frames(&mut self.frames, &spans);
        self.decoded.clear();
        self.extra_spans.clear();
        self.frames.drain(..).map(|f| (f.prefix, f.data)).collect()
    }

    fn cross_frame_spans(&self) -> Vec<(usize, usize)> {
        let mut spans = self.hint_matches();
        spans.extend_from_slice(&self.extra_spans);
        spans
            .into_iter()
            .filter(|(s, e)| self.crosses_frame_boundary(*s, *e))
            .collect()
    }

    fn hint_matches(&self) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for hint in &self.hints {
            if hint.chars().count() < 2 {
                continue;
            }
            let mut from = 0;
            while let Some(idx) = self.decoded[from..].find(hint.as_str()) {
                let s = from + idx;
                out.push((s, s + hint.len()));
                from = s + self.decoded[s..].chars().next().map_or(1, char::len_utf8);
                if from >= self.decoded.len() {
                    break;
                }
            }
        }
        out
    }

    fn crosses_frame_boundary(&self, s: usize, e: usize) -> bool {
        self.frames
            .iter()
            .any(|f| f.decoded_start > s && f.decoded_start < e)
    }
}

/// 帧尾最长「hint 真前缀」的字节长度（无则 0）：仅计严格短于 hint 的后缀，
/// 故完整等于某 hint 的后缀不算滞留（交由跨帧掩码/逐帧逻辑处理）。
fn trailing_hint_prefix_len(text: &str, hints: &[String]) -> usize {
    let Some(max_hint) = hints.iter().map(|h| h.chars().count()).max() else {
        return 0;
    };
    let text_chars = text.chars().count();
    let max_len = max_hint.saturating_sub(1).min(text_chars);
    for len in (1..=max_len).rev() {
        let start = text
            .char_indices()
            .nth(text_chars - len)
            .map(|(i, _)| i)
            .unwrap_or(0);
        let suffix = &text[start..];
        if hints
            .iter()
            .any(|h| h.chars().count() > len && h.starts_with(suffix))
        {
            return suffix.len();
        }
    }
    0
}

/// 把合并解码空间的跨帧区间映射回各帧原字节并右到左掩码（防坐标漂移）。
fn mask_frames(frames: &mut [HeldFrame], spans: &[(usize, usize)]) {
    for frame in frames.iter_mut() {
        let start = frame.decoded_start;
        let end = start + frame.decoded_len;
        let mut raws: Vec<(usize, usize)> = Vec::new();
        for (s, e) in spans {
            let ls = (*s).max(start);
            let le = (*e).min(end);
            if ls < le
                && let Some((rs, re)) = map_filtered_span(&frame.map, ls - start, le - start)
            {
                raws.push((rs, re));
            }
        }
        raws.sort_unstable_by_key(|a| std::cmp::Reverse(a.0));
        for (rs, re) in raws {
            mask_span_bytes(&mut frame.data, rs, re);
        }
    }
}

/// P1/D2 自定义规则跨帧前缀 hold 单测：半截不泄、完整掩码、不匹配放行、flush/clear。
#[cfg(test)]
mod prefix_hold_tests {
    use super::{super::BoundaryHold, PrefixHold};

    fn hint(v: &str) -> Vec<String> { vec![v.to_string()] }

    #[test]
    fn custom_prefix_hold_dict_name_split_masked() {
        let mut h = PrefixHold::new(hint("张三"));
        let out = h.push("data: ".to_string(), "张".to_string(), &[]);
        assert!(out.is_empty(), "首帧半截须滞留: {out:?}");
        assert!(h.has_held());
        let preview = h.preview("三好");
        assert!(preview.ends_with("张三好"), "{preview}");
        let out = h.push("data: ".to_string(), "三好".to_string(), &[]);
        assert_eq!(out.len(), 2, "续接后两帧须一起放行: {out:?}");
        let joined: String = out.iter().map(|(p, d)| format!("{p}{d}")).collect();
        assert!(!joined.contains("张三"), "跨帧字典名须掩码: {joined}");
        assert!(joined.contains('好'), "非敏感尾部须保留: {joined}");
        assert!(!h.has_held());
    }

    #[test]
    fn custom_prefix_hold_nonmatch_passthrough_no_loss() {
        let mut h = PrefixHold::new(hint("张三"));
        let out = h.push(String::new(), "李四".to_string(), &[]);
        assert_eq!(out, vec![(String::new(), "李四".to_string())]);
        assert!(!h.has_held());
    }

    #[test]
    fn custom_prefix_hold_regex_literal_and_extra_spans() {
        let mut h = PrefixHold::new(hint("TAG-"));
        assert!(h.push(String::new(), "TA".to_string(), &[]).is_empty());
        let preview = h.preview("G-123");
        let s = preview.find("TAG-123").expect("预览须缝合字面量");
        let extra = vec![(s, s + "TAG-123".len())];
        let out = h.push(String::new(), "G-123".to_string(), &extra);
        let joined: String = out.iter().map(|(_, d)| d.clone()).collect();
        assert!(!joined.contains("TAG-123"), "跨帧正则命中须掩码: {joined}");
    }

    #[test]
    fn custom_prefix_hold_flush_and_clear() {
        let mut h = PrefixHold::new(hint("张三"));
        assert!(h.push(String::new(), "张".to_string(), &[]).is_empty());
        let flushed = h.flush();
        assert_eq!(
            flushed,
            vec![(String::new(), "张".to_string())],
            "终止 flush 须放行滞留"
        );
        assert!(!h.has_held());
        assert!(h.flush().is_empty());
        assert!(h.push(String::new(), "张".to_string(), &[]).is_empty());
        h.clear();
        assert!(!h.has_held());
        assert!(h.flush().is_empty(), "阻断 clear 后不再透出");
    }

    #[test]
    fn custom_prefix_hold_matrix_and_window_zero() {
        // 场景 1：字典名跨两帧 -> 完整命中掩码。
        let mut dict = PrefixHold::new(hint("张三"));
        assert!(dict.push(String::new(), "张".to_string(), &[]).is_empty());
        let out = dict.push(String::new(), "三".to_string(), &[]);
        let joined: String = out.iter().map(|(_, d)| d.clone()).collect();
        assert!(!joined.contains("张三"), "字典名跨帧须掩码: {joined}");
        // 场景 2：自定义正则字面前缀跨两帧 -> 字面量掩码。
        let mut re = PrefixHold::new(hint("TAG-"));
        assert!(re.push(String::new(), "TAG".to_string(), &[]).is_empty());
        let out = re.push(String::new(), "-1".to_string(), &[]);
        let joined: String = out.iter().map(|(_, d)| d.clone()).collect();
        assert!(!joined.contains("TAG-"), "正则字面前缀跨帧须掩码: {joined}");
        // 场景 3：终止 flush 放行不阻塞。
        let mut term = PrefixHold::new(hint("张三"));
        assert!(term.push(String::new(), "张".to_string(), &[]).is_empty());
        assert_eq!(term.flush().len(), 1, "终止须放行滞留");
        // 场景 4：阻断 clear 丢弃不再透出。
        let mut blocked = PrefixHold::new(hint("张三"));
        assert!(
            blocked
                .push(String::new(), "张".to_string(), &[])
                .is_empty()
        );
        blocked.clear();
        assert!(!blocked.has_held() && blocked.flush().is_empty());
        // PII_HOLD_MAX=0 定稿：缝窗直通时前缀 hold 仍生效（独立于窗口）。
        let mut zero = BoundaryHold::new(0);
        let (p, d) = zero.push("e\n".to_string(), "张".to_string(), |_, _| vec![]);
        assert_eq!((p.as_str(), d.as_str()), ("e\n", "张"), "窗口 0 缝窗直通");
        let mut prefix = PrefixHold::new(hint("张三"));
        assert!(
            prefix.push(String::new(), "张".to_string(), &[]).is_empty(),
            "前缀 hold 独立于缝窗，窗口 0 时仍滞留"
        );
    }

    #[test]
    fn custom_prefix_hold_bounded_buffer_forces_release() {
        let mut h = PrefixHold::new(hint("ab"));
        for _ in 0..(super::PREFIX_HOLD_MAX_CHARS + 2) {
            if !h.push(String::new(), "a".to_string(), &[]).is_empty() {
                return;
            }
        }
        panic!("超上限须强制放行，不得无限滞留");
    }
}
