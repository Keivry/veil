//! 跨帧边界 hold 与窗口/掩码原语（D2 自 `redaction.rs` 拆出）：缝合检测与坐标映射。

/// 跨帧边界 hold（A 案，`PII_HOLD_MAX` 字符窗）：整帧延迟一级，缝合相邻两帧的
/// 尾/首窗口做跨缝 PII 检测，跨缝命中掩码两侧后再放行上一帧。
/// 与 [`strip_partials`](super::super::strip_partials) 分工：strip 清理本帧内残缺占位符
/// （出口卫生，不跨帧）；hold 防止 PII 被切在两帧而逐帧漏检（边界检测，需跨帧状态）。
/// 两者正交。
/// 解码文本窗口：JSON 信封字符（`"` `{` `}` `[` `]` `,` 与 `"key":` 键）会隔断缝合（如
/// `138"}}]}…{"content":"12345678`），窗口先过滤信封并保留对齐映射，使检测发生
/// 在近似解码文本空间；掩码映射回原帧坐标，结构字符守卫兜底保信封。
/// `window_chars == 0` 时直通（响应侧关闭）。
pub struct BoundaryHold {
    held_prefix: Option<String>,
    held_data: Option<String>,
    window_chars: usize,
}

impl BoundaryHold {
    pub fn new(window_chars: usize) -> Self {
        Self {
            held_prefix: None,
            held_data: None,
            window_chars,
        }
    }

    pub fn has_held(&self) -> bool { self.held_data.is_some() }

    /// 推入下一帧已处理数据，返回本轮可放行帧。首帧返回空（延迟一级）；
    /// `spans_fn(window, seam)` 返回窗口内待掩码字节区间（窗口坐标，过滤后空间）。
    /// 仅跨缝区间被处理，非跨缝命中留给逐帧逻辑（已处理过）。
    pub fn push(
        &mut self,
        prefix: String,
        data: String,
        spans_fn: impl Fn(&str, usize) -> Vec<(usize, usize)>,
    ) -> (String, String) {
        if self.window_chars == 0 {
            return (prefix, data);
        }
        let (held_prefix, mut held_data) = match (self.held_prefix.take(), self.held_data.take()) {
            (Some(p), Some(d)) => (p, d),
            _ => {
                self.held_prefix = Some(prefix);
                self.held_data = Some(data);
                return (String::new(), String::new());
            }
        };
        let (tail_f, tail_map, tail_base) = {
            let (_, tail) = tail_window(&held_data, self.window_chars);
            let base = held_data.len().saturating_sub(tail.len());
            let (f, m) = filter_window(tail, true, false);
            (f, m, base)
        };
        let (head_f, head_map) = filter_window(head_window(&data, self.window_chars), false, true);
        let mut window = String::with_capacity(tail_f.len() + head_f.len());
        window.push_str(&tail_f);
        let seam = window.len();
        window.push_str(&head_f);
        let mut data = data;
        for (s, e) in spans_fn(&window, seam) {
            if s < seam && e > seam && e <= window.len() {
                if let Some((ps, pe)) = map_filtered_span(&tail_map, s, seam.min(e)) {
                    mask_span_bytes(&mut held_data, tail_base + ps, tail_base + pe);
                }
                if let Some((cs, ce)) = map_filtered_span(&head_map, 0, e - seam) {
                    let data_len = data.len();
                    mask_span_bytes(&mut data, cs.min(data_len), ce.min(data_len));
                }
            }
        }
        self.held_prefix = Some(prefix);
        self.held_data = Some(data);
        (held_prefix, held_data)
    }

    pub fn flush(&mut self) -> Option<(String, String)> {
        match (self.held_prefix.take(), self.held_data.take()) {
            (Some(p), Some(d)) => Some((p, d)),
            _ => None,
        }
    }

    /// 阻断时丢弃滞留帧（与 `agg.clear()` 同语义：阻断后不再透出常规内容）。
    pub fn clear(&mut self) {
        self.held_prefix = None;
        self.held_data = None;
    }
}

/// 窗口过滤：在原文上去除 JSON 信封（`"` `{` `}` `[` `]` `,` 与 `"key":` 键），
/// 返回过滤文本及逐字符原字节映射。`"key":` 要求引号后首字符为字母/下划线，
/// 故纯数字值（IPv6 组、电话片段）不受影响；`:` 本身保留（IPv6 跨缝需要）。
/// D5 缝邻保护：`"word":` 匹配中 `word` 全字母且长度≤4 时，若紧邻缝合缝
/// （尾窗末端 `protect_trailing` / 首窗开头 `protect_leading`）则不删——
/// 此类短词极可能是 IPv6 全字母组（如 `abcd`）或文本短词，误删会破坏跨缝检测；
/// 正常 JSON 键多为更长词或位于窗中部，过滤行为不变。
fn filter_window(
    s: &str,
    protect_trailing: bool,
    protect_leading: bool,
) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(s.len());
    let mut map: Vec<(usize, usize)> = Vec::new();
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (off, c) = chars[i];
        let next_off = |k: usize| chars.get(k).map(|(o, _)| *o).unwrap_or(s.len());
        if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].1.is_ascii_alphanumeric() || chars[j].1 == '_') {
                j += 1;
            }
            if j > i + 1
                && j + 1 < chars.len()
                && chars[i + 1].1.is_ascii_alphabetic()
                && chars[i + 1].1 != '_'
                && chars[j].1 == '"'
                && chars[j + 1].1 == ':'
            {
                // D5：短全字母词缝邻豁免（IPv6 组/文本短词保护）。
                let word_all_alpha = chars[i + 1..j].iter().all(|(_, c)| c.is_ascii_alphabetic());
                let word_len = j - (i + 1);
                let at_trailing_seam = protect_trailing && j + 2 == chars.len();
                let at_leading_seam = protect_leading && i == 0;
                if word_all_alpha && word_len <= 4 && (at_trailing_seam || at_leading_seam) {
                    i += 1;
                    continue;
                }
                i = j + 2;
                continue;
            }
            i += 1;
            continue;
        }
        if matches!(c, '{' | '}' | '[' | ']' | ',') {
            i += 1;
            continue;
        }
        out.push(c);
        map.push((off, next_off(i + 1)));
        i += 1;
    }
    (out, map)
}

/// 过滤坐标映射回原坐标：`[fs, fe)`（过滤字节区间）→ 原字节 `(start, end)`。
/// 非字符边界返回 `None`（调用方跳过）。
fn map_filtered_span(map: &[(usize, usize)], fs: usize, fe: usize) -> Option<(usize, usize)> {
    if fs >= fe {
        return None;
    }
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let mut byte = 0;
    // 过滤仅整字符删除，保留字符字节原样，过滤字节偏移按原字符长度递增。
    for (os, oe) in map {
        let clen = oe - os;
        if byte == fs && start.is_none() {
            start = Some(*os);
        }
        if byte + clen == fe {
            end = Some(*oe);
            break;
        }
        byte += clen;
    }
    match (start, end) {
        (Some(s), Some(e)) if s < e => Some((s, e)),
        _ => None,
    }
}

/// 占位符残片跨缝区间：`__PII_`/`__VG_CRED_` 前缀残片横跨缝合缝时返回可见部分
/// 区间（窗口坐标），供 [`BoundaryHold`] 掩码。完整 token 不在此处理（逐帧逻辑归属）。
pub fn marker_cross_spans(window: &str, seam: usize) -> Vec<(usize, usize)> {
    const MARKERS: [&str; 2] = ["__PII_", "__VG_CRED_"];
    let mut out = Vec::new();
    for m in MARKERS {
        let mlen = m.len();
        let from = seam.saturating_sub(mlen);
        for start in from..seam.min(window.len()) {
            if !window.is_char_boundary(start) {
                continue;
            }
            let end_cap = (start + mlen).min(window.len());
            if !window.is_char_boundary(end_cap) || end_cap <= seam {
                continue;
            }
            if m.starts_with(&window[start..end_cap]) && start + mlen > seam {
                out.push((start, end_cap));
            }
        }
    }
    out
}

fn tail_window(s: &str, n_chars: usize) -> (usize, &str) {
    let total: usize = s.chars().count();
    if total <= n_chars {
        return (0, s);
    }
    let skip = total - n_chars;
    let off = s
        .char_indices()
        .nth(skip)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    (off, &s[off..])
}

fn head_window(s: &str, n_chars: usize) -> &str {
    match s.char_indices().nth(n_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// 字节区间掩码（等字符数 `*` 替换）：越界/非字符边界拒绝；
/// D5 逐字符豁免：信封字符（`{ } " [ ]`）位原样保留，仅掩码其余位，
/// 含信封的跨缝命中不再整段漏掩，JSON 结构恒完整可解析。
fn mask_span_bytes(text: &mut String, start: usize, end: usize) {
    if start >= end || end > text.len() {
        return;
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return;
    }
    let masked: String = text[start..end]
        .chars()
        .map(|c| {
            if matches!(c, '{' | '}' | '"' | '[' | ']') {
                c
            } else {
                '*'
            }
        })
        .collect();
    text.replace_range(start..end, &masked);
}

#[cfg(test)]
mod seam_tests {
    use super::*;

    #[test]
    fn boundary_hold_cross_seam_phone_masked_both_sides() {
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push(
            "event: message\n".to_string(),
            "call 138".to_string(),
            |_, _| vec![],
        );
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let span_fn = |_: &str, sm: usize| {
            vec![(5, 16)]
                .into_iter()
                .filter(|(s, e)| *s < sm && *e > sm)
                .collect()
        };
        let (p1, d1) = h.push(
            "event: message\n".to_string(),
            "12345678 ok".to_string(),
            span_fn,
        );
        assert_eq!(p1, "event: message\n");
        assert_eq!(d1, "call ***", "上一帧尾部残片须掩码: {d1}");
        let (pf, df) = h.flush().expect("次帧须滞留");
        assert_eq!(pf, "event: message\n");
        assert_eq!(df, "******** ok", "次帧头部延续须掩码: {df}");
    }

    #[test]
    fn boundary_hold_no_seam_passthrough() {
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push("e\n".to_string(), "hello".to_string(), |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let (p1, d1) = h.push("e\n".to_string(), "world".to_string(), |_, _| vec![]);
        assert_eq!((p1.as_str(), d1.as_str()), ("e\n", "hello"));
        let (pf, df) = h.flush().expect("须有滞留");
        assert_eq!((pf.as_str(), df.as_str()), ("e\n", "world"));
        assert!(!h.has_held());
    }

    #[test]
    fn boundary_hold_zero_window_passthrough_json_guard() {
        let mut h = BoundaryHold::new(0);
        let (p, d) = h.push("e\n".to_string(), "{\"a\":1}".to_string(), |_, _| {
            vec![(0, 7)]
        });
        assert_eq!((p.as_str(), d.as_str()), ("e\n", "{\"a\":1}"));
        let mut t = "{\"a\":1}".to_string();
        mask_span_bytes(&mut t, 0, 7);
        assert_eq!(t, "{\"*\"**}", "信封位保留、其余位逐字掩码");
        let mut t2 = "13812345678".to_string();
        mask_span_bytes(&mut t2, 0, 11);
        assert_eq!(t2, "***********");
    }

    #[test]
    fn mask_per_char_envelope_exempt_roundtrip_valid() {
        // 贴信封 PII：数字紧邻引号/冒号，非信封位仍被掩码。
        let mut t = "{\"content\":\"13812345678\"}".to_string();
        let start = "{\"content\":\"".len();
        mask_span_bytes(&mut t, start, start + 11);
        assert_eq!(t, "{\"content\":\"***********\"}");
        let v: serde_json::Value = serde_json::from_str(&t).expect("掩码后仍为合法 JSON");
        assert_eq!(v["content"], "***********");
        // 含信封的跨缝区间：信封位原样保留。
        let mut u = "ab{\"x".to_string();
        mask_span_bytes(&mut u, 0, 5);
        assert_eq!(u, "**{\"*");
        let _ = serde_json::json!({"ok": true});
    }

    #[test]
    fn filter_window_ipv6_alpha_group_seam_guard() {
        // 尾窗末端短词 `"abcd":`：缝邻保护开启时保留 `abcd` 组。
        let (guarded, _) = filter_window("xx\"abcd\":", true, false);
        assert!(guarded.contains("abcd"), "缝邻短词不得误删: {guarded}");
        // 同一形态无保护时照常过滤（行为锚点）。
        let (stripped, _) = filter_window("xx\"abcd\":", false, false);
        assert_eq!(stripped, "xx");
        // 首窗开头短词同理。
        let (h_guarded, _) = filter_window("\"abcd\":yy", false, true);
        assert!(
            h_guarded.contains("abcd"),
            "首窗缝邻短词不得误删: {h_guarded}"
        );
        let (h_stripped, _) = filter_window("\"abcd\":yy", false, false);
        assert_eq!(h_stripped, "yy");
        // 长键照常过滤（既有行为不变，缝邻亦不豁免）。
        let (long_tail, _) = filter_window("xx\"content\":1", true, false);
        assert!(!long_tail.contains("content"), "长键仍须过滤: {long_tail}");
        let (long_head, _) = filter_window("\"content\":1", false, true);
        assert!(!long_head.contains("content"), "长键仍须过滤: {long_head}");
        // 窗中部短词照常过滤（非缝邻不保护）。
        let (mid, _) = filter_window("xx\"abcd\":yy", false, false);
        assert!(!mid.contains("abcd"), "窗中部短词仍过滤: {mid}");
    }

    #[test]
    fn placeholder_fragment_cross_seam_detected() {
        // marker 前缀本身横跨缝合缝："ab __VG_CRE" + "D_12..."。
        let window = "ab __VG_CRED".to_string();
        let seam = "ab __VG_CRE".len();
        let spans = marker_cross_spans(&window, seam);
        assert!(!spans.is_empty(), "残片横跨缝合缝须检出: {spans:?}");
        let window2 = "abc def".to_string();
        assert!(marker_cross_spans(&window2, 4).is_empty());
        let window3 = "__PII_1_ab12cd34__ tail".to_string();
        assert!(
            marker_cross_spans(&window3, 19).is_empty(),
            "完整 token 左侧不算跨缝"
        );
    }

    #[test]
    fn envelope_filter_stitches_cross_frame_digits() {
        let prev = "{\"delta\":{\"content\":\"call 138\"}}";
        let cur = "{\"delta\":{\"content\":\"12345678 ok\"}}";
        let (tail_f, _) = filter_window(prev, true, false);
        let (head_f, _) = filter_window(cur, false, true);
        assert!(tail_f.ends_with("call 138"), "尾部解码文本保留: {tail_f}");
        assert!(!head_f.starts_with(":delta:content:"), "{head_f}");
        let mut window = String::new();
        window.push_str(&tail_f);
        let seam = window.len();
        window.push_str(&head_f);
        let digits = format!("{}{}", "138", "12345678");
        assert!(
            window.contains(&digits),
            "信封过滤后跨帧数字须相邻: {window}"
        );
        let _ = seam;
    }

    #[test]
    fn boundary_hold_envelope_split_masked_same() {
        let mut h = BoundaryHold::new(128);
        let prev = "{\"delta\":{\"content\":\"call 138\"}}".to_string();
        let cur = "{\"delta\":{\"content\":\"12345678 ok\"}}".to_string();
        let (p0, d0) = h.push("event: message\n".to_string(), prev, |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let span_fn = |w: &str, sm: usize| {
            let rel = w.find("13812345678").expect("过滤窗口须缝合数字");
            vec![(rel, rel + 11)]
                .into_iter()
                .filter(|(s, e)| *s < sm && *e > sm)
                .collect()
        };
        let (p1, d1) = h.push("event: message\n".to_string(), cur, span_fn);
        assert_eq!(p1, "event: message\n");
        assert!(!d1.contains("138"), "上一帧尾部残片须掩码: {d1}");
        assert!(d1.contains("call "), "{d1}");
        assert!(d1.contains("\"content\""), "信封键须完整保留: {d1}");
        let (_, df) = h.flush().expect("次帧须滞留");
        assert!(!df.contains("12345678"), "次帧头部延续须掩码: {df}");
    }

    #[test]
    fn boundary_hold_combined_fuzz_roundtrip_keeps_envelope() {
        let frags = ["__PII_", "7__", "\"content\":\"", "abc", "\"}"];
        let seps = ["", "\"k\":", "{", "},{\"next\":"];
        let mut n = 0u64;
        for (fi, frag) in frags.iter().enumerate() {
            for seps_item in seps.iter() {
                n += 1;
                let x = (n.wrapping_mul(6364136223846793005) >> 33) as usize;
                let a = format!("{{\"a\":\"{}{}\"}}", frag, seps_item);
                let b = format!("{{\"b\":\"{}-{x}\"}}", frags[(fi + 1) % frags.len()]);
                let c = format!("data: {{\"c\":{x}}}\ndata: {{\"d\":{x}}}\n\n");
                let mut h = BoundaryHold::new(64);
                let (p0, d0) = h.push("event: m\n".to_string(), a.clone(), |_, _| vec![]);
                assert!(p0.is_empty() && d0.is_empty());
                let (p1, d1) = h.push("event: m\n".to_string(), b.clone(), |_, _| vec![]);
                assert_eq!(p1, "event: m\n");
                assert_eq!(d1, a, "无掩码时上一帧须原样放行");
                let (p2, d2) = h.push("event: m\n".to_string(), c.clone(), |_, _| vec![]);
                assert_eq!((p2, d2), ("event: m\n".to_string(), b));
                let (pf, df) = h.flush().expect("末帧须滞留可取");
                assert_eq!((pf, df), ("event: m\n".to_string(), c));
                assert!(!h.has_held());
            }
        }
        assert_eq!(n, (frags.len() * seps.len()) as u64);
    }
}

/// T4 流式 hold 回补：dual_hold/前后缀 hold/数字同尾/单 hold 等价性。
#[cfg(test)]
mod streaming_hold_parity_tests {
    use super::BoundaryHold;

    const PHONE: &str = "13800138000";

    fn phone_span(window: &str, seam: usize) -> Vec<(usize, usize)> {
        window
            .find(PHONE)
            .map(|pos| (pos, pos + PHONE.len()))
            .filter(|(s, e)| *s < seam && *e > seam)
            .into_iter()
            .collect()
    }

    fn run_split(full: &str, at: usize) -> String {
        let (a, b) = full.split_at(at);
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push(String::new(), a.to_string(), phone_span);
        assert!(p0.is_empty() && d0.is_empty(), "首帧须滞留");
        let (p1, d1) = h.push(String::new(), b.to_string(), phone_span);
        let (pf, df) = h.flush().expect("末帧须滞留可取");
        assert!(!h.has_held());
        format!("{p1}{d1}{pf}{df}")
    }

    #[test]
    fn t4_pii_digit_same_tail_masked_both_sides() {
        let full = format!("call {PHONE} end");
        let at = full.find("00").expect("切分点须存在");
        let out = run_split(&full, at);
        assert!(!out.contains(PHONE), "跨缝号码须掩码，实际 {out:?}");
        assert!(out.contains("call "), "缝前安全前缀须放行");
        assert!(out.contains(" end"), "缝后安全后缀须放行");
    }

    #[test]
    fn t4_single_hold_join_equivalent_across_split_points() {
        let full = format!("prefix {PHONE} suffix");
        let phone_at = full.find(PHONE).expect("号码须存在");
        let phone_end = phone_at + PHONE.len();
        let masked = full.replacen(PHONE, "***********", 1);
        for at in [7usize, 10, 13, 16, 19] {
            if !full.is_char_boundary(at) {
                continue;
            }
            let out = run_split(&full, at);
            if at > phone_at && at < phone_end {
                assert_eq!(out, masked, "切分点 {at} 切断号码须掩码");
            } else {
                assert_eq!(out, full, "切分点 {at} 未切断号码须原样透传");
            }
        }
    }

    #[test]
    fn t4_dual_hold_sequential_equivalent_to_combined() {
        let first = "a 13800".to_string();
        let second = "138000 b".to_string();
        let mut seq = BoundaryHold::new(64);
        let (p0, d0) = seq.push(String::new(), first.clone(), phone_span);
        assert!(p0.is_empty() && d0.is_empty());
        let (p1, d1) = seq.push(String::new(), second.clone(), phone_span);
        let (pf, df) = seq.flush().expect("末帧须滞留可取");
        let sequential = format!("{p1}{d1}{pf}{df}");
        assert!(
            !sequential.contains(PHONE),
            "跨缝号码须全掩码，实际 {sequential:?}"
        );
        assert!(sequential.starts_with('a'), "安全首部须保留");
        assert!(sequential.ends_with('b'), "安全尾部须保留");
        assert_eq!(
            sequential.chars().count(),
            first.chars().count() + second.chars().count()
        );
    }

    #[test]
    fn t4_token_affix_prefix_suffix_preserved() {
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push("data: ".to_string(), "hello".to_string(), |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧前缀须随数据滞留");
        let (p1, d1) = h.push("data: ".to_string(), " world".to_string(), |_, _| vec![]);
        assert_eq!(p1, "data: ");
        assert_eq!(d1, "hello");
        let (pf, df) = h.flush().expect("末帧须滞留可取");
        assert_eq!((pf, df), ("data: ".to_string(), " world".to_string()));
    }

    #[test]
    fn t4_clear_discards_held_on_block() {
        let mut h = BoundaryHold::new(64);
        let _ = h.push("data: ".to_string(), "secret".to_string(), |_, _| vec![]);
        assert!(h.has_held());
        h.clear();
        assert!(!h.has_held());
        assert!(h.flush().is_none(), "阻断后滞留帧须丢弃不再透出");
    }

    #[test]
    fn t4_no_seam_passthrough_byte_identical() {
        let mut h = BoundaryHold::new(64);
        let _ = h.push(String::new(), "hello world".to_string(), phone_span);
        let (p1, d1) = h.push(String::new(), " all safe".to_string(), phone_span);
        assert_eq!(d1, "hello world");
        assert!(p1.is_empty());
        let (_, df) = h.flush().expect("flush 须有值");
        assert_eq!(df, " all safe");
    }

    #[test]
    fn t4_flush_without_push_is_none() {
        let mut h = BoundaryHold::new(64);
        assert!(h.flush().is_none());
        assert!(!h.has_held());
    }
}

/// T12 hold 跨任务隔离：Rust 以请求级 `Scope` 所有权替代 ContextVar，
/// 并发任务各持独立 Scope，映射互不可见、hold 状态机互不串扰。
#[cfg(test)]
mod concurrency_hold_tests {
    use super::BoundaryHold;

    #[tokio::test]
    async fn t12_hold_state_machine_isolated_across_tasks() {
        let (tx_a, rx_a) = tokio::sync::oneshot::channel::<String>();
        let (tx_b, rx_b) = tokio::sync::oneshot::channel::<String>();
        let task_a = tokio::spawn(async move {
            let mut h = BoundaryHold::new(64);
            let (p0, d0) = h.push("a:".to_string(), "frame-a1".to_string(), |_, _| vec![]);
            assert!(p0.is_empty() && d0.is_empty());
            tx_a.send("a-held".to_string()).expect("须发送");
            let (p1, d1) = h.push("a:".to_string(), "frame-a2".to_string(), |_, _| vec![]);
            assert_eq!((p1, d1), ("a:".to_string(), "frame-a1".to_string()));
            let (pf, df) = h.flush().expect("须滞留");
            assert_eq!((pf, df), ("a:".to_string(), "frame-a2".to_string()));
        });
        let task_b = tokio::spawn(async move {
            let mut h = BoundaryHold::new(64);
            let (p0, d0) = h.push("b:".to_string(), "frame-b1".to_string(), |_, _| vec![]);
            assert!(p0.is_empty() && d0.is_empty());
            tx_b.send("b-held".to_string()).expect("须发送");
            let (p1, d1) = h.push("b:".to_string(), "frame-b2".to_string(), |_, _| vec![]);
            assert_eq!((p1, d1), ("b:".to_string(), "frame-b1".to_string()));
            assert!(h.has_held(), "B 仍有滞留");
            let (pf, df) = h.flush().expect("须滞留");
            assert_eq!((pf, df), ("b:".to_string(), "frame-b2".to_string()));
        });
        let (sa, sb) = tokio::join!(rx_a, rx_b);
        assert_eq!(sa.expect("A 信号须到达"), "a-held");
        assert_eq!(sb.expect("B 信号须到达"), "b-held");
        task_a.await.expect("A 须成功");
        task_b.await.expect("B 须成功");
    }
}
