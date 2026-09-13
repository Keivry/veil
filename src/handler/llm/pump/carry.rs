//! 跨帧占位符缝合 carry（D4/S4）：token 被上游按 JSON 内容值切开时，
//! 把帧尾合法残缺前缀移入请求级 carry，下一帧与续段拼回完整 token 交既有还原路径。
//!
//! 帧各为独立 JSON 文档（如 `__VG_CRE` + `D_000001__`），无法在原始字节层缝合；
//! [`TokenCarry::prepare`] 先在字符串值头部补全既有 carry（补全后由
//! `Scope::restore_response_with_spans_json` 还原明文并按 RFC 8259 转义），再从帧尾
//! 吸收新的残缺前缀；[`TokenCarry::finish`] 对流末残余按 `strip_cred_partials`/
//! `strip_pii_partials` 口径清理（fail-closed：残缺前缀从不落盘）。
//! `seam.rs::marker_cross_spans` 跨缝掩码保留为第二道防线，不做替换。

use {
    crate::service::redaction::strip_partials,
    regex::Regex,
    std::{borrow::Cow, sync::OnceLock},
};

/// 请求级跨帧 carry：至多持一个 token 形态的残缺前缀（长度有界）。
#[derive(Debug, Default)]
pub(crate) struct TokenCarry {
    pending: String,
}

impl TokenCarry {
    pub(crate) fn new() -> Self { Self::default() }

    /// 当前持有的残缺前缀（观测/单测断言）。
    #[cfg(test)]
    pub(crate) fn pending(&self) -> &str { &self.pending }

    /// 帧入口：先补全既有 carry（若有配对续段），再从帧尾吸收新残缺前缀。
    /// 无 carry 参与时零拷贝返回原文。
    pub(crate) fn prepare<'a>(&mut self, frame: &'a str) -> Cow<'a, str> {
        let stitched = self.stitch(frame);
        if self.pending.is_empty() {
            self.absorb(stitched)
        } else {
            stitched
        }
    }

    /// 流末残余清理：按残缺剥离口径剥离后丢弃（残留经此不再透出）。
    pub(crate) fn finish(&mut self) {
        if !self.pending.is_empty() {
            debug_assert!(strip_partials(&self.pending).is_empty());
            self.pending.clear();
        }
    }

    /// 在帧的字符串值头部补全 carry：命中完整 token 形态即原位写回，交后续还原路径
    /// 产出明文；续段仍未完整则并入 carry 并从本帧摘除（fail-closed 不落盘）。
    fn stitch<'a>(&mut self, frame: &'a str) -> Cow<'a, str> {
        if self.pending.is_empty() {
            return Cow::Borrowed(frame);
        }
        for (start, end) in json_string_ranges(frame) {
            let value = &frame[start..end];
            let combined = format!("{}{}", self.pending, value);
            if let Some(tok_len) = complete_token_len(&combined) {
                let consumed = tok_len - self.pending.len();
                if consumed <= value.len() {
                    let mut out = String::with_capacity(frame.len() + tok_len);
                    out.push_str(&frame[..start]);
                    out.push_str(&combined[..tok_len]);
                    out.push_str(&value[consumed..]);
                    out.push_str(&frame[end..]);
                    self.pending.clear();
                    return Cow::Owned(out);
                }
            } else if combined.len() > self.pending.len() && is_partial_only(&combined) {
                self.pending = combined;
                let mut out = String::with_capacity(frame.len() - value.len());
                out.push_str(&frame[..start]);
                out.push_str(&frame[end..]);
                return Cow::Owned(out);
            }
        }
        Cow::Borrowed(frame)
    }

    /// 从帧尾吸收合法残缺前缀：仅当其后续帧内容只剩 JSON 结构/空白
    /// （即位于末个字符串值尾部）时成立，避免误摘正文中间的占位符形文本。
    fn absorb<'a>(&mut self, frame: Cow<'a, str>) -> Cow<'a, str> {
        let Some((start, cand)) = trailing_partial(&frame) else {
            return frame;
        };
        let end = start + cand.len();
        let mut out = String::with_capacity(frame.len() - cand.len());
        out.push_str(&frame[..start]);
        out.push_str(&frame[end..]);
        self.pending.clear();
        self.pending.push_str(cand);
        Cow::Owned(out)
    }
}

/// 凭据完整 token（行首锚定）。
fn cred_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^__VG_CRED_\d{4,}__").expect("凭据 token 正则恒合法"))
}

/// PII 完整 token（行首锚定）。
fn pii_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^__PII_\d+_[0-9a-fA-F]{8}__").expect("PII token 正则恒合法"))
}

/// 凭据合法残缺前缀（`__VG_`/`__VG_C`/`.../__VG_CRED_000`），可续写为完整 token。
fn cred_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^__VG_(?:C(?:R(?:E(?:D(?:_?\d*_?)?)?)?)?)?$").expect("凭据残缺前缀正则恒合法")
    })
}

/// PII 合法残缺前缀（`__PII_`/`__PII_1_`/`.../__PII_1_ab12`），可续写为完整 token。
fn pii_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^__P(?:I(?:I(?:_(?:\d+(?:_[0-9a-fA-F]*_?)?)?)?)?)?$")
            .expect("PII 残缺前缀正则恒合法")
    })
}

/// 行首完整 token 长度（凭据/PII 形态；未命中返回 `None`）。
fn complete_token_len(s: &str) -> Option<usize> {
    [cred_full_re(), pii_full_re()]
        .into_iter()
        .find_map(|re| re.find(s).filter(|m| m.start() == 0).map(|m| m.end()))
}

/// 是否恰为合法残缺前缀（非完整 token）。
fn is_partial_only(s: &str) -> bool {
    (cred_prefix_re().is_match(s) || pii_prefix_re().is_match(s))
        && !cred_full_re().is_match(s)
        && !pii_full_re().is_match(s)
}

/// 占位符 marker（与 `seam.rs` 跨缝检测同前缀集）。
const MARKERS: [&str; 2] = ["__VG_", "__PII_"];

/// 帧尾合法残缺前缀：取最右侧、且尾随帧内容只剩 JSON 结构/空白的候选。
fn trailing_partial(frame: &str) -> Option<(usize, &str)> {
    let mut best: Option<(usize, &str)> = None;
    for marker in MARKERS {
        let mut from = 0;
        while let Some(idx) = frame[from..].find(marker) {
            let start = from + idx;
            if let Some(cand) = value_tail_candidate(frame, start)
                && is_partial_only(cand)
            {
                let take = match best {
                    Some((s, _)) => start > s,
                    None => true,
                };
                if take {
                    best = Some((start, cand));
                }
            }
            from = start + marker.len();
        }
    }
    best
}

/// 自 `start` 起连续 token 字符段；仅当其尾随帧内容只剩 JSON 结构/空白时返回。
fn value_tail_candidate(frame: &str, start: usize) -> Option<&str> {
    let rest = &frame[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if !is_structural_only(&frame[start + end..]) {
        return None;
    }
    Some(&rest[..end])
}

/// 是否仅含 JSON 结构字符与空白。
fn is_structural_only(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_whitespace() || matches!(c, '"' | '{' | '}' | '[' | ']' | ',' | ':'))
}

/// 扫描 JSON 文本的字符串内容区间（去引号，含键与值；转义安全）。
fn json_string_ranges(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i += 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => break,
                _ => i += 1,
            }
        }
        out.push((start, i.min(b.len())));
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absorb_then_stitch_cred_across_valid_json_frames() {
        let mut c = TokenCarry::new();
        let f1 = c.prepare(r#"{"choices":[{"delta":{"content":"__VG_CRE"}}]}"#);
        assert_eq!(&*f1, r#"{"choices":[{"delta":{"content":""}}]}"#);
        assert_eq!(c.pending(), "__VG_CRE", "残缺前缀须移入 carry");
        let f2 = c.prepare(r#"{"choices":[{"delta":{"content":"D_000001__"}}]}"#);
        assert_eq!(
            &*f2, r#"{"choices":[{"delta":{"content":"__VG_CRED_000001__"}}]}"#,
            "续段须与 carry 拼回完整 token"
        );
        assert!(c.pending().is_empty(), "成功缝合后 carry 须清空");
    }

    #[test]
    fn absorb_ignores_complete_token_and_mid_value_partial() {
        let mut c = TokenCarry::new();
        let full = c.prepare(r#"{"text":"__VG_CRED_000001__"}"#);
        assert_eq!(&*full, r#"{"text":"__VG_CRED_000001__"}"#);
        assert!(c.pending().is_empty(), "完整 token 不absorb");
        let mid = c.prepare(r#"{"text":"x __VG_CRE y"}"#);
        assert_eq!(&*mid, r#"{"text":"x __VG_CRE y"}"#);
        assert!(c.pending().is_empty(), "正文中间残缺不absorb");
    }

    #[test]
    fn pii_partial_absorbed_and_stitched() {
        let mut c = TokenCarry::new();
        let f1 = c.prepare(r#"{"content":"__PII_1_ab"}"#);
        assert_eq!(&*f1, r#"{"content":""}"#);
        assert_eq!(c.pending(), "__PII_1_ab");
        let f2 = c.prepare(r#"{"content":"12cd34__"}"#);
        assert_eq!(&*f2, r#"{"content":"__PII_1_ab12cd34__"}"#);
        assert!(c.pending().is_empty());
    }

    #[test]
    fn finish_strips_residual_and_clears() {
        let mut c = TokenCarry::new();
        let _ = c.prepare(r#"{"content":"prefix __VG_CRE"}"#);
        assert_eq!(c.pending(), "__VG_CRE");
        c.finish();
        assert!(c.pending().is_empty(), "流末残余须剥离清空");
    }
}
