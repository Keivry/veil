//! 分块扫描：超长输入 `char` 边界分块 + 内置联合一次扫描 + 重叠仲裁 + 位置化替换。

use {
    super::{
        super::json_walk::SCAN_INPUT_LIMIT,
        detector::{
            PiiHit,
            cached_id_ok,
            cached_luhn,
            cached_reserved,
            data_url_re,
            id_card_ok,
            is_reserved_ip,
            is_valid_ipv4,
            is_valid_ipv6,
            luhn_ok,
            protected_token_re,
            strip_ip_trailing,
            url_query_param_re,
        },
    },
    std::{
        collections::{HashMap, HashSet},
        sync::OnceLock,
    },
};

pub(crate) fn overlaps_any(spans: &[(usize, usize)], s: usize, e: usize) -> bool {
    spans
        .iter()
        .any(|(a, b)| *a <= s && s < *b || *a < e && e <= *b || s <= *a && *b <= e)
}

/// 超长输入分块：`char` 边界安全切分，`overlap` 字节交叠防跨界切断。
/// 短输入返回单块 `(0, 全文)`；空输入返回空。
pub(crate) fn split_chunks(text: &str, limit: usize, overlap: usize) -> Vec<(usize, String)> {
    if text.is_empty() {
        return Vec::new();
    }
    if text.len() <= limit {
        return vec![(0, text.to_string())];
    }
    let step = limit.saturating_sub(overlap).max(1);
    let mut out = Vec::new();
    let mut off = 0;
    while off < text.len() {
        let mut end = (off + limit).min(text.len());
        while end > off && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end <= off {
            end = off + 1;
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
        }
        out.push((off, text[off..end].to_string()));
        if end == text.len() {
            break;
        }
        let mut next = off.saturating_add(step);
        while next < text.len() && !text.is_char_boundary(next) {
            next += 1;
        }
        if next <= off || next >= text.len() {
            break;
        }
        off = next;
    }
    out
}

/// 文本中凭据值的位置区间（位置化优先：落入则 PII 跳过）。
pub fn credential_spans(
    text: &str,
    credential_p2t: &HashMap<String, String>,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for cred in credential_p2t.keys() {
        if cred.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(idx) = text[from..].find(cred) {
            let s = from + idx;
            spans.push((s, s + cred.len()));
            from = s + 1;
            if from >= text.len() {
                break;
            }
        }
    }
    spans
}

/// 占位符 + data URL 保护区间（重叠匹配整体跳过）。
pub fn protected_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for m in data_url_re().find_iter(text) {
        spans.push((m.start(), m.end()));
    }
    for m in protected_token_re().find_iter(text) {
        spans.push((m.start(), m.end()));
    }
    spans
}

/// PII 残缺形态，对标 `_PII_PARTIAL_TOKEN_RE`：
/// `__PI` 后负向前瞻排除完整形态，使完整 token 不被误剥；
/// 结尾覆盖行中残缺（后跟空白/标点/汉字等非单词字符同样剥离）。
fn pii_partial_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(
            r"__PI(?!I_\d+_[0-9a-f]{8}__)(?:I(?:_(?:\d+_)?[0-9a-fA-F]*)?)?(?:_*$|(?=\s|[^\w]))",
        )
        .expect("PII 残缺正则恒合法")
    })
}

/// 清理 PII 残缺前缀（完整 `__PII_<seq>_<rand8>__` 原样保留）。
pub fn strip_pii_partials(text: &str) -> String {
    pii_partial_re().replace_all(text, "").into_owned()
}

pub(crate) fn coarse_hit(text: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"[\dA-Za-z@.\-]").expect("粗筛正则恒合法"))
        .is_match(text)
}

/// 联合正则命中分类：按命名组顺序返回 `(kind, 原文)`，未命中任一组返回 `None`。
pub(crate) fn classify_hit<'t>(
    caps: &fancy_regex::Captures<'t, str>,
) -> Option<(&'static str, &'t str)> {
    const ORDER: [&str; 7] = [
        "email",
        "phone",
        "id_card",
        "bank_card",
        "ipv4",
        "ipv6",
        "api_key",
    ];
    ORDER
        .iter()
        .find_map(|kind| caps.name(kind).map(|m| (*kind, m.as_str())))
}

/// 内置联合正则一次扫描（同步版，供 json-walk 叶回调）。
/// 返回位置化命中；凭据区间/保护区间落入跳过（凭据优先）。
/// 超长输入按 1MB 分块（交叠 256，`char` 边界安全），边界重复命中去重。
pub fn scan_builtin_sync(text: &str, credential_p2t: &HashMap<String, String>) -> Vec<PiiHit> {
    if text.is_empty() || !coarse_hit(text) {
        return Vec::new();
    }
    let protected = protected_spans(text);
    let cred = credential_spans(text, credential_p2t);
    let mut out = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for (base, chunk) in split_chunks(text, SCAN_INPUT_LIMIT, 256) {
        for (kind, value, s, e) in builtin_chunk_sync(&chunk) {
            let (abs_s, abs_e) = (base + s, base + e);
            if !seen.insert((abs_s, abs_e)) {
                continue;
            }
            if overlaps_any(&protected, abs_s, abs_e) || overlaps_any(&cred, abs_s, abs_e) {
                continue;
            }
            if credential_p2t.contains_key(&value) {
                continue;
            }
            out.push((kind, value, abs_s, abs_e));
        }
    }
    out
}

fn builtin_chunk_sync(chunk: &str) -> Vec<(String, String, usize, usize)> {
    let mut out = Vec::new();
    for caps in super::detector::combined_re()
        .captures_iter(chunk)
        .flatten()
    {
        let Some((kind, raw)) = classify_hit(&caps) else {
            continue;
        };
        let mut value = raw.to_string();
        let mut end = caps.get(0).map(|m| m.end()).unwrap_or(0);
        let start = end.saturating_sub(raw.len());
        match kind {
            "ipv6" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv6(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv6(raw) {
                    continue;
                }
            }
            "ipv4" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv4(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv4(raw) {
                    continue;
                }
            }
            "bank_card" => {
                let cs = start.saturating_sub(64);
                let ce = (end + 16).min(chunk.len());
                if url_query_param_re().is_match(&chunk[cs..ce]) {
                    continue;
                }
                if !luhn_ok(&value) {
                    continue;
                }
            }
            "id_card" if !id_card_ok(&value) => continue,
            _ => {}
        }
        if matches!(kind, "ipv4" | "ipv6") && is_reserved_ip(&value, kind) {
            continue;
        }
        out.push((kind.to_string(), value, start, end));
    }
    out
}

/// 内置联合正则一次扫描（异步版，走全局 moka 校验 LRU）。
/// 超长输入按 1MB 分块（交叠 256，`char` 边界安全），边界重复命中去重。
pub async fn scan_builtin(text: &str, credential_p2t: &HashMap<String, String>) -> Vec<PiiHit> {
    if text.is_empty() || !coarse_hit(text) {
        return Vec::new();
    }
    let protected = protected_spans(text);
    let cred = credential_spans(text, credential_p2t);
    let mut out = Vec::new();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for (base, chunk) in split_chunks(text, SCAN_INPUT_LIMIT, 256) {
        for caps in super::detector::combined_re()
            .captures_iter(chunk.as_str())
            .flatten()
        {
            let Some((kind, raw)) = classify_hit(&caps) else {
                continue;
            };
            let mut value = raw.to_string();
            let mut end = caps.get(0).map(|m| m.end()).unwrap_or(0);
            let start = end.saturating_sub(raw.len());
            match kind {
                "ipv6" => {
                    let core = strip_ip_trailing(raw);
                    if !core.is_empty() && is_valid_ipv6(core) {
                        value = core.to_string();
                        end = start + value.len();
                    } else if !is_valid_ipv6(raw) {
                        continue;
                    }
                }
                "ipv4" => {
                    let core = strip_ip_trailing(raw);
                    if !core.is_empty() && is_valid_ipv4(core) {
                        value = core.to_string();
                        end = start + value.len();
                    } else if !is_valid_ipv4(raw) {
                        continue;
                    }
                }
                "bank_card" => {
                    let cs = start.saturating_sub(64);
                    let ce = (end + 16).min(chunk.len());
                    if url_query_param_re().is_match(&chunk[cs..ce]) {
                        continue;
                    }
                    if !cached_luhn(&value).await {
                        continue;
                    }
                }
                "id_card" if !cached_id_ok(&value).await => continue,
                _ => {}
            }
            if matches!(kind, "ipv4" | "ipv6") && cached_reserved(&value, kind).await {
                continue;
            }
            let (abs_s, abs_e) = (base + start, base + end);
            if !seen.insert((abs_s, abs_e)) {
                continue;
            }
            if overlaps_any(&protected, abs_s, abs_e) || overlaps_any(&cred, abs_s, abs_e) {
                continue;
            }
            if credential_p2t.contains_key(&value) {
                continue;
            }
            out.push((kind.to_string(), value, abs_s, abs_e));
        }
    }
    out
}

/// 重叠仲裁：按 `(start, 长度降序)` 排序，重叠者仅保留首个（长跨度优先）。
pub fn arbitrate(mut hits: Vec<PiiHit>) -> Vec<PiiHit> {
    hits.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| b.3.cmp(&a.3)));
    let mut kept: Vec<PiiHit> = Vec::new();
    let mut kept_spans: Vec<(usize, usize)> = Vec::new();
    for h in hits {
        if overlaps_any(&kept_spans, h.2, h.3) {
            continue;
        }
        kept_spans.push((h.2, h.3));
        kept.push(h);
    }
    kept
}

/// 位置化替换（按字节区间一次成形，避免重复值错位）。
/// R6 单函数化：`with_dedup=true` 时先按 `(s, e, rep)` 去重（原
/// `redaction::apply_spans_dedup` 语义内联），`false` 时沿用原 `apply_spans` 路径。
pub fn apply_spans(text: &str, spans: &[(usize, usize, String)], with_dedup: bool) -> String {
    let spans: Vec<(usize, usize, String)> = if with_dedup {
        let mut seen = HashSet::new();
        spans
            .iter()
            .filter(|(s, e, r)| seen.insert((*s, *e, r.clone())))
            .cloned()
            .collect()
    } else {
        spans.to_vec()
    };
    let mut ordered = spans;
    ordered.sort_by_key(|(s, ..)| *s);
    let mut out = String::with_capacity(text.len() + ordered.len() * 8);
    let mut cursor = 0;
    for (s, e, rep) in ordered {
        if s < cursor || s > text.len() || e > text.len() || s > e {
            continue;
        }
        out.push_str(&text[cursor..s]);
        out.push_str(&rep);
        cursor = e;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::service::pii::detector::test_support::{detector, empty_cred, kinds},
    };

    #[test]
    fn b4_trailing_punct_span_edges() {
        // B4.1：句末标点保留在命中 span 之外（span 精确，标点在原文）。
        let text = "电话 13812345678。谢谢";
        let hits = scan_builtin_sync(text, &empty_cred());
        let hit = hits.iter().find(|h| h.0 == "phone").expect("手机号须命中");
        assert_eq!(&text[hit.2..hit.3], "13812345678");
        assert!(text[hit.3..].starts_with('。'));
        // 句号紧贴命中：span 排除句号。
        let text = "Visit 8.8.8.8.";
        let hits = scan_builtin_sync(text, &empty_cred());
        let hit = hits
            .iter()
            .find(|h| h.0 == "ipv4")
            .expect("公网 IPv4 须命中");
        assert_eq!(&text[hit.2..hit.3], "8.8.8.8");
        assert_eq!(&text[hit.3..], ".");
        // 多句号：span 精确，余部全为句号。
        let text = "电话 13812345678。。。";
        let hits = scan_builtin_sync(text, &empty_cred());
        let hit = hits.iter().find(|h| h.0 == "phone").expect("手机号须命中");
        assert_eq!(&text[hit.2..hit.3], "13812345678");
        assert_eq!(&text[hit.3..], "。。。");
        // 句号紧贴已注册占位符：受保护无新命中。
        let hits = scan_builtin_sync("回拨 __PII_7_ab12cd34__。", &empty_cred());
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn partial_strip_keeps_complete_token() {
        assert_eq!(
            strip_pii_partials("__PII_1_ab12cd34__ tail"),
            "__PII_1_ab12cd34__ tail"
        );
        assert!(!strip_pii_partials("半截 __PII_1_ab 结尾").contains("__PII"));
        assert!(!strip_pii_partials("前缀 __PI ").contains("__PI"));
    }

    #[test]
    fn credential_values_skipped() {
        let mut cred = HashMap::new();
        cred.insert("13812345678".to_string(), "__VG_CRED_000001__".to_string());
        let hits = scan_builtin_sync("电话 13812345678", &cred);
        assert!(hits.is_empty(), "凭据值 PII 必须跳过: {hits:?}");
    }

    #[tokio::test]
    async fn oversized_input_chunked_without_losing_hits() {
        let d = detector();
        d.load_custom_patterns(&[("tail".to_string(), "TAIL-\\d{6}".to_string())]);
        let mut big = "中".repeat(600_000);
        big.push_str("TAIL-123456");
        big.push_str(&"文".repeat(600_000));
        assert!(big.len() > SCAN_INPUT_LIMIT);
        let hits = d.scan_custom(&big, &empty_cred()).await;
        assert!(
            hits.iter().any(|h| h.1 == "TAIL-123456"),
            "分块边界命中不得丢失"
        );
        let mut builtin_big = "前言 ".repeat(300_000);
        builtin_big.push_str("联系 13812345678 处理");
        let hits = scan_builtin_sync(&builtin_big, &empty_cred());
        assert!(hits.iter().any(|h| h.0 == "phone"), "内置分块命中不得丢失");
    }

    #[test]
    fn order_url_param_not_flagged_as_bank_card() {
        // Luhn 合法卡号作订单号时：URL 查询参数上下文抑制 bank_card。
        let card = "4532015112830366";
        for url in [
            format!("https://pay.example.com/order?id={card} 支付"),
            format!("https://pay.example.com/order?order={card} 支付"),
            format!("https://pay.example.com/q?sn={card}&page=2 查询"),
            format!("https://pay.example.com/q?amount={card} 结算"),
        ] {
            let hits = scan_builtin_sync(&url, &empty_cred());
            assert!(
                hits.iter().all(|h| h.0 != "bank_card"),
                "URL 参数订单号不得判卡: {url} -> {hits:?}"
            );
        }
        // 阳性对照：同一卡号裸露出现必须命中（守卫是上下文抑制，非漏报）。
        let hits = scan_builtin_sync(&format!("卡号 {card} 付款"), &empty_cred());
        assert!(
            hits.iter().any(|h| h.0 == "bank_card" && h.1 == card),
            "裸卡号须命中: {hits:?}"
        );
    }

    #[test]
    fn base64_and_long_digit_run_zero_false_positive() {
        // base64 data URL 内嵌数字串：保护区间整体跳过。
        let blob = format!("data:image/png;base64,MTM4{}AAAA", "13812345678");
        let hits = scan_builtin_sync(&format!("图片 {blob} 结束"), &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "phone"),
            "data URL 内数字不得检出 phone: {hits:?}"
        );
        // 阳性对照：同一号码裸露出现必须命中。
        let hits = scan_builtin_sync("联系 13812345678 处理", &empty_cred());
        assert!(hits.iter().any(|h| h.0 == "phone"), "{hits:?}");
        // 超长连续数字（22 位）：超出银行卡/身份证/手机长度上限且边界守卫齐备。
        let long = "1381234567813812345678";
        assert_eq!(long.len(), 22);
        let hits = scan_builtin_sync(&format!("单号 {long} 结束"), &empty_cred());
        assert!(
            hits.iter()
                .all(|h| h.0 != "bank_card" && h.0 != "id_card" && h.0 != "phone"),
            "22 位连续数字零误报: {hits:?}"
        );
    }

    #[test]
    fn trailing_punct_stripped_still_matches() {
        // IPv4：ASCII 句末标点剥离后公网判定不变。
        for text in [
            "访问 8.8.8.8, 继续",
            "访问 8.8.8.8; 继续",
            "访问 (8.8.8.8) 继续",
            "访问 [8.8.8.8] 继续",
        ] {
            let hits = scan_builtin_sync(text, &empty_cred());
            assert!(
                hits.iter().any(|h| h.0 == "ipv4" && h.1 == "8.8.8.8"),
                "句末标点须剥离命中: {text} -> {hits:?}"
            );
        }
        // IPv6：句末逗点/英文句号剥离。
        let hits = scan_builtin_sync("地址 2001:4860:4860::8888, 可达", &empty_cred());
        assert!(
            hits.iter().any(|h| h.0 == "ipv6"),
            "句末逗点 IPv6 须命中: {hits:?}"
        );
        // 手机号：中文句末标点不属数字边界，仍命中且值干净。
        let hits = scan_builtin_sync("联系13812345678。谢谢", &empty_cred());
        assert!(
            hits.iter().any(|h| h.0 == "phone" && h.1 == "13812345678"),
            "中文句号后手机须命中: {hits:?}"
        );
        // 邮箱：中文句号不属 TLD 边界，命中且值干净（英文句号归属域名，
        // 口径与现有正则一致，此处只锁定中文句号形态）。
        let hits = scan_builtin_sync("邮箱 test.user@example.com。结束", &empty_cred());
        assert!(
            hits.iter()
                .any(|h| h.0 == "email" && h.1 == "test.user@example.com"),
            "句末句号邮箱须命中且值干净: {hits:?}"
        );
    }

    #[test]
    fn country_code_86_new_api_keys_and_62_card_shapes() {
        // +86 冠码三形态均命中 phone。
        for text in [
            "联系 +86 13812345678 处理",
            "联系 +86-13812345678 处理",
            "联系 8613812345678 处理",
        ] {
            let hits = scan_builtin_sync(text, &empty_cred());
            assert!(
                kinds(&hits).contains(&"phone"),
                "+86 冠码须命中: {text} -> {hits:?}"
            );
        }
        // sk-proj-/sk-ant- 长前缀与 ghp_ 形态均命中 api_key。
        for key in [
            "sk-proj-abcdefgh12345678",
            "sk-ant-abcdefgh12345678",
            "ghp_abcdefgh12345678",
        ] {
            let hits = scan_builtin_sync(&format!("密钥 {key} 结束"), &empty_cred());
            assert!(
                hits.iter().any(|h| h.0 == "api_key" && h.1 == key),
                "新密钥形态须命中: {key} -> {hits:?}"
            );
        }
        // 62 开头 13 位 Luhn 合法卡命中；末位改动即非法不命中。
        let hits = scan_builtin_sync("卡号 6200000000000 付款", &empty_cred());
        assert!(
            hits.iter()
                .any(|h| h.0 == "bank_card" && h.1 == "6200000000000"),
            "13 位 62 卡须命中: {hits:?}"
        );
        let hits = scan_builtin_sync("卡号 6200000000001 付款", &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "bank_card"),
            "Luhn 非法 62 卡不得命中: {hits:?}"
        );
    }

    #[test]
    fn perf_incremental_scan_time_anchor() {
        let d = detector();
        let base = "联系 13812345678 地址 2001:4860:4860::8888 结束 ".repeat(20);
        let start = std::time::Instant::now();
        let mut total = 0usize;
        for round in 1..=10 {
            let text = base.repeat(round);
            let hits = d.scan_spans_sync(&text, &empty_cred());
            total += hits.len();
            assert!(
                hits.iter().any(|h| h.0 == "phone"),
                "第 {round} 轮增量须命中 phone"
            );
        }
        let elapsed = start.elapsed();
        assert!(total >= 10, "增量累计命中须递增: {total}");
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "10 轮增量扫描须 <10s，实测 {elapsed:?}"
        );
    }

    /// T11 ipv6 逐项展开 16 项：毫秒/单位数/日期 T 分隔/`::` 压缩/保留段前缀。
    mod ipv6_parity_tests {
        use {
            super::scan_builtin_sync,
            crate::service::pii::detector::{
                is_reserved_ip,
                is_valid_ipv6,
                test_support::empty_cred,
            },
        };

        fn no_ipv6(text: &str) {
            let hits = scan_builtin_sync(text, &empty_cred());
            assert!(
                hits.iter().all(|h| h.0 != "ipv6"),
                "{text} 不得出 ipv6: {hits:?}"
            );
        }

        #[test]
        fn t11_01_hhmmss_not_ipv6() {
            assert!(!is_valid_ipv6("12:34:56"));
            assert!(!is_valid_ipv6("23:59:59"));
            no_ipv6("会议 12:34:56 开始");
        }

        #[test]
        fn t11_02_all_zero_timestamp_not_ipv6() {
            assert!(!is_valid_ipv6("00:00:00"));
            no_ipv6("at 00:00:00 启动");
        }

        #[test]
        fn t11_03_millis_not_ipv6() {
            assert!(!is_valid_ipv6("12:34:56.789"));
            assert!(!is_valid_ipv6("21:42,728"));
            no_ipv6("at 21:42,728 打点");
        }

        #[test]
        fn t11_04_single_digit_time_not_ipv6() {
            assert!(!is_valid_ipv6("9:05:07"));
            assert!(!is_valid_ipv6("3:4:5"));
            no_ipv6("9:05:07 闹钟");
        }

        #[test]
        fn t11_05_iso_datetime_t_separator_not_ipv6() {
            let hits = scan_builtin_sync("2024-01-01T12:34:56 上线", &empty_cred());
            assert!(hits.iter().all(|h| h.0 != "ipv6"), "{hits:?}");
            no_ipv6("Date: Thu Aug 27 21:42:05 2026 +0800");
        }

        #[test]
        fn t11_06_seven_groups_no_compression_invalid() {
            assert!(!is_valid_ipv6("1:2:3:4:5:6:7"));
            assert!(!is_valid_ipv6("2001:db8:0:1:2:3:4"));
        }

        #[test]
        fn t11_07_nine_groups_invalid() {
            assert!(!is_valid_ipv6("1:2:3:4:5:6:7:8:9"));
        }

        #[test]
        fn t11_08_full_8_groups_hit() {
            assert!(is_valid_ipv6("1:2:3:4:5:6:7:8"));
            assert!(!is_reserved_ip("1:2:3:4:5:6:7:8", "ipv6"));
            let hits = scan_builtin_sync("地址 1:2:3:4:5:6:7:8 结束", &empty_cred());
            assert!(
                hits.iter()
                    .any(|h| h.0 == "ipv6" && h.1 == "1:2:3:4:5:6:7:8"),
                "{hits:?}"
            );
        }

        #[test]
        fn t11_09_uppercase_full_hit() {
            let hits = scan_builtin_sync(
                "地址 ABCD:EF01:2345:6789:ABCD:EF01:2345:6789 结束",
                &empty_cred(),
            );
            assert!(hits.iter().any(|h| h.0 == "ipv6"), "{hits:?}");
        }

        #[test]
        fn t11_10_leading_compressed_hit() {
            assert!(is_valid_ipv6("2001:4860:4860::8888"));
            let hits = scan_builtin_sync("地址 2001:4860:4860::8888 结束", &empty_cred());
            assert!(hits.iter().any(|h| h.0 == "ipv6"), "{hits:?}");
        }

        #[test]
        fn t11_11_mid_zero_compressed_hit() {
            assert!(is_valid_ipv6("3900:cce:0:0:0:0:347a:2c83"));
            assert!(!is_reserved_ip("3900:cce:0:0:0:0:347a:2c83", "ipv6"));
        }

        #[test]
        fn t11_12_loopback_reserved() {
            assert!(is_valid_ipv6("::1"));
            assert!(is_reserved_ip("::1", "ipv6"));
            no_ipv6("回环 ::1 本机");
        }

        #[test]
        fn t11_13_ula_reserved() {
            assert!(is_reserved_ip("fd00::1", "ipv6"));
            assert!(is_reserved_ip("fc00::1", "ipv6"));
            no_ipv6("内网 fd00::1 互联");
        }

        #[test]
        fn t11_14_doc_range_reserved() {
            assert!(is_valid_ipv6("2001:db8::1"));
            assert!(is_reserved_ip("2001:db8::1", "ipv6"));
            assert!(is_valid_ipv6("2001:db8::"));
            assert!(is_reserved_ip("2001:db8::", "ipv6"));
            no_ipv6("文档 2001:db8::1 示例");
        }

        #[test]
        fn t11_15_non_hex_and_url_port_not_ipv6() {
            assert!(!is_valid_ipv6("gggg::1"));
            no_ipv6("http://host:8080/path");
            no_ipv6("127.0.0.1:8080 服务");
        }

        #[test]
        fn t11_16_sentence_punct_stripped_still_hit() {
            let hits = scan_builtin_sync("地址 1:2:3:4:5:6:7:8。继续", &empty_cred());
            assert!(
                hits.iter().any(|h| h.0 == "ipv6"),
                "句末标点须剥离后命中: {hits:?}"
            );
        }
    }
}

#[cfg(test)]
mod perf_budget_tests {
    use {
        super::scan_builtin_sync,
        crate::service::pii::detector::{PiiDetector, test_support::empty_cred},
        std::time::Duration,
    };

    fn mixed_text(size: usize) -> String {
        let unit = "身份证 13800138000 测试 abc123 @example.com 联系我\n";
        let text = unit.repeat(size / unit.len() + 1);
        text[..text.floor_char_boundary(size)].to_string()
    }

    #[test]
    fn t8_1kb_chunk_scan_under_50ms() {
        let text = mixed_text(1024);
        let start = std::time::Instant::now();
        let hits = scan_builtin_sync(&text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(!hits.is_empty(), "混合文本须命中");
        assert!(
            elapsed < Duration::from_millis(50),
            "1KB 扫描 {elapsed:?} 超门禁"
        );
    }

    #[test]
    fn t8_100kb_scan_under_800ms() {
        let text = mixed_text(100_000);
        let start = std::time::Instant::now();
        let hits = scan_builtin_sync(&text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(hits.len() > 100, "100KB 须批量命中");
        assert!(
            elapsed < Duration::from_millis(800),
            "100KB 扫描 {elapsed:?} 超门禁"
        );
    }

    #[test]
    fn t8_1mb_full_scan_under_8s() {
        let text = mixed_text(1_048_576);
        let start = std::time::Instant::now();
        let hits = scan_builtin_sync(&text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(hits.len() > 1000, "1MB 须批量命中");
        assert!(
            elapsed < Duration::from_secs(8),
            "1MB 扫描 {elapsed:?} 超门禁"
        );
    }

    #[test]
    fn t8_pure_cjk_coarse_skip_fast() {
        let unit = "你好世界这是一个测试文本没有数字和字母";
        let text = unit.repeat(298_000 / unit.len() + 1);
        let start = std::time::Instant::now();
        let hits = scan_builtin_sync(&text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(hits.is_empty(), "纯 CJK 无数字须零命中");
        assert!(
            elapsed < Duration::from_millis(100),
            "粗筛 {elapsed:?} 超门禁"
        );
    }

    #[test]
    fn t8_dict_scan_1kb_under_20ms() {
        let d = PiiDetector::new();
        let entries: Vec<(String, String)> = (0..5000)
            .map(|i| (format!("测试姓名{i:04}"), "name".to_string()))
            .collect();
        d.load_dict(&entries);
        let text = "测试姓名0001 测试姓名4999 中间内容 测试姓名2500";
        let start = std::time::Instant::now();
        let hits = d.scan_dict_sync(text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(hits.len() >= 3, "字典三处须命中");
        assert!(
            elapsed < Duration::from_millis(20),
            "字典扫描 {elapsed:?} 超门禁"
        );
    }

    #[test]
    fn t8_incremental_200_chunks_under_2s() {
        let chunk = mixed_text(1024);
        let start = std::time::Instant::now();
        let mut total = 0usize;
        for _ in 0..200 {
            total += scan_builtin_sync(&chunk, &empty_cred()).len();
        }
        let elapsed = start.elapsed();
        assert!(total > 100, "增量累计须命中");
        assert!(
            elapsed < Duration::from_secs(2),
            "增量扫描 {elapsed:?} 超门禁"
        );
    }
}
