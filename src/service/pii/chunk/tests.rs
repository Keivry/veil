#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("chunk.rs", include_str!("../chunk.rs"));
    crate::test_support::file_len_under_800_or_split(
        "chunk/scan.rs",
        include_str!("../chunk/scan.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "chunk/strip.rs",
        include_str!("../chunk/strip.rs"),
    );
    crate::test_support::file_len_under_800_or_split("chunk/tests.rs", include_str!("tests.rs"));
}

use {
    super::*,
    crate::service::pii::detector::test_support::{detector, empty_cred, kinds},
};

#[test]
fn b4_trailing_punct_span_edges() {
    // 句末标点保留在命中 span 之外（span 精确，标点在原文）。
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
fn partial_strip_cross_family_complete_token_kept() {
    // 完整 token 的闭合 `__` + 后随字面 `PI` 不得被判为残缺（跨族负向后顾）。
    for kept in [
        "__CRED_000123__PI",
        "__PII_1_ab12cd34__PI",
        // 2 下划线：第二段 `PII_3_ab` 无 `__` 前缀，非残缺形态，整体保留。
        "__PII_1_ab12cd34__PII_3_ab",
    ] {
        assert_eq!(strip_pii_partials(kept), kept, "须原样保留: {kept}");
    }
    // 真残缺紧跟完整 token（4 下划线）仍剥，且不腐蚀前完整 token。
    assert_eq!(
        strip_pii_partials("__PII_1_ab12cd34____PII_3_ab"),
        "__PII_1_ab12cd34__"
    );
}

#[test]
fn credential_values_skipped() {
    let mut cred = HashMap::new();
    cred.insert("13812345678".to_string(), "__CRED_000001__".to_string());
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

/// ipv6 逐项展开 16 项：毫秒/单位数/日期 T 分隔/`::` 压缩/保留段前缀。
mod ipv6_parity_tests {
    use {
        super::scan_builtin_sync,
        crate::service::pii::detector::{is_reserved_ip, is_valid_ipv6, test_support::empty_cred},
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

#[test]
fn pii_partial_narrowed() {
    // 仅剥离确证残缺续段；无序号 hex 形与合法正文不剥。
    assert_eq!(
        strip_pii_partials("值 __PII_AB 后"),
        "值 __PII_AB 后",
        "无序号 hex 形须原样保留"
    );
    assert_eq!(
        strip_pii_partials("__PIXEL__ 与 __PII_DATA__"),
        "__PIXEL__ 与 __PII_DATA__",
        "后随合法单词字符的正文须原样保留"
    );
    // 带序号的确证残缺续段剥离。
    assert!(
        !strip_pii_partials("半截 __PII_12_ 结尾").contains("__PII_12_"),
        "带序号残段须被剥离"
    );
    // 完整形态原样保留。
    assert_eq!(
        strip_pii_partials("完整 __PII_1_ab12cd34__ 保留"),
        "完整 __PII_1_ab12cd34__ 保留"
    );
}

/// 长叶节点尾部 PII 定向用例（tasks 1.2）。
///
/// `Err` 阈值有两套口径，勿混用：
///
/// - **历史实测（默认 100 万步上界，即改造前）**：`'a'` ≈66K 字符、CJK ≈50K， `@` / `_` 类低至
///   **10K–50K 字符**。当时 `.flatten()` 静默吞掉 `Err`，
///   这些输入一律**零命中**——即向上游送出未脱敏 PII，这是本模块存在的证据。
/// - **当前构建（上界 `1MiB + 8n`）**：`@` / `_` 类 ≈512KiB 才 `Err`，`x` / `1` 类 ≈1MiB，CJK 在
///   1MiB 内不 `Err`。注意此处的 ≈512KiB 是**按精确长度标定**（`for_len = n`）时的阈值；而 `n ≤
///   BACKTRACK_CACHE_MAX_LEN`（1MiB）的输入实际复用**1MiB 缓存档**实例，上界为 `1M + 8×1MiB ≈
///   9.39M` 步，故真实 `Err` 阈值更高（实测落在 600K–940K 区间）。 下面统一用 600K `@`
///   填充并在每个用例 **前置断言整段确实 `Err`**；该断言在运行时自证，
///   不依赖任何标定算式，因此上界口径变化也不会让它空转通过。
///
/// 断言用「命中存在 + span 贴尾」而非耗时（耗时是门禁用例的职责）。
mod long_leaf_tail_tests {
    use {
        super::scan_builtin_sync,
        crate::service::{
            json_walk::SCAN_INPUT_LIMIT,
            pii::detector::{combined_re, test_support::empty_cred},
        },
    };

    /// 600K `@` 填充：整段扫描必 `Err`（`n ≤ 1MiB` 走 1MiB 缓存档，真实阈值 ≈600K–940K），
    /// 且 < `SCAN_INPUT_LIMIT` 保证不经外层分块——只有单区间才谈得上「同一区间的重扫」。
    const FILLER: usize = 600_000;

    /// 前置事实（防假绿）：整段一次性扫描确实 `Err`，否则用例根本没走到重扫分支。
    fn at_filler_tail(tail: &str) -> String {
        let text = format!("{}{tail}", "@".repeat(FILLER));
        assert!(text.len() < SCAN_INPUT_LIMIT, "须单区间，不经外层分块");
        assert!(
            matches!(
                combined_re(text.len()).captures_iter(&text).next(),
                Some(Err(_))
            ),
            "整段扫描须 `Err` 才进入重扫路径（600K `@` 在 1MiB 缓存档上界 ≈9.39M 下仍越过）"
        );
        text
    }

    #[test]
    fn at_filler_tail_email_hit() {
        // `@` 不属邮箱本地部字符集，故命中值恰为尾部字面量。
        let tail = "a@b.co";
        let text = at_filler_tail(tail);
        let hits = scan_builtin_sync(&text, &empty_cred());
        let emails: Vec<_> = hits.iter().filter(|h| h.0 == "email").collect();
        assert_eq!(emails.len(), 1, "600K `@` 填充后置邮箱须唯一命中: {hits:?}");
        assert_eq!(emails[0].1, tail, "取值须精确");
        assert_eq!(
            (emails[0].2, emails[0].3),
            (text.len() - tail.len(), text.len()),
            "span 须落在全文末尾"
        );
    }

    #[test]
    fn at_filler_tail_phone_hit() {
        let tail = "13800138000";
        let text = at_filler_tail(tail);
        let hits = scan_builtin_sync(&text, &empty_cred());
        let phones: Vec<_> = hits.iter().filter(|h| h.0 == "phone").collect();
        assert_eq!(
            phones.len(),
            1,
            "600K `@` 填充后置手机号须唯一命中: {hits:?}"
        );
        assert_eq!(phones[0].1, tail, "取值须精确");
        assert_eq!(
            (phones[0].2, phones[0].3),
            (text.len() - tail.len(), text.len()),
            "span 须落在全文末尾"
        );
    }

    #[test]
    fn at_filler_tail_bank_card_hit() {
        // Luhn 合法（同 `multibyte_boundary_tests::LUHN_CARDS` 的 62 段首项）。
        let tail = "6200000000000005";
        let text = at_filler_tail(tail);
        let hits = scan_builtin_sync(&text, &empty_cred());
        let cards: Vec<_> = hits.iter().filter(|h| h.0 == "bank_card").collect();
        assert_eq!(
            cards.len(),
            1,
            "600K `@` 填充后置银行卡须唯一命中: {hits:?}"
        );
        assert_eq!(cards[0].1, tail, "取值须精确");
        assert_eq!(
            (cards[0].2, cards[0].3),
            (text.len() - tail.len(), text.len()),
            "span 须落在全文末尾"
        );
    }
}

/// 重扫等价性与上下文正确性（tasks 3.4）。
mod rescan_equivalence_tests {
    use {
        super::scan_builtin_sync,
        crate::service::{
            json_walk::SCAN_INPUT_LIMIT,
            pii::{
                chunk::{
                    scan::{RawMatch, SCAN_WINDOW_FLOOR, scan_range},
                    split_chunk_ranges,
                },
                detector::{PiiHit, combined_re, test_support::empty_cred},
            },
        },
    };

    /// 走生产路径（分块 + [`scan_range`] 的整段优先 + `Err` 时递归缩窗）。
    fn hits_via_production(text: &str) -> Vec<PiiHit> { scan_builtin_sync(text, &empty_cred()) }

    /// 强制多窗口路径：把区间切成 `window` 字节的小窗口逐个扫描，绕过生产路径
    /// 的「整段优先」次序，用于证明缩窗本身不改变结论。
    fn hits_via_forced_windows(text: &str, window: usize) -> Vec<RawMatch> {
        let re = combined_re(text.len());
        let mut out = Vec::new();
        let mut ranges: Vec<(usize, usize)> = split_chunk_ranges(text, SCAN_INPUT_LIMIT, 0);
        ranges.sort_unstable();
        for (base, end) in ranges {
            let mut start = base;
            while start < end {
                let stop = text.floor_char_boundary((start + window).min(end));
                let len = stop - start;
                if len == 0 {
                    break;
                }
                // 窗口 ≤ 默认 `Err` 阈值，`scan_range` 必走「整段成功」分支。
                let ok = scan_range(text, start, len, &re, &mut out);
                assert!(ok, "子窗口 {start}..{stop} 仍 Err（窗口 {len} 已小于地板）");
                if stop >= end {
                    break;
                }
                start = stop;
            }
        }
        out
    }

    fn sorted(v: Vec<PiiHit>) -> Vec<PiiHit> {
        let mut v = v;
        v.sort();
        v
    }

    /// `@` 填充长度：精确长度标定下 `Err` 阈值约 512KiB，而 `n ≤ 1MiB` 实际走 1MiB 缓存档
    /// （上界 ≈9.39M 步），真实阈值更高；600K 实测仍越过，且 < `SCAN_INPUT_LIMIT`（不触发
    /// 外层分块，保证是**同一区间**的重扫）。
    const RESCAN_FILLER: usize = 600_000;

    #[test]
    fn rescan_matches_single_window_hits() {
        // 600K `@` 填充后接邮箱：整段扫描必 `Err`，故生产路径必然走递归缩窗；
        // 手工按地板窗口切分的路径作为独立基准。二者命中集合须完全一致
        // （取值与**绝对**偏移均一致）——任何「相对子窗口」的偏移算术都会在
        // 尾部命中上暴露（尾部命中的绝对终点恒为全文长）。
        let text = format!("{}a@b.co", "@".repeat(RESCAN_FILLER));
        assert!(text.len() < SCAN_INPUT_LIMIT, "须单区间，不经外层分块");
        let expected_start = text.len() - "a@b.co".len();

        // 前置事实（防假绿）：整段一次性扫描确实 `Err`，否则本用例根本没走到
        // `scan_range` 的重扫分支。实测 `@` 类阈值约 512KiB，故取 600K。
        let whole = combined_re(text.len()).captures_iter(&text).next();
        assert!(
            matches!(whole, Some(Err(_))),
            "整段扫描须 `Err` 才进入重扫路径（实测阈值约 512KiB）"
        );

        let prod = sorted(hits_via_production(&text));
        let prod_email: Vec<&PiiHit> = prod.iter().filter(|h| h.0 == "email").collect();
        assert_eq!(
            prod_email.len(),
            1,
            "生产路径须唯一命中邮箱: {prod_email:?}"
        );
        let (_, value, start, end) = prod_email[0];
        assert_eq!(value, "a@b.co", "`@` 不属本地部字符集，取值须精确");
        assert_eq!((*start, *end), (expected_start, text.len()));

        let raw = hits_via_forced_windows(&text, SCAN_WINDOW_FLOOR);
        let raw_email: Vec<&RawMatch> = raw.iter().filter(|m| m.kind == "email").collect();
        assert_eq!(raw_email.len(), 1, "强制窗口路径须唯一命中邮箱");
        assert_eq!(
            (raw_email[0].start, raw_email[0].end),
            (*start, *end),
            "两条路径的命中偏移须逐字节一致"
        );
        assert_eq!(
            &text[raw_email[0].start..raw_email[0].end],
            value.as_str(),
            "绝对偏移须精确指向原文"
        );
    }

    #[test]
    fn rescan_bank_card_context_from_full_text() {
        // 卡号候选的前 64 字节含 URL 查询参数形态、且整段落在子窗口之外：
        // 上下文 MUST 取自全文，否则 `url_query_param_re` 判定翻转 → 误命中。
        let card = "4532015112830366";
        let url_ctx = format!("https://pay.example.com/order?id={card}");
        let pad = "🍡".repeat(3_000);
        assert!(pad.len() > SCAN_WINDOW_FLOOR);
        let text = format!("{url_ctx}{pad}");
        let hits = scan_builtin_sync(&text, &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "bank_card"),
            "URL 参数上下文在子窗口之外时仍须抑制 bank_card: {hits:?}"
        );
        // 阳性对照：同卡号脱离 URL 上下文即命中（守卫是上下文抑制，非漏报）。
        let bare = format!("卡号 {card} 付款");
        assert!(
            scan_builtin_sync(&bare, &empty_cred())
                .iter()
                .any(|h| h.0 == "bank_card" && h.1 == card),
            "裸卡号须命中"
        );
    }
}
