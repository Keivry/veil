#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("detector.rs", include_str!("../detector.rs"));
    crate::test_support::file_len_under_800_or_split("detector/tests.rs", include_str!("tests.rs"));
}

use {
    super::*,
    test_support::{detector, empty_cred, kinds},
};

#[test]
fn builtin_names_len_locked() {
    assert_eq!(
        BUILTIN_NAMES.len(),
        7,
        "D8 互锁：内置 recognizer 名恒为 7（email/phone/id_card/bank_card/ipv4/ipv6/api_key）"
    );
    for name in [
        "email",
        "phone",
        "id_card",
        "bank_card",
        "ipv4",
        "ipv6",
        "api_key",
    ] {
        assert!(BUILTIN_NAMES.contains(&name), "缺失内置名: {name}");
    }
}

#[tokio::test]
async fn six_recognizer_kinds_match() {
    let d = detector();
    // 手机号（含 +86 冠码与中文紧贴）。
    let hits = d.scan_spans("联系13812345678处理", &empty_cred()).await;
    assert!(
        kinds(&hits).contains(&"phone"),
        "手机号紧贴中文应命中: {hits:?}"
    );
    // 邮箱。
    let hits = d
        .scan_spans("邮箱 test.user@example.com 结束", &empty_cred())
        .await;
    assert!(kinds(&hits).contains(&"email"));
    // 身份证（GB 校验位合法：11010519491231002X 为经典合法号）。
    let hits = d
        .scan_spans("身份证11010519491231002X", &empty_cred())
        .await;
    assert!(
        kinds(&hits).contains(&"id_card"),
        "合法身份证应命中: {hits:?}"
    );
    // 身份证（校验位非法不替换）。
    let hits = d
        .scan_spans("身份证110105194912310021", &empty_cred())
        .await;
    assert!(
        !kinds(&hits).contains(&"id_card"),
        "非法身份证不得命中: {hits:?}"
    );
    // 银行卡（Luhn 合法：6225880123456789 需校验，改用经典测试号 4532015112830366）。
    let hits = d.scan_spans("卡号4532015112830366", &empty_cred()).await;
    assert!(
        kinds(&hits).contains(&"bank_card"),
        "合法卡号应命中: {hits:?}"
    );
    // 银行卡（Luhn 非法不替换）。
    let hits = d.scan_spans("卡号4532015112830367", &empty_cred()).await;
    assert!(!kinds(&hits).contains(&"bank_card"));
    // 公网 IPv4。
    let hits = d.scan_spans("访问 8.8.8.8 获取", &empty_cred()).await;
    assert!(kinds(&hits).contains(&"ipv4"));
    // 公网 IPv6。
    let hits = d
        .scan_spans("地址 2001:4860:4860::8888 可达", &empty_cred())
        .await;
    assert!(kinds(&hits).contains(&"ipv6"), "公网 IPv6 应命中: {hits:?}");
    // API key（sk- 前缀 + 最小 16 字符）。
    let hits = d
        .scan_spans("密钥 sk-abcdefgh12345678 结束", &empty_cred())
        .await;
    assert!(kinds(&hits).contains(&"api_key"));
    // API key 过短不命中。
    let hits = d.scan_spans("密钥 sk-abc 结束", &empty_cred()).await;
    assert!(!kinds(&hits).contains(&"api_key"));
}

#[tokio::test]
async fn reserved_allowlist_exempted() {
    let d = detector();
    for ip in [
        "10.0.0.1",
        "192.168.1.100",
        "172.16.5.4",
        "127.0.0.1",
        "169.254.10.20",
        "224.0.0.1",
        "192.0.2.1",
        "100.64.0.1",
    ] {
        let hits = d
            .scan_spans(&format!("地址 {ip} 结束"), &empty_cred())
            .await;
        assert!(
            !kinds(&hits).contains(&"ipv4"),
            "保留 {ip} 应豁免: {hits:?}"
        );
    }
    for ip in ["::1", "fe80::1", "2001:db8::1", "ff02::1"] {
        let hits = d
            .scan_spans(&format!("地址 {ip} 结束"), &empty_cred())
            .await;
        assert!(
            !kinds(&hits).contains(&"ipv6"),
            "保留 {ip} 应豁免: {hits:?}"
        );
    }
    // 句末英文句号不吞没公网判定（core 剥离后仍命中，句号保留在原文）。
    let hits = d.scan_spans("Visit 8.8.8.8.", &empty_cred()).await;
    assert!(
        kinds(&hits).contains(&"ipv4"),
        "句末公网 IPv4 应命中: {hits:?}"
    );
    // 裸前缀子串不豁免：`fcfake` 不是保留地址。
    assert!(!is_reserved_ip("fcfake", "ipv6"));
}

#[test]
fn ipv4_reserved_192_88_99_exempt() {
    // APP-9（4.16）：6to4 中继任播网段 192.88.99.0/24 须在保留豁免清单，
    // 命中不脱敏（避免过度脱敏）；紧邻的非保留地址不受影响。
    assert!(is_reserved_ip("192.88.99.1", "ipv4"), "该段须豁免");
    assert!(is_reserved_ip("192.88.99.254", "ipv4"), "该段尾值须豁免");
    assert!(
        !is_reserved_ip("192.88.100.1", "ipv4"),
        "相邻非保留段不得被误豁免"
    );
    assert!(
        is_reserved_ip("192.168.1.1", "ipv4"),
        "既有私有段豁免不回退"
    );
}

#[test]
fn hardening_drops_attached_and_leading_zero_ipv4() {
    // 默认关闭：粘连手机号仍命中（历史口径不变）。
    let plain = detector();
    assert!(!plain.hardening());
    let hits = plain.scan_spans_sync("x13812345678y", &empty_cred());
    assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
    // 开启后：两侧 ASCII 粘连丢弃，独立出现仍命中。
    let hard = detector();
    hard.set_hardening(true);
    assert!(hard.hardening());
    let hits = hard.scan_spans_sync("x13812345678y", &empty_cred());
    assert!(!kinds(&hits).contains(&"phone"), "{hits:?}");
    let hits = hard.scan_spans_sync("联系 13812345678 处理", &empty_cred());
    assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
    // 前导零 IPv4：关闭命中，开启丢弃；正常公网 IP 两侧一致命中。
    assert!(
        kinds(&plain.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred())).contains(&"ipv4")
    );
    let hits = hard.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred());
    assert!(!kinds(&hits).contains(&"ipv4"), "{hits:?}");
    let hits = hard.scan_spans_sync("访问 8.8.8.8 获取", &empty_cred());
    assert!(kinds(&hits).contains(&"ipv4"), "{hits:?}");
}

#[test]
fn hardening_adjacency() {
    // P13/D14：ASCII 粘连门仅在 `PII_DETECTION_HARDENING=1` 生效（有意收紧）。
    let plain = detector();
    let hard = detector();
    hard.set_hardening(true);
    for (text, kind) in [
        ("x13812345678y", "phone"),
        ("a11010519491231002Xb", "id_card"),
        ("a4532015112830366b", "bank_card"),
    ] {
        let off = plain.scan_spans_sync(text, &empty_cred());
        assert!(
            kinds(&off).contains(&kind),
            "强化关粘连须保留 {kind}: {off:?}"
        );
        let on = hard.scan_spans_sync(text, &empty_cred());
        assert!(
            !kinds(&on).contains(&kind),
            "强化开粘连须丢弃 {kind}: {on:?}"
        );
    }
    // 独立出现（无 ASCII 粘连）两态均命中。
    let text = "联系 13812345678 处理";
    assert!(kinds(&plain.scan_spans_sync(text, &empty_cred())).contains(&"phone"));
    assert!(kinds(&hard.scan_spans_sync(text, &empty_cred())).contains(&"phone"));
    // IPv4 前导零：关命中、开拒；公网无前导零两态一致命中。
    assert!(
        kinds(&plain.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred())).contains(&"ipv4")
    );
    assert!(
        !kinds(&hard.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred())).contains(&"ipv4")
    );
    assert!(kinds(&hard.scan_spans_sync("访问 8.8.8.8 获取", &empty_cred())).contains(&"ipv4"));
}

#[test]
fn mask_six_branch_shapes_correct() {
    assert_eq!(mask_pii_value("phone", "13812345678"), "138****5678");
    assert_eq!(mask_pii_value("email", "a@b.com"), "***@***.com");
    assert_eq!(
        mask_pii_value("bank_card", "4532015112830366"),
        "**** **** **** 0366"
    );
    assert_eq!(mask_pii_value("ipv4", "8.8.8.8"), "8.8.**.**");
    assert_eq!(
        mask_pii_value("ipv6", "2001:4860:4860::8888"),
        "2001****8888"
    );
    assert_eq!(
        mask_pii_value("api_key", "sk-abcdefgh12345678"),
        "sk-a****5678"
    );
    assert_eq!(mask_pii_value("other", "abcdef"), "abc****def");
    assert_eq!(mask_pii_value("phone", ""), "***");
}

#[test]
fn mask_pii_value_ipv4_non4_and_email_nodot_parity() {
    // RED-3：非 4 段 IPv4 形按原仓 `<8` → 首 1/尾 1、`>=8` → 前 4/后 4；
    // 含 `@` 但域名无 `.` 的 email 归 `***@***`。
    assert_eq!(mask_pii_value("ipv4", "12345678"), "1234****5678");
    assert_eq!(mask_pii_value("ipv4", "123456"), "1****6");
    assert_eq!(mask_pii_value("ipv4", "1234567"), "1****7");
    assert_eq!(mask_pii_value("ipv4", "1.2.3"), "1****3");
    assert_eq!(mask_pii_value("ipv4", "8.8.8.8"), "8.8.**.**");
    assert_eq!(mask_pii_value("email", "a@b"), "***@***");
    assert_eq!(mask_pii_value("email", "a@b.com"), "***@***.com");
}

#[test]
fn mask_edge_samples_readme_7_10() {
    // §7.10 列举边缘样例：6/7 字符非 4 段 IPv4、无点 email、别名 kind。
    assert_eq!(mask_pii_value("ipv4", "123456"), "1****6");
    assert_eq!(mask_pii_value("ipv4", "1234567"), "1****7");
    assert_eq!(mask_pii_value("email", "a@b"), "***@***");
    assert_eq!(
        mask_pii_value("id_card", "123456789012345678"),
        "**** **** **** 5678"
    );
}

#[test]
fn mask_pii_value_alias_equivalent() {
    // P9/D10 + RED-3：bankcard/apikey/id_card 为已声明别名，行为与主名逐字一致。
    for v in ["4532015112830366", "12345678", "1234"] {
        assert_eq!(
            mask_pii_value("bankcard", v),
            mask_pii_value("bank_card", v),
            "bankcard 别名须等价 bank_card: {v}"
        );
        assert_eq!(
            mask_pii_value("id_card", v),
            mask_pii_value("bank_card", v),
            "id_card 别名须等价 bank_card: {v}"
        );
    }
    for v in ["abcd1234", "sk-abcdefgh12345678", "12345"] {
        assert_eq!(
            mask_pii_value("apikey", v),
            mask_pii_value("api_key", v),
            "apikey 别名须等价 api_key: {v}"
        );
    }
}

#[test]
fn mask_pii_value_branches_and_64_cap_regression() {
    assert_eq!(mask_pii_value("phone", "13812345678"), "138****5678");
    assert_eq!(mask_pii_value("email", "a@b.com"), "***@***.com");
    assert_eq!(
        mask_pii_value("bank_card", "4532015112830366"),
        "**** **** **** 0366"
    );
    assert_eq!(
        mask_pii_value("ipv6", "2001:4860:4860::8888"),
        "2001****8888"
    );
    assert_eq!(
        mask_pii_value("api_key", "sk-abcdefgh12345678"),
        "sk-a****5678"
    );
    assert_eq!(mask_pii_value("other", "abcdef"), "abc****def");
    assert_eq!(mask_pii_value("phone", ""), "***");
    let long_email = format!("a@b.{}", "x".repeat(70));
    assert_eq!(mask_pii_value("email", &long_email).chars().count(), 64);
}

#[test]
fn keep_prefix_covers_special_ranges() {
    assert!(is_keep_prefix_ip("10.1.2.3", "ipv4"));
    assert!(is_keep_prefix_ip("100.64.0.1", "ipv4"));
    assert!(is_keep_prefix_ip("192.0.2.1", "ipv4"));
    assert!(is_keep_prefix_ip("fc00::1", "ipv6"));
    assert!(!is_keep_prefix_ip("8.8.8.8", "ipv4"));
    assert!(!is_keep_prefix_ip("2001:4860:4860::8888", "ipv6"));
    assert!(is_reserved_ip("100.64.0.1", "ipv4"));
}

#[test]
fn b4_mixed_forms_regression() {
    // B4.1/B4.2 回归：时间戳混合、前导零归一、订单号规则、CJK/URL编码边缘。
    assert_eq!(normalize_ipv4_leading_zeros("010.000.000.001"), "10.0.0.1");
    assert_eq!(
        normalize_ipv4_leading_zeros("192.168.001.001"),
        "192.168.1.1"
    );
    let d = detector();
    // 时间戳与公网 IPv6 混合：时间戳不误杀，公网 IPv6 仍命中。
    let hits = d.scan_spans_sync("会议12:34:56，网关2001:4860:4860::8888在线", &empty_cred());
    assert!(kinds(&hits).contains(&"ipv6"), "{hits:?}");
    assert!(hits.iter().all(|h| h.1 != "12:34:56"), "{hits:?}");
    // 前导零公网 IPv4 按归一口径命中（默认非硬化；010 打头归一后落 10/8 保留段故用 8 打头）。
    let hits = d.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred());
    assert!(kinds(&hits).contains(&"ipv4"), "{hits:?}");
    // URL 订单号按豁免规则处理（不判卡），裸卡号仍命中。
    let hits = d.scan_spans_sync(
        "https://pay.example.com/order?id=4532015112830366 支付",
        &empty_cred(),
    );
    assert!(hits.iter().all(|h| h.0 != "bank_card"), "{hits:?}");
    let hits = d.scan_spans_sync("卡号 4532015112830366 扣款", &empty_cred());
    assert!(hits.iter().any(|h| h.0 == "bank_card"), "{hits:?}");
    // URL 编码形态不误判、不崩溃。
    let hits = d.scan_spans_sync("https://x.example.com/?id=%34%35%33%32 支付", &empty_cred());
    assert!(hits.iter().all(|h| h.0 != "bank_card"), "{hits:?}");
    // 中英混排不断字误杀。
    let hits = d.scan_spans_sync("Contact联系13812345678Done处理", &empty_cred());
    assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
    // 纯 CJK 无敏感零命中。
    let hits = d.scan_spans_sync("中文测试文本不含敏感信息", &empty_cred());
    assert!(hits.is_empty(), "{hits:?}");
}

#[test]
fn ipv6_timestamp_not_ipv6_and_uncompressed_requires_8_groups() {
    // 01-03: 典型 HH:MM:SS 时间戳恒非法（RFC4291 无 `::` 须 8 组）。
    assert!(!is_valid_ipv6("12:34:56"), "时分秒不得判 IPv6");
    assert!(!is_valid_ipv6("23:59:59"), "时分秒不得判 IPv6");
    assert!(!is_valid_ipv6("00:00:00"), "全零时间戳不得判 IPv6");
    // 04: 7 组无缩写非法。
    assert!(!is_valid_ipv6("1:2:3:4:5:6:7"), "无::须足 8 组");
    // 05: 9 组非法。
    assert!(!is_valid_ipv6("1:2:3:4:5:6:7:8:9"), "超 8 组非法");
    // 06: 8 组无缩写合法（公网可路由，后续扫描应命中）。
    assert!(is_valid_ipv6("1:2:3:4:5:6:7:8"));
    assert!(!is_reserved_ip("1:2:3:4:5:6:7:8", "ipv6"));
    // 07: 全写公网合法。
    assert!(is_valid_ipv6("2001:4860:4860:0:0:0:0:8888"));
    // 08: 压缩形态合法。
    assert!(is_valid_ipv6("2001:4860:4860::8888"));
    // 09-11: 回环/链路本地/文档合法但保留豁免。
    assert!(is_valid_ipv6("::1"));
    assert!(is_reserved_ip("::1", "ipv6"));
    assert!(is_valid_ipv6("fe80::1"));
    assert!(is_reserved_ip("fe80::1", "ipv6"));
    assert!(is_valid_ipv6("2001:db8::1"));
    assert!(is_reserved_ip("2001:db8::1", "ipv6"));
    // 12: 非十六进制非法。
    assert!(!is_valid_ipv6("gggg::1"), "非法十六进制不得判 IPv6");
    // 13: 带毫秒时间戳非法。
    assert!(!is_valid_ipv6("12:34:56.789"), "毫秒时间戳不得判 IPv6");
    // 14: ISO 日期时间中的时间段扫描不得出 ipv6。
    let hits = super::super::chunk::scan_builtin_sync("2024-01-01T12:34:56 上线", &empty_cred());
    assert!(
        hits.iter().all(|h| h.0 != "ipv6"),
        "日期时间不得检出 ipv6: {hits:?}"
    );
    // 15: 纯时间句子扫描不得出 ipv6。
    let hits = super::super::chunk::scan_builtin_sync("会议 12:34:56 开始", &empty_cred());
    assert!(
        hits.iter().all(|h| h.0 != "ipv6"),
        "时间戳不得检出 ipv6: {hits:?}"
    );
    // 16: 全写公网扫描命中且值完整（大小写均可）。
    let hits = super::super::chunk::scan_builtin_sync("地址 1:2:3:4:5:6:7:8 结束", &empty_cred());
    assert!(
        hits.iter()
            .any(|h| h.0 == "ipv6" && h.1 == "1:2:3:4:5:6:7:8"),
        "全写公网须命中: {hits:?}"
    );
    let hits = super::super::chunk::scan_builtin_sync(
        "地址 ABCD:EF01:2345:6789:ABCD:EF01:2345:6789 结束",
        &empty_cred(),
    );
    assert!(
        hits.iter().any(|h| h.0 == "ipv6"),
        "大写全写须命中: {hits:?}"
    );
    // 17: 尾部双冒号（`2001:db8::`）合法但文档段保留豁免，与 `2001:db8::1` 同口径。
    assert!(is_valid_ipv6("2001:db8::"));
    assert!(is_reserved_ip("2001:db8::", "ipv6"));
    let hits = super::super::chunk::scan_builtin_sync("地址 2001:db8:: 结束", &empty_cred());
    assert!(
        hits.iter().all(|h| h.0 != "ipv6"),
        "文档段豁免：尾部双冒号文档地址不得检出: {hits:?}"
    );
}

#[tokio::test]
async fn hardening_boundary_rules() {
    // G6/P13：开启态三断言——ASCII 粘连拒绝、前导零 IPv4 丢弃、CJK 边界不误伤。
    let hard = detector();
    hard.set_hardening(true);
    assert!(
        !kinds(&hard.scan_spans_sync("x13812345678y", &empty_cred())).contains(&"phone"),
        "ASCII 粘连须拒绝"
    );
    assert!(
        !kinds(&hard.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred())).contains(&"ipv4"),
        "前导零 IPv4 须丢弃"
    );
    assert!(
        kinds(&hard.scan_spans_sync("联系13812345678处理", &empty_cred())).contains(&"phone"),
        "CJK 边界不得误伤手机号"
    );
}

#[tokio::test]
async fn hardening_analyzer_cache_reuse() {
    // F8/D8：缓存断言升级为可观测命中——首算未命中、第二次跨调用命中计数 +1，
    // 替代「同输入同输出」的替代性断言。
    let cache = ValidationCache::build();
    assert!(
        !cache.check("analyzer:k1", || false).await,
        "首算须返回计算值"
    );
    assert_eq!(cache.hit_count(), 0, "首算不得命中缓存");
    assert!(
        !cache.check("analyzer:k1", || true).await,
        "第二次须命中缓存值（不得重算）"
    );
    assert_eq!(cache.hit_count(), 1, "跨调用复用须观测到一次命中");
    assert!(cache.check("analyzer:k2", || true).await);
    assert_eq!(cache.hit_count(), 1, "新键不得命中缓存");
}

/// 4.18 互锁：canonical `pii-parity-closeout` spec 的 IPv4 掩码文本与 `mask_pii_value`
/// 实现逐字一致。 文本漂移或实现回退（`<8` 误改为前 4/后 4）时本测试失败。
#[test]
fn ipv4_mask_text_consistency() {
    const SPEC: &str = include_str!("../../../../openspec/specs/pii-parity-closeout/spec.md");
    assert!(
        SPEC.contains("字符数 `<8` 时取首 1/尾 1（如 `123456` → `1****6`）"),
        "canonical spec 须声明 <8 → 首 1/尾 1 规则"
    );
    assert!(
        SPEC.contains("`>=8` 时取前 4/后 4（如 `12345678` → `1234****5678`"),
        "canonical spec 须声明 >=8 → 前 4/后 4 规则"
    );
    assert_eq!(mask_pii_value("ipv4", "123456"), "1****6");
    assert_eq!(mask_pii_value("ipv4", "12345678"), "1234****5678");
    assert_eq!(mask_pii_value("ipv4", "192.168.1.1"), "192.168.**.**");
}

/// 4.19 互锁：canonical `redaction` spec 文本与内置 recognizer 计数同为 7（含 `ipv6`）。
/// 计数漂移或正文漏列 `ipv6` 时本测试失败。
#[test]
fn recognizer_count_seven() {
    assert_eq!(BUILTIN_NAMES.len(), 7, "内置 recognizer 名单恒为 7");
    assert!(BUILTIN_NAMES.contains(&"ipv6"), "内置须含 ipv6");
    const SPEC: &str = include_str!("../../../../openspec/specs/redaction/spec.md");
    assert!(
        SPEC.contains("### Requirement: 7 recognizer + 联合正则 + 中文边界"),
        "canonical 需求名须为 7 recognizer"
    );
    assert!(
        SPEC.contains("内置 7 recognizer") && SPEC.contains("IPv6"),
        "canonical 正文须列出 7 recognizer 且含 IPv6"
    );
    assert!(
        SPEC.contains("`email/phone/id_card/bank_card/ipv4/ipv6/api_key`"),
        "canonical 须列出全部七个内置名（含 ipv6）"
    );
}
