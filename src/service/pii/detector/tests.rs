#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../detector.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "detector.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "detector/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
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
