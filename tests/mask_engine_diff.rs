//! D4/hygiene-round5 跨引擎差分测试：`pii::detector::mask_pii_value`（LLM 可见掩码）
//! vs `metrics::sample::sample_mask`（指标采样掩码）。
//!
//! 两引擎为文档化契约分治（消费方不同：面向 LLM/上游展示 vs 指标采样聚合），
//! SHALL NOT 合并（不抽 `mask_core`、不互相委托）。本测试以 kind×value 矩阵把
//! 既有分叉从「静默」转为「显式」：一致项断言相等，差异项断言各自的具体允许
//! 输出并注明理由。任何新增未登记分叉（或既有分叉被误对齐）都会使本测试失败。
//! 两引擎实现与消费方输出零变更。

use veil::service::{metrics::sample::PiiValueSampler, pii::detector::mask_pii_value};

/// 指标侧掩码入口（关联函数 `PiiValueSampler::sample_mask` 的短名包装）。
fn sample_mask(kind: &str, value: &str) -> String { PiiValueSampler::sample_mask(kind, value) }

/// 两引擎在同一 `(kind, value)` 下的预期关系。
enum Relation {
    /// 等价项：两引擎输出必须逐字符相等。
    Same(&'static str),
    /// 已登记分叉：分别断言各自具体允许输出（差异即设计，理由见矩阵条目与 design D4）。
    Diff {
        detector: &'static str,
        sample: &'static str,
        reason: &'static str,
    },
}

#[test]
fn mask_engine_diff_matrix_registered_relations() {
    use Relation::{Diff, Same};

    let long_cjk = "中".repeat(100);
    let long_suffix_value = format!("a@b.{}", "x".repeat(70));

    let cases: &[(&str, &str, Relation)] = &[
        // 空值：两引擎同口径 `***`。
        ("phone", "", Same("***")),
        ("email", "", Same("***")),
        ("bank", "", Same("***")),
        ("other", "", Same("***")),
        // phone 各长度边界（<2 / 2-5 / 6 / ≥7）逐分支核对为等价。
        ("phone", "1", Same("***")),
        ("phone", "12", Same("1****2")),
        ("phone", "12345", Same("1****5")),
        ("phone", "123456", Same("123****456")),
        ("phone", "1234567", Same("123****4567")),
        ("phone", "12345678", Same("123****5678")),
        ("phone", "13812345678", Same("138****5678")),
        // email 有点域名：两引擎同口径（不透 local/domain 首字符）。
        ("email", "a@b.com", Same("***@***.com")),
        ("email", "a@b.c.d", Same("***@***.d")),
        ("email", "user@example.com", Same("***@***.com")),
        // email 空后缀（`a@b.`）与空 local：两引擎同口径 `***@***`。
        ("email", "a@b.", Same("***@***")),
        ("email", "@b.com", Same("***@***.com")),
        // email 无 `@`：两引擎同走「短值/前3后3」口径。
        ("email", "abcde", Same("a****e")),
        ("email", "abcdef", Same("abc****def")),
        // 非差异 kind 边界（6/7/8）等价。
        ("ipv6", "12345", Same("1****5")),
        ("ipv6", "123456", Same("123****456")),
        ("ipv6", "1234567", Same("123****567")),
        ("ipv6", "12345678", Same("1234****5678")),
        ("api_key", "abcd1234", Same("abcd****1234")),
        ("other", "1", Same("***")),
        ("other", "ab", Same("a****b")),
        ("other", "abcdef", Same("abc****def")),
        // 超长（>64）：other 前3后3 恒短（不进截断）；email 长后缀两引擎同截断。
        ("other", long_cjk.as_str(), Same("中中中****中中中")),
        (
            "email",
            long_suffix_value.as_str(),
            Same("***@***.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ),
        // ipv4 四段与非四段短值（len<6）：等价。
        ("ipv4", "192.168.1.10", Same("192.168.**.**")),
        ("ipv4", "1.2.3", Same("1****3")),
        // ipv4 非四段 6-7 / len≥8：RED-3 对齐原仓后 detector 与 sample 等价。
        ("ipv4", "123456", Same("1****6")),
        ("ipv4", "1234567", Same("1****7")),
        ("ipv4", "12345678", Same("1234****5678")),
        // bank 别名集：sample 识别 `bank`，detector 不识别（落 other）。
        (
            "bank",
            "1234",
            Diff {
                detector: "1****4",
                sample: "**** **** **** 1234",
                reason: "bank 别名仅 sample 识别（detector 落 other short）",
            },
        ),
        (
            "bank",
            "12345678",
            Diff {
                detector: "123****678",
                sample: "**** **** **** 5678",
                reason: "bank 别名仅 sample 识别（detector 落 other 前3后3）",
            },
        ),
        // bankcard/id_card 别名集：detector 识别，sample 不识别（落 other）。
        (
            "bankcard",
            "12345678",
            Diff {
                detector: "**** **** **** 5678",
                sample: "123****678",
                reason: "bankcard 别名仅 detector 识别（sample 落 other 前3后3）",
            },
        ),
        (
            "bankcard",
            "1234",
            Diff {
                detector: "**** **** **** 1234",
                sample: "1****4",
                reason: "bankcard 别名仅 detector 识别（sample 落 other short）",
            },
        ),
        (
            "id_card",
            "12345678",
            Diff {
                detector: "**** **** **** 5678",
                sample: "123****678",
                reason: "id_card 别名仅 detector 识别（sample 落 other 前3后3）",
            },
        ),
        // apikey 别名：detector 识别，sample 仅 api_key（落 other）。
        (
            "apikey",
            "abcd1234",
            Diff {
                detector: "abcd****1234",
                sample: "abc****234",
                reason: "apikey 别名仅 detector 识别（sample 落 other 前3后3）",
            },
        ),
        // email 无点域名：RED-3 对齐原仓后 detector 与 sample 同归 `***@***`（等价）。
        ("email", "a@b", Same("***@***")),
        ("email", "user@domain", Same("***@***")),
        ("email", "abcde@f", Same("***@***")),
    ];

    for (kind, value, rel) in cases {
        let d = mask_pii_value(kind, value);
        let s = sample_mask(kind, value);
        match rel {
            Same(expected) => {
                assert_eq!(&d, expected, "detector 等价输出 [{kind}/{value}]");
                assert_eq!(&s, expected, "sample 等价输出 [{kind}/{value}]");
                assert_eq!(d, s, "等价项不得分叉 [{kind}/{value}]");
            }
            Diff {
                detector,
                sample,
                reason,
            } => {
                assert_eq!(
                    &d, detector,
                    "detector 允许输出 [{kind}/{value}]（{reason}）"
                );
                assert_eq!(&s, sample, "sample 允许输出 [{kind}/{value}]（{reason}）");
                assert_ne!(d, s, "登记差异项须确实分叉 [{kind}/{value}]（{reason}）");
            }
        }
    }
}

#[test]
fn mask_engine_diff_phone_boundaries_equivalent() {
    // spec 要求：phone <2 / 2-5 / 6 / ≥7 各边界等价由测试锁定（实测无差异）。
    for v in [
        "",
        "1",
        "12",
        "123",
        "1234",
        "12345",
        "123456",
        "1234567",
        "13812345678",
    ] {
        assert_eq!(
            mask_pii_value("phone", v),
            sample_mask("phone", v),
            "phone 边界须等价: {v}"
        );
    }
}

#[test]
fn mask_engine_diff_bank_alias_sets() {
    // detector: bank_card|bankcard|id_card；sample: bank|bank_card。
    // 别名集差异即设计（两消费方各自承载历史契约），不合并。
    assert_eq!(
        mask_pii_value("bankcard", "6225880123456789"),
        "**** **** **** 6789"
    );
    assert_eq!(sample_mask("bankcard", "6225880123456789"), "622****789");
    assert_eq!(
        mask_pii_value("id_card", "6225880123456789"),
        "**** **** **** 6789"
    );
    assert_eq!(sample_mask("id_card", "6225880123456789"), "622****789");
    assert_eq!(mask_pii_value("bank", "6225880123456789"), "622****789");
    assert_eq!(
        sample_mask("bank", "6225880123456789"),
        "**** **** **** 6789"
    );
    // bank_card 为双方共同别名：输出等价。
    assert_eq!(
        mask_pii_value("bank_card", "6225880123456789"),
        sample_mask("bank_card", "6225880123456789")
    );
}

#[test]
fn mask_engine_diff_apikey_alias() {
    // detector 识别 `apikey`；sample 仅 `api_key`（`apikey` 落 other）—— 登记差异。
    assert_eq!(mask_pii_value("apikey", "abcd1234"), "abcd****1234");
    assert_eq!(sample_mask("apikey", "abcd1234"), "abc****234");
    assert_eq!(
        mask_pii_value("api_key", "abcd1234"),
        sample_mask("api_key", "abcd1234")
    );
}

#[test]
fn mask_engine_diff_ipv4_non_quad_equivalent() {
    // RED-3 对齐原仓后：非四段 6-7 / len≥8 两引擎同口径（等价）。
    assert_eq!(mask_pii_value("ipv4", "12345678"), "1234****5678");
    assert_eq!(sample_mask("ipv4", "12345678"), "1234****5678");
    assert_eq!(mask_pii_value("ipv4", "123456"), "1****6");
    assert_eq!(sample_mask("ipv4", "123456"), "1****6");
    assert_eq!(mask_pii_value("ipv4", "1234567"), "1****7");
    assert_eq!(sample_mask("ipv4", "1234567"), "1****7");
    // 非四段 len<6：两引擎同走短值口径（等价）。
    assert_eq!(
        mask_pii_value("ipv4", "1.2.3"),
        sample_mask("ipv4", "1.2.3")
    );
}

#[test]
fn mask_engine_diff_email_no_dot_domain_equivalent() {
    // RED-3：无点域名 detector 与 sample 同归 `***@***`（等价）。
    assert_eq!(mask_pii_value("email", "a@b"), "***@***");
    assert_eq!(sample_mask("email", "a@b"), "***@***");
    assert_eq!(mask_pii_value("email", "user@domain"), "***@***");
    assert_eq!(sample_mask("email", "user@domain"), "***@***");
    // 有点域名/空后缀：完全等价。
    for v in ["a@b.com", "a@b.c.d", "a@b.", "@b.com"] {
        assert_eq!(
            mask_pii_value("email", v),
            sample_mask("email", v),
            "email 有点域名须等价: {v}"
        );
    }
}

#[test]
fn mask_engine_diff_truncation_over_64_equivalent() {
    // >64：两引擎同按字符边界截断至 64，口径一致。
    let value = format!("a@b.{}", "x".repeat(70));
    let d = mask_pii_value("email", &value);
    let s = sample_mask("email", &value);
    assert_eq!(d, s, ">64 截断口径须一致");
    assert_eq!(d.chars().count(), 64);
}
