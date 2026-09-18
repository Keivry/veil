//! 残缺占位符清理（`strip_partials`/`strip_token_forms`）单测（自 `scope_tests.rs`
//! 拆出，测试名与断言不变）。

use super::super::*;

#[test]
fn strip_partials_legal_text_untouched() {
    // D7：合法正文前缀续段/单词字符逐字节不变（不得误删）。
    for legal in [
        "__VG_CREDENTIALS",
        "__VG_CUSTOMER",
        "__VG_CREDIT",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文不得误删: {legal}");
    }
    // 真残缺仍被清理（保护不退化）。
    for partial in ["__VG_", "__VG_CRED_000", "__PII_3_ab"] {
        let cleaned = strip_partials(partial);
        assert!(!cleaned.contains("__VG"), "{partial} -> {cleaned:?}");
        assert!(!cleaned.contains("__PI"), "{partial} -> {cleaned:?}");
    }
}

#[test]
fn strip_partials_differential() {
    // design D7 差分用例表（合法正文 vs 真残缺 vs 前缀本身），逐条锁定边界。
    for legal in [
        "__VG_CREDENTIALS",
        "__VG_CUSTOMER",
        "__VG_CREDIT",
        "__VG_CREDX",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
        "__VG_CRED_000extra",
        "__PII_3_abzz",
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文须不变: {legal}");
    }
    for partial in [
        "__VG_",
        "__VG__",
        "__VG_C",
        "__VG_CR",
        "__VG_CRE",
        "__VG_CRED",
        "__VG_CRED_",
        "__VG_CRED_000",
        "__VG_CRED_000001",
        "__PI",
        "__PI_",
        "__PII",
        "__PII_",
        "__PII__",
        "__PII_3",
        "__PII_3_",
        "__PII_3_ab",
    ] {
        let out = strip_partials(partial);
        assert!(out.is_empty(), "真残缺/前缀须剥净: {partial:?} -> {out:?}");
    }
    // 完整形态口径：凭据完整剥离（还原先行）；PII 完整保留（响应期新 token）。
    assert_eq!(strip_partials("__VG_CRED_000001__"), "");
    assert!(
        strip_partials("__PII_1_ab12cd34__").contains("__PII_1_ab12cd34__"),
        "PII 完整形态须保留"
    );
    // 尾随边界（空白）剥离，后随合法单词字符不剥离。
    assert_eq!(strip_partials("尾部 __VG_CRED_12 结束"), "尾部  结束");
    assert_eq!(
        strip_partials("正文 __PII_2_ab 结束"),
        "正文  结束",
        "残缺后随空白须剥离"
    );
}

#[test]
fn strip_partial_and_token_fn_semantics() {
    let vault = CredentialVault::new();
    assert_eq!(strip_partials("a __VG_CRED_00 b"), "a  b");
    assert_eq!(strip_partials("a __PII_3_ab b"), "a  b");
    assert_eq!(strip_token_forms(&vault, "x __VG_CRED_123456__ y"), "x  y");
    // PII 完整形态保留（响应期新 token 语义）。
    assert!(strip_token_forms(&vault, "x __PII_1_ab12cd34__ y").contains("__PII_1_ab12cd34__"));
}
