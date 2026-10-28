//! 重排差分等价（tasks 2.5）：以**旧**正则为对照基准，逐例断言新实现输出一致。
//!
//! 背景：`harden-partial-strip-regex` design Decision 1 把字面量 `__C` / `__PI`
//! 提到两条变长负向后顾之前、并把字面量追加进后顾尾部，论证为语义逐字等价。
//! 该论证若无测试守护，重排的任何漂移只能靠既有 5 条 strip 用例兜底——覆盖率
//! 远不及本文件的笛卡尔积语料。
//!
//! 对照基准的可用性：旧正则在**足够高**的 `backtrack_limit` 下仍可正确执行
//! （它的问题只是逐位置回溯的 O(n²) 耗时，而非结果错误）；本语料全部是短串，
//! 故对照组取 `backtrack_limit = 100_000_000` 即恒不触发上限。
//!
//! 语料构造：`{前缀} × {单元} × {后缀}` 的笛卡尔积，前缀/后缀含空、空白、
//! 标点、字母数字、中文字符；单元含真残缺形态、完整 token、跨族闭合形态与
//! 应保留的合法正文。规模控制在数千例（单例字符串极短，整体毫秒级）。

use crate::service::{
    credential_vault::{CRED_PARTIAL_PATTERN, strip_cred_partials},
    pii::{chunk::strip::PII_PARTIAL_PATTERN, strip_pii_partials},
};

/// 旧（重排前）凭据残缺正则：与 `git show HEAD~:src/service/credential_vault.rs`
/// 中的字面量逐字节一致。仅作对照基准，MUST NOT 用于生产。
const OLD_CRED_PATTERN: &str = r"(?<!__PII_\d+_[0-9a-fA-F]{8})(?<!__CRED_\d{4,})__C(?!RED_\d{4,}__)(?:R(?:E(?:D(?:_?\d*)?)?)?)?(?:_*$|(?=\s|[^\w]))";

/// 旧（重排前）PII 残缺正则，同上。
const OLD_PII_PATTERN: &str = r"(?<!__CRED_\d{4,})(?<!__PII_\d+_[0-9a-fA-F]{8})__PI(?!I_\d+_[0-9a-f]{8}__)(?:I(?:_\d+(?:_[0-9a-fA-F]*)?)?)?(?:_*$|(?=\s|[^\w]))";

/// 对照组回溯上界：短串语料下恒不触发（仅消除旧模式的耗时问题）。
const CONTROL_BACKTRACK_LIMIT: usize = 100_000_000;

fn control(pattern: &str) -> fancy_regex::Regex {
    fancy_regex::RegexBuilder::new(pattern)
        .backtrack_limit(CONTROL_BACKTRACK_LIMIT)
        .build()
        .expect("对照正则恒合法")
}

fn old_strip(re: &fancy_regex::Regex, text: &str) -> String {
    re.try_replacen(text, 0, "")
        .expect("对照正则在上界内恒不 Err")
        .into_owned()
}

/// 单元：真残缺 / 续写 / 完整形态 / 跨族闭合 / 应保留正文。
fn units() -> Vec<&'static str> {
    vec![
        // —— 凭据侧残缺与续写 ——
        "__C",
        "__C_",
        "__CR",
        "__CRE",
        "__CRED",
        "__CRED_",
        "__CRED_000",
        "__CRED_0001",
        "__CRED_000123",
        // —— PII 侧残缺与续写 ——
        "__PI",
        "__PI_",
        "__PII",
        "__PII_",
        "__PII__",
        "__PII_3",
        "__PII_3_",
        "__PII_3_ab",
        "__PII_1_ab",
        // —— 完整 token（两侧均应豁免）——
        "__CRED_000001__",
        "__PII_1_ab12cd34__",
        // —— 应保留的合法正文 ——
        "__CREDENTIALS",
        "__CUSTOMER",
        "__CREDIT",
        "__CREDX",
        "__PIXEL",
        "__PIANO",
        "__PII_DATA",
        "__PII_AB",
        "__CRED_000extra",
        "__PII_3_abzz",
        // —— 组合形态（跨族闭合 + 背靠背）——
        "__C__C",
        "__PI__PI",
        "__CRED_000123__C",
        "__CRED_000123__PI",
        "__PII_1_ab12cd34__C",
        "__PII_1_ab12cd34__PI",
        "__PII_1_ab12cd34____CRED_000",
        "__PII_1_ab12cd34____PII_3_ab",
        "__CRED_000001__C",
        "__C__PI",
        "__PI__C",
        "__CRED_000123__CRED_000456",
        "__PII_1_ab12cd34__PII_2_cd34ef56",
        "B__PII_1_2adda239__C",
    ]
}

/// 前缀：空 / 空白 / 标点 / 单词字符 / 中文 / 令牌起始。
fn prefixes() -> Vec<&'static str> {
    vec!["", " ", "a", "A", "1", "_", "-", ".", "中", "x__", "B"]
}

/// 后缀：空 / 空白 / 标点 / 单词字符 / 中文 / 令牌续起。
fn suffixes() -> Vec<&'static str> {
    vec!["", " ", "。", "a", "1", "_", "-", ".", "中", "__", "\n"]
}

fn diff_report(old: &str, new: &str, input: &str) -> String {
    format!("输入 {input:?}：旧 {old:?} vs 新 {new:?}")
}

#[test]
fn strip_partials_reorder_differential() {
    let old_cred = control(OLD_CRED_PATTERN);
    let old_pii = control(OLD_PII_PATTERN);
    let mut cases = 0usize;
    for p in prefixes() {
        for u in units() {
            for s in suffixes() {
                let input = format!("{p}{u}{s}");
                cases += 1;
                assert_eq!(
                    old_strip(&old_cred, &input),
                    strip_cred_partials(&input),
                    "{}",
                    diff_report(
                        &old_strip(&old_cred, &input),
                        &strip_cred_partials(&input),
                        &input
                    )
                );
                assert_eq!(
                    old_strip(&old_pii, &input),
                    strip_pii_partials(&input),
                    "{}",
                    diff_report(
                        &old_strip(&old_pii, &input),
                        &strip_pii_partials(&input),
                        &input
                    )
                );
            }
        }
    }
    assert!(cases >= 4_000, "语料规模须达数千例，实为 {cases}");
}

/// 两条模式各自与自身重排前的对照一致，且**互不干扰**（串联顺序下的组合输出
/// 也须与旧串联逐字节一致）。
#[test]
fn strip_partials_reorder_differential_chained() {
    let old_cred = control(OLD_CRED_PATTERN);
    let old_pii = control(OLD_PII_PATTERN);
    for p in prefixes() {
        for u in units() {
            for s in suffixes() {
                let input = format!("{p}{u}{s}");
                let old_chained = old_strip(&old_pii, &old_strip(&old_cred, &input));
                let new_chained = strip_pii_partials(&strip_cred_partials(&input));
                assert_eq!(old_chained, new_chained, "串联顺序下亦须等价: {input:?}");
            }
        }
    }
}

/// 两条模式在**重排后**仍各自只处理本族形态：本用例锁定「新模式的字面量前置
/// 未把跨族后顾的窗口算错」这一最容易出错之处。
#[test]
fn strip_partials_reorder_cross_family_window_not_off_by_literal() {
    let old_cred = control(OLD_CRED_PATTERN);
    let old_pii = control(OLD_PII_PATTERN);
    // 跨族闭合豁免的边界：后顾长度各增加 3（`__C`）/ 4（`__PI`）字节，
    // 故 `__PII_<seq>_<hex8>` 与 `__CRED_<digits>` 两侧各取最小/最大长度。
    for pii_body in [
        "__PII_1_ab12cd34",
        "__PII_123456_ABCDEF01",
        "__PII_999999999_fedcba98",
    ] {
        for follow in ["C", "PI", "__C", "__PI"] {
            for sep in ["__", "___", "____"] {
                let input = format!("{pii_body}{sep}{follow}");
                assert_eq!(
                    old_strip(&old_cred, &input),
                    strip_cred_partials(&input),
                    "凭据侧跨族窗口: {input:?}"
                );
                assert_eq!(
                    old_strip(&old_pii, &input),
                    strip_pii_partials(&input),
                    "PII 侧跨族窗口: {input:?}"
                );
            }
        }
    }
    for cred_body in ["__CRED_0001", "__CRED_000001", "__CRED_123456789"] {
        for follow in ["C", "PI", "__C", "__PI"] {
            for sep in ["__", "___", "____"] {
                let input = format!("{cred_body}{sep}{follow}");
                assert_eq!(
                    old_strip(&old_cred, &input),
                    strip_cred_partials(&input),
                    "凭据侧跨族窗口: {input:?}"
                );
                assert_eq!(
                    old_strip(&old_pii, &input),
                    strip_pii_partials(&input),
                    "PII 侧跨族窗口: {input:?}"
                );
            }
        }
    }
}

/// 新模式必须**仍是**重排形态：字面量在后顾**之前**，且两条跨族后顾尾部各含
/// 该字面量。若有人把字面量移回后顾之后，差分测试仍会通过（语义不变）但
/// O(n²) 回归——本用例是那道防线的唯一守卫。
#[test]
fn strip_partials_patterns_are_literal_anchored() {
    assert!(
        CRED_PARTIAL_PATTERN.starts_with("__C(?<!"),
        "凭据模式须以字面 `__C` 起首: {CRED_PARTIAL_PATTERN}"
    );
    assert_eq!(
        CRED_PARTIAL_PATTERN.matches("__C)").count(),
        2,
        "凭据模式的两条跨族后顾尾部各须含 `__C`: {CRED_PARTIAL_PATTERN}"
    );
    assert!(
        PII_PARTIAL_PATTERN.starts_with("__PI(?<!"),
        "PII 模式须以字面 `__PI` 起首: {PII_PARTIAL_PATTERN}"
    );
    assert_eq!(
        PII_PARTIAL_PATTERN.matches("__PI)").count(),
        2,
        "PII 模式的两条跨族后顾尾部各须含 `__PI`: {PII_PARTIAL_PATTERN}"
    );
}
