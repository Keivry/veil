//! 声明上限与余量单测（tasks 2.4）：`strip_partials` 的两条模式在 1MiB / 10MiB
//! 最坏输入下须返回 `Ok` 且逐字节不变，并自证 ≥2× 回溯余量。
//!
//! 断言形式说明（`design.md` Decision 2「余量必须自证」）：不写「留 2×」这种
//! 不可验证的话——单测断言 `backtrack_limit_for(len) / 2` 仍使同类最坏输入
//! 返回 `Ok`，那才等于 ≥2× 余量。
//!
//! 运行通道：
//!
//! - 常驻（debug/release 均可）：1MiB 四档 + 1MiB 余量断言。
//! - `#[ignore]`（慢通道，须 release）：10MiB 四档 + 10MiB 余量断言 + 线性性比值 + 生产形态复验。
//!   命令：`cargo test --release --lib strip_partials_release_channel -- --ignored`
//!
//! debug 下 10MiB 纯数字的匹配本身是线性的，但 debug 无优化约慢 10–20×，
//! 故默认不跑；release 下整条慢通道实测 1.6s。

use {
    super::super::strip_partials,
    crate::service::{
        credential_vault::{CRED_PARTIAL_PATTERN, strip_cred_partials},
        pii::{
            chunk::strip::{PII_PARTIAL_PATTERN, backtrack_limit_for},
            strip_pii_partials,
        },
    },
    fancy_regex::RegexBuilder,
};

/// 常驻规模 1MiB。
const MIB: usize = 1_048_576;
/// 单次调用声明上限：`config::env_parse::GATEWAY_BODY_LIMIT_BYTES`（10MiB）。
const DECLARED_LIMIT: usize = 10 * 1024 * 1024;

type StripFn = fn(&str) -> String;

fn strips() -> [(&'static str, StripFn); 2] {
    [
        ("cred", strip_cred_partials as StripFn),
        ("pii", strip_pii_partials as StripFn),
    ]
}

/// 四档最坏填充：纯数字（曾 O(n²)）、纯 ASCII 字母、CJK（3 字节）、emoji（4 字节）。
fn worst_units() -> [(&'static str, &'static str); 4] {
    [
        ("digit", "1"),
        ("letter", "a"),
        ("cjk", "中"),
        ("emoji", "😀"),
    ]
}

/// 按 `size` 字节生成填充（`char` 边界安全截断）。
fn worst_fill(unit: &str, size: usize) -> String {
    let text = unit.repeat(size / unit.len() + 1);
    text[..text.floor_char_boundary(size)].to_string()
}

/// 断言 `size` 字节的每种填充经两条剥离函数后逐字节不变，且**未进入降级**。
///
/// 只断言内容不变是盲的：`Err` 降级路径同样原样返回，内容断言无法区分两者。
/// 故此处另按声明标定的上界直接断言 `try_replacen` 返回 `Ok`。
fn assert_roundtrip(size: usize) {
    for (name, strip) in strips() {
        for (label, unit) in worst_units() {
            let text = worst_fill(unit, size);
            let out = strip(&text);
            assert_eq!(
                out.as_bytes(),
                text.as_bytes(),
                "{name}/{label} {size} 字节须逐字节不变"
            );
        }
    }
    let limit = backtrack_limit_for(size);
    for (label, pattern) in [("cred", CRED_PARTIAL_PATTERN), ("pii", PII_PARTIAL_PATTERN)] {
        let re = RegexBuilder::new(pattern)
            .backtrack_limit(limit)
            .build()
            .expect("模式恒合法");
        for (unit_label, unit) in worst_units() {
            let text = worst_fill(unit, size);
            assert!(
                re.try_replacen(&text, 0, "").is_ok(),
                "{label}/{unit_label} {size} 字节在标定上界 {limit} 下须 Ok（不得进入降级）"
            );
        }
    }
    let one = "1".repeat(size);
    assert_eq!(
        strip_partials(&one).len(),
        one.len(),
        "组合入口须逐字节不变"
    );
}

#[test]
fn strip_partials_declared_limit_1mib_all_classes() { assert_roundtrip(MIB); }

/// 余量自证：把上界压到标定值的**一半**，同类最坏输入仍须 `Ok`。
///
/// 直接用 `RegexBuilder` 以 `backtrack_limit_for(size) / 2` 编译两条模式，
/// 断言 `try_replacen` 返回 `Ok`——这等价于「标定值至少有 2× 余量」。
fn assert_backtrack_margin_half(size: usize) {
    let half = backtrack_limit_for(size) / 2;
    for (label, pattern) in [("cred", CRED_PARTIAL_PATTERN), ("pii", PII_PARTIAL_PATTERN)] {
        let re = RegexBuilder::new(pattern)
            .backtrack_limit(half)
            .build()
            .expect("模式恒合法");
        for (unit_label, unit) in worst_units() {
            let text = worst_fill(unit, size);
            let out = re.try_replacen(&text, 0, "");
            assert!(
                out.is_ok(),
                "{label}/{unit_label} {size} 字节在 limit/2 = {half} 下仍须 Ok"
            );
        }
    }
}

#[test]
fn strip_partials_backtrack_margin_two_x() { assert_backtrack_margin_half(MIB); }

/// release 慢通道：10MiB 声明上限（tasks 2.4）+ 线性性比值（tasks 4.1）+
/// 生产形态复验（tasks 4.3）三组断言合并。
///
/// 合并原因：三者都必须在 **release** 下才有意义（debug 的 10–20× 放大会让
/// 2s 预算与耗时比值同时失真），故同属 `#[ignore]` 慢通道，共用一条运行命令：
///
/// ```text
/// cargo test --release --lib strip_partials_release_channel -- --ignored
/// ```
#[test]
#[ignore = "含 10MiB 档与耗时比值，须 release 通道；debug 下过慢且计时噪声大"]
fn strip_partials_release_channel() {
    use std::time::{Duration, Instant};

    // —— tasks 2.4：10MiB 四档逐字节不变 + 声明上限余量自证 ——
    // 10MiB 档只放慢通道：常驻套件里跑一次约 60MiB 匹配，与「常驻只跑 1MiB」自述冲突。
    assert_roundtrip(DECLARED_LIMIT);
    assert_backtrack_margin_half(DECLARED_LIMIT);

    // —— tasks 4.1：纯数字 t(512KiB) / t(256KiB) ≤ 3 ——
    // 平方退化给出 ≈4（输入翻倍 ⇒ 耗时 ×4），线性给出 ≈1–2。
    let timed = |n: usize| -> Duration {
        let text = "1".repeat(n);
        let _ = strip_cred_partials("1".repeat(1024).as_str());
        let start = Instant::now();
        let out = strip_cred_partials(&text);
        let elapsed = start.elapsed();
        assert_eq!(out.len(), text.len(), "无 token 须逐字节不变");
        elapsed
    };
    let small = timed(256 * 1024);
    let large = timed(512 * 1024);
    let ratio = large.as_secs_f64() / small.as_secs_f64().max(f64::EPSILON);
    assert!(
        ratio <= 3.0,
        "512KiB/256KiB 耗时比 {ratio:.2} 超 3（平方退化会给出 ≈4）：{large:?} / {small:?}"
    );

    // —— tasks 4.3：四类生产形态均须 <2s 且逐字节不变 ——
    let cjk_json = {
        let item = r#"{"text":"中文内容测试数据","n":12345},"#;
        let body = item.repeat(2_250_000 / item.len() + 1);
        let body = &body[..body.floor_char_boundary(2_250_000)];
        format!("[{body}\"end\"]")
    };
    for (label, text) in [
        ("1MiB 纯数字", "1".repeat(MIB)),
        ("1MiB 纯字母", "a".repeat(MIB)),
        ("2.25MB 中文 JSON", cjk_json),
        ("10MiB 纯数字", "1".repeat(DECLARED_LIMIT)),
    ] {
        let start = Instant::now();
        let out = strip_partials(&text);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "{label} 剥离耗时 {elapsed:?} 超 2s"
        );
        assert_eq!(
            out, text,
            "{label} 无 token 形态须逐字节不变（不得进入降级）"
        );
    }
}
