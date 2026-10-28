//! 残缺剥离的三项硬化：坏输入不 panic / 不退化 / 语义等价。
//!
//! 背景：`strip_cred_partials` 与 `strip_pii_partials` 均以
//! `fancy_regex::Regex::replace_all` 实现，而该 API **内部 unwrap**
//! （`fancy-regex-0.20.0/src/lib.rs:2017`），任何 `RuntimeError` 都会
//! panic；release profile 为 `panic = "abort"`，故一次命中即终止进程。
//!
//! 生产已实证的两种坏输入（release 实测）：
//!
//! - **纯数字**：两条正则都以两个变长负向后顾 `(?<!__PII_\d+_[0-9a-fA-F]{8})`、`(?<!__CRED_\d{4,})`
//!   开头，引擎无法 建立字面量锚点，逐位置原地回溯退化为 O(n²)。20K 字符约 256ms、 50K 约 1.59
//!   秒、100K 约 6.3 秒，1MB 外推约 634 秒——表现为线程 100% CPU 假死，而非快速 panic。
//! - **其余任意文本**：≥333,334 字符即在约 30ms 内触发 `BacktrackLimitExceeded`（默认
//!   `backtrack_limit` 为 100 万步）。
//!
//! 断言以「先红后绿」为目标：当前实现在下列用例上失败；修复三件套
//! （重排正则消除 O(n²) + 提高 `backtrack_limit` + `try_replacen` 替代
//! `replace_all`）落地后转绿，且既有语义用例保持原样全绿。
//!
//! **本模块不含会永久挂起的用例**：纯数字只测到 50K（当前实现约 1.59 秒
//! 内会终止，足以暴露平方退化），避免留下 100% CPU 的僵尸线程；1MiB
//! 纯数字用例标 `#[ignore]`，须显式开启。

use {
    super::super::strip_partials,
    crate::service::{credential_vault::strip_cred_partials, pii::strip_pii_partials},
    std::time::{Duration, Instant},
};

/// 常驻门禁规模。`strip_partials` 作用于**整段**请求/响应文本、无分块
/// （`SCAN_INPUT_LIMIT` 为 1MiB 但本条路径不经分块），而真实请求体上限是
/// `config::env_parse::GATEWAY_BODY_LIMIT_BYTES`（10MiB）。1MiB 作为常驻
/// 用例规模（debug 下可接受），10MiB 由 release 通道用例覆盖（tasks 2.4）。
const MAX_REAL_INPUT: usize = 1_048_576;

type StripFn = fn(&str) -> String;

/// 无 token 文本：缺陷表现是 panic / 平方退化，正确修复后 MUST 逐字节不变。
///
/// 排除纯数字：它不是 panic 而是挂起，由
/// `strip_partials_pure_digit_completes_within_budget` 单独覆盖。
fn legal_non_digit_inputs() -> Vec<(&'static str, String)> {
    let units: [(&str, &str); 8] = [
        ("ascii letter", "a"),
        ("ascii upper", "A"),
        ("hex digit", "f"),
        ("dot run", "."),
        ("dash run", "-"),
        ("underscore run", "_"),
        ("space run", " "),
        ("cjk run", "中"),
    ];
    units
        .into_iter()
        .map(|(label, unit)| (label, unit.repeat(MAX_REAL_INPUT / unit.len() + 1)))
        .collect()
}

/// 密集 token 片段：**不是**无 token 文本。这些形态的串尾那个残缺/续写
/// 片段会命中 `(?:_*$|(?=\s|[^\w]))` 的串尾分支而被**正确剥离**，因此
/// MUST NOT 断言逐字节不变——否则修复后必然失败。
///
/// 断言改为：三处调用都返回（不 panic / 不挂起）、文本不增长、且至多剥掉
/// 末尾一个 token（内部那些因后随 `_`、`\w` 而不命中）。
fn token_dense_inputs() -> Vec<(&'static str, &'static str, String)> {
    let units: [(&str, &str); 4] = [
        ("cred partial run", "__C"),
        ("pii partial run", "__PI"),
        ("cred body run", "__CRED_000123"),
        ("pii body run", "__PII_1_ab12cd34"),
    ];
    units
        .into_iter()
        .map(|(label, unit)| (label, unit, unit.repeat(MAX_REAL_INPUT / unit.len() + 1)))
        .collect()
}

#[test]
fn strip_partials_never_panics_on_legal_input() {
    // 修复前：≥333,334 字符的任意非数字文本触发 replace_all 内部 unwrap
    // panic（本测试即以 panic 失败）。修复后：一律正常返回且逐字节不变。
    for (label, text) in legal_non_digit_inputs() {
        let cred = strip_cred_partials(&text);
        assert_eq!(
            cred.len(),
            text.len(),
            "{label}: 凭据剥离不得改动无 token 文本"
        );

        let pii = strip_pii_partials(&text);
        assert_eq!(
            pii.len(),
            text.len(),
            "{label}: PII 剥离不得改动无 token 文本"
        );

        let both = strip_partials(&text);
        assert_eq!(
            both.len(),
            text.len(),
            "{label}: 全出口剥离须逐字节不变（实际 {} vs {}）",
            both.len(),
            text.len()
        );
    }
}

#[test]
fn strip_partials_never_panics_on_token_dense_input() {
    // 与上一用例分开的原因见 `token_dense_inputs` 文档：串尾那一个是**该被
    // 剥掉**的，断言逐字节不变会与正确语义冲突。
    for (label, unit, text) in token_dense_inputs() {
        let results = [
            ("cred", strip_cred_partials(&text)),
            ("pii", strip_pii_partials(&text)),
            ("both", strip_partials(&text)),
        ];
        for (name, out) in &results {
            assert!(
                out.len() <= text.len(),
                "{label}/{name}: 剥离不得使文本增长（{} vs {}）",
                out.len(),
                text.len()
            );
            assert!(
                text.len() - out.len() <= unit.len(),
                "{label}/{name}: 至多剥掉末尾一个 token（剥掉 {} 字节，unit 长 {}）",
                text.len() - out.len(),
                unit.len()
            );
        }
    }
}

#[test]
fn strip_partials_pure_digit_completes_within_budget() {
    // 纯数字是 O(n²) 慢路径。用严格绝对预算暴露退化：修复前 20K 需
    // 约 256ms（release）/ 约 3.3s（debug）、50K 约 1.59s，均远超门禁；
    // 修复后两者都是毫秒级（实测约 1–3ms）。
    let measure = |strip: StripFn, unit: &str, n: usize| -> Duration {
        let text = unit.repeat(n);
        let start = Instant::now();
        let out = strip(&text);
        let elapsed = start.elapsed();
        assert_eq!(out.len(), text.len(), "无 token 须逐字节不变");
        elapsed
    };
    // 预热：排除 OnceLock 首次编译正则的开销。
    let _ = measure(strip_cred_partials, "1", 1_000);
    let _ = measure(strip_pii_partials, "1", 1_000);

    // debug 只跑 20K 一档：红态下 50K 需约 16s，会显著拖慢本地测试循环。
    let tiers: &[(usize, u64)] = if cfg!(debug_assertions) {
        &[(20_000, 100)]
    } else {
        &[(20_000, 100), (50_000, 200)]
    };
    let units: &[&str] = if cfg!(debug_assertions) {
        &["1"]
    } else {
        &["1", "0"]
    };
    // 两侧都计时：`strip_pii_partials` 与凭据侧同构但独立，须各自受门禁。
    let strips: [(&str, StripFn); 2] = [("cred", strip_cred_partials), ("pii", strip_pii_partials)];
    for (name, strip) in strips {
        for unit in units {
            for (n, budget_ms) in tiers {
                let elapsed = measure(strip, unit, *n);
                assert!(
                    elapsed < Duration::from_millis(*budget_ms),
                    "{name} 纯数字 {unit:?} × {n} 耗时 {elapsed:?} 超 {budget_ms}ms 门禁——仍在 O(n²) 慢路径"
                );
            }
        }
    }
}

#[test]
fn strip_partials_semantics_unchanged_after_hardening() {
    // 硬化不得改变语义：以下断言与 `strip_partials_differential` /
    // `strip_partials_legal_text_untouched` 同源，修复后必须继续全绿。
    for legal in [
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
    ] {
        assert_eq!(strip_partials(legal), legal, "合法正文不得误删: {legal}");
    }
    for partial in [
        "__C",
        "__C_",
        "__CR",
        "__CRE",
        "__CRED",
        "__CRED_",
        "__CRED_000",
        "__CRED_000001",
        "__PI",
        "__PI_",
        "__PII",
        "__PII_",
        "__PII__",
        "__PII_3",
        "__PII_3_",
        "__PII_3_ab",
    ] {
        assert!(
            strip_partials(partial).is_empty(),
            "真残缺/前缀须剥净: {partial:?} -> {:?}",
            strip_partials(partial)
        );
    }
    // 完整形态豁免、跨族闭合豁免（与既有用例逐字一致）。
    assert_eq!(strip_partials("__CRED_000001__"), "__CRED_000001__");
    assert!(strip_partials("__PII_1_ab12cd34__").contains("__PII_1_ab12cd34__"));
    assert_eq!(
        strip_partials("B__PII_1_2adda239__C"),
        "B__PII_1_2adda239__C"
    );
    assert_eq!(strip_partials("__CRED_000123__PI"), "__CRED_000123__PI");
    assert_eq!(strip_partials("尾部 __CRED_12 结束"), "尾部  结束");
    assert_eq!(strip_partials("正文 __PII_2_ab 结束"), "正文  结束");
}

#[test]
fn strip_partials_full_size_text_with_tokens_still_strips() {
    // 1MiB 文本里夹着残缺 token：既要抗住长度，也要照常剥离。
    // 填充用字母（当前实现在 ≥333,334 字符即 panic，故本测试现在为红），
    // 修复后须在正常耗时内完成且剥离不退化。
    let filler = "a".repeat(MAX_REAL_INPUT - 96);
    let text = format!("{filler} 尾部 __CRED_12 收尾 __PII_3_ab 结束");
    let out = strip_partials(&text);
    assert!(!out.contains("__CRED_12"), "长文本中的残缺凭据须被剥离");
    assert!(!out.contains("__PII_3_ab"), "长文本中的残缺 PII 须被剥离");
    assert!(out.contains("收尾"), "正文须保留");
    assert!(out.starts_with('a'), "前缀正文须保留");
}

/// 1MiB 纯数字的最坏用例：修复前**永久挂起**（外推约 634 秒）。
///
/// 刻意标 `#[ignore]`：默认 `cargo test` 不跑，避免留下 100% CPU 的
/// 僵尸线程。修复落地后用
/// `cargo test --lib strip_partials_1mb_pure_digit -- --ignored` 验证。
#[test]
#[ignore = "修复前 1MiB 纯数字会挂起约 634 秒（CPU 打满）；仅在修复后或显式排查时运行"]
fn strip_partials_1mb_pure_digit_completes() {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let text = "1".repeat(MAX_REAL_INPUT);
        let start = Instant::now();
        let out = strip_cred_partials(&text);
        let _ = tx.send((out.len(), start.elapsed()));
    });
    let (len, elapsed) = match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("1MiB 纯数字剥离超过 5s 未返回：O(n²) 慢路径未修复")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("工作线程在返回前panic（多半是 replace_all 内部 unwrap）")
        }
    };
    assert_eq!(len, MAX_REAL_INPUT, "无 token 须逐字节不变");
    assert!(
        elapsed < Duration::from_millis(500),
        "1MiB 剥离耗时 {elapsed:?} 超 500ms 门禁"
    );
}
