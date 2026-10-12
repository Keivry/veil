//! 回退分支逐出现点回调与两路径等价性的 sibling 单测（自 `credential_vault.rs`
//! 外迁，避免单文件越 800 行红线）。

use {super::super::*, std::collections::HashMap};

/// 正则编译失败/触顶回退（原文单次扫描）输出正确且无 panic。
#[test]
fn alternation_fallback() {
    let mut map = HashMap::new();
    map.insert(
        "alpha-secret-value".to_string(),
        "__CRED_000001__".to_string(),
    );
    map.insert(
        "beta-secret-value".to_string(),
        "__CRED_000002__".to_string(),
    );
    let text = "a alpha-secret-value b beta-secret-value c";
    let limited = replace_all_by_map_limited(text, &map, 1);
    assert_eq!(limited, "a __CRED_000001__ b __CRED_000002__ c");
    assert_eq!(
        replace_all_by_map(text, &map),
        limited,
        "回退与常规路径输出须一致"
    );
}

/// 计数口径：回退分支逐出现点回调（同键出现两次 → 回调两次），
/// 与 alternation 路径对称，避免 `cred_hits` 低估。
#[test]
fn alternation_fallback_reports_each_occurrence() {
    let mut map = HashMap::new();
    map.insert(
        "alpha-secret-value".to_string(),
        "__CRED_000001__".to_string(),
    );
    let snapshot = P2tSnapshot {
        map,
        alternation: None,
    };
    let text = "x alpha-secret-value y alpha-secret-value z";
    let mut calls = 0usize;
    let out = snapshot.redact_tracked(text, &mut |_| calls += 1);
    assert_eq!(out, "x __CRED_000001__ y __CRED_000001__ z");
    assert_eq!(calls, 2, "同键两次出现须逐出现点回调");
}

fn map_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn fallback_snapshot(map: HashMap<String, String>) -> P2tSnapshot {
    P2tSnapshot {
        map,
        alternation: None,
    }
}

/// 等价矩阵：同一 `(text, map)` 下回退与 alternation 逐字节一致。
/// 覆盖子串键、互为前缀键、同键 3 次、未注册字面 token 与空映射。
#[test]
fn fallback_matches_alternation_byte_for_byte() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        // 子串键：明文 `CRED` 是 token `__CRED_*__` 的子串（旧实现会替换进 token 内部）。
        (
            "x CRED y sk-abc123 z",
            &[
                ("CRED", "__CRED_000001__"),
                ("sk-abc123", "__CRED_000002__"),
            ],
        ),
        // 互为前缀：`ab` 与 `abc` 须取最长匹配。
        (
            "z ab abc abcd",
            &[("ab", "__CRED_000003__"), ("abc", "__CRED_000004__")],
        ),
        // 同键出现 3 次。
        (
            "alpha beta alpha gamma alpha",
            &[("alpha", "__CRED_000005__")],
        ),
        // 未注册字面 token 原样保留。
        (
            "keep __CRED_999999__ and sk-xyz789",
            &[("sk-xyz789", "__CRED_000006__")],
        ),
        // 空映射原样返回。
        ("nothing to replace", &[]),
    ];
    for (text, pairs) in cases {
        let map = map_of(pairs);
        let fast = P2tSnapshot::build(&map);
        assert!(
            fast.alternation.is_some() || map.is_empty(),
            "小映射 alternation 须编译成功: {text:?}"
        );
        assert_eq!(
            fast.redact(text),
            fallback_snapshot(map).redact(text),
            "两路径须逐字节一致: {text:?}"
        );
    }
}

/// 子串键回归（旧实现必失败）：回退不得改写已生成 token 内部，回调次数等于
/// 真实匹配数（旧实现把 `__CRED_000002__` 内的 `CRED` 再替换且回调 3 次）。
#[test]
fn fallback_does_not_mutate_emitted_token() {
    let mut calls = 0usize;
    let out = fallback_snapshot(map_of(&[
        ("CRED", "__CRED_000001__"),
        ("sk-abc123", "__CRED_000002__"),
    ]))
    .redact_tracked("x CRED y sk-abc123 z", &mut |_| calls += 1);
    assert_eq!(out, "x __CRED_000001__ y __CRED_000002__ z");
    assert!(out.contains("__CRED_000002__"), "token 形态不得被破坏");
    assert_eq!(calls, 2, "回调次数须等于真实匹配数（不得因产物变化膨胀）");
}

/// 超限强制回退（`size_limit=1`）：输出仍与 alternation 逐字节一致。
#[test]
fn size_limited_fallback_matches_alternation() {
    let map = map_of(&[
        ("sk-long-secret-abcdef", "__CRED_000010__"),
        ("CRED", "__CRED_000011__"),
    ]);
    let text = "a CRED b sk-long-secret-abcdef c __PII_7_cafebabe__";
    let forced_fallback = replace_all_by_map_limited(text, &map, 1);
    assert_eq!(
        forced_fallback,
        replace_all_by_map(text, &map),
        "超限回退须与 alternation 逐字节一致"
    );
    assert_eq!(
        forced_fallback,
        "a __CRED_000011__ b __CRED_000010__ c __PII_7_cafebabe__"
    );
}
