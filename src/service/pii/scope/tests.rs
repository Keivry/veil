//! `PiiScope` 单测（自 `scope.rs` 外迁，sibling 模块模式）。

use {super::*, std::sync::Arc};

#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split("scope.rs", include_str!("../scope.rs"));
    crate::test_support::file_len_under_800_or_split("scope/tests.rs", include_str!("tests.rs"));
}

#[test]
fn same_value_reuse_and_gap_skip_stable_index() {
    let scope = PiiScope::new();
    let t1 = scope.register("13812345678").unwrap();
    let t2 = scope.register("13812345678").unwrap();
    assert_eq!(t1, t2, "同值必须复用同一 token");
    assert!(pii_token_re().is_match(&t1));
    // token 形态值拒绝注册。
    assert!(scope.register(&t1).is_err());
    assert!(scope.register("__PII_1_ab").is_err());
    // 空洞跳过：仅 t1 占用序号 1 → 下一空闲为 2。
    assert_eq!(scope.next_available_index(), 2);
}

#[test]
fn concurrent_register_no_index_conflict() {
    let scope = Arc::new(PiiScope::new());
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let s = scope.clone();
            std::thread::spawn(move || s.register(&format!("并发值-{i:03}")).unwrap())
        })
        .collect();
    let mut toks: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 32, "并发注册不得串扰或冲突");
    let mut seqs: Vec<usize> = toks.iter().filter_map(|t| parse_pii_seq(t)).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=32).collect::<Vec<_>>());
}

#[test]
fn rand8_shape_and_unpredictable_length() {
    for _ in 0..10 {
        let r = gen_rand8().unwrap();
        assert_eq!(r.len(), 8);
        assert!(r.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(r, r.to_ascii_lowercase());
    }
}

#[test]
fn loose_shape_unknown_passthrough() {
    let scope = PiiScope::new();
    // 未知完整 token 还原时原样透传（不伪造明文）。
    let out = scope.restore("回拨 __PII_9_ab12cd34__ 结束");
    assert_eq!(
        out, "回拨 __PII_9_ab12cd34__ 结束",
        "未知 token 须透传: {out}"
    );
    // 已注册 token 仍精确还原，不受未知形态干扰。
    let tok = scope.register("13812345678").unwrap();
    let out = scope.restore(&format!("回拨 {tok} 与 __PII_9_ab12cd34__"));
    assert!(out.contains("13812345678"), "{out}");
    assert!(out.contains("__PII_9_ab12cd34__"), "{out}");
}

#[test]
fn request_table_capacity_split_lru_eviction() {
    // 请求单表 1000，与凭据 5000 不在同一容量口径。
    assert_eq!(PII_MAX_ENTRIES, 1000);
    assert_eq!(crate::service::credential_vault::MAX_TOKEN_ENTRIES, 5000);
    assert_ne!(
        PII_MAX_ENTRIES,
        crate::service::credential_vault::MAX_TOKEN_ENTRIES
    );
    let scope = PiiScope::new();
    let first = scope.register("13812340000").unwrap();
    let mut last_tok = String::new();
    for i in 1..=(PII_MAX_ENTRIES as u32 + 4) {
        last_tok = scope.register(&format!("139{:08}", i)).unwrap();
    }
    // 最久未用被淘汰，新值驻留；淘汰腾出的序号被复用（空洞跳过）。
    assert!(
        !scope.contains_request_token(&first),
        "最久条目须被 LRU 淘汰"
    );
    let newest = format!("139{:08}", PII_MAX_ENTRIES as u32 + 4);
    assert!(scope.contains_request_token(&last_tok));
    assert_eq!(
        scope.register(&newest).unwrap(),
        last_tok,
        "最新条目须驻留复用同一 token"
    );
}

#[test]
fn b4_lru_hit_reuse_and_thousand_boundary() {
    // 缓存命中复用与容量 1000 边界行为。
    assert_eq!(PII_MAX_ENTRIES, 1000);
    let scope = PiiScope::new();
    // 命中复用：同值注册返回同一 token，还原一致。
    let a = scope.register("13812345678").unwrap();
    assert_eq!(scope.register("13812345678").unwrap(), a);
    assert!(scope.restore(&format!("回拨 {a}")).contains("13812345678"));
    // 首条 + 999 条 = 1000 满容量，下一序号为 1001。
    for i in 0..999 {
        scope.register(&format!("b4-val-{i:04}")).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    // 再注一条触发淘汰：最旧（首 token）被逐出，空洞 1 可复用。
    scope.register("b4-val-0999").unwrap();
    assert!(!scope.contains_request_token(&a), "最久条目须被淘汰");
    assert_eq!(scope.next_available_index(), 1);
}

#[test]
fn f5_cursor_alloc_is_linear_no_full_rebuild() {
    // K 次顺序注册探测步数线性（游标分配），不随每次注册全量重建。
    let scope = PiiScope::new();
    const K: usize = PII_MAX_ENTRIES;
    for i in 0..K {
        scope.register(&format!("f5-linear-{i:04}")).unwrap();
    }
    let inner = lock_or_recover(scope.inner.lock());
    assert_eq!(
        inner.scan_steps, K,
        "顺序分配每注册恰探测一次候选（实际 {}）；旧全量重建为 O(K^2)",
        inner.scan_steps
    );
}

#[test]
fn f5_hole_reuse_after_eviction_no_conflict() {
    // 淘汰释放的序号被后续注册复用，且不与在用序号冲突。
    let scope = PiiScope::new();
    let first = scope.register("f5-first").unwrap();
    let first_seq = parse_pii_seq(&first).unwrap();
    for i in 0..PII_MAX_ENTRIES - 1 {
        scope.register(&format!("f5-fill-{i:04}")).unwrap();
    }
    scope.register("f5-overflow").unwrap();
    assert!(!scope.contains_request_token(&first), "最旧条目须被淘汰");
    let reused = scope.register("f5-reused").unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(first_seq), "空洞须被复用");
    let inner = lock_or_recover(scope.inner.lock());
    let req_seqs: Vec<usize> = inner
        .pii_t2p
        .keys()
        .filter_map(|t| parse_pii_seq(t))
        .collect();
    let uniq: HashSet<usize> = req_seqs.iter().copied().collect();
    assert_eq!(uniq.len(), req_seqs.len(), "请求表在用序号不得重复");
    assert_eq!(inner.req_used, uniq, "请求表已用集须与表内容一致");
}

#[test]
fn f5_upper_bound_unique_and_in_range() {
    // 单请求注册至 PII_MAX_ENTRIES，序号互不重复且落在 [1, PII_MAX_ENTRIES]。
    let scope = PiiScope::new();
    let mut seqs = Vec::new();
    for i in 0..PII_MAX_ENTRIES {
        let tok = scope.register(&format!("f5-bound-{i:04}")).unwrap();
        seqs.push(parse_pii_seq(&tok).unwrap());
    }
    assert_eq!(seqs.len(), PII_MAX_ENTRIES);
    let uniq: HashSet<usize> = seqs.iter().copied().collect();
    assert_eq!(uniq.len(), PII_MAX_ENTRIES, "序号不得重复");
    assert!(
        seqs.iter().all(|s| (1..=PII_MAX_ENTRIES).contains(s)),
        "序号须落在 [1, {PII_MAX_ENTRIES}]"
    );
}

#[test]
fn fuzzy_case_insensitive_restore() {
    let scope = PiiScope::new();
    let token = scope.register("13812345678").unwrap();
    let seq: usize = token
        .strip_prefix("__PII_")
        .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
        .flatten()
        .unwrap();
    // 大写变体同样按序号回查（IGNORECASE 口径）。
    let upper = format!("__PII_{seq}_ZZZZABCD__");
    assert!(pii_loose_re().is_match(&upper), "宽松形态须忽略大小写");
    let restored = scope.restore_with_fuzzy(&format!("回拨 {upper}"), true);
    assert!(restored.contains("13812345678"), "{restored}");
}

/// 锁中毒后隔离判定返回真实值、注册/还原无 panic。
#[test]
fn pii_poison_recovery() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let scope = PiiScope::new();
    let tok = scope.register("13812345678").unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = scope.inner.lock().unwrap();
        panic!("注入 inner 锁中毒");
    }));
    assert!(
        scope.contains_request_token(&tok),
        "中毒后隔离判定须返回真实结果（不得静默 false）"
    );
    let tok2 = scope.register("13900000001").unwrap();
    assert!(scope.contains_request_token(&tok2));
    assert!(scope.restore(&tok2).contains("13900000001"));
}

// ---- vault 回补：空洞跳过/rand8 不可枚举/100 并发 gather/同值复用 ----

fn rand8_of(token: &str) -> &str {
    let rest = token.strip_prefix("__PII_").expect("须为 PII token");
    rest.split('_')
        .nth(1)
        .expect("须含 rand8 段")
        .trim_end_matches('_')
}

#[test]
fn t7_hole_reused_after_eviction() {
    let scope = PiiScope::new();
    assert_eq!(PII_MAX_ENTRIES, 1000, "请求单表容量锁定");
    for i in 0..PII_MAX_ENTRIES {
        scope.register(&format!("hole-val-{i:04}")).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    scope.register("hole-val-overflow").unwrap();
    assert_eq!(scope.next_available_index(), 1, "淘汰最旧后空洞 1 须可复用");
    let reused = scope.register("hole-val-new").unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(1), "新值须跳回空洞 1");
}

#[test]
fn t7_rand8_unenumerable_shape_and_entropy() {
    let scope = PiiScope::new();
    let mut tokens = Vec::new();
    for i in 0..10 {
        let tok = scope.register(&format!("13800000{i:03}")).unwrap();
        assert!(pii_token_re().is_match(&tok), "{tok}");
        tokens.push(tok);
    }
    assert_eq!(
        tokens
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        10
    );
    let rand8s: Vec<&str> = tokens.iter().map(|t| rand8_of(t)).collect();
    assert!(rand8s.iter().all(|r| r.len() == 8));
    assert!(
        rand8s
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1
    );
    for _ in 0..10 {
        assert_eq!(gen_rand8().unwrap().len(), 8);
    }
}

#[test]
fn b6_rand8_batch_unique_and_holes_ordered() {
    // 批量生成无碰撞、无可预测序列；连续空洞按序复用。
    let scope = PiiScope::new();
    let mut tokens = Vec::new();
    for i in 0..100 {
        let tok = scope.register(&format!("b6-batch-{i:03}")).unwrap();
        assert!(pii_token_re().is_match(&tok), "{tok}");
        tokens.push(tok);
    }
    assert_eq!(
        tokens
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        100,
        "批量 token 不得碰撞"
    );
    let rand8s: Vec<&str> = tokens.iter().map(|t| rand8_of(t)).collect();
    assert!(
        rand8s
            .iter()
            .all(|r| r.len() == 8 && r.chars().all(|c| c.is_ascii_hexdigit()))
    );
    assert!(
        rand8s
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            >= 95,
        "rand8 须无可预测序列"
    );
    // 连续空洞复用顺序：填满后溢出 1 条（淘汰 seq 1，空洞 1），后续新值依次取 1/2/3，
    // 每取一洞淘汰下一最旧（稳态下标口径）。
    for i in 100..PII_MAX_ENTRIES {
        scope.register(&format!("b6-fill-{i:04}")).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    scope.register("b6-overflow-0").unwrap();
    assert_eq!(scope.next_available_index(), 1);
    for (i, expect) in [1usize, 2, 3].iter().enumerate() {
        let tok = scope.register(&format!("b6-reuse-{i}")).unwrap();
        assert_eq!(parse_pii_seq(&tok), Some(*expect), "{tok}");
    }
}

#[test]
fn b6_fuzzy_illegal_matrix_state_unchanged() {
    // fuzzy 非法形态矩阵均被拒绝还原（原样保留），vault 状态不变。
    let scope = PiiScope::new();
    let tok = scope.register("13812345678").unwrap();
    for bad in [
        "__PII__",
        "__PII_x_",
        "__PII_999_zzzz__",
        "__CRED_000001__",
        "not-a-token",
    ] {
        let out = scope.restore_with_fuzzy(&format!("回拨 {bad} 结束"), true);
        assert_eq!(out, format!("回拨 {bad} 结束"), "{bad}");
        assert!(!scope.contains_request_token(bad), "{bad}");
    }
    // 精确形态但未注册：非 fuzzy 下原样保留（fuzzy 下按序号回查为已知值，口径有意不同）。
    let unknown_exact = "__PII_1_ab12cd34__";
    assert_eq!(
        scope.restore_with_fuzzy(&format!("回拨 {unknown_exact}"), false),
        format!("回拨 {unknown_exact}")
    );
    // 非法输入不污染状态：已注册值仍精确还原。
    assert_eq!(scope.restore(&tok), "13812345678");
}

#[tokio::test]
async fn t7_100_way_join_set_no_conflict() {
    let scope = Arc::new(PiiScope::new());
    let mut set = tokio::task::JoinSet::new();
    for i in 0..100 {
        let s = scope.clone();
        set.spawn(async move { s.register(&format!("join-val-{i:03}")).unwrap() });
    }
    let mut toks = Vec::new();
    while let Some(r) = set.join_next().await {
        toks.push(r.expect("任务须成功"));
    }
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 100, "100 并发注册不得冲突");
    let mut seqs: Vec<usize> = toks.iter().filter_map(|t| parse_pii_seq(t)).collect();
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=100).collect::<Vec<_>>());
}

#[tokio::test]
async fn t7_concurrent_duplicate_reuse_single_token() {
    let scope = Arc::new(PiiScope::new());
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..100 {
        let s = scope.clone();
        set.spawn(async move { s.register("13812345678").unwrap() });
    }
    let mut toks = Vec::new();
    while let Some(r) = set.join_next().await {
        toks.push(r.expect("任务须成功"));
    }
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 1, "同值并发须复用同一 token");
    assert_eq!(scope.next_available_index(), 2);
}

// ---- 还原命中提升 LRU 与 fuzzy 宽松还原 ----

#[test]
fn restore_touch_lru() {
    // 还原命中提升 LRU，热值在容量压力下不被逐出，冷值先逐出。
    let scope = PiiScope::new();
    let hot = scope.register("hot-value-13812345678").unwrap();
    let cold = scope.register("cold-value-13900000000").unwrap();
    for i in 0..(PII_MAX_ENTRIES - 2) {
        scope.register(&format!("lru-fill-{i:04}")).unwrap();
    }
    for _ in 0..3 {
        assert!(scope.restore(&hot).contains("hot-value-13812345678"));
    }
    scope.register("lru-overflow-trigger").unwrap();
    assert!(
        scope.contains_request_token(&hot),
        "持续还原的热值不得被容量压力逐出"
    );
    assert!(!scope.contains_request_token(&cold), "冷值须先于热值被逐出");
}

#[test]
fn fuzzy_rewrite_restored() {
    // fuzzy 命中按序号回查还原为原值。
    let scope = PiiScope::new();
    let token = scope.register("13812345678").unwrap();
    let seq = parse_pii_seq(&token).unwrap();
    let rewritten = format!("__PII_{seq}_ZZZZZZZZ__");
    let restored = scope.restore_with_fuzzy(&format!("回拨 {rewritten}"), true);
    assert!(restored.contains("13812345678"), "{restored}");
}

#[test]
fn fuzzy_disabled_exact() {
    // 开关关闭时仅精确还原，改写形原样保留。
    let scope = PiiScope::new();
    let token = scope.register("13812345678").unwrap();
    let seq = parse_pii_seq(&token).unwrap();
    let rewritten = format!("__PII_{seq}_ZZZZZZZZ__");
    let out = scope.restore_with_fuzzy(&format!("回拨 {rewritten}"), false);
    assert_eq!(out, format!("回拨 {rewritten}"), "关闭态改写形须原样保留");
    assert_eq!(scope.restore(&token), "13812345678");
}

#[test]
fn alloc_seq_cursor() {
    // 游标分配——顺序递增、满表返回 MAX+1、淘汰释放序号回卷复用。
    let scope = PiiScope::new();
    let first = scope.register("cursor-first").unwrap();
    assert_eq!(parse_pii_seq(&first), Some(1));
    for i in 0..(PII_MAX_ENTRIES - 1) {
        scope.register(&format!("cursor-fill-{i:04}")).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    {
        let mut inner = lock_or_recover(scope.inner.lock());
        // 满表：直接分配返回 PII_MAX_ENTRIES + 1，探测步数线性有界（非全量重建）。
        assert_eq!(inner.alloc_seq(), PII_MAX_ENTRIES + 1);
        assert!(
            inner.scan_steps <= 3 * PII_MAX_ENTRIES + 4,
            "分配探测步数须线性有界，实际 {}",
            inner.scan_steps
        );
    }
    // 注册触发紧随淘汰并释放序号，随后分配回卷复用该空洞。
    scope.register("cursor-overflow").unwrap();
    let reused = scope.register("cursor-reused").unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(1), "淘汰释放的序号须被复用");
}

#[test]
fn fuzzy_unknown_seq_passthrough() {
    // 未知序号原样保留、不还原（无请求表序号映射）。
    let scope = PiiScope::new();
    scope.register("13812345678").unwrap();
    let unknown = "__PII_9999_ab12cd34__";
    let input = format!("回拨 {unknown} 结束");
    assert_eq!(scope.restore_with_fuzzy(&input, true), input);
}

#[test]
fn register_error_classification_token_shape_vs_entropy() {
    // token 形态拒绝与熵源故障必须分开，MUST NOT 共用同一错误分支。
    let scope = PiiScope::new();
    assert_eq!(
        scope.register("__PII_1_ab12cd34__"),
        Err(PiiRegisterError::TokenShape)
    );
    assert_eq!(
        scope.register("__CRED_42__"),
        Err(PiiRegisterError::TokenShape)
    );
    scope.force_entropy_failure(true);
    assert_eq!(
        scope.register("13812345678"),
        Err(PiiRegisterError::EntropyUnavailable)
    );
    // token 形态判定先于熵源：故障注入下仍归 TokenShape。
    assert_eq!(
        scope.register("__PII_1_ab12cd34__"),
        Err(PiiRegisterError::TokenShape)
    );
    scope.force_entropy_failure(false);
    assert!(scope.register("13812345678").is_ok());
}

#[test]
fn saturated_request_table_keeps_uniqueness_and_exact_restore() {
    // 请求表饱和后再注册第 N+1 个值，锁定真实可观测不变量——
    // ① 第 N+1 个值仍可用且可精确还原；② 表内不存在两条在用条目共享序号。
    // 诚实声明：本测试**不**主张「饱和哨兵从不出现」——满表时 `alloc_seq` 确会返回
    // `PII_MAX_ENTRIES + 1`（既有 `alloc_seq_cursor` 已锁定该行为），紧随的 LRU 淘汰
    // 释放一个空洞，故哨兵序号至多驻留于一条在用条目上。此处只锁定「唯一性」。
    let scope = PiiScope::new();

    // 阶段 1：请求表从 1 起分配。
    let req_alpha = scope.register("req-sat-alpha").unwrap();
    assert_eq!(parse_pii_seq(&req_alpha), Some(1));

    // 阶段 2：填满请求表（1..=PII_MAX_ENTRIES）。
    for i in 1..PII_MAX_ENTRIES {
        scope.register(&format!("req-sat-{i:04}")).unwrap();
    }
    assert_eq!(scope.table_sizes(), PII_MAX_ENTRIES, "请求表须恰满容量");

    // 阶段 3：第 N+1 个不同值走满表饱和/淘汰路径，仍须在用且可精确还原。
    let req_overflow = scope.register("req-sat-overflow").unwrap();
    assert_eq!(
        parse_pii_seq(&req_overflow),
        Some(PII_MAX_ENTRIES + 1),
        "满表分配返回饱和哨兵（既有行为，非缺陷；已由 alloc_seq_cursor 锁定）"
    );
    assert!(scope.contains_request_token(&req_overflow));
    assert_eq!(
        scope.restore(&format!("回 {req_overflow} 结束")),
        "回 req-sat-overflow 结束",
        "第 N+1 个值须可精确还原"
    );

    // 阶段 4：表内序号唯一 + 已用集与表内容一致（请求表饱和后仍成立）。
    // 淘汰使 req-sat-alpha（序号 1）离场；请求表在序号 2..=1000 与哨兵 1001 上各一条。
    let inner = lock_or_recover(scope.inner.lock());
    let req_seqs: Vec<usize> = inner
        .pii_t2p
        .keys()
        .filter_map(|t| parse_pii_seq(t))
        .collect();
    assert_eq!(req_seqs.len(), PII_MAX_ENTRIES);
    let uniq: HashSet<usize> = req_seqs.iter().copied().collect();
    assert_eq!(uniq.len(), req_seqs.len(), "请求表在用序号不得重复");
    assert_eq!(inner.req_used, uniq, "请求表已用集须与表内容一致");
    assert!(!inner.req_used.contains(&1), "序号 1 已被淘汰释放");
}

#[test]
fn register_tracked_reports_reuse_in_same_critical_section() {
    let scope = PiiScope::new();
    let (t1, reused1) = scope.register_tracked("13812345678").unwrap();
    assert!(!reused1, "首次注册须为新铸");
    let (t2, reused2) = scope.register_tracked("13812345678").unwrap();
    assert!(reused2, "同值二次注册须报复用");
    assert_eq!(t1, t2, "复用须返回同一 token");
    // 空值透传且按 non-reuse-miss 处理（不计新铸）。
    let (empty, reused_empty) = scope.register_tracked("").unwrap();
    assert!(empty.is_empty() && reused_empty);
    // 既有 `register` 包装语义不变。
    assert_eq!(
        scope.register("13812345678").unwrap(),
        t1,
        "register 包装须与 tracked 变体同 token"
    );
}
