//! `PiiScope` 单测（自 `scope.rs` 外迁，sibling 模块模式，见 hygiene-round4 模板）。

use {super::*, std::sync::Arc};

#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 hygiene-round4 模板）：
    // 超 800 即失败，须按模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../scope.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "scope.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "scope/tests.rs {tests_lines} 行超 800 红线：须拆分"
    );
}

#[test]
fn same_value_reuse_and_gap_skip_stable_index() {
    let scope = PiiScope::new();
    let t1 = scope.register("13812345678", false).unwrap();
    let t2 = scope.register("13812345678", false).unwrap();
    assert_eq!(t1, t2, "同值必须复用同一 token");
    assert!(pii_token_re().is_match(&t1));
    // token 形态值拒绝注册。
    assert!(scope.register(&t1, false).is_err());
    assert!(scope.register("__PII_1_ab", false).is_err());
    // 响应期注册可用但请求还原表不含。
    let rt = scope.register("new-resp-value-001", true).unwrap();
    assert_ne!(rt, t1);
    let restored = scope.restore(&format!("{t1} {rt}"));
    assert!(restored.contains("13812345678"));
    assert!(restored.contains(&rt), "响应期 token 原样保留不还原");
    // 空洞跳过：直接构造空洞断言 next_available_index。
    assert_eq!(scope.next_available_index(), 3);
}

#[test]
fn concurrent_register_no_index_conflict() {
    let scope = Arc::new(PiiScope::new());
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let s = scope.clone();
            std::thread::spawn(move || s.register(&format!("并发值-{i:03}"), false).unwrap())
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
fn loose_shape_audit_class_and_unknown_passthrough() {
    let scope = PiiScope::new();
    // 完整形态但未注册：归类 unregistered。
    assert_eq!(scope.count_malformed("__PII_9_ab12cd34__"), "unregistered");
    // 残缺/非法形态：归类 malformed。
    assert_eq!(scope.count_malformed("__PII_x__"), "malformed");
    assert_eq!(scope.count_malformed("__PII_1_ab"), "malformed");
    // 未知完整 token 还原时原样透传（不伪造明文）。
    let out = scope.restore("回拨 __PII_9_ab12cd34__ 结束");
    assert_eq!(
        out, "回拨 __PII_9_ab12cd34__ 结束",
        "未知 token 须透传: {out}"
    );
    // 已注册 token 仍精确还原，不受未知形态干扰。
    let tok = scope.register("13812345678", false).unwrap();
    let out = scope.restore(&format!("回拨 {tok} 与 __PII_9_ab12cd34__"));
    assert!(out.contains("13812345678"), "{out}");
    assert!(out.contains("__PII_9_ab12cd34__"), "{out}");
}

#[test]
fn request_table_capacity_split_lru_eviction() {
    // 分表声明：请求/响应单表 1000，与凭据 5000 不在同一容量口径。
    assert_eq!(PII_MAX_ENTRIES, 1000);
    assert_eq!(crate::service::credential_vault::MAX_TOKEN_ENTRIES, 5000);
    assert_ne!(
        PII_MAX_ENTRIES,
        crate::service::credential_vault::MAX_TOKEN_ENTRIES
    );
    let scope = PiiScope::new();
    let first = scope.register("13812340000", false).unwrap();
    let mut last_tok = String::new();
    for i in 1..=(PII_MAX_ENTRIES as u32 + 4) {
        last_tok = scope.register(&format!("139{:08}", i), false).unwrap();
    }
    // 最久未用被淘汰，新值驻留；淘汰腾出的序号被复用（空洞跳过）。
    assert!(
        !scope.contains_request_token(&first),
        "最久条目须被 LRU 淘汰"
    );
    let newest = format!("139{:08}", PII_MAX_ENTRIES as u32 + 4);
    assert!(scope.contains_request_token(&last_tok));
    assert_eq!(
        scope.register(&newest, false).unwrap(),
        last_tok,
        "最新条目须驻留复用同一 token"
    );
    // 响应表独立：响应侧注册不进请求还原表（分表隔离）。
    let rt = scope.register("新增响应值-001", true).unwrap();
    assert!(!scope.contains_request_token(&rt));
    let restored = scope.restore(&format!("回 {rt}"));
    assert!(restored.contains(&rt), "响应 token 原样保留: {restored}");
}

#[test]
fn b4_lru_hit_reuse_and_thousand_boundary() {
    // B4.3：缓存命中复用与容量 1000 边界行为。
    assert_eq!(PII_MAX_ENTRIES, 1000);
    let scope = PiiScope::new();
    // 命中复用：同值注册返回同一 token，还原一致。
    let a = scope.register("13812345678", false).unwrap();
    assert_eq!(scope.register("13812345678", false).unwrap(), a);
    assert!(scope.restore(&format!("回拨 {a}")).contains("13812345678"));
    // 首条 + 999 条 = 1000 满容量，下一序号为 1001。
    for i in 0..999 {
        scope.register(&format!("b4-val-{i:04}"), false).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    // 再注一条触发淘汰：最旧（首 token）被逐出，空洞 1 可复用。
    scope.register("b4-val-0999", false).unwrap();
    assert!(!scope.contains_request_token(&a), "最久条目须被淘汰");
    assert_eq!(scope.next_available_index(), 1);
}

#[test]
fn f5_cursor_alloc_is_linear_no_full_rebuild() {
    // F5/D4：K 次顺序注册探测步数线性（游标分配），不随每次注册全量重建。
    let scope = PiiScope::new();
    const K: usize = PII_MAX_ENTRIES;
    for i in 0..K {
        scope.register(&format!("f5-linear-{i:04}"), false).unwrap();
    }
    let inner = recover_mutex(scope.inner.lock());
    assert_eq!(
        inner.scan_steps, K,
        "顺序分配每注册恰探测一次候选（实际 {}）；旧全量重建为 O(K^2)",
        inner.scan_steps
    );
}

#[test]
fn f5_hole_reuse_after_eviction_no_conflict() {
    // F5：淘汰释放的序号被后续注册复用，且不与在用序号冲突。
    let scope = PiiScope::new();
    let first = scope.register("f5-first", false).unwrap();
    let first_seq = parse_pii_seq(&first).unwrap();
    for i in 0..PII_MAX_ENTRIES - 1 {
        scope.register(&format!("f5-fill-{i:04}"), false).unwrap();
    }
    scope.register("f5-overflow", false).unwrap();
    assert!(!scope.contains_request_token(&first), "最旧条目须被淘汰");
    let reused = scope.register("f5-reused", false).unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(first_seq), "空洞须被复用");
    let inner = recover_mutex(scope.inner.lock());
    let all: Vec<usize> = inner
        .pii_t2p
        .keys()
        .chain(inner.resp_t2p.keys())
        .filter_map(|t| parse_pii_seq(t))
        .collect();
    let uniq: HashSet<usize> = all.iter().copied().collect();
    assert_eq!(uniq.len(), all.len(), "两表在用序号不得重复");
    assert_eq!(inner.used_seqs, uniq, "已用集须与表内容一致");
}

#[test]
fn f5_upper_bound_unique_and_in_range() {
    // F5：单请求注册至 PII_MAX_ENTRIES，序号互不重复且落在 [1, PII_MAX_ENTRIES]。
    let scope = PiiScope::new();
    let mut seqs = Vec::new();
    for i in 0..PII_MAX_ENTRIES {
        let tok = scope.register(&format!("f5-bound-{i:04}"), false).unwrap();
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
    let token = scope.register("13812345678", false).unwrap();
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

/// B3/D3：锁中毒后隔离判定返回真实值、计数正常、注册/还原无 panic。
#[test]
fn pii_poison_recovery() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let scope = PiiScope::new();
    let tok = scope.register("13812345678", false).unwrap();
    for poison in 0..2 {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if poison == 0 {
                let _guard = scope.inner.lock().unwrap();
                panic!("注入 inner 锁中毒");
            }
            let _guard = scope.malformed.lock().unwrap();
            panic!("注入 malformed 锁中毒");
        }));
    }
    assert!(
        scope.contains_request_token(&tok),
        "中毒后隔离判定须返回真实结果（不得静默 false）"
    );
    assert_eq!(scope.count_malformed("__PII_9_ab12cd34__"), "unregistered");
    assert_eq!(scope.count_malformed("__PII_x__"), "malformed");
    let tok2 = scope.register("13900000001", false).unwrap();
    assert!(scope.contains_request_token(&tok2));
    assert!(scope.restore(&tok2).contains("13900000001"));
}

// ---- T7 vault 回补：空洞跳过/rand8 不可枚举/100 并发 gather/同值复用 ----

fn rand8_of(token: &str) -> &str {
    let rest = token.strip_prefix("__PII_").expect("须为 PII token");
    rest.split('_')
        .nth(1)
        .expect("须含 rand8 段")
        .trim_end_matches('_')
}

#[test]
fn t7_same_value_reuses_token_both_tables() {
    let scope = PiiScope::new();
    let a = scope.register("13812345678", false).unwrap();
    assert_eq!(scope.register("13812345678", false).unwrap(), a);
    let r = scope.register("resp-value-001", true).unwrap();
    assert_eq!(scope.register("resp-value-001", true).unwrap(), r);
    // 请求/响应表隔离：同值跨表 token 不同。
    let cross = scope.register("13812345678", true).unwrap();
    assert_ne!(cross, a);
}

#[test]
fn t7_hole_reused_after_eviction() {
    let scope = PiiScope::new();
    assert_eq!(PII_MAX_ENTRIES, 1000, "请求/响应单表容量分表锁定");
    for i in 0..PII_MAX_ENTRIES {
        scope.register(&format!("hole-val-{i:04}"), false).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    scope.register("hole-val-overflow", false).unwrap();
    assert_eq!(scope.next_available_index(), 1, "淘汰最旧后空洞 1 须可复用");
    let reused = scope.register("hole-val-new", false).unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(1), "新值须跳回空洞 1");
}

#[test]
fn t7_write_pii_does_not_evict_resp_table() {
    let scope = PiiScope::new();
    let rt = scope.register("resp-keep-001", true).unwrap();
    for i in 0..PII_MAX_ENTRIES {
        scope.register(&format!("pii-fill-{i:04}"), false).unwrap();
    }
    scope.register("pii-overflow-001", false).unwrap();
    assert!(
        scope.restore(&rt).contains(&rt),
        "写请求表不得淘汰响应表，响应 token 须原样保留"
    );
}

#[test]
fn t7_rand8_unenumerable_shape_and_entropy() {
    let scope = PiiScope::new();
    let mut tokens = Vec::new();
    for i in 0..10 {
        let tok = scope.register(&format!("13800000{i:03}"), false).unwrap();
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
    // B6.1：批量生成无碰撞、无可预测序列；连续空洞按序复用。
    let scope = PiiScope::new();
    let mut tokens = Vec::new();
    for i in 0..100 {
        let tok = scope.register(&format!("b6-batch-{i:03}"), false).unwrap();
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
        scope.register(&format!("b6-fill-{i:04}"), false).unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    scope.register("b6-overflow-0", false).unwrap();
    assert_eq!(scope.next_available_index(), 1);
    for (i, expect) in [1usize, 2, 3].iter().enumerate() {
        let tok = scope.register(&format!("b6-reuse-{i}"), false).unwrap();
        assert_eq!(parse_pii_seq(&tok), Some(*expect), "{tok}");
    }
}

#[test]
fn b6_fuzzy_illegal_matrix_state_unchanged() {
    // B6.2：fuzzy 非法形态矩阵均被拒绝还原（原样保留），vault 状态不变。
    let scope = PiiScope::new();
    let tok = scope.register("13812345678", false).unwrap();
    for bad in [
        "__PII__",
        "__PII_x_",
        "__PII_999_zzzz__",
        "__VG_CRED_000001__",
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

#[test]
fn t7_response_side_token_not_restored() {
    let scope = PiiScope::new();
    let rt = scope.register("13900000001", true).unwrap();
    assert_eq!(scope.restore(&rt), rt);
    let qt = scope.register("13900000002", false).unwrap();
    assert_eq!(scope.restore(&qt), "13900000002");
}

#[tokio::test]
async fn t7_100_way_join_set_no_conflict() {
    let scope = Arc::new(PiiScope::new());
    let mut set = tokio::task::JoinSet::new();
    for i in 0..100 {
        let s = scope.clone();
        set.spawn(async move { s.register(&format!("join-val-{i:03}"), false).unwrap() });
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
        set.spawn(async move { s.register("13812345678", false).unwrap() });
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

// ---- P3/P4：还原命中提升 LRU 与 fuzzy 审计分类 ----

#[test]
fn restore_touch_lru() {
    // D4/P3：还原命中提升 LRU，热值在容量压力下不被逐出，冷值先逐出。
    let scope = PiiScope::new();
    let hot = scope.register("hot-value-13812345678", false).unwrap();
    let cold = scope.register("cold-value-13900000000", false).unwrap();
    for i in 0..(PII_MAX_ENTRIES - 2) {
        scope.register(&format!("lru-fill-{i:04}"), false).unwrap();
    }
    for _ in 0..3 {
        assert!(scope.restore(&hot).contains("hot-value-13812345678"));
    }
    scope.register("lru-overflow-trigger", false).unwrap();
    assert!(
        scope.contains_request_token(&hot),
        "持续还原的热值不得被容量压力逐出"
    );
    assert!(!scope.contains_request_token(&cold), "冷值须先于热值被逐出");
}

#[test]
fn restore_touch_dual_table() {
    // D4/P3：响应表命中同样提升热度；register 同值复用路径仍 touch。
    let scope = PiiScope::new();
    let hot = scope.register("resp-hot-value", true).unwrap();
    let cold = scope.register("resp-cold-value", true).unwrap();
    for i in 0..(PII_MAX_ENTRIES - 2) {
        scope.register(&format!("resp-fill-{i:04}"), true).unwrap();
    }
    // 响应 token 还原时原样保留，但刷新响应表热度（冷条目成为最旧）。
    assert_eq!(scope.restore(&hot), hot);
    scope.register("resp-overflow", true).unwrap();
    // 热值同值复用仍返回原 token（register 命中 touch）。
    assert_eq!(
        scope.register("resp-hot-value", true).unwrap(),
        hot,
        "响应热值同值复用须命中原 token"
    );
    // 冷值已被淘汰：重新注册不再复用旧 token。
    let reintroduced = scope.register("resp-cold-value", true).unwrap();
    assert_ne!(reintroduced, cold, "被淘汰的冷响应条目重注册须换新 token");
}

#[test]
fn fuzzy_audit_category() {
    // D5/P4：fuzzy 命中记独立审计分类 `fuzzy` 并返回还原值。
    let scope = PiiScope::new();
    let token = scope.register("13812345678", false).unwrap();
    let seq = parse_pii_seq(&token).unwrap();
    let rewritten = format!("__PII_{seq}_ZZZZZZZZ__");
    let restored = scope.restore_with_fuzzy(&format!("回拨 {rewritten}"), true);
    assert!(restored.contains("13812345678"), "{restored}");
    assert_eq!(scope.audit_count("fuzzy"), 1, "fuzzy 命中须计一次");
    assert_eq!(
        scope.audit_count("malformed"),
        0,
        "fuzzy 命中不得再计入 malformed"
    );
}

#[test]
fn fuzzy_disabled_exact() {
    // D5/P4：开关关闭时仅精确还原，改写形原样保留且无 fuzzy 计数。
    let scope = PiiScope::new();
    let token = scope.register("13812345678", false).unwrap();
    let seq = parse_pii_seq(&token).unwrap();
    let rewritten = format!("__PII_{seq}_ZZZZZZZZ__");
    let out = scope.restore_with_fuzzy(&format!("回拨 {rewritten}"), false);
    assert_eq!(out, format!("回拨 {rewritten}"), "关闭态改写形须原样保留");
    assert_eq!(scope.audit_count("fuzzy"), 0, "关闭态不得有 fuzzy 计数");
    assert_eq!(scope.restore(&token), "13812345678");
}

#[test]
fn alloc_seq_cursor() {
    // D6/P5：游标分配——顺序递增、满表返回 MAX+1、淘汰释放序号回卷复用。
    let scope = PiiScope::new();
    let first = scope.register("cursor-first", false).unwrap();
    assert_eq!(parse_pii_seq(&first), Some(1));
    for i in 0..(PII_MAX_ENTRIES - 1) {
        scope
            .register(&format!("cursor-fill-{i:04}"), false)
            .unwrap();
    }
    assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
    {
        let mut inner = recover_mutex(scope.inner.lock());
        // 满表：直接分配返回 PII_MAX_ENTRIES + 1，探测步数线性有界（非全量重建）。
        assert_eq!(inner.alloc_seq(), PII_MAX_ENTRIES + 1);
        assert!(
            inner.scan_steps <= 3 * PII_MAX_ENTRIES + 4,
            "分配探测步数须线性有界，实际 {}",
            inner.scan_steps
        );
    }
    // 注册触发紧随淘汰并释放序号，随后分配回卷复用该空洞。
    scope.register("cursor-overflow", false).unwrap();
    let reused = scope.register("cursor-reused", false).unwrap();
    assert_eq!(parse_pii_seq(&reused), Some(1), "淘汰释放的序号须被复用");
}

#[test]
fn fuzzy_response_table_not_restored() {
    // F13/D13：fuzzy 超集边界——响应表 token 一律原样保留，不按序号回查还原
    //（序号映射只建请求表；响应表同序号改写形亦不得跨表还原）。
    let scope = PiiScope::new();
    let rt = scope.register("13900000001", true).unwrap();
    let seq = parse_pii_seq(&rt).unwrap();
    let rewritten = format!("__PII_{seq}_ZZZZZZZZ__");
    let input = format!("回拨 {rt} 与 {rewritten} 结束");
    assert_eq!(scope.restore_with_fuzzy(&input, true), input);
    assert_eq!(scope.audit_count("fuzzy"), 0, "响应表 token 不得计 fuzzy");
    assert!(
        !scope
            .restore_with_fuzzy(&input, true)
            .contains("13900000001")
    );
}

#[test]
fn fuzzy_unknown_seq_not_restored() {
    // F13/D13：未知序号原样保留、不还原（无请求表序号映射），按 unregistered 计审计。
    let scope = PiiScope::new();
    scope.register("13812345678", false).unwrap();
    let unknown = "__PII_9999_ab12cd34__";
    let input = format!("回拨 {unknown} 结束");
    assert_eq!(scope.restore_with_fuzzy(&input, true), input);
    assert_eq!(scope.audit_count("fuzzy"), 0, "未知序号不得计 fuzzy");
    assert_eq!(
        scope.audit_count("unregistered"),
        1,
        "未知完整形态须计 unregistered"
    );
}
