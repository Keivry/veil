mod fallback_count;

use super::*;

#[test]
fn token_shape_zero_padded_six_digits() {
    assert_eq!(make_cred_token(1), "__CRED_000001__");
    assert_eq!(make_cred_token(42), "__CRED_000042__");
}

#[test]
fn partial_prefix_stripped_without_leak() {
    for partial in [
        "__C",
        "__CR",
        "__CRE",
        "__CRED",
        "__CRED_",
        "__CRED_000",
        "__CRED_000001",
        "尾部残缺 __CRED_12 ",
    ] {
        let cleaned = strip_cred_partials(partial);
        assert!(
            !cleaned.contains("__C"),
            "残缺必须清理: {partial:?} -> {cleaned:?}"
        );
    }
    // 完整凭据形态由负向前瞻豁免，原样保留（不再被残缺清理剥离）。
    assert_eq!(strip_cred_partials("__CRED_000001__"), "__CRED_000001__");
}

#[test]
fn hallucinated_token_passthrough_while_real_restored() {
    let vault = CredentialVault::new();
    let tok = vault.register("s3cr3t-value").unwrap();
    let text = format!("real={tok} fake=__CRED_999999__");
    let restored = vault.restore(&text);
    assert!(restored.contains("s3cr3t-value"));
    assert!(
        restored.contains("__CRED_999999__"),
        "未注册完整 token 原样透传: {restored}"
    );
    let cleaned = strip_cred_partials(&restored);
    assert!(
        cleaned.contains("__CRED_999999__"),
        "完整未注册 token 免于残缺剥离: {cleaned}"
    );
    assert!(cleaned.contains("s3cr3t-value"));
}

#[test]
fn complete_token_closing_not_mistaken_for_partial() {
    // 完整 token 的闭合 `__` + 后随字面 `C`/标点不得被判为残缺（跨族负向后顾）。
    for kept in [
        "__PII_1_ab12cd34__C",
        "__CRED_000001__C",
        "__CRED_000123__C.",
        // 2 下划线：第二段 `CRED_000` 无 `__` 前缀，非残缺形态，整体保留。
        "__CRED_000123__CRED_000",
    ] {
        assert_eq!(strip_cred_partials(kept), kept, "须原样保留: {kept}");
    }
    // 真残缺紧跟完整 token（4 下划线）仍剥，且不腐蚀前完整 token。
    assert_eq!(
        strip_cred_partials("__CRED_000123____CRED_000"),
        "__CRED_000123__"
    );
    // 精度锚：hex 结尾正文后的真残缺仍剥（未退化为 hex 后顾）。
    assert_eq!(strip_cred_partials("deadbeef__CRED_00"), "deadbeef");
}

#[test]
fn longest_first_ordering_prevents_substring_collision() {
    let vault = CredentialVault::new();
    vault.register("abcd-1234-long").unwrap();
    vault.register("abcd").unwrap();
    let out = redact_with_map("值 abcd-1234-long 结束", &vault.snapshot_p2t());
    assert!(!out.contains("abcd-1234-long"));
    assert!(out.contains("__CRED_"));
}

#[test]
fn short_values_and_token_shapes_rejected() {
    let vault = CredentialVault::new();
    assert_eq!(vault.register("abc").unwrap(), "abc");
    assert!(vault.register("__CRED_000001__").is_err());
    assert!(vault.register("__CRED_xxx").is_err());
}

#[test]
fn same_secret_maps_to_same_token_across_requests() {
    let vault = CredentialVault::new();
    let first = vault.register("跨请求秘密-xyz789").unwrap();
    let second = vault.register("跨请求秘密-xyz789").unwrap();
    assert_eq!(first, second);
    assert!(first.starts_with("__CRED_"));
    assert_eq!(vault.len(), 1);
}

#[test]
fn restore_one_matches_full_restore_per_token() {
    let vault = CredentialVault::new();
    let tok_a = vault.register("alpha-secret-001").unwrap();
    let tok_b = vault.register("beta-secret-002").unwrap();
    assert_eq!(
        vault.restore_one(&tok_a).as_deref(),
        Some("alpha-secret-001")
    );
    assert_eq!(
        vault.restore_one(&tok_b).as_deref(),
        Some("beta-secret-002")
    );
    // 与全量 restore 的同 token 子串一致。
    let full = vault.restore(&format!("a={tok_a} b={tok_b}"));
    assert_eq!(full, "a=alpha-secret-001 b=beta-secret-002");
    // 未注册/非 token 直查返回 None（不克隆全表、不猜测）。
    assert_eq!(vault.restore_one("__CRED_999999__"), None);
    assert_eq!(vault.restore_one("plain-text"), None);
}

#[test]
fn snapshot_maps_and_redact_with_map_reflect_registrations() {
    // 只读快照语义改走生产等价路径（`snapshot_p2t`/`snapshot_t2p` +
    // `redact_with_map`/`restore`）；旧 `VaultSnapshot` 类型（生产零引用）已删。
    let vault = CredentialVault::new();
    let token = vault.register("快照秘密-abc456").unwrap();
    let p2t = vault.snapshot_p2t();
    assert_eq!(p2t.len(), 1);
    let out = redact_with_map("正文含 快照秘密-abc456 结尾", &p2t);
    assert_eq!(out, format!("正文含 {token} 结尾"));
    assert_eq!(vault.restore(&out), "正文含 快照秘密-abc456 结尾");
    assert_eq!(vault.len(), 1);
    let fresh = vault.register("另一秘密-def000").unwrap();
    let p2t2 = vault.snapshot_p2t();
    assert_eq!(p2t2.len(), 2);
    assert!(redact_with_map("另一秘密-def000", &p2t2).contains(&fresh));
}

#[test]
fn bounded_global_map_evicts_oldest_via_lru() {
    let vault = CredentialVault::new();
    assert_eq!(MAX_TOKEN_ENTRIES, 5000, "凭据表容量分表锁定");
    for i in 0..MAX_TOKEN_ENTRIES + 5 {
        vault.register(&format!("secret-value-{i:06}")).unwrap();
    }
    assert_eq!(vault.len(), MAX_TOKEN_ENTRIES);
    // 最早注册的已被淘汰。
    assert!(!vault.snapshot_p2t().contains_key("secret-value-000000"));
}

#[test]
fn lru_hot_entry_retained_cold_evicted_first() {
    let vault = CredentialVault::new();
    for i in 0..MAX_TOKEN_ENTRIES {
        vault.register(&format!("secret-value-{i:06}")).unwrap();
    }
    // 触达最早条目提升为热点（复用提升 LRU），再溢出一条。
    vault.register("secret-value-000000").unwrap();
    vault.register("secret-overflow-000001").unwrap();
    let snap = vault.snapshot_p2t();
    assert_eq!(vault.len(), MAX_TOKEN_ENTRIES);
    assert!(
        snap.contains_key("secret-value-000000"),
        "热点须驻留而非按 FIFO 逐出"
    );
    assert!(
        !snap.contains_key("secret-value-000001"),
        "从未触达的次冷条目须先逐出"
    );
}

/// 并发回补：100 路注册隔离 + 同值复用（tokio JoinSet）。
#[tokio::test]
async fn t12_100_way_register_isolation_no_conflict() {
    use std::sync::Arc;
    let vault = Arc::new(CredentialVault::new());
    let mut set = tokio::task::JoinSet::new();
    for i in 0..100 {
        let v = vault.clone();
        set.spawn(async move { v.register(&format!("join-secret-{i:03}")).unwrap() });
    }
    let mut toks = Vec::new();
    while let Some(r) = set.join_next().await {
        toks.push(r.expect("任务须成功"));
    }
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 100, "100 并发注册不得冲突");
    assert_eq!(vault.len(), 100);
}

#[tokio::test]
async fn t12_concurrent_duplicate_reuse_single_token() {
    use std::sync::Arc;
    let vault = Arc::new(CredentialVault::new());
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..100 {
        let v = vault.clone();
        set.spawn(async move { v.register("shared-secret-xyz").unwrap() });
    }
    let mut toks = Vec::new();
    while let Some(r) = set.join_next().await {
        toks.push(r.expect("任务须成功"));
    }
    toks.sort();
    toks.dedup();
    assert_eq!(toks.len(), 1, "同值并发须复用同一 token");
    assert_eq!(vault.len(), 1);
}

/// 帧路径零全量快照、还原路径不重建 p2t 快照（不随帧数增长）。
#[tokio::test]
async fn stream_frame_no_full_snapshot() {
    use crate::service::redaction::Scope;
    let vault = CredentialVault::new();
    vault.register("frame-secret-001").unwrap();
    let scope = Scope::new();
    let frame = r#"{"a":"frame-secret-001","b":"8.8.8.8"}"#;
    let t2p_before = vault.snapshot_calls();
    let p2t_before = vault.p2t_build_calls();
    for _ in 0..20 {
        let _ = scope.restore_response_with_spans_json(&vault, frame);
    }
    assert_eq!(
        vault.snapshot_calls() - t2p_before,
        0,
        "逐帧不得全量快照 t2p"
    );
    assert_eq!(
        vault.p2t_build_calls() - p2t_before,
        0,
        "还原路径不得重建 p2t 快照（不随帧数增长）"
    );
}

/// 帧间注册新凭据后缓存失效，后续帧可还原新 token。
#[tokio::test]
async fn restore_after_register() {
    use crate::service::{pii::PiiDetector, redaction::Scope};
    let vault = CredentialVault::new();
    let scope = Scope::new();
    let first = vault.register("first-secret-001").unwrap();
    assert!(vault.p2t_snapshot().contains_key("first-secret-001"));
    let builds_before = vault.p2t_build_calls();
    let fresh = vault.register("fresh-secret-002").unwrap();
    // 两 token 均须经本请求脱敏实际产出方可还原。
    let _ = scope
        .redact_request(&vault, &PiiDetector::new(), "fresh-secret-002")
        .await;
    let (restored, _) = scope.restore_response_with_spans(&vault, &format!("值 {fresh} 结束"));
    assert_eq!(restored, "值 fresh-secret-002 结束");
    assert!(
        vault.p2t_snapshot().contains_key("fresh-secret-002"),
        "缓存失效重建后须含新凭据"
    );
    assert!(vault.p2t_build_calls() > builds_before, "注册后缓存须重建");
    let _ = scope
        .redact_request(&vault, &PiiDetector::new(), "first-secret-001")
        .await;
    let (restored_old, _) = scope.restore_response_with_spans(&vault, &format!("值 {first} 结束"));
    assert_eq!(restored_old, "值 first-secret-001 结束");
}

/// 并发注册 + 还原无死锁/无 panic，结果与串行语义一致。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restore_concurrent_register() {
    use {
        crate::service::{pii::PiiDetector, redaction::Scope},
        std::sync::Arc,
    };
    let vault = Arc::new(CredentialVault::new());
    let mut set = tokio::task::JoinSet::new();
    for i in 0..8 {
        let v = vault.clone();
        set.spawn(async move {
            let secret = format!("concurrent-secret-{i:03}");
            let token = v.register(&secret).unwrap();
            let scope = Scope::new();
            // 请求侧脱敏铸造 token。
            let _ = scope.redact_request(&v, &PiiDetector::new(), &secret).await;
            let (restored, _) = scope.restore_response_with_spans(&v, &format!("v {token}"));
            assert_eq!(restored, format!("v {secret}"));
        });
    }
    while let Some(r) = set.join_next().await {
        r.expect("并发任务不得 panic");
    }
    let snap = vault.p2t_snapshot();
    let all: String = (0..8)
        .map(|i| format!("concurrent-secret-{i:03} "))
        .collect();
    let masked = snap.redact(&all);
    for i in 0..8 {
        assert!(
            !masked.contains(&format!("concurrent-secret-{i:03}")),
            "注册值须可被收敛后的快照脱敏: {masked}"
        );
    }
}

/// 锁中毒后 register/restore 恢复可用、无 panic。
#[test]
fn vault_poison_recovery() {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let vault = CredentialVault::new();
    let tok = vault.register("poison-secret-001").unwrap();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = vault.inner.write().unwrap();
        panic!("注入锁中毒");
    }));
    assert_eq!(
        vault.restore_one(&tok).as_deref(),
        Some("poison-secret-001")
    );
    assert_eq!(vault.restore(&format!("v {tok}")), "v poison-secret-001");
    assert_eq!(
        strip_cred_partials("x __CRED_999999__ y"),
        "x __CRED_999999__ y"
    );
    let tok2 = vault.register("poison-secret-002").unwrap();
    assert_eq!(
        vault.restore_one(&tok2).as_deref(),
        Some("poison-secret-002")
    );
    assert_eq!(vault.len(), 2);
    assert!(!vault.p2t_snapshot().is_empty());
}

/// 正则规模上限复核——`MAX_TOKEN_ENTRIES` 映射编译成功或回退，
/// 输出与 alternation 路径逐字节一致且无 panic。
#[test]
fn regex_size_ceiling_max_entries() {
    let map: HashMap<String, String> = (0..MAX_TOKEN_ENTRIES)
        .map(|i| {
            (
                format!("ceiling-secret-{i:06}"),
                make_cred_token(i as u64 + 1),
            )
        })
        .collect();
    let text = "前缀 ceiling-secret-000000 中 ceiling-secret-004999 后缀";
    let out = replace_all_by_map(text, &map);
    assert!(!out.contains("ceiling-secret-000000"), "{out}");
    assert!(!out.contains("ceiling-secret-004999"), "{out}");
    assert!(out.contains("__CRED_000001__"), "{out}");
    assert!(out.contains("__CRED_005000__"), "{out}");
    // `usize::MAX` 强制编译 alternation，作为与回退分支独立的 oracle。
    let fast = replace_all_by_map_limited(text, &map, usize::MAX);
    assert_eq!(out, fast, "上限规模输出须与 alternation 路径逐字节一致");
}

/// 每帧快照计数与表规模解耦（大表与空表均为 0 增量）。
#[tokio::test]
async fn stream_restore_complexity() {
    use crate::service::{pii::PiiDetector, redaction::Scope};
    let vault = CredentialVault::new();
    for i in 0..MAX_TOKEN_ENTRIES - 1 {
        vault
            .register(&format!("complexity-secret-{i:06}"))
            .unwrap();
    }
    let token = vault.register("big-table-target-secret").unwrap();
    assert_eq!(vault.len(), MAX_TOKEN_ENTRIES, "须构造上限规模表");
    let scope = Scope::new();
    // 请求侧脱敏铸造 token（基线快照计数之前）。
    let _ = scope
        .redact_request(&vault, &PiiDetector::new(), "big-table-target-secret")
        .await;
    let frame = format!("{{\"k\":\"{token}\"}}");
    let before = vault.snapshot_calls();
    for _ in 0..20 {
        let (restored, _) = scope.restore_response_with_spans(&vault, &frame);
        assert!(restored.contains("big-table-target-secret"), "{restored}");
    }
    let big_table_delta = vault.snapshot_calls() - before;
    let empty = CredentialVault::new();
    let empty_scope = Scope::new();
    let before_empty = empty.snapshot_calls();
    for _ in 0..20 {
        let _ = empty_scope.restore_response_with_spans(&empty, &frame);
    }
    assert_eq!(big_table_delta, 0, "大表逐帧快照计数须为 0 增量");
    assert_eq!(
        empty.snapshot_calls() - before_empty,
        0,
        "空表逐帧快照计数须为 0 增量"
    );
}
