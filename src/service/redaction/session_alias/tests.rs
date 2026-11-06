//! 会话别名表测试（sibling，`redaction/session_alias.rs`）。
//!
//! 覆盖 tasks 3.1 Verify：first-writer-wins、多对一、逐出、跨租户不可解析、`clear`
//! 条数、并发原子绑定、`Debug` 脱敏、容量 1024 / 每响应 2 条行为。

use {
    super::*,
    crate::service::{llm_gateway::GatewayMetrics, redaction::conversation_key::scoped_key},
    std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    },
};

const SECRET: &[u8] = b"alias-test-secret";
const TENANT: &str = "tenant-fp";

fn key(name: &str) -> ConversationKey { scoped_key(SECRET, TENANT, name) }

#[test]
fn first_writer_wins_and_conflict_counted() {
    let metrics = Arc::new(GatewayMetrics::default());
    let map = SessionAliasMap::new(8).with_metrics(metrics.clone());
    let k1 = key("K1");
    let k2 = key("K2");

    assert_eq!(map.bind(SECRET, TENANT, "resp_1", &k1), BindOutcome::Bound);
    assert_eq!(
        map.bind(SECRET, TENANT, "resp_1", &k1),
        BindOutcome::AlreadyBound,
        "同 canonical 幂等"
    );
    assert_eq!(metrics.session_alias_conflict_count(), 0, "幂等不计数冲突");
    assert_eq!(
        map.bind(SECRET, TENANT, "resp_1", &k2),
        BindOutcome::Conflict
    );
    assert_eq!(metrics.session_alias_conflict_count(), 1);
    assert_eq!(
        map.resolve(SECRET, TENANT, "resp_1"),
        Some(k1),
        "既有绑定必须保留"
    );
    assert_eq!(map.len(), 1);
}

#[test]
fn many_to_one_aliases_share_canonical() {
    let map = SessionAliasMap::new(8);
    let k1 = key("K1");
    assert_eq!(map.bind(SECRET, TENANT, "resp_1", &k1), BindOutcome::Bound);
    assert_eq!(map.bind(SECRET, TENANT, "conv_1", &k1), BindOutcome::Bound);
    assert_eq!(map.len(), 2);
    assert_eq!(map.resolve(SECRET, TENANT, "resp_1"), Some(k1.clone()));
    assert_eq!(map.resolve(SECRET, TENANT, "conv_1"), Some(k1));
}

#[test]
fn capacity_eviction_drops_oldest_and_counts() {
    let metrics = Arc::new(GatewayMetrics::default());
    let map = SessionAliasMap::new(2).with_metrics(metrics.clone());
    let k = key("K1");
    map.bind(SECRET, TENANT, "a", &k);
    map.bind(SECRET, TENANT, "b", &k);
    assert_eq!(metrics.session_alias_evict_count(), 0, "未满不逐出");
    map.bind(SECRET, TENANT, "c", &k);
    assert_eq!(map.len(), 2, "容量有界");
    assert_eq!(metrics.session_alias_evict_count(), 1);
    assert_eq!(map.resolve(SECRET, TENANT, "a"), None, "最旧须被逐出");
    assert!(map.resolve(SECRET, TENANT, "c").is_some());
}

#[test]
fn resolve_hit_counts_and_miss_does_not() {
    let metrics = Arc::new(GatewayMetrics::default());
    let map = SessionAliasMap::new(8).with_metrics(metrics.clone());
    map.bind(SECRET, TENANT, "resp_1", &key("K1"));
    assert!(map.resolve(SECRET, TENANT, "resp_1").is_some());
    assert!(map.resolve(SECRET, TENANT, "resp_1").is_some());
    assert_eq!(metrics.session_alias_hit_count(), 2);
    assert!(map.resolve(SECRET, TENANT, "unknown").is_none());
    assert_eq!(metrics.session_alias_hit_count(), 2, "未命不计");
}

#[test]
fn empty_upstream_id_is_noop() {
    let metrics = Arc::new(GatewayMetrics::default());
    let map = SessionAliasMap::new(1).with_metrics(metrics.clone());
    // 容量 1：先占一条，再用空 id 绑定不得触发逐出。
    map.bind(SECRET, TENANT, "a", &key("K1"));
    assert_eq!(
        map.bind(SECRET, TENANT, "", &key("K2")),
        BindOutcome::Skipped
    );
    assert_eq!(map.len(), 1);
    assert_eq!(metrics.session_alias_evict_count(), 0, "空 id 不得逐出");
    assert_eq!(map.resolve(SECRET, TENANT, ""), None);
    assert_eq!(metrics.session_alias_hit_count(), 0);
}

#[test]
fn cross_tenant_does_not_resolve() {
    let map = SessionAliasMap::new(8);
    let k = key("K1");
    map.bind(SECRET, "tenant-a", "resp_1", &k);
    assert!(
        map.resolve(SECRET, "tenant-b", "resp_1").is_none(),
        "跨租户 MUST NOT 解析"
    );
    assert!(map.resolve(SECRET, "tenant-a", "resp_1").is_some());
    // 不同密钥同样分域。
    assert!(map.resolve(b"other-secret", "tenant-a", "resp_1").is_none());
}

#[test]
fn clear_returns_entry_count_and_empties() {
    let map = SessionAliasMap::new(8);
    let k = key("K1");
    map.bind(SECRET, TENANT, "a", &k);
    map.bind(SECRET, TENANT, "b", &k);
    assert_eq!(map.clear(), 2);
    assert_eq!(map.len(), 0);
    assert!(map.is_empty());
    assert_eq!(map.clear(), 0, "重复清空返回 0");
}

#[test]
fn concurrent_binds_produce_no_dirty_binding() {
    // 100 轮并发：同一 alias 名以两个不同 canonical 竞争，最终必须恰为其中之一，
    // 且与 resolve 一致（无「半写入/既非 A 又非 B」的脏绑定）。
    const ROUNDS: usize = 100;
    let map = Arc::new(SessionAliasMap::new(8));
    let ka = key("KA");
    let kb = key("KB");
    let conflict = Arc::new(AtomicUsize::new(0));

    for round in 0..ROUNDS {
        let upstream = format!("resp_{round}");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [ka.clone(), kb.clone()]
            .into_iter()
            .map(|canonical| {
                let map = map.clone();
                let barrier = barrier.clone();
                let upstream = upstream.clone();
                let conflict = conflict.clone();
                thread::spawn(move || {
                    barrier.wait();
                    if map.bind(SECRET, TENANT, &upstream, &canonical) == BindOutcome::Conflict {
                        conflict.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("并发绑定线程不得 panic");
        }
        let resolved = map
            .resolve(SECRET, TENANT, &upstream)
            .unwrap_or_else(|| panic!("第 {round} 轮须有绑定结果"));
        assert!(resolved == ka || resolved == kb, "第 {round} 轮出现脏绑定");
    }
    assert_eq!(conflict.load(Ordering::Relaxed), ROUNDS, "每轮须恰一次冲突");
}

#[test]
fn debug_hides_ids_and_canonicals() {
    let map = SessionAliasMap::new(4);
    let k = key("canonical-secret");
    map.bind(SECRET, TENANT, "upstream-secret-id", &k);
    let debug = format!("{map:?}");
    assert!(!debug.contains("upstream-secret-id"), "{debug}");
    assert!(!debug.contains("canonical-secret"), "{debug}");
    assert!(!debug.contains(k.as_str()), "{debug}");
    assert!(debug.contains("entries"));
}

#[test]
fn default_capacity_1024_holds_two_entries_per_response() {
    // 1024 条目容量 → 至多 512 个响应会话（每响应写 response.id + conversation.id）。
    let map = SessionAliasMap::new(1024);
    let k = key("K1");
    for i in 0..512 {
        assert_eq!(
            map.bind(SECRET, TENANT, &format!("resp_{i}"), &k),
            BindOutcome::Bound
        );
        assert_eq!(
            map.bind(SECRET, TENANT, &format!("conv_{i}"), &k),
            BindOutcome::Bound
        );
    }
    assert_eq!(map.len(), 1024);
    // 再加一对：逐出最旧两条，容量恒 1024。
    map.bind(SECRET, TENANT, "resp_new", &k);
    map.bind(SECRET, TENANT, "conv_new", &k);
    assert_eq!(map.len(), 1024, "条目容量恒为 1024");
    assert!(
        map.resolve(SECRET, TENANT, "resp_0").is_none(),
        "最旧被逐出"
    );
    assert!(map.resolve(SECRET, TENANT, "resp_new").is_some());
}

/// tasks 6.3：同一会话（同一 upstream id、同一 canonical）100 轮并发绑定必须收敛
/// 到唯一 canonical，且 `session_alias_conflict` 恒为 0（幂等不计数）。
#[test]
fn same_session_concurrent_binds_converge_without_conflict() {
    const ROUNDS: usize = 100;
    const WORKERS: usize = 8;
    let metrics = Arc::new(GatewayMetrics::default());
    let map = Arc::new(SessionAliasMap::new(8).with_metrics(metrics.clone()));
    let k1 = key("K1");

    for round in 0..ROUNDS {
        let upstream = format!("resp_same_{round}");
        let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
        let handles: Vec<_> = (0..WORKERS)
            .map(|_| {
                let map = map.clone();
                let barrier = barrier.clone();
                let upstream = upstream.clone();
                let k1 = k1.clone();
                thread::spawn(move || {
                    barrier.wait();
                    map.bind(SECRET, TENANT, &upstream, &k1)
                })
            })
            .collect();
        let outcomes: Vec<BindOutcome> = handles
            .into_iter()
            .map(|h| h.join().expect("并发绑定线程不得 panic"))
            .collect();
        assert!(
            outcomes
                .iter()
                .all(|o| matches!(o, BindOutcome::Bound | BindOutcome::AlreadyBound)),
            "第 {round} 轮须全部成功或幂等: {outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == BindOutcome::Bound)
                .count(),
            1,
            "第 {round} 轮须恰一次首次绑定"
        );
        assert_eq!(
            map.resolve(SECRET, TENANT, &upstream),
            Some(k1.clone()),
            "第 {round} 轮须收敛到唯一 canonical"
        );
    }
    assert_eq!(metrics.session_alias_conflict_count(), 0, "不得出现冲突");
    assert_eq!(map.len(), 8, "容量 8 时条目数恒为上限");
}

/// tasks 6.3：并发首轮冲突的**计数与绑定结果一致**——每轮恰一次 `Conflict`，
/// 解析结果恒为既有绑定，`session_alias_conflict` 恰等于冲突次数。
#[test]
fn concurrent_first_writer_conflicts_match_metrics_exactly() {
    const ROUNDS: usize = 100;
    let metrics = Arc::new(GatewayMetrics::default());
    let map = Arc::new(SessionAliasMap::new(8).with_metrics(metrics.clone()));
    let ka = key("KA");
    let kb = key("KB");

    let mut conflicts = 0usize;
    for round in 0..ROUNDS {
        let upstream = format!("resp_first_{round}");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [ka.clone(), kb.clone()]
            .into_iter()
            .map(|canonical| {
                let map = map.clone();
                let barrier = barrier.clone();
                let upstream = upstream.clone();
                thread::spawn(move || {
                    barrier.wait();
                    map.bind(SECRET, TENANT, &upstream, &canonical)
                })
            })
            .collect();
        let outcomes: Vec<BindOutcome> = handles
            .into_iter()
            .map(|h| h.join().expect("并发绑定线程不得 panic"))
            .collect();
        let round_conflicts = outcomes
            .iter()
            .filter(|o| **o == BindOutcome::Conflict)
            .count();
        assert_eq!(
            round_conflicts, 1,
            "第 {round} 轮须恰一次冲突: {outcomes:?}"
        );
        conflicts += round_conflicts;
        let resolved = map
            .resolve(SECRET, TENANT, &upstream)
            .unwrap_or_else(|| panic!("第 {round} 轮须有绑定"));
        assert!(resolved == ka || resolved == kb, "第 {round} 轮出现脏绑定");
    }
    assert_eq!(
        metrics.session_alias_conflict_count() as usize,
        conflicts,
        "冲突计数须与绑定结果一致"
    );
    assert_eq!(conflicts, ROUNDS);
}

/// tasks 6.3：逐出后解析未命中（回退到下一身份来源），且逐出计数与条目数有界。
#[test]
fn eviction_then_resolve_misses_and_counts_are_bounded() {
    let metrics = Arc::new(GatewayMetrics::default());
    let map = SessionAliasMap::new(2).with_metrics(metrics.clone());
    let k = key("K-evict");
    map.bind(SECRET, TENANT, "a", &k);
    map.bind(SECRET, TENANT, "b", &k);
    assert_eq!(map.resolve(SECRET, TENANT, "a"), Some(k.clone()));
    map.bind(SECRET, TENANT, "c", &k);
    assert_eq!(map.len(), 2, "容量恒有界");
    assert_eq!(metrics.session_alias_evict_count(), 1);
    assert_eq!(
        map.resolve(SECRET, TENANT, "b"),
        None,
        "b 为最久未用，已逐出"
    );
    assert_eq!(map.resolve(SECRET, TENANT, "a"), Some(k.clone()));
    assert_eq!(map.resolve(SECRET, TENANT, "c"), Some(k));
}
