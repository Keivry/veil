use {
    super::super::{
        BeginOutcome,
        DECISION_TABLE_MAX_ENTRIES,
        DecisionEntry,
        DecisionSlot,
        DecisionTable,
        credential_decision_len,
        record_credential_decision,
    },
    crate::service::credential::test_support::*,
};

#[test]
fn decision_table_capacity_bounded() {
    // ARC-2：软上限 4096，仅驱逐终态条目，决策表长度有界。
    let state = cred_state(&cred_env(&[]));
    for i in 0..(DECISION_TABLE_MAX_ENTRIES + 128) {
        record_credential_decision(&state, &format!("cap-key-{i}"), Some(true));
    }
    let len = credential_decision_len(&state);
    assert!(len > 0, "写入后决策表须非空");
    assert!(
        len <= DECISION_TABLE_MAX_ENTRIES,
        "决策表长度须有界（<= {DECISION_TABLE_MAX_ENTRIES}），实得 {len}"
    );
}

#[test]
fn decision_table_soft_cap_evicts_only_decided() {
    // ARC-2：含 InFlight 的表触发驱逐时，InFlight 保留、仅最早终态被逐。
    use std::time::Duration;
    let mut table = DecisionTable::with_max_entries(2);
    table.resolve("d-old", Some(true));
    std::thread::sleep(Duration::from_millis(2));
    table.resolve("d-new", Some(true));
    assert_eq!(table.begin("live"), BeginOutcome::Reserved);
    assert_eq!(table.entries.len(), 3);
    table.resolve("d-newest", Some(true));
    assert!(
        table.entries.len() <= 2,
        "驱逐终态后须回到软上限内，实得 {}",
        table.entries.len()
    );
    assert_eq!(
        table.slot("live"),
        Some(DecisionSlot::Pending),
        "InFlight 永不驱逐"
    );
    assert_eq!(table.slot("d-newest"), Some(DecisionSlot::Approved));
    assert_eq!(table.overflow_count(), 0, "有可驱逐终态时不得计入溢出");
}

#[test]
fn decision_table_overflow_only_inflight_no_evict() {
    // ARC-2：驱逐尽终态后仅余 InFlight——零驱逐、overflow 计数 +1、允许暂时超出。
    let mut table = DecisionTable::with_max_entries(2);
    for k in ["i1", "i2", "i3"] {
        assert_eq!(table.begin(k), BeginOutcome::Reserved);
    }
    table.resolve("decided-once", Some(true));
    assert_eq!(table.overflow_count(), 1, "软上限溢出计数须递增 1");
    assert_eq!(table.entries.len(), 3, "仅 InFlight 超限时不驱逐");
    for k in ["i1", "i2", "i3"] {
        assert_eq!(table.slot(k), Some(DecisionSlot::Pending), "{k} 在途须保留");
    }
}

#[test]
fn decision_table_overflow_count_public_accessor_monotonic() {
    // ARC-2（只读观测）：仅 InFlight 超软上限时每次落定终态尝试驱逐均递增
    // overflow_count，且 entry_count 反映允许暂时超出的条目数。
    let mut table = DecisionTable::with_max_entries(2);
    for k in ["p1", "p2", "p3"] {
        assert_eq!(table.begin(k), BeginOutcome::Reserved);
    }
    assert_eq!(table.overflow_count(), 0, "初始无溢出");
    assert_eq!(table.entry_count(), 3, "三条 InFlight 已超软上限");
    table.resolve("decided-a", Some(true));
    assert_eq!(table.overflow_count(), 1, "首次溢出须递增 1");
    table.resolve("decided-b", Some(false));
    assert_eq!(table.overflow_count(), 2, "再次溢出须继续递增");
    assert_eq!(table.entry_count(), 3, "仅 InFlight 超限时不驱逐条目");
}

#[test]
fn decision_table_terminal_writes_bounded_by_soft_cap() {
    // ARC-2：以可注入软上限写入超上限终态，表条目数 ≤ 软上限且所余恒为终态。
    let mut table = DecisionTable::with_max_entries(2);
    for i in 0..10 {
        table.resolve(&format!("k{i}"), Some(true));
    }
    assert!(table.entries.len() <= 2, "终态写入须受软上限约束");
    assert!(
        table
            .entries
            .values()
            .all(|e| matches!(e, DecisionEntry::Decided { .. })),
        "所余条目恒为终态"
    );
}
