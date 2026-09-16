use {
    super::super::{
        BeginOutcome,
        DECISION_TABLE_MAX_ENTRIES,
        DecisionEntry,
        DecisionSlot,
        DecisionTable,
        approval_async_202,
        credential_decision_len,
        record_credential_decision,
    },
    crate::{
        error::VeilError,
        registry::RegisterParams,
        service::credential::{
            AppStateParts,
            test_support::*,
            vault_ops::{register_caller_with_approval, revoke_caller_with_approval},
        },
    },
    axum::{http::StatusCode, response::IntoResponse as _},
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
    // ARC-2/D4：满表中 begin 新键先驱逐最早终态腾位，InFlight 保留。
    use std::time::Duration;
    let mut table = DecisionTable::with_max_entries(2);
    table.resolve("d-old", Some(true));
    std::thread::sleep(Duration::from_millis(2));
    table.resolve("d-new", Some(true));
    assert_eq!(table.begin("live"), BeginOutcome::Reserved);
    assert_eq!(table.slot("d-old"), None, "created 最早的终态须被驱逐腾位");
    assert_eq!(table.entries.len(), 2, "驱逐一终态后插入，不超软上限");
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
    // ARC-2/D4：满表仅余 InFlight 时 begin 饱和拒绝（零插入、零驱逐、溢出计数 +1）；
    // 落定终态时纪律驱逐自身终态，不叠加溢出。
    let mut table = DecisionTable::with_max_entries(2);
    for k in ["i1", "i2"] {
        assert_eq!(table.begin(k), BeginOutcome::Reserved);
    }
    assert_eq!(
        table.begin("i3"),
        BeginOutcome::Saturated,
        "仅余 InFlight 时新键须饱和拒绝"
    );
    assert_eq!(table.overflow_count(), 1, "饱和拒绝须递增溢出计数");
    assert_eq!(table.entries.len(), 2, "饱和不得插入或驱逐");
    for k in ["i1", "i2"] {
        assert_eq!(table.slot(k), Some(DecisionSlot::Pending), "{k} 在途须保留");
    }
    table.resolve("decided-once", Some(true));
    assert_eq!(table.entries.len(), 2, "落定终态驱逐后回软上限");
    assert_eq!(
        table.overflow_count(),
        1,
        "有可驱逐终态时 enforcement 不叠加溢出"
    );
}

#[test]
fn decision_table_overflow_count_public_accessor_monotonic() {
    // ARC-2/D4（只读观测）：每次饱和拒绝递增 overflow_count；entry_count 保持有界。
    let mut table = DecisionTable::with_max_entries(2);
    for k in ["p1", "p2"] {
        assert_eq!(table.begin(k), BeginOutcome::Reserved);
    }
    assert_eq!(table.overflow_count(), 0, "初始无溢出");
    assert_eq!(table.entry_count(), 2, "两条 InFlight 已达软上限");
    assert_eq!(table.begin("p3"), BeginOutcome::Saturated);
    assert_eq!(table.overflow_count(), 1, "首次饱和须递增 1");
    assert_eq!(table.begin("p4"), BeginOutcome::Saturated);
    assert_eq!(table.overflow_count(), 2, "再次饱和须继续递增");
    assert_eq!(table.entry_count(), 2, "饱和不插入，条目数保持软上限");
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

#[tokio::test]
async fn decision_table_begin_saturated_429() {
    // D4：满表仅余 InFlight 时新键 `429 + Retry-After: 60`；同键在途仍 `202 + E_PENDING`。
    let mut table = DecisionTable::with_max_entries(2);
    assert_eq!(table.begin("live-a"), BeginOutcome::Reserved);
    assert_eq!(table.begin("live-b"), BeginOutcome::Reserved);
    assert_eq!(
        table.begin("live-c"),
        BeginOutcome::Saturated,
        "仅余 InFlight 须饱和拒绝"
    );
    assert_eq!(
        table.begin("live-a"),
        BeginOutcome::Busy,
        "同键在途仍复用既有票"
    );
    assert_eq!(table.entry_count(), 2, "饱和路径 SHALL NOT 插入新键");
    assert_eq!(table.overflow_count(), 1, "饱和须递增 overflow_count");
    for k in ["live-a", "live-b"] {
        assert_eq!(
            table.slot(k),
            Some(DecisionSlot::Pending),
            "InFlight 永不驱逐"
        );
    }

    let state = cred_state(&cred_env(&[]));
    {
        let mut guard = state.decisions().lock().expect("决策表锁可获取");
        for i in 0..DECISION_TABLE_MAX_ENTRIES {
            assert_eq!(
                guard.begin(&format!("sat-{i}")),
                BeginOutcome::Reserved,
                "填满表须以 InFlight 占位（i={i}）"
            );
        }
    }

    let new_err = approval_async_202(
        &state,
        "/s/sat-new.sh:badhash",
        "hash_mismatch",
        "网易",
        Some("授权码"),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        new_err.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "饱和新键须 429"
    );
    match &new_err {
        VeilError::RateLimited { retry_after_secs } => assert_eq!(*retry_after_secs, 60),
        other => panic!("饱和须映射 RateLimited，实得: {other:?}"),
    }
    let response = new_err.into_response();
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("60"),
        "429 须携带 Retry-After: 60"
    );

    let busy_err = approval_async_202(
        &state,
        "sat-0",
        "hash_mismatch",
        "网易",
        Some("授权码"),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(
        busy_err.status_code(),
        StatusCode::ACCEPTED,
        "同键在途须仍 202"
    );
    assert!(matches!(busy_err, VeilError::PendingApproval { .. }));

    let reg_err = register_caller_with_approval(
        &state,
        &RegisterParams {
            caller_path: "/s/sat-reg.sh".to_string(),
            ..RegisterParams::default()
        },
        "sat-test",
    )
    .await
    .unwrap_err();
    assert_eq!(
        reg_err.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "注册调用点饱和须 429"
    );

    enroll_allow(&state, "/s/sat-revoke.sh", "sathash").await;
    let revoke_err = revoke_caller_with_approval(&state, "/s/sat-revoke.sh")
        .await
        .unwrap_err();
    assert_eq!(
        revoke_err.status_code(),
        StatusCode::TOO_MANY_REQUESTS,
        "吊销调用点饱和须 429"
    );
}

#[test]
fn decision_table_begin_saturated_metrics() {
    // D4：饱和路径后 `approval_decision_overflow_total` 递增、`decision_table_size`
    // 仍随占位正确导出且不因饱和增长/清表，防 begin 改造致指标退化。
    let state = cred_state(&cred_env(&[]));
    let mut table = state.decisions().lock().expect("决策表锁可获取");
    for i in 0..DECISION_TABLE_MAX_ENTRIES {
        assert_eq!(table.begin(&format!("m-{i}")), BeginOutcome::Reserved);
        assert_eq!(
            table.entry_count(),
            i + 1,
            "decision_table_size 须随占位递增"
        );
    }
    assert_eq!(table.overflow_count(), 0, "未饱和前 overflow 恒零");
    assert_eq!(table.begin("m-overflow"), BeginOutcome::Saturated);
    assert_eq!(
        table.overflow_count(),
        1,
        "饱和须递增 approval_decision_overflow_total"
    );
    assert_eq!(
        table.entry_count(),
        DECISION_TABLE_MAX_ENTRIES,
        "饱和不插入，decision_table_size 保持软上限"
    );
    assert_eq!(table.begin("m-overflow-2"), BeginOutcome::Saturated);
    assert_eq!(table.overflow_count(), 2, "重复饱和须继续递增");
    assert_eq!(
        table.entry_count(),
        DECISION_TABLE_MAX_ENTRIES,
        "饱和 SHALL NOT 清表"
    );
    assert_eq!(
        table.slot("m-0"),
        Some(DecisionSlot::Pending),
        "既有 InFlight 不被驱逐"
    );
}
