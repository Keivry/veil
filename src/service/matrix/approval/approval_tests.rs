use {
    super::{
        super::{FixedCleanup, MatrixBot, TextCommand},
        *,
    },
    crate::{
        approval::{PENDING_TTL_SECS, PendingRecord},
        service::credential::{
            health_status,
            test_support::{cred_env, cred_state},
        },
    },
};

fn approval() -> MatrixApproval { MatrixApproval::new(vec!["@admin:example.com".to_string()], 90) }

#[tokio::test]
async fn approve_reject_idempotent_and_mismatch_ignored() {
    let gw = approval();
    assert!(gw.submit("$ev1").await);
    assert!(!gw.submit("$ev1").await);
    assert_eq!(
        gw.resolve("$ev1", "@ghost:example.com", true).await,
        ResolveOutcome::Ignored("发送者不在白名单")
    );
    assert_eq!(
        gw.resolve("$nope", "@admin:example.com", true).await,
        ResolveOutcome::Ignored("event id 无精确匹配")
    );
    assert_eq!(
        gw.resolve("$ev1", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        gw.resolve("$ev1", "@admin:example.com", false).await,
        ResolveOutcome::Duplicate
    );
    assert_eq!(gw.ask("$ev1", Duration::from_secs(1)).await, Some(true));
}

#[tokio::test]
async fn timeout_returns_none_and_cleans_up_with_default_deny() {
    let gw = approval();
    gw.submit("$slow").await;
    let out = gw.ask("$slow", Duration::from_millis(120)).await;
    assert_eq!(out, None);
    assert_eq!(gw.pending_len().await, 0);
}

#[tokio::test]
async fn orphan_pending_swept_after_60s() {
    let gw = approval();
    gw.submit("$orphan").await;
    {
        let mut guard = gw.pending.lock().await;
        if let Some(e) = guard.get_mut("$orphan") {
            e.created = Instant::now() - Duration::from_secs(ORPHAN_SWEEP_SECS + 1);
        }
    }
    assert_eq!(gw.sweep_orphans().await, 1);
    assert_eq!(gw.pending_len().await, 0);
}

#[tokio::test]
async fn blocking_ticket_survives_60s_sweep() {
    use std::sync::Arc;
    let gw = Arc::new(approval());
    let event_id = "evt-blocking-cred";
    assert!(gw.submit_branch(event_id, MatrixBranch::Credential).await);
    // 推进测试时钟越过 60s（老化建单时刻，但不越过 300s 分支 TTL）。
    {
        let mut guard = gw.pending.lock().await;
        let entry = guard.get_mut(event_id).expect("票已建");
        entry.created = Instant::now() - Duration::from_secs(ORPHAN_SWEEP_SECS + 1);
    }
    assert_eq!(
        gw.sweep_orphans().await,
        0,
        "存在阻塞等待者的凭据票不得在 60s 清扫"
    );
    let waiter = {
        let gw = Arc::clone(&gw);
        tokio::spawn(async move { gw.ask(event_id, Duration::from_secs(300)).await })
    };
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        gw.resolve(event_id, "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        waiter.await.expect("等待任务未 panic"),
        Some(true),
        "阻塞问询须被 reaction 解除并读到批准"
    );
}

#[tokio::test]
async fn audit_orphan_still_swept_after_60s() {
    let gw = approval();
    gw.submit_branch("$audit-orphan", MatrixBranch::Audit).await;
    {
        let mut guard = gw.pending.lock().await;
        if let Some(e) = guard.get_mut("$audit-orphan") {
            e.created = Instant::now() - Duration::from_secs(ORPHAN_SWEEP_SECS + 1);
        }
    }
    assert_eq!(gw.sweep_orphans().await, 1, "审计类存量票维持 60s 回收");
    assert_eq!(gw.pending_len().await, 0);
}

#[test]
fn timeout_credential_300s_audit_90s() {
    assert_eq!(CREDENTIAL_TIMEOUT_SECS, 300);
    let gw = approval();
    assert_eq!(gw.audit_timeout(), Duration::from_secs(90));
    assert_eq!(gw.credential_timeout(), Duration::from_secs(300));
}

#[tokio::test]
async fn unknown_event_and_branch_mismatch_noop_preserves_state() {
    let gw = approval();
    gw.submit_branch("$known", MatrixBranch::Credential).await;
    let unknown = ReactionInput {
        target_event_id: "$missing".to_string(),
        key: "✅".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        gw.on_reaction(&unknown, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("event id 无精确匹配")
    );
    let wrong_room = ReactionInput {
        room_id: "!other:example.com".to_string(),
        ..unknown.clone()
    };
    assert_eq!(
        gw.on_reaction(&wrong_room, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("非目标房间")
    );
    let historic = ReactionInput {
        server_ts_ms: 500,
        ..unknown.clone()
    };
    assert_eq!(
        gw.on_reaction(&historic, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("历史事件")
    );
    let not_member = ReactionInput {
        target_event_id: "$known".to_string(),
        sender: "@ghost:example.com".to_string(),
        server_ts_ms: 2000,
        ..unknown.clone()
    };
    assert_eq!(
        gw.on_reaction(&not_member, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("发送者不在白名单")
    );
    assert_eq!(gw.pending_len().await, 1);
}

#[tokio::test]
async fn five_branch_reactions_settle_with_text_command_echo() {
    let gw = approval();
    gw.submit_branch("$cred", MatrixBranch::Credential).await;
    let approve = ReactionInput {
        target_event_id: "$cred".to_string(),
        key: "✅".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        gw.on_reaction(&approve, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: false
        }
    );
    assert_eq!(
        gw.on_reaction(&approve, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Duplicate
    );
    gw.submit_branch("$reg", MatrixBranch::Register).await;
    let auto = ReactionInput {
        target_event_id: "$reg".to_string(),
        key: "🔓".to_string(),
        ..approve.clone()
    };
    assert_eq!(
        gw.on_reaction(&auto, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: true
        }
    );
    assert_eq!(gw.applied_auto("$reg").await, Some(true));
    assert_eq!(gw.applied_auto("$cred").await, Some(false));
    assert_eq!(gw.applied_auto("$missing").await, None);
    let self_echo = ReactionInput {
        sender: "@bot:example.com".to_string(),
        ..approve.clone()
    };
    assert_eq!(
        gw.on_reaction(&self_echo, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("自反应")
    );
    let locked = gw.lock_reject_all().await;
    assert_eq!(locked, 0);
    gw.submit_branch("$open", MatrixBranch::Audit).await;
    assert_eq!(gw.lock_reject_all().await, 1);
    assert_eq!(
        gw.ask("$open", Duration::from_millis(10)).await,
        Some(false)
    );
    let status = MatrixBot::handle_text_command(&gw, TextCommand::Status).await;
    assert!(status.is_some_and(|s| s.contains("待审批") && s.contains("LLM secrets")));
    let forget = MatrixBot::handle_text_command(&gw, TextCommand::Forget).await;
    assert!(forget.is_some_and(|s| s.contains("已清除")));
    assert_eq!(gw.pending_len().await, 0);
}

#[tokio::test]
async fn lock_clears_all_without_residue_and_matches_legacy_copy() {
    let gw = approval();
    gw.submit_branch("$a", MatrixBranch::Credential).await;
    gw.submit_branch("$b", MatrixBranch::Audit).await;
    assert_eq!(
        gw.resolve("$a", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    // 全清：已决 + 未决一并清空。
    assert_eq!(gw.lock_clear_all().await, 2);
    assert_eq!(gw.pending_len().await, 0);
    let lock = MatrixBot::handle_text_command_full(
        &gw,
        TextCommand::Lock,
        &FixedCleanup {
            unlocked: true,
            secrets: 0,
        },
    )
    .await;
    assert!(lock.is_some_and(|s| s.contains("🔒 Proxy 已锁定")));
    let status = MatrixBot::handle_text_command_full(
        &gw,
        TextCommand::Status,
        &FixedCleanup {
            unlocked: false,
            secrets: 3,
        },
    )
    .await;
    assert_eq!(
        status.as_deref(),
        Some("Proxy: 🔒 未解锁 | 待审批: 0 | LLM secrets: 3")
    );
}

#[tokio::test]
async fn concurrent_single_ask_shares_same_decision() {
    use std::sync::Arc;
    let gw = Arc::new(approval());
    gw.submit("$shared").await;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let g = Arc::clone(&gw);
        handles.push(tokio::spawn(async move {
            g.ask("$shared", Duration::from_secs(5)).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        gw.resolve("$shared", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    for h in handles {
        assert_eq!(h.await.unwrap(), Some(true), "单次落定须广播给全部等待者");
    }
}

#[tokio::test]
async fn unlock_branch_emoji_semantics_with_timeout_cleanup() {
    assert_eq!(
        reaction_to_decision(MatrixBranch::Unlock, "✅"),
        Some((true, false))
    );
    assert_eq!(
        reaction_to_decision(MatrixBranch::Unlock, "❎"),
        Some((false, false))
    );
    assert_eq!(reaction_to_decision(MatrixBranch::Unlock, "🔓"), None);
    let gw = approval();
    gw.submit_branch("$unlock1", MatrixBranch::Unlock).await;
    assert_eq!(gw.ask("$unlock1", Duration::from_millis(80)).await, None);
    assert_eq!(gw.pending_len().await, 0);
}

#[tokio::test]
async fn credential_and_audit_auto_reaction_not_settled() {
    assert_eq!(reaction_to_decision(MatrixBranch::Credential, "🔓"), None);
    assert_eq!(reaction_to_decision(MatrixBranch::Audit, "🔓"), None);
    let gw = approval();
    gw.submit_branch("$cred-auto", MatrixBranch::Credential)
        .await;
    let auto = ReactionInput {
        target_event_id: "$cred-auto".to_string(),
        key: "🔓".to_string(),
        sender: "@admin:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        gw.on_reaction(&auto, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Ignored("未知表情")
    );
    assert_eq!(gw.applied_auto("$cred-auto").await, None);
}

#[tokio::test]
async fn decided_ticket_ttl_reclaim() {
    let state = cred_state(&cred_env(&[("APPROVAL_WHITELIST", "@admin:example.com")]));
    let gw = &state.approval;
    assert!(
        gw.submit_branch("$decided-leak", MatrixBranch::Credential)
            .await
    );
    assert_eq!(
        gw.resolve("$decided-leak", "@admin:example.com", true)
            .await,
        ResolveOutcome::Applied(true)
    );
    let mut record = PendingRecord::new("$decided-leak", "emergency_revoke转常规审批");
    record.created_ms = record
        .created_ms
        .saturating_sub(u128::from(PENDING_TTL_SECS) * 1000 + 1);
    state.pending.insert(record);
    assert_eq!(health_status(&state).pending, 1);
    assert_eq!(gw.sweep_orphans().await, 0, "落定未超 TTL 不得回收");
    assert_eq!(gw.pending_len().await, 1);
    // 老化落定时刻与内存建单时刻越过凭据分支 TTL。
    let stale = Instant::now() - Duration::from_secs(CREDENTIAL_TIMEOUT_SECS + 1);
    {
        let mut guard = gw.pending.lock().await;
        let entry = guard.get_mut("$decided-leak").expect("票在");
        entry.decided_at = Some(stale);
        entry.created = stale;
    }
    assert_eq!(gw.sweep_orphans().await, 1, "已决无 waiter 票超 TTL 须回收");
    assert_eq!(gw.pending_len().await, 0, "矩阵侧票数下降");
    state.pending.sweep_expired();
    assert_eq!(health_status(&state).pending, 0, "health.pending 归零");
}

#[tokio::test]
async fn sweep_orphans_bounded() {
    let gw = approval();
    for cycle in 0..4 {
        for i in 0..10 {
            let id = format!("$bounded-{cycle}-{i}");
            gw.submit_branch(&id, MatrixBranch::Credential).await;
            gw.resolve(&id, "@admin:example.com", true).await;
        }
        assert_eq!(
            gw.pending_len().await,
            10,
            "周期 {cycle} 票数上界恒为单周期产生量，不随产生次数单调增长"
        );
        let stale = Instant::now() - Duration::from_secs(CREDENTIAL_TIMEOUT_SECS + 1);
        {
            let mut guard = gw.pending.lock().await;
            for entry in guard.values_mut().filter(|e| e.decided.is_some()) {
                entry.decided_at = Some(stale);
            }
        }
        assert_eq!(gw.sweep_orphans().await, 10, "每周期回收 10 张已决票");
        assert_eq!(gw.pending_len().await, 0, "周期末票数有界归零");
    }

    // 已决有 waiter 的正常消费路径不受 TTL 影响。
    use std::sync::Arc;
    let gw = Arc::new(approval());
    gw.submit_branch("$waiter-ok", MatrixBranch::Credential)
        .await;
    let waiter = {
        let gw = Arc::clone(&gw);
        tokio::spawn(async move { gw.ask("$waiter-ok", Duration::from_secs(5)).await })
    };
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        gw.resolve("$waiter-ok", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        waiter.await.expect("等待任务未 panic"),
        Some(true),
        "已决有 waiter 正常消费路径不受 TTL 影响"
    );
}

#[tokio::test]
async fn ask_wakes_on_decision() {
    let gw = Arc::new(approval());
    gw.submit("$wake").await;
    let waiter = {
        let gw = Arc::clone(&gw);
        tokio::spawn(async move { gw.ask("$wake", Duration::from_secs(5)).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    let start = Instant::now();
    assert_eq!(
        gw.resolve("$wake", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    let got = tokio::time::timeout(Duration::from_millis(200), waiter)
        .await
        .expect("决议须即时唤醒，不得空等")
        .expect("等待任务未 panic");
    assert_eq!(got, Some(true));
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "唤醒延迟须远小于 50ms 轮询叠加，实测 {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn ask_timeout_returns_none_and_cleans() {
    let gw = approval();
    gw.submit("$none").await;
    assert_eq!(gw.ask("$none", Duration::from_millis(80)).await, None);
    assert_eq!(gw.pending_len().await, 0, "超时须清理票据");
}

#[tokio::test]
async fn ask_multi_waiter_notification() {
    let gw = Arc::new(approval());
    gw.submit_branch("$multi", MatrixBranch::Credential).await;
    let g1 = Arc::clone(&gw);
    let w1 = tokio::spawn(async move { g1.ask("$multi", Duration::from_secs(5)).await });
    let g2 = Arc::clone(&gw);
    let w2 = tokio::spawn(async move { g2.ask_audit("$multi").await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        gw.resolve("$multi", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        w1.await.expect("等待任务未 panic"),
        Some(true),
        "ask 与 ask_audit 共用同一票据不互相吞通知"
    );
    assert_eq!(w2.await.expect("等待任务未 panic"), Some(true));
}

#[tokio::test]
async fn ask_no_busy_poll() {
    let gw = Arc::new(approval());
    gw.submit("$nopoll").await;
    let start = Instant::now();
    assert_eq!(
        gw.ask("$nopoll", Duration::from_millis(150)).await,
        None,
        "无决议须超时返回 None"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(140),
        "须等到超时而非忙返回: {elapsed:?}"
    );
    assert!(
        !include_str!("../approval.rs").contains("from_millis(50)"),
        "须无 50ms 固定轮询"
    );
    assert_eq!(gw.pending_len().await, 0, "超时清理票据");
}

#[tokio::test]
async fn ask_wakes_on_lock_reject() {
    let gw = Arc::new(approval());
    gw.submit_branch("$lock-wake", MatrixBranch::Credential)
        .await;
    let g = Arc::clone(&gw);
    let waiter = tokio::spawn(async move { g.ask("$lock-wake", Duration::from_secs(300)).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let start = Instant::now();
    assert_eq!(gw.lock_reject_all().await, 1);
    let got = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("lock 期间 waiter 不得空等 300s TTL")
        .expect("等待任务未 panic");
    assert_eq!(got, Some(false), "lock 须按拒绝即时唤醒");
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn approval_after_lock_clear_still_works() {
    let gw = approval();
    gw.submit_branch("$pre", MatrixBranch::Credential).await;
    assert_eq!(gw.lock_clear_all().await, 1);
    assert_eq!(gw.pending_len().await, 0);
    gw.submit_branch("$post", MatrixBranch::Credential).await;
    assert_eq!(
        gw.resolve("$post", "@admin:example.com", true).await,
        ResolveOutcome::Applied(true)
    );
    assert_eq!(
        gw.ask("$post", Duration::from_millis(100)).await,
        Some(true),
        "lock_clear_all 后正常建单/落定/消费路径可用"
    );
}

#[tokio::test]
async fn lock_notify_no_double_send_no_lost_wakeup() {
    // 先写决议后订阅：起点 borrow() 兜底读到 Some(false)。
    let gw = Arc::new(approval());
    gw.submit_branch("$after", MatrixBranch::Credential).await;
    assert_eq!(gw.lock_reject_all().await, 1);
    assert_eq!(
        gw.ask("$after", Duration::from_millis(50)).await,
        Some(false)
    );
    assert_eq!(
        gw.lock_reject_all().await,
        0,
        "已决票不重复落定（无重复发送）"
    );
    // 先订阅后写决议：多 waiter 各只唤醒一次。
    let gw2 = Arc::new(approval());
    gw2.submit_branch("$before", MatrixBranch::Credential).await;
    let mut handles = Vec::new();
    for _ in 0..4 {
        let g = Arc::clone(&gw2);
        handles.push(tokio::spawn(async move {
            g.ask("$before", Duration::from_secs(5)).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(gw2.lock_reject_all().await, 1);
    for h in handles {
        assert_eq!(h.await.expect("等待任务未 panic"), Some(false));
    }
}

#[tokio::test]
async fn on_reaction_empty_whitelist_no_filter_settles() {
    // TST-6 / POL-5：`APPROVAL_WHITELIST` 为空时白名单层不过滤——
    // 任意发送者的有效 reaction 照常落定（与 POL-5「空=不过滤」同源）。
    let gw = MatrixApproval::new(Vec::new(), 90);
    gw.submit_branch("$open-wl", MatrixBranch::Credential).await;
    let input = ReactionInput {
        target_event_id: "$open-wl".to_string(),
        key: "✅".to_string(),
        sender: "@stranger:example.com".to_string(),
        room_id: "!r:example.com".to_string(),
        server_ts_ms: 2000,
    };
    assert_eq!(
        gw.on_reaction(&input, "@bot:example.com", "!r:example.com", 1000)
            .await,
        ReactionOutcome::Applied {
            approved: true,
            auto: false
        },
        "空白名单不得忽略非成员 reaction"
    );
    assert_eq!(
        gw.ask("$open-wl", Duration::from_millis(100)).await,
        Some(true)
    );
}
