//! Matrix 审批网关：async 问询 + sync trait 兼容（D2 自 `matrix.rs` 拆出）。

use {
    super::branch::{
        CREDENTIAL_TIMEOUT_SECS,
        MatrixBranch,
        ORPHAN_SWEEP_SECS,
        ReactionInput,
        ReactionOutcome,
        ResolveOutcome,
        is_mxid_allowed,
        reaction_to_decision,
    },
    crate::approval::{ApprovalGateway, ApprovalOutcome, PendingRecord},
    std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    },
};

#[derive(Debug, Clone)]
struct PendingEntry {
    created: Instant,
    decided: Option<bool>,
    branch: MatrixBranch,
}

/// Matrix 审批网关：async 问询 + sync trait 兼容。
#[derive(Debug)]
pub struct MatrixApproval {
    whitelist: Vec<String>,
    audit_timeout: Duration,
    credential_timeout: Duration,
    pending: tokio::sync::Mutex<HashMap<String, PendingEntry>>,
}

impl MatrixApproval {
    pub fn new(whitelist: Vec<String>, audit_timeout_secs: u64) -> Self {
        Self {
            whitelist,
            audit_timeout: Duration::from_secs(audit_timeout_secs.max(1)),
            credential_timeout: Duration::from_secs(CREDENTIAL_TIMEOUT_SECS),
            pending: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn audit_timeout(&self) -> Duration { self.audit_timeout }

    pub fn credential_timeout(&self) -> Duration { self.credential_timeout }

    /// 登记一个待审批 event；已存在返回 false（幂等建单）。
    pub async fn submit(&self, event_id: &str) -> bool {
        self.submit_branch(event_id, MatrixBranch::Unknown).await
    }

    /// 按分支登记待审批 event；四段日志之“已发送”由调用方在发送后记录。
    pub async fn submit_branch(&self, event_id: &str, branch: MatrixBranch) -> bool {
        let mut guard = self.pending.lock().await;
        if guard.contains_key(event_id) {
            return false;
        }
        guard.insert(
            event_id.to_string(),
            PendingEntry {
                created: Instant::now(),
                decided: None,
                branch,
            },
        );
        true
    }

    async fn pending_branch(&self, event_id: &str) -> Option<MatrixBranch> {
        self.pending.lock().await.get(event_id).map(|e| e.branch)
    }

    /// reaction 落定：白名单 + event id 精确匹配 + 幂等。
    pub async fn resolve(&self, event_id: &str, sender: &str, approved: bool) -> ResolveOutcome {
        if !is_mxid_allowed(sender, &self.whitelist) {
            tracing::warn!("审批 reaction 被忽略: 发送者 {sender} 不在白名单");
            return ResolveOutcome::Ignored("发送者不在白名单");
        }
        let mut guard = self.pending.lock().await;
        match guard.get_mut(event_id) {
            None => ResolveOutcome::Ignored("event id 无精确匹配"),
            Some(entry) => {
                if entry.decided.is_some() {
                    return ResolveOutcome::Duplicate;
                }
                entry.decided = Some(approved);
                tracing::info!(
                    "审批结果: event {event_id} 发送者 {sender} 决议 {}",
                    if approved { "批准" } else { "拒绝" }
                );
                ResolveOutcome::Applied(approved)
            }
        }
    }

    /// `on_reaction` 五分支入口：房间/自反应/启动时间戳/表情/分支/白名单逐层过滤，
    /// 失配一律 no-op；命中后经 `resolve` 落定。
    pub async fn on_reaction(
        &self,
        input: &ReactionInput,
        own_user_id: &str,
        expected_room: &str,
        start_ts_ms: u128,
    ) -> ReactionOutcome {
        if input.room_id != expected_room {
            return ReactionOutcome::Ignored("非目标房间");
        }
        if input.server_ts_ms < start_ts_ms {
            return ReactionOutcome::Ignored("历史事件");
        }
        if !own_user_id.is_empty() && input.sender == own_user_id {
            return ReactionOutcome::Ignored("自反应");
        }
        if input.target_event_id.is_empty() {
            return ReactionOutcome::Ignored("event id 无精确匹配");
        }
        let branch = self.pending_branch(&input.target_event_id).await;
        let Some(branch) = branch else {
            return ReactionOutcome::Ignored("event id 无精确匹配");
        };
        if !branch.is_known() {
            return ReactionOutcome::Ignored("未知分支");
        }
        let Some((approved, auto)) = reaction_to_decision(branch, &input.key) else {
            return ReactionOutcome::Ignored("未知表情");
        };
        if !is_mxid_allowed(&input.sender, &self.whitelist) {
            tracing::warn!("审批 reaction 被忽略: 发送者 {} 不在白名单", input.sender);
            return ReactionOutcome::Ignored("发送者不在白名单");
        }
        match self
            .resolve(&input.target_event_id, &input.sender, approved)
            .await
        {
            ResolveOutcome::Applied(_) => ReactionOutcome::Applied { approved, auto },
            ResolveOutcome::Duplicate => ReactionOutcome::Duplicate,
            ResolveOutcome::Ignored(reason) => ReactionOutcome::Ignored(reason),
        }
    }

    /// `lock` 指令：未决单全部按拒绝落定并返回落定条数。
    pub async fn lock_reject_all(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let mut count = 0;
        for entry in guard.values_mut() {
            if entry.decided.is_none() {
                entry.decided = Some(false);
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!("审批锁定: {count} 单已按拒绝落定");
        }
        count
    }

    /// `lock` 全清：全部未决按拒绝落定后清空 pending 表（对标 Python `pending_requests.clear()`）。
    /// 网关接线人注意：`lock` 还须清理口令缓存 + KeePass 会话（`_kp=None` 对等）+
    /// PII scope 缓存，见 [`super::bot::MatrixBot::handle_text_command_full`] 的 BREAKING 说明。
    pub async fn lock_clear_all(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let mut count = 0;
        for entry in guard.values_mut() {
            if entry.decided.is_none() {
                entry.decided = Some(false);
                count += 1;
            }
        }
        let total = guard.len();
        guard.clear();
        if total > 0 {
            tracing::info!("审批锁定全清: {total} 单清空（含已决），其中 {count} 未决按拒绝落定");
        }
        total
    }

    /// `forget` 指令：清理已决单并返回清理条数。
    pub async fn forget_decided(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let before = guard.len();
        guard.retain(|_, e| e.decided.is_none());
        let cleared = before - guard.len();
        if cleared > 0 {
            tracing::info!("审批遗忘: 已清理 {cleared} 单");
        }
        cleared
    }

    /// 等待审批：超时/发送失败返回 None（调用方 MUST 按 rejected 处理并清理）。
    /// 四段日志之“等待中/超时/结果”在此记录，“已发送”由建单调用方记录。
    pub async fn ask(&self, event_id: &str, timeout: Duration) -> Option<bool> {
        tracing::info!("审批等待中: event {event_id} 超时 {}s", timeout.as_secs());
        let deadline = Instant::now() + timeout;
        loop {
            {
                let guard = self.pending.lock().await;
                if let Some(entry) = guard.get(event_id)
                    && let Some(decided) = entry.decided
                {
                    tracing::info!(
                        "审批结果: event {event_id} 决议 {}",
                        if decided { "批准" } else { "拒绝" }
                    );
                    return Some(decided);
                }
            }
            if Instant::now() >= deadline {
                tracing::warn!(
                    "审批超时: event {event_id} 超时 {}s，按拒绝处理",
                    timeout.as_secs()
                );
                self.remove(event_id).await;
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// 审计便捷问询（90s 超时口径）。
    pub async fn ask_audit(&self, event_id: &str) -> Option<bool> {
        let timeout = self.audit_timeout;
        self.ask(event_id, timeout).await
    }

    async fn remove(&self, event_id: &str) { self.pending.lock().await.remove(event_id); }

    /// 清扫孤儿 pending（超 60s 未决）；返回清理条数。
    pub async fn sweep_orphans(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let before = guard.len();
        guard.retain(|_, e| {
            e.decided.is_some() || e.created.elapsed() < Duration::from_secs(ORPHAN_SWEEP_SECS)
        });
        before - guard.len()
    }

    pub async fn pending_len(&self) -> usize { self.pending.lock().await.len() }

    /// 待审批 event 列表（只读快照，凭据阻塞双模的测试/运维可观测用）。
    pub async fn pending_event_ids(&self) -> Vec<String> {
        self.pending.lock().await.keys().cloned().collect()
    }

    /// 启动 60s 间隔清扫 tokio 任务；返回句柄（调用方持有，drop 即停）。
    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(ORPHAN_SWEEP_SECS));
            loop {
                ticker.tick().await;
                me.sweep_orphans().await;
            }
        })
    }
}

impl ApprovalGateway for MatrixApproval {
    fn request_approval(&self, _record: &PendingRecord) -> ApprovalOutcome {
        ApprovalOutcome::Pending
    }
}

#[cfg(test)]
mod approval_tests {
    use super::{
        super::{MatrixBot, TextCommand},
        *,
    };

    fn approval() -> MatrixApproval {
        MatrixApproval::new(vec!["@admin:example.com".to_string()], 90)
    }

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
        let lock = MatrixBot::handle_text_command_full(&gw, TextCommand::Lock, true, 0).await;
        assert!(lock.is_some_and(|s| s.contains("🔒 Proxy 已锁定")));
        let status = MatrixBot::handle_text_command_full(&gw, TextCommand::Status, false, 3).await;
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
}
