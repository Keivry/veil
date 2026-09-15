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
    std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    },
};

struct PendingEntry {
    created: Instant,
    decided: Option<bool>,
    /// 落定时刻（`decided` 写入时设置），供已决无 waiter 票的有界回收（`S2`/D2）。
    decided_at: Option<Instant>,
    /// 落定是否来自「自动放行」表情（`🔓`，C1 注册三态用）。
    auto: bool,
    branch: MatrixBranch,
    /// 决议唤醒通道（D3）：所有决议路径经同一 setter 在此发送 `Some(decided)`。
    notify: tokio::sync::watch::Sender<Option<bool>>,
}

impl std::fmt::Debug for PendingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingEntry")
            .field("created", &self.created)
            .field("decided", &self.decided)
            .field("decided_at", &self.decided_at)
            .field("auto", &self.auto)
            .field("branch", &self.branch)
            .finish_non_exhaustive()
    }
}

/// `C7`/D7 + `S2`/D2：按分支取回收 TTL（秒）。凭据类 300s（覆盖阻塞等待者），
/// 审计/解锁类 60s；已决票按落定时刻、未决票按建单时刻施加同一族 TTL。
fn orphan_ttl_secs(branch: MatrixBranch) -> u64 {
    match branch {
        MatrixBranch::Register | MatrixBranch::HashChange | MatrixBranch::Credential => {
            CREDENTIAL_TIMEOUT_SECS
        }
        MatrixBranch::Unlock | MatrixBranch::Audit | MatrixBranch::Unknown => ORPHAN_SWEEP_SECS,
    }
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
    #[cfg(test)]
    pub(crate) async fn submit(&self, event_id: &str) -> bool {
        self.submit_branch(event_id, MatrixBranch::Unknown).await
    }

    /// 按分支登记待审批 event；四段日志之“已发送”由调用方在发送后记录。
    pub async fn submit_branch(&self, event_id: &str, branch: MatrixBranch) -> bool {
        let mut guard = self.pending.lock().await;
        if guard.contains_key(event_id) {
            return false;
        }
        let (notify, _rx) = tokio::sync::watch::channel(None);
        guard.insert(
            event_id.to_string(),
            PendingEntry {
                created: Instant::now(),
                decided: None,
                decided_at: None,
                auto: false,
                branch,
                notify,
            },
        );
        true
    }

    /// 决议写入唯一 setter（D3）：同一 `pending` 锁临界区内写 `decided`/`decided_at`/
    /// `auto` 后 `send(Some(decided))`；已决则幂等短路（每票至多一次发送）。
    fn settle(entry: &mut PendingEntry, decided: bool, auto: bool) {
        if entry.decided.is_some() {
            return;
        }
        entry.decided = Some(decided);
        entry.decided_at = Some(Instant::now());
        entry.auto = auto;
        entry.notify.send_replace(Some(decided));
    }

    async fn pending_branch(&self, event_id: &str) -> Option<MatrixBranch> {
        self.pending.lock().await.get(event_id).map(|e| e.branch)
    }

    /// reaction 落定：白名单 + event id 精确匹配 + 幂等。
    pub async fn resolve(&self, event_id: &str, sender: &str, approved: bool) -> ResolveOutcome {
        self.resolve_with_auto(event_id, sender, approved, false)
            .await
    }

    /// 带自动放行标志的落定：`auto=true` 表示 `🔓`（C1 注册保持未激活）。
    /// `decided` 与 `auto` 在同一锁临界区写入，等待者读到决议时 `auto` 必已就绪。
    pub async fn resolve_with_auto(
        &self,
        event_id: &str,
        sender: &str,
        approved: bool,
        auto: bool,
    ) -> ResolveOutcome {
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
                Self::settle(entry, approved, auto);
                tracing::info!(
                    "审批结果: event {event_id} 发送者 {sender} 决议 {}",
                    if approved { "批准" } else { "拒绝" }
                );
                ResolveOutcome::Applied(approved)
            }
        }
    }

    /// 已落定票的 `auto` 标志（未落定/无票返回 None）；C1 三态落定消费。
    pub async fn applied_auto(&self, event_id: &str) -> Option<bool> {
        self.pending
            .lock()
            .await
            .get(event_id)
            .and_then(|e| e.decided.map(|_| e.auto))
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
            .resolve_with_auto(&input.target_event_id, &input.sender, approved, auto)
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
                Self::settle(entry, false, false);
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
                Self::settle(entry, false, false);
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
    /// D3：事件驱动（`watch`），订阅后先读 `borrow()` 兜底「决议先写、后订阅」。
    pub async fn ask(&self, event_id: &str, timeout: Duration) -> Option<bool> {
        tracing::info!("审批等待中: event {event_id} 超时 {}s", timeout.as_secs());
        let deadline = tokio::time::Instant::now() + timeout;
        let mut rx = {
            let guard = self.pending.lock().await;
            match guard.get(event_id) {
                Some(entry) => entry.notify.subscribe(),
                None => {
                    drop(guard);
                    self.timeout_and_remove(event_id, deadline, timeout).await;
                    return None;
                }
            }
        };
        if let Some(decided) = *rx.borrow() {
            return Some(Self::log_decision(event_id, decided));
        }
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.changed()).await {
                Ok(Ok(())) => {
                    if let Some(decided) = *rx.borrow() {
                        return Some(Self::log_decision(event_id, decided));
                    }
                }
                Ok(Err(_)) => {
                    if let Some(decided) = *rx.borrow() {
                        return Some(Self::log_decision(event_id, decided));
                    }
                    self.timeout_and_remove(event_id, deadline, timeout).await;
                    return None;
                }
                Err(_) => break,
            }
        }
        self.timeout_and_remove(event_id, deadline, timeout).await;
        None
    }

    fn log_decision(event_id: &str, decided: bool) -> bool {
        tracing::info!(
            "审批结果: event {event_id} 决议 {}",
            if decided { "批准" } else { "拒绝" }
        );
        decided
    }

    /// 无决议（票据缺失/通道关闭）时等到 deadline 再按既有超时口径清理。
    async fn timeout_and_remove(
        &self,
        event_id: &str,
        deadline: tokio::time::Instant,
        timeout: Duration,
    ) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            tokio::time::sleep(remaining).await;
        }
        tracing::warn!(
            "审批超时: event {event_id} 超时 {}s，按拒绝处理",
            timeout.as_secs()
        );
        self.remove(event_id).await;
    }

    /// 审计便捷问询（90s 超时口径）。
    pub async fn ask_audit(&self, event_id: &str) -> Option<bool> {
        let timeout = self.audit_timeout;
        self.ask(event_id, timeout).await
    }

    /// 终态清理（`C8`/D8）：按 event id 移除矩阵侧票，供 `service::credential::approval`
    /// 在 `ask` 返回后与内存侧 `PendingApprovals` 同批清理，保证 health `pending` 即时一致。
    pub async fn remove(&self, event_id: &str) { self.pending.lock().await.remove(event_id); }

    /// 清扫孤儿 pending（`C7`/D7 + `S2`/D2 按分支 TTL）；返回清理条数。凭据类分支
    /// （`Register`/`HashChange`/`Credential`）取 `CREDENTIAL_TIMEOUT_SECS`（300s），
    /// 保证 `ask` 阻塞等待者（自身 300s 超时）在阻塞期内不被清扫；审计/解锁维持 60s。
    /// `S2`/D2：已决票不再恒保留——无 waiter 的已决票按**落定时刻**施加同族有界 TTL，
    /// 超时回收使矩阵侧票数与 `pending` 有界；已决有 waiter 者在其轮询窗口内不被误收。
    pub async fn sweep_orphans(&self) -> usize {
        let mut guard = self.pending.lock().await;
        let before = guard.len();
        guard.retain(|_, e| {
            let ttl = orphan_ttl_secs(e.branch);
            let reference = if e.decided.is_some() {
                e.decided_at.unwrap_or(e.created)
            } else {
                e.created
            };
            reference.elapsed() < Duration::from_secs(ttl)
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

#[cfg(test)]
mod approval_tests;
