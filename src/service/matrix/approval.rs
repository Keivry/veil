//! Matrix 审批网关：async 问询 + sync trait 兼容（自 `matrix.rs` 拆出）。

use {
    super::branch::{
        CREDENTIAL_TIMEOUT_SECS,
        MatrixBranch,
        ORPHAN_SWEEP_SECS,
        ReactionAction,
        ReactionInput,
        ReactionOutcome,
        ResolveOutcome,
        is_known_reaction,
        is_mxid_allowed,
        reaction_to_decision,
    },
    std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    },
};

/// 分支不受理该表情时的回执（票保持未决）。
const NOTICE_NOT_ACCEPTED: &str = "该分支不受理此表情，票保持未决（可用：✅/❎）";
/// 未知表情（含已退役的旧解锁表情）回执。
const NOTICE_UNKNOWN_REACTION: &str = "未知表情，票保持未决（可用：✅/♾️/❎；旧解锁表情已退役）";

struct PendingEntry {
    created: Instant,
    decided: Option<bool>,
    /// 落定时刻（`decided` 写入时设置），供已决无 waiter 票的有界回收。
    decided_at: Option<Instant>,
    /// 落定是否来自「批准并持久放行」表情（`♾️`）。
    always: bool,
    branch: MatrixBranch,
    /// 决议唤醒通道：所有决议路径经同一 setter 在此发送 `Some(decided)`。
    notify: tokio::sync::watch::Sender<Option<bool>>,
}

impl std::fmt::Debug for PendingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingEntry")
            .field("created", &self.created)
            .field("decided", &self.decided)
            .field("decided_at", &self.decided_at)
            .field("always", &self.always)
            .field("branch", &self.branch)
            .finish_non_exhaustive()
    }
}

/// 按分支取回收 TTL（秒）。有阻塞等待者的分支 300s，其余 60s。
fn orphan_ttl_secs(branch: MatrixBranch) -> u64 {
    match branch {
        MatrixBranch::Register
        | MatrixBranch::HashChange
        | MatrixBranch::Credential
        | MatrixBranch::Command
        | MatrixBranch::Revoke => CREDENTIAL_TIMEOUT_SECS,
        MatrixBranch::Audit | MatrixBranch::Unknown => ORPHAN_SWEEP_SECS,
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

    /// 文本指令发送者白名单判定（与 reaction 同口径；空白名单＝不过滤）。
    pub fn is_sender_allowed(&self, mxid: &str) -> bool { is_mxid_allowed(mxid, &self.whitelist) }

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
                always: false,
                branch,
                notify,
            },
        );
        true
    }

    /// 决议写入唯一 setter：同一 `pending` 锁临界区内写 `decided`/`decided_at`/
    /// `auto` 后 `send(Some(decided))`；已决则幂等短路（每票至多一次发送）。
    fn settle(entry: &mut PendingEntry, decided: bool, always: bool) {
        if entry.decided.is_some() {
            return;
        }
        entry.decided = Some(decided);
        entry.decided_at = Some(Instant::now());
        entry.always = always;
        entry.notify.send_replace(Some(decided));
    }

    async fn pending_branch(&self, event_id: &str) -> Option<MatrixBranch> {
        self.pending.lock().await.get(event_id).map(|e| e.branch)
    }

    /// reaction 落定：白名单 + event id 精确匹配 + 幂等。
    pub async fn resolve(&self, event_id: &str, sender: &str, approved: bool) -> ResolveOutcome {
        self.resolve_with_always(event_id, sender, approved, false)
            .await
    }

    /// 带持久放行标志的落定：`always=true` 表示 `♾️`。
    /// `decided` 与 `always` 在同一锁临界区写入，等待者读到决议时两者必已就绪。
    pub async fn resolve_with_always(
        &self,
        event_id: &str,
        sender: &str,
        approved: bool,
        always: bool,
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
                Self::settle(entry, approved, always);
                tracing::info!(
                    "审批结果: event {event_id} 发送者 {sender} 决议 {}",
                    if approved { "批准" } else { "拒绝" }
                );
                ResolveOutcome::Applied(approved)
            }
        }
    }

    /// 已落定票的 `auto` 标志（未落定/无票返回 None）；三态落定消费。
    /// 非阻塞读取已落定决议：`None` = 仍待审；`Some(Some(bool))` = 已决。
    pub async fn decision(&self, event_id: &str) -> Option<Option<bool>> {
        self.pending.lock().await.get(event_id).map(|e| e.decided)
    }

    pub async fn applied_always(&self, event_id: &str) -> Option<bool> {
        self.pending
            .lock()
            .await
            .get(event_id)
            .and_then(|e| e.decided.map(|_| e.always))
    }

    /// `on_reaction` 入口：房间/时间/自反应/票/分支/白名单/表情逐层过滤。
    /// 非白名单成员与非建单分支保持静默；分支不受理与未知表情回一条说明。
    pub async fn on_reaction(
        &self,
        input: &ReactionInput,
        own_user_id: &str,
        expected_room: &str,
        start_ts_ms: u128,
    ) -> ReactionOutcome {
        if input.room_id != expected_room {
            return ReactionOutcome::Silent("非目标房间");
        }
        if input.server_ts_ms < start_ts_ms {
            return ReactionOutcome::Silent("历史事件");
        }
        if own_user_id.is_empty() {
            return ReactionOutcome::Silent("whoami 失败，自反应过滤不可用");
        }
        if input.sender == own_user_id {
            return ReactionOutcome::Silent("自反应");
        }
        if input.target_event_id.is_empty() {
            return ReactionOutcome::Silent("event id 无精确匹配");
        }
        let Some(branch) = self.pending_branch(&input.target_event_id).await else {
            return ReactionOutcome::Silent("event id 无精确匹配");
        };
        if !branch.is_known() || !branch.is_matrix_order_branch() {
            return ReactionOutcome::Silent("非建单分支");
        }
        if !is_mxid_allowed(&input.sender, &self.whitelist) {
            tracing::warn!("审批 reaction 被忽略: 发送者 {} 不在白名单", input.sender);
            return ReactionOutcome::Silent("发送者不在白名单");
        }
        if !is_known_reaction(&input.key) {
            return ReactionOutcome::Notify(NOTICE_UNKNOWN_REACTION);
        }
        let (approved, always) = match reaction_to_decision(branch, &input.key) {
            ReactionAction::Approve => (true, false),
            ReactionAction::Reject => (false, false),
            ReactionAction::ApproveAlways => (true, true),
            ReactionAction::NotAccepted => return ReactionOutcome::Notify(NOTICE_NOT_ACCEPTED),
            ReactionAction::NotAnOrderBranch => return ReactionOutcome::Silent("非建单分支"),
        };
        match self
            .resolve_with_always(&input.target_event_id, &input.sender, approved, always)
            .await
        {
            ResolveOutcome::Applied(_) => ReactionOutcome::Applied { approved, always },
            ResolveOutcome::Duplicate => ReactionOutcome::Duplicate,
            ResolveOutcome::Ignored(reason) => ReactionOutcome::Silent(reason),
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

    /// `lock` 全清：清空 pending 表并返回清掉的条目数。
    /// 内存材料（口令缓存、KeePass 会话、PII 会话作用域）的清理归
    /// [`super::GatewayCleanup::lock_cleanup`]，由调用方在同一序列内先行触发。
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
    /// 事件驱动（`watch`），订阅后先读 `borrow()` 兜底「决议先写、后订阅」。
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

    /// 终态清理：按 event id 移除矩阵侧票，供 `service::credential::approval`
    /// 在 `ask` 返回后与内存侧 `PendingApprovals` 同批清理，保证 health `pending` 即时一致。
    pub async fn remove(&self, event_id: &str) { self.pending.lock().await.remove(event_id); }

    /// 清扫孤儿 pending（按分支 TTL）；返回清理条数。有阻塞等待者的分支
    /// （`Register`/`HashChange`/`Credential`/`Command`/`Revoke`）取
    /// `CREDENTIAL_TIMEOUT_SECS`（300s），保证 `ask` 阻塞等待者（自身 300s 超时）
    /// 在阻塞期内不被清扫；`Audit`/`Unknown` 维持 `ORPHAN_SWEEP_SECS`（60s）。
    /// 已决票不再恒保留——无 waiter 的已决票按**落定时刻**施加同族有界 TTL，
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
    /// 集成测试以非 `cfg(test)` 构建链接本库并直接调用
    /// （`tests/http_e2e_credential*.rs`/`http_e2e_vault_stability.rs`），
    /// 降级 `#[cfg(test)] pub(crate)` 会破坏其编译，故暂保留 `pub`。
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
mod tests;
