//! 审批/pending 链：建单、双模问询、哈希变更通知、问询口径。
//!
//! H3.1 owner 声明：双模执行（`approval_dual_mode`）归本文件；单据存储与问询
//! trait 归 `crate::approval`（经其 `PendingApprovals`/`PendingRecord` 接口协作），
//! 分支流转归 `service::matrix`；三处互不垫片。

use {
    super::{super::matrix, AppStateParts, vault_ops::query_keepass},
    crate::{
        approval::{PENDING_TTL_SECS, PendingRecord},
        error::{Result, VeilError},
    },
    std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    },
};

/// `CRD-12`：宽限通知去重上限（进程级，防无界增长；容量触发 TTL 清扫 + 逐出最小 `expires_at`）。
const GRACE_NOTIFY_DEDUP_MAX: usize = 4096;

/// `CRD-12`/D6：宽限通知去重表（键 = 条目 + 宽限窗口，value = 该窗口 `expires_at` 秒），
/// 同窗口仅首次通知。
static GRACE_NOTIFY_DEDUP: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

/// `CRD-12`/D6：`dedup_key` 是否首次出现（同窗口重复返回 `false`，不重复通知）。
/// 容量满（`>= GRACE_NOTIFY_DEDUP_MAX`）时先 `retain` 清扫过期条目（`expires_at <= now_secs`），
/// 仍满则逐出 `expires_at` 最小者并记 warn，**SHALL NOT** 整表清空（与
/// `ratelimit::RateTable` 的「容量触发清扫 + 硬上限逐出」同模式）。
fn first_grace_notification(dedup_key: &str, expires_at: u64, now_secs: u64) -> bool {
    let map = GRACE_NOTIFY_DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match map.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if guard.contains_key(dedup_key) {
        return false;
    }
    if guard.len() >= GRACE_NOTIFY_DEDUP_MAX {
        guard.retain(|_, e| *e > now_secs);
        if guard.len() >= GRACE_NOTIFY_DEDUP_MAX
            && let Some(victim) = guard
                .iter()
                .min_by_key(|(_, e)| **e)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&victim);
            tracing::warn!(
                entries = guard.len(),
                max = GRACE_NOTIFY_DEDUP_MAX,
                "宽限通知去重表满，逐出 expires_at 最小条目"
            );
        }
    }
    guard.insert(dedup_key.to_string(), expires_at);
    true
}

/// `C10`/D10：审批摘要 = 机器可读原因 + 调用方键 + 条目/字段元数据。
/// 仅接收调用元数据，不接收凭据明文/部署 Secret，敏感值不落消息。
pub(crate) fn approval_summary(
    reason: &str,
    key: &str,
    entry: &str,
    field: Option<&str>,
) -> String {
    let entry = entry.trim();
    let field = field.map(str::trim).filter(|f| !f.is_empty());
    match (entry.is_empty(), field) {
        (false, Some(field)) => format!("{reason} :: {key} :: {entry}/{field}"),
        (false, None) => format!("{reason} :: {key} :: {entry}"),
        (true, _) => format!("{reason} :: {key}"),
    }
}

/// `C8`/D8：统一终态清理——同时清内存侧 `PendingApprovals`（health `pending` 计数来源）
/// 与矩阵侧票，使 `GET /health pending` 在批准/拒绝/超时后即时归零，不等 60s 清扫。
pub(crate) async fn clear_terminal_pending(state: &impl AppStateParts, key: &str, event_id: &str) {
    state.pending().remove(key);
    state.approval().remove(event_id).await;
}

pub(crate) async fn submit_pending(
    state: &impl AppStateParts,
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
) -> Result<String> {
    let branch = matrix::MatrixBranch::from_reason(reason);
    submit_pending_with_branch(state, key, reason, branch, entry, field).await
}

/// `AUTH-9`：按分支取内存 pending 清扫 TTL（秒）——凭据/注册/哈希变更类阻塞票
/// 保留至 300s 阻塞超时，空闲/审计/解锁类维持 60s 上限。
fn pending_ttl_secs(branch: matrix::MatrixBranch) -> u64 {
    match branch {
        matrix::MatrixBranch::Register
        | matrix::MatrixBranch::HashChange
        | matrix::MatrixBranch::Credential => matrix::CREDENTIAL_TIMEOUT_SECS,
        _ => PENDING_TTL_SECS,
    }
}

/// 显式分支建单：C1/C2 注册/吊销复用 `Register` 分支，避免调用方路径内的
/// 关键词（如 `unlock`/`credential`）经 `from_reason` 误判分支。
///
/// `F1`/D1：审批建单走 tracked 发送——先 `await` 取 Bot 返回的真实 Matrix event id，
/// 以真实 id 为 pending 键 `submit_branch`；发送失败/未取得 id 时 fail-closed（不建单，
/// 返回错误）。与事件环/spool 的 `notify_text` best-effort 语义分属两条路由。
pub(crate) async fn submit_pending_with_branch(
    state: &impl AppStateParts,
    key: &str,
    reason: &str,
    branch: matrix::MatrixBranch,
    entry: &str,
    field: Option<&str>,
) -> Result<String> {
    let summary = approval_summary(reason, key, entry, field);
    let text = state.notify().format_approval(branch, None, &summary);
    let Some(event_id) = state.notify().send_tracked(text).await else {
        tracing::warn!("审批发送失败，按拒绝 fail-closed（不建单）: 原因 {reason}");
        return Err(VeilError::Auth {
            message: "审批发送失败，已按拒绝处理".to_string(),
        });
    };
    state.pending().insert(PendingRecord::with_ttl(
        key,
        reason,
        pending_ttl_secs(branch),
    ));
    state.approval().submit_branch(&event_id, branch).await;
    for emoji in branch.reaction_presets() {
        if !state.notify().send_reaction(&event_id, emoji).await {
            tracing::warn!(
                "审批预置 reaction 发送失败，仅告警不阻断: event {event_id} emoji {emoji}"
            );
        }
    }
    tracing::info!("审批已发送: event {event_id} 原因 {reason}");
    Ok(event_id)
}

pub(crate) async fn record_pending(
    state: &impl AppStateParts,
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
) -> VeilError {
    match submit_pending(state, key, reason, entry, field).await {
        Ok(_) => VeilError::PendingApproval {
            message: format!("已转 Matrix 人工审批: {reason}"),
        },
        Err(err) => err,
    }
}

/// `R2`/D2：异步 `202` 决策三态。后台 waiter 落定后按 `pending_key` 落表，
/// 重试请求先消费此表：批准 → 取凭据，拒绝/超时 → `403`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialDecision {
    Approved,
    Denied,
    TimedOut,
}

/// `T1`/D1：闭环批准动作对「自动放行」表情（`🔓` → `auto=true`）的策略。
/// 吊销 lane 传 [`AutoPolicy::Reject`]——`decision == Some(true) && auto` 落定为拒绝，
/// 使其与常规吊销路径的 `!auto` 守卫一致；凭据 lane 传 [`AutoPolicy::Accept`]（行为不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoPolicy {
    Accept,
    Reject,
}

/// `T1`/D1：闭环 lane 声明——终态文案与「自动放行」策略成对传入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClosureLane {
    pub label: &'static str,
    pub auto_policy: AutoPolicy,
    /// `AUTH-9`：建单分支——决定矩阵票与内存 pending 的 TTL 口径（凭据/注册类 300s）。
    pub branch: matrix::MatrixBranch,
}

/// 决策表槽位（只读观测/测试用）：未决与三终态可区分。
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionSlot {
    Pending,
    Approved,
    Denied,
    TimedOut,
}

/// `begin` 结果：新占位（须建单）/ 已在途（复用既有票，不再建单）/ 已决（终态待显式消费）/
/// 饱和（满表且仅余 `InFlight`，调用点按 `429 + Retry-After` 拒绝新键）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BeginOutcome {
    Reserved,
    Busy,
    Decided(CredentialDecision),
    /// `D4`：满表仅余 `InFlight`——新键无票，SHALL NOT 伪造 `202 + E_PENDING`。
    Saturated,
}

#[derive(Debug)]
enum DecisionEntry {
    InFlight {
        event_id: Option<String>,
    },
    Decided {
        decision: CredentialDecision,
        created: Instant,
    },
}

/// `ARC-2`/D4：审批决策表（键 = `pending_key`），由 `AppState` 以
/// `Arc<Mutex<DecisionTable>>` 承载（进程级 `static` 已移除）。容量约束仅作用于终态：
/// `begin` 满表时先驱逐终态 `Decided`（按 `created` 升序，同刻以 key 字典序 tie-break）
/// 腾位，仅余 `InFlight` 时返回 [`BeginOutcome::Saturated`]（调用点映射
/// `429 + Retry-After: 60`，不插入、不伪造 `202`），`InFlight` 永不驱逐；`resolve`
/// 落定终态同受驱逐约束，无可驱逐终态时记 warn 并递增 `overflow_count`
/// （`approval_decision_overflow_total`）。
#[derive(Debug)]
pub struct DecisionTable {
    entries: HashMap<String, DecisionEntry>,
    max_entries: usize,
    overflow_count: u64,
}

const DECISION_TABLE_MAX_ENTRIES: usize = 4096;

impl Default for DecisionTable {
    fn default() -> Self { Self::with_max_entries(DECISION_TABLE_MAX_ENTRIES) }
}

impl DecisionTable {
    fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            overflow_count: 0,
        }
    }

    /// 清扫过期已决条目（一次性消费语义的兜底）。
    fn sweep(&mut self, now: Instant) {
        self.entries.retain(|_, e| match e {
            DecisionEntry::InFlight { .. } => true,
            DecisionEntry::Decided { created, .. } => {
                now.duration_since(*created).as_secs() < PENDING_TTL_SECS
            }
        });
    }

    /// `CRD-6`/D4：占位入口。顺序为 `sweep(now)` → 满表时循环驱逐最早终态 `Decided`
    /// 腾位 → 满表且仅余 `InFlight` 时饱和拒绝（不插入、不驱逐在途）；同键在途仍
    /// [`BeginOutcome::Busy`]，同键终态仍只读 [`BeginOutcome::Decided`]。
    fn begin(&mut self, key: &str) -> BeginOutcome {
        let now = Instant::now();
        self.sweep(now);
        match self.entries.get(key) {
            Some(DecisionEntry::Decided { decision, .. }) => BeginOutcome::Decided(*decision),
            Some(DecisionEntry::InFlight { .. }) => BeginOutcome::Busy,
            None => {
                while self.entries.len() >= self.max_entries {
                    if self.evict_oldest_decided() {
                        continue;
                    }
                    self.overflow_count = self.overflow_count.saturating_add(1);
                    tracing::warn!(
                        entries = self.entries.len(),
                        max = self.max_entries,
                        metric = "approval_decision_overflow_total",
                        "决策表满且仅余 InFlight，新键拒绝为 429 且不驱逐在途审批"
                    );
                    return BeginOutcome::Saturated;
                }
                self.entries
                    .insert(key.to_string(), DecisionEntry::InFlight { event_id: None });
                BeginOutcome::Reserved
            }
        }
    }

    /// `S3`/D3：终态显式消费。`begin` 只读，动作成功/终态返回后由调用方消费；
    /// 动作失败时保留已批准态，使同一请求重试仍可按已批准执行。
    fn consume(&mut self, key: &str) -> bool { self.entries.remove(key).is_some() }

    fn set_event_id(&mut self, key: &str, event_id: &str) {
        if let Some(DecisionEntry::InFlight { event_id: slot }) = self.entries.get_mut(key) {
            *slot = Some(event_id.to_string());
        }
    }

    fn cancel(&mut self, key: &str) { self.entries.remove(key); }

    /// `ARC-2`/D4：驱逐 `created` 最早的终态 `Decided`（同刻以 key 字典序 tie-break）；
    /// 仅余 `InFlight` 时返回 `false`（在途永不驱逐）。
    fn evict_oldest_decided(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .filter_map(|(k, e)| match e {
                DecisionEntry::Decided { created, .. } => Some((k.clone(), *created)),
                DecisionEntry::InFlight { .. } => None,
            })
            .min_by(|(ka, ca), (kb, cb)| ca.cmp(cb).then_with(|| ka.cmp(kb)))
            .map(|(k, _)| k);
        match victim {
            Some(k) => {
                self.entries.remove(&k);
                true
            }
            None => false,
        }
    }

    /// `ARC-2`/D4：软上限驱逐——循环驱逐终态 `Decided` 至不超上限；驱逐尽仍超限
    /// （仅余 `InFlight`）时不驱逐、记 warn 并递增 `overflow_count`。
    fn enforce_soft_cap(&mut self) {
        while self.entries.len() > self.max_entries {
            if !self.evict_oldest_decided() {
                self.overflow_count = self.overflow_count.saturating_add(1);
                tracing::warn!(
                    entries = self.entries.len(),
                    max = self.max_entries,
                    metric = "approval_decision_overflow_total",
                    "决策表仅余 InFlight，软上限暂时超出且不驱逐在途审批"
                );
                break;
            }
        }
    }

    /// waiter 落定：写入终态；容量按软上限驱逐终态条目（`InFlight` 永不驱逐）。
    fn resolve(&mut self, key: &str, decision: Option<bool>) {
        let decision = match decision {
            Some(true) => CredentialDecision::Approved,
            Some(false) => CredentialDecision::Denied,
            None => CredentialDecision::TimedOut,
        };
        self.entries.insert(
            key.to_string(),
            DecisionEntry::Decided {
                decision,
                created: Instant::now(),
            },
        );
        self.enforce_soft_cap();
    }

    #[cfg(test)]
    fn slot(&self, key: &str) -> Option<DecisionSlot> {
        self.entries.get(key).map(|e| match e {
            DecisionEntry::InFlight { .. } => DecisionSlot::Pending,
            DecisionEntry::Decided { decision, .. } => match decision {
                CredentialDecision::Approved => DecisionSlot::Approved,
                CredentialDecision::Denied => DecisionSlot::Denied,
                CredentialDecision::TimedOut => DecisionSlot::TimedOut,
            },
        })
    }

    /// `ARC-2`：软上限溢出累计（只读观测）——`/_admin/metrics` 暴露为
    /// `approval_decision_overflow_total`；`InFlight` 超限且无可驱逐终态时递增。
    pub fn overflow_count(&self) -> u64 { self.overflow_count }

    /// `ARC-2`：当前条目数（只读观测）——`/_admin/metrics` 暴露为
    /// `decision_table_size`，使软上限占用状态可观测（含暂时超限的 `InFlight`）。
    pub fn entry_count(&self) -> usize { self.entries.len() }
}

/// `ARC-2`：后台 waiter 落定（`None` = 超时按拒绝）——经受管状态决策表写入终态。
pub(crate) fn record_credential_decision(
    state: &impl AppStateParts,
    key: &str,
    decision: Option<bool>,
) {
    if let Ok(mut table) = state.decisions().lock() {
        table.resolve(key, decision);
    }
}

/// 只读决策槽位（测试/观测用）。
#[cfg(test)]
pub(crate) fn credential_decision_slot(
    state: &impl AppStateParts,
    key: &str,
) -> Option<DecisionSlot> {
    state
        .decisions()
        .lock()
        .ok()
        .and_then(|table| table.slot(key))
}

/// 只读决策表条目数（测试/观测用）。
#[cfg(test)]
pub(crate) fn credential_decision_len(state: &impl AppStateParts) -> usize {
    state
        .decisions()
        .lock()
        .map(|table| table.entries.len())
        .unwrap_or(0)
}

/// 显式消费决策表终态（`S3`/D3）。
fn consume_decision(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        table.consume(key);
    }
}

/// `CRD-6`：决策表占位/读取（注册/吊销 `202` 重试幂等复用；`Busy` = 已有在途票）。
pub(crate) fn begin_decision(state: &impl AppStateParts, key: &str) -> Option<BeginOutcome> {
    state
        .decisions()
        .lock()
        .ok()
        .map(|mut table| table.begin(key))
}

/// `CRD-6`：撤销占位（注册/吊销提交失败时回退，使同一请求可重试）。
pub(crate) fn cancel_decision(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        table.cancel(key);
    }
}

/// `CRD-6`：消费终态（阻塞模式在终态返回后清理占位）。
pub(crate) fn consume_decision_key(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        let _ = table.consume(key);
    }
}

fn pending_error(reason: &str) -> VeilError {
    VeilError::PendingApproval {
        message: format!("已转 Matrix 人工审批: {reason}"),
    }
}

/// `S1`/D1：泛化审批决策闭环——共享 `DecisionTable`（`:140`）、后台 waiter
/// [`await_credential_approval`] 与 [`clear_terminal_pending`] 终态清理，仅「批准后动作」
/// 由调用方注入（凭据取库 [`query_keepass`] / 吊销注册 `revoke_caller`）。三态对外一致：
/// 批准 → 执行动作并返回成功；拒绝/超时 → `403`；未决 → `202 + E_PENDING` 复用既有票
/// （不重复建单、不叠加 Matrix 消息）；满表仅余在途 → `429 + Retry-After: 60`
/// （`D4`，不伪造未决票）。`lane` 提供终态文案与自动放行策略。
/// `S3`/D3：批准动作成功后方消费决策表项，动作失败保留批准态供重试。
pub(crate) async fn approval_decision_closure<T, F, Fut>(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
    lane: ClosureLane,
    approved: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let begin = state
        .decisions()
        .lock()
        .ok()
        .map(|mut table| table.begin(key));
    match begin {
        None => return Err(record_pending(state, key, reason, entry, field).await),
        Some(BeginOutcome::Decided(CredentialDecision::Approved)) => {
            let result = approved().await;
            if result.is_ok() {
                consume_decision(state, key);
            }
            return result;
        }
        Some(BeginOutcome::Decided(CredentialDecision::Denied)) => {
            consume_decision(state, key);
            return Err(VeilError::Auth {
                message: format!("{}审批被拒绝", lane.label),
            });
        }
        Some(BeginOutcome::Decided(CredentialDecision::TimedOut)) => {
            consume_decision(state, key);
            return Err(VeilError::Auth {
                message: format!("{}审批超时，按拒绝处理", lane.label),
            });
        }
        Some(BeginOutcome::Busy) => return Err(pending_error(reason)),
        Some(BeginOutcome::Saturated) => {
            return Err(VeilError::RateLimited {
                retry_after_secs: 60,
            });
        }
        Some(BeginOutcome::Reserved) => {}
    }
    match submit_pending_with_branch(state, key, reason, lane.branch, entry, field).await {
        Ok(event_id) => {
            if let Ok(mut table) = state.decisions().lock() {
                table.set_event_id(key, &event_id);
            }
            let owned = (*state).clone();
            let key_owned = key.to_string();
            tokio::spawn(async move {
                let decision = await_credential_approval(&owned, &event_id).await;
                // `T1`/D1：`applied_auto` 必须早于 `clear_terminal_pending` 读取——
                // 后者移除矩阵侧票后回读恒 `None`。吊销 lane（`Reject`）把 `🔓`
                // （`Some(true) && auto`）落定的批准改写为拒绝。
                let auto = owned
                    .approval()
                    .applied_auto(&event_id)
                    .await
                    .unwrap_or(false);
                let decision =
                    if lane.auto_policy == AutoPolicy::Reject && decision == Some(true) && auto {
                        Some(false)
                    } else {
                        decision
                    };
                clear_terminal_pending(&owned, &key_owned, &event_id).await;
                record_credential_decision(&owned, &key_owned, decision);
            });
            Err(pending_error(reason))
        }
        Err(err) => {
            if let Ok(mut table) = state.decisions().lock() {
                table.cancel(key);
            }
            Err(err)
        }
    }
}

/// `R2`/D2：异步 `202` 消费闭环（凭据路径）。入口先消费决策表——批准取凭据、
/// 拒绝/超时 `403`；未决则复用既有票（不再建单），无记录方建单并 spawn 后台 waiter 落定。
async fn approval_async_202(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    approval_decision_closure(
        state,
        key,
        reason,
        entry,
        field,
        ClosureLane {
            label: "凭据",
            auto_policy: AutoPolicy::Accept,
            branch: matrix::MatrixBranch::Credential,
        },
        || query_keepass(state, entry, field, use_token),
    )
    .await
}

/// `C8`/D8：凭据审批三个终态（批准/拒绝/超时）的唯一落定入口；
/// 无论何种终态均先同批清理内存侧与矩阵侧票，再返回。
async fn settle_approval(
    state: &impl AppStateParts,
    key: &str,
    event_id: &str,
    decision: Option<bool>,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    clear_terminal_pending(state, key, event_id).await;
    match decision {
        Some(true) => query_keepass(state, entry, field, use_token).await,
        Some(false) => Err(VeilError::Auth {
            message: "凭据审批被拒绝".to_string(),
        }),
        None => Err(VeilError::Auth {
            message: "凭据审批超时，按拒绝处理".to_string(),
        }),
    }
}

pub(crate) async fn approval_dual_mode(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    reason: &str,
    entry: &str,
    field: Option<&str>,
    use_token: bool,
) -> Result<serde_json::Value> {
    if !state.config().credential_block_wait {
        return approval_async_202(state, key, reason, entry, field, use_token).await;
    }
    let event_id = submit_pending_with_branch(
        state,
        key,
        reason,
        matrix::MatrixBranch::Credential,
        entry,
        field,
    )
    .await?;
    let timeout =
        Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64);
    let decision = state.approval().ask(&event_id, timeout).await;
    settle_approval(state, key, &event_id, decision, entry, field, use_token).await
}

pub(crate) fn notify_hash_change(state: &impl AppStateParts, key: &str, detail: &str) {
    let summary = format!("哈希变更 :: {key} :: {detail}");
    let text = state
        .notify()
        .format_approval(matrix::MatrixBranch::Credential, None, &summary);
    state.notify().notify_text(text);
    tracing::warn!("调用方哈希变更通知: {summary}");
}

/// `CRD-12`：旧哈希宽限内放行通知（按条目 + 宽限窗口去重，同窗口仅发一次）。
pub(crate) fn notify_hash_grace_once(
    state: &impl AppStateParts,
    entry: &str,
    old_hash: &str,
    expires_at: u64,
) {
    let dedup_key = format!("{entry}\u{1}{old_hash}\u{1}{expires_at}");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    if !first_grace_notification(&dedup_key, expires_at, now_secs) {
        return;
    }
    notify_hash_change(state, entry, "old_hash宽限内放行");
}

/// 凭据审批问询（`credential_approval_timeout_secs` 超时口径，默认 300s；与阻塞模式同源）：
/// 超时/发送失败返回 None，调用方按 rejected 处理。
pub async fn await_credential_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    let timeout =
        Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64);
    state.approval().ask(event_id, timeout).await
}

/// 审计审批问询（`AUDIT_TIMEOUT` 口径，默认 90s）：超时返回 None，调用方按 rejected 处理。
pub async fn await_audit_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    state.approval().ask_audit(event_id).await
}

#[cfg(test)]
mod tests;
