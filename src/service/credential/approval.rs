//! 审批/pending 链：建单、双模问询、哈希变更通知、问询口径。
//!
//! owner 声明：双模执行（`approval_dual_mode`）归本文件；单据存储与问询
//! trait 归 `crate::approval`（经其 `PendingApprovals`/`PendingRecord` 接口协作），
//! 分支流转归 `service::matrix`；三处互不垫片。

use {
    super::{
        super::{
            audit::sanitize_for_log,
            matrix::{self, CallerIdentity, Fact, MatrixBranch, TicketContext},
        },
        AppStateParts,
        vault_ops::{self, query_keepass},
    },
    crate::{
        approval::{PENDING_TTL_SECS, PendingRecord},
        error::{Result, VeilError},
    },
    std::{
        collections::HashMap,
        sync::{Mutex, OnceLock},
        time::Duration,
    },
};

// 决策表已迁至 `super::decision`（800 行预算）；经此处重导出保持既有导入路径不变。
pub use super::decision::DecisionTable;
pub(crate) use super::decision::{BeginOutcome, CredentialDecision, record_credential_decision};
#[cfg(test)]
pub(crate) use super::decision::{
    DECISION_TABLE_MAX_ENTRIES,
    DecisionEntry,
    DecisionSlot,
    credential_decision_len,
    credential_decision_slot,
};

/// 授权到期建票的原因标签：该原因的票在批准后须刷新授权窗口（续期）。
pub(crate) const AUTHORIZATION_EXPIRED_REASON: &str = "authorization_expired";

/// 凭据票的请求对象：`{entry} / {field}`，缺字段时仅 `{entry}`。
pub(crate) fn credential_subject(entry: &str, field: Option<&str>) -> String {
    let entry = entry.trim();
    match field.map(str::trim).filter(|field| !field.is_empty()) {
        Some(field) if !entry.is_empty() => format!("{entry} / {field}"),
        _ => entry.to_string(),
    }
}

/// 哈希变更票的唯一事实行：期望 → 实际（各自 8 位短前缀）。
pub(crate) fn hash_change_fact<'a>(expected: &str, actual: &str) -> Vec<Fact<'a>> {
    vec![Fact {
        label: "哈希",
        value: format!(
            "{} → {}",
            matrix::short_hash(expected),
            matrix::short_hash(actual)
        ),
    }]
}

/// 一次凭据审批请求的上下文（双模入口共用，避免长参数列表）。
pub(crate) struct CredentialApproval<'a> {
    pub key: &'a str,
    /// 调用方路径，仅 `authorization_expired` 票在批准后用它刷新授权窗口。
    pub caller_path: &'a str,
    pub reason: &'a str,
    pub entry: &'a str,
    pub field: Option<&'a str>,
    pub use_token: bool,
    pub caller: CallerIdentity<'a>,
    pub subject: String,
    pub facts: Vec<Fact<'a>>,
}

impl<'a> CredentialApproval<'a> {
    pub(crate) fn new(
        key: &'a str,
        caller_path: &'a str,
        reason: &'a str,
        entry: &'a str,
        field: Option<&'a str>,
        use_token: bool,
    ) -> Self {
        Self {
            key,
            caller_path,
            reason,
            entry,
            field,
            use_token,
            caller: CallerIdentity {
                path: caller_path,
                name: None,
                desc: None,
                enrolled: false,
            },
            subject: credential_subject(entry, field),
            facts: Vec::new(),
        }
    }

    pub(crate) fn with_caller(mut self, caller: CallerIdentity<'a>) -> Self {
        self.caller = caller;
        self
    }

    pub(crate) fn with_facts(mut self, facts: Vec<Fact<'a>>) -> Self {
        if !facts.is_empty() {
            self.facts = facts;
        }
        self
    }

    /// 渲染上下文：`subject`/`facts` 由本结构持有，借用期与 `self` 同寿。
    pub(crate) fn ticket(&self) -> TicketContext<'_> {
        TicketContext {
            branch: MatrixBranch::Credential,
            subject: self.subject.as_str(),
            caller: self.caller,
            reason: self.reason,
            facts: &self.facts,
        }
    }
}

/// 宽限通知去重上限（进程级，防无界增长；容量触发 TTL 清扫 + 逐出最小 `expires_at`）。
const GRACE_NOTIFY_DEDUP_MAX: usize = 4096;

/// 宽限通知去重表（键 = 条目 + 宽限窗口，value = 该窗口 `expires_at` 秒），
/// 同窗口仅首次通知。
static GRACE_NOTIFY_DEDUP: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();

/// `dedup_key` 是否首次出现（同窗口重复返回 `false`，不重复通知）。
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

/// 统一终态清理——同时清内存侧 `PendingApprovals`（health `pending` 计数来源）
/// 与矩阵侧票，使 `GET /health pending` 在批准/拒绝/超时后即时归零，不等 60s 清扫。
pub(crate) async fn clear_terminal_pending(state: &impl AppStateParts, key: &str, event_id: &str) {
    state.pending().remove(key);
    state.approval().remove(event_id).await;
}

/// Matrix 功能关闭时的 fail-closed 错误：指名缺失键，明确「按拒绝处理」，
/// 区别于泛化的 tracked 发送失败文案。供建单前早退与异步 202 预留前早退共用。
fn matrix_disabled_error(state: &impl AppStateParts) -> VeilError {
    let keys = state.config().missing_matrix_keys().join("、");
    VeilError::Auth {
        message: format!("Matrix 未配置（缺 {keys}），审批功能已关闭，按拒绝处理"),
    }
}

/// 建单（原因串分类入口）：`reason` 决定分支，票面上下文提供了请求对象与调用方。
pub(crate) async fn submit_pending(
    state: &impl AppStateParts,
    key: &str,
    ctx: &TicketContext<'_>,
) -> Result<String> {
    let branch = matrix::MatrixBranch::from_reason(ctx.reason)
        .map_err(|message| VeilError::BadRequest { message })?;
    if !branch.is_known() {
        return Err(VeilError::BadRequest {
            message: format!("审批原因无法分类，按拒绝 fail-closed: {}", ctx.reason),
        });
    }
    if !branch.is_matrix_order_branch() {
        return Err(VeilError::BadRequest {
            message: format!(
                "审批原因被分类为 HashChange/Audit 标签，该标签不建 Matrix 票（仅用于原因串分类与文案），按拒绝 fail-closed: {}",
                ctx.reason
            ),
        });
    }
    let classified = TicketContext {
        branch,
        ..ctx.clone()
    };
    submit_pending_with_branch(state, key, &classified).await
}

/// 按分支取内存 pending 清扫 TTL（秒）——凭据/注册/命令/吊销四类建单票
/// 保留至 300s 阻塞超时；`HashChange`/`Audit`/`Unknown` 等非建单分类标签
/// 与空闲类一样维持 60s 上限（`HashChange` 已改为同步 `reaction` 落定、不建票）。
fn pending_ttl_secs(branch: matrix::MatrixBranch) -> u64 {
    match branch {
        matrix::MatrixBranch::Register
        | matrix::MatrixBranch::Revoke
        | matrix::MatrixBranch::Credential
        | matrix::MatrixBranch::Command => matrix::CREDENTIAL_TIMEOUT_SECS,
        _ => PENDING_TTL_SECS,
    }
}

/// 显式分支建单：调用方直接指定分支，避免调用方路径内的
/// 关键词（如 `unlock`/`credential`）经 `from_reason` 误判分支。
///
/// 审批建单走 tracked 发送——先 `await` 取 Bot 返回的真实 Matrix event id，
/// 以真实 id 为 pending 键 `submit_branch`；发送失败/未取得 id 时 fail-closed（不建单，
/// 返回错误）。与事件环/spool 的 `notify_text` best-effort 语义分属两条路由。
pub(crate) async fn submit_pending_with_branch(
    state: &impl AppStateParts,
    key: &str,
    ctx: &TicketContext<'_>,
) -> Result<String> {
    let branch = ctx.branch;
    if !branch.is_matrix_order_branch() {
        return Err(VeilError::BadRequest {
            message: format!(
                "分支 {branch:?} 不是 Matrix 建单分支（HashChange/Audit 仅为原因分类标签），按拒绝 fail-closed"
            ),
        });
    }
    if !state.config().matrix_enabled() {
        return Err(matrix_disabled_error(state));
    }
    let text = state.notify().format_ticket(ctx);
    let Some(event_id) = state.notify().send_tracked(text).await else {
        tracing::warn!(
            "审批发送失败，按拒绝 fail-closed（不建单）: key {key} 原因 {} subject {}",
            ctx.reason,
            sanitize_for_log(ctx.subject)
        );
        return Err(VeilError::Auth {
            message: "审批发送失败，已按拒绝处理".to_string(),
        });
    };
    state.pending().insert(PendingRecord::with_ttl(
        key,
        ctx.reason,
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
    tracing::info!(
        "审批已发送: event {event_id} key {key} 原因 {} subject {}",
        ctx.reason,
        sanitize_for_log(ctx.subject)
    );
    Ok(event_id)
}

pub(crate) async fn record_pending(
    state: &impl AppStateParts,
    key: &str,
    ctx: &TicketContext<'_>,
) -> VeilError {
    match submit_pending(state, key, ctx).await {
        Ok(_) => VeilError::PendingApproval {
            message: format!(
                "已转 Matrix 人工审批: {} ({})",
                sanitize_for_log(ctx.subject),
                ctx.reason
            ),
        },
        Err(err) => err,
    }
}

/// 闭环批准动作对「持久放行」表情（`♾️` → `always=true`）的策略。
/// 吊销 lane 传 [`AutoPolicy::Reject`]（纵深防御：吊销票本就不受理 `♾️`）；
/// 凭据 lane 传 [`AutoPolicy::Accept`]（行为不变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoPolicy {
    Accept,
    Reject,
}

/// 闭环 lane 声明——终态文案与「持久放行」策略成对传入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClosureLane {
    pub label: &'static str,
    pub auto_policy: AutoPolicy,
    /// 建单分支——决定矩阵票与内存 pending 的 TTL 口径（凭据/注册类 300s）。
    pub branch: matrix::MatrixBranch,
}

/// 显式消费决策表终态。
fn consume_decision(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        table.consume(key);
    }
}

/// 决策表占位/读取（注册/吊销 `202` 重试幂等复用；`Busy` = 已有在途票）。
pub(crate) fn begin_decision(state: &impl AppStateParts, key: &str) -> Option<BeginOutcome> {
    state
        .decisions()
        .lock()
        .ok()
        .map(|mut table| table.begin(key))
}

/// 撤销占位（注册/吊销提交失败时回退，使同一请求可重试）。
pub(crate) fn cancel_decision(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        table.cancel(key);
    }
}

/// 消费终态（阻塞模式在终态返回后清理占位）。
pub(crate) fn consume_decision_key(state: &impl AppStateParts, key: &str) {
    if let Ok(mut table) = state.decisions().lock() {
        let _ = table.consume(key);
    }
}

fn pending_error(ctx: &TicketContext<'_>) -> VeilError {
    VeilError::PendingApproval {
        message: format!(
            "已转 Matrix 人工审批: {} ({})",
            sanitize_for_log(ctx.subject),
            ctx.reason
        ),
    }
}

/// 泛化审批决策闭环——共享 `DecisionTable`（`super::decision`）、后台 waiter
/// [`await_credential_approval`] 与 [`clear_terminal_pending`] 终态清理，仅「批准后动作」
/// 由调用方注入（凭据取库 [`query_keepass`] / 吊销注册 `revoke_caller`）。三态对外一致：
/// 批准 → 执行动作并返回成功；拒绝/超时 → `403`；未决 → `202 + E_PENDING` 复用既有票
/// （不重复建单、不叠加 Matrix 消息）；满表仅余在途 → `429 + Retry-After: 60`
/// （不伪造未决票）。`lane` 提供终态文案与自动放行策略。
/// 批准动作成功后方消费决策表项，动作失败保留批准态供重试。
pub(crate) async fn approval_decision_closure<T, F, Fut>(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    key: &str,
    ctx: &TicketContext<'_>,
    lane: ClosureLane,
    approved: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    if !state.config().matrix_enabled() {
        return Err(matrix_disabled_error(state));
    }
    let begin = state
        .decisions()
        .lock()
        .ok()
        .map(|mut table| table.begin(key));
    match begin {
        None => return Err(record_pending(state, key, ctx).await),
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
        Some(BeginOutcome::Busy) => return Err(pending_error(ctx)),
        Some(BeginOutcome::Saturated) => {
            return Err(VeilError::RateLimited {
                retry_after_secs: 60,
            });
        }
        Some(BeginOutcome::Reserved) => {}
    }
    let ticket = TicketContext {
        branch: lane.branch,
        ..ctx.clone()
    };
    match submit_pending_with_branch(state, key, &ticket).await {
        Ok(event_id) => {
            if let Ok(mut table) = state.decisions().lock() {
                table.set_event_id(key, &event_id);
            }
            let owned = (*state).clone();
            let key_owned = key.to_string();
            crate::logging::spawn_in_request_span(async move {
                let decision = await_credential_approval(&owned, &event_id).await;
                // `applied_always` 必须早于 `clear_terminal_pending` 读取——
                // 后者移除矩阵侧票后回读恒 `None`。
                let always = owned
                    .approval()
                    .applied_always(&event_id)
                    .await
                    .unwrap_or(false);
                let decision =
                    if lane.auto_policy == AutoPolicy::Reject && decision == Some(true) && always {
                        Some(false)
                    } else {
                        decision
                    };
                clear_terminal_pending(&owned, &key_owned, &event_id).await;
                record_credential_decision(&owned, &key_owned, decision);
            });
            Err(pending_error(ctx))
        }
        Err(err) => {
            if let Ok(mut table) = state.decisions().lock() {
                table.cancel(key);
            }
            Err(err)
        }
    }
}

/// 异步 `202` 消费闭环（凭据路径）。入口先消费决策表——批准取凭据、
/// 拒绝/超时 `403`；未决则复用既有票（不再建单），无记录方建单并 spawn 后台 waiter 落定。
async fn approval_async_202(
    state: &(impl AppStateParts + Clone + Send + Sync + 'static),
    req: &CredentialApproval<'_>,
) -> Result<serde_json::Value> {
    let renew = req.reason == AUTHORIZATION_EXPIRED_REASON;
    let (entry, field, use_token, caller_path) =
        (req.entry, req.field, req.use_token, req.caller_path);
    let ctx = req.ticket();
    approval_decision_closure(
        state,
        req.key,
        &ctx,
        ClosureLane {
            label: "凭据",
            auto_policy: AutoPolicy::Accept,
            branch: matrix::MatrixBranch::Credential,
        },
        || async move {
            let outcome = query_keepass(state, entry, field, use_token).await;
            if renew && outcome.is_ok() {
                vault_ops::renew_authorization(state, caller_path).await;
            }
            outcome
        },
    )
    .await
}

/// 凭据审批三个终态（批准/拒绝/超时）的唯一落定入口；
/// 无论何种终态均先同批清理内存侧与矩阵侧票，再返回。
async fn settle_approval(
    state: &impl AppStateParts,
    req: &CredentialApproval<'_>,
    event_id: &str,
    decision: Option<bool>,
) -> Result<serde_json::Value> {
    clear_terminal_pending(state, req.key, event_id).await;
    match decision {
        Some(true) => {
            let outcome = query_keepass(state, req.entry, req.field, req.use_token).await;
            if req.reason == AUTHORIZATION_EXPIRED_REASON && outcome.is_ok() {
                vault_ops::renew_authorization(state, req.caller_path).await;
            }
            outcome
        }
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
    req: &CredentialApproval<'_>,
) -> Result<serde_json::Value> {
    if !state.config().credential_block_wait {
        return approval_async_202(state, req).await;
    }
    let ctx = req.ticket();
    let event_id = submit_pending_with_branch(state, req.key, &ctx).await?;
    let timeout =
        Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64);
    let decision = state.approval().ask(&event_id, timeout).await;
    settle_approval(state, req, &event_id, decision).await
}

pub(crate) fn notify_hash_change(
    state: &impl AppStateParts,
    key: &str,
    detail: &str,
    approved: Option<bool>,
) {
    let facts = vec![Fact {
        label: "说明",
        value: detail.to_string(),
    }];
    let ctx = TicketContext {
        branch: MatrixBranch::HashChange,
        subject: key,
        caller: CallerIdentity {
            path: "",
            name: None,
            desc: None,
            enrolled: false,
        },
        reason: "hash_mismatch",
        facts: &facts,
    };
    let text = state.notify().format_notice(&ctx, approved);
    state.notify().notify_text(text);
    tracing::warn!("调用方哈希变更通知: {key} :: {detail}");
}

/// 旧哈希宽限内放行通知（按条目 + 宽限窗口去重，同窗口仅发一次）。
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
    notify_hash_change(state, entry, "old_hash宽限内放行", Some(true));
}

/// 凭据审批问询（`credential_approval_timeout_secs` 超时口径，默认 300s；与阻塞模式同源）：
/// 超时/发送失败返回 None，调用方按 rejected 处理。
pub async fn await_credential_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    let timeout =
        Duration::from_secs(state.config().credential_approval_timeout_secs.max(1) as u64);
    state.approval().ask(event_id, timeout).await
}

/// 审计审批问询（`AUDIT_TIMEOUT_SECS` 口径，默认 90s）：超时返回 None，调用方按 rejected 处理。
pub async fn await_audit_approval(state: &impl AppStateParts, event_id: &str) -> Option<bool> {
    state.approval().ask_audit(event_id).await
}

#[cfg(test)]
mod tests;
