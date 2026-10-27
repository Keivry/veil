//! 审批决策表：三态、占位结果与 `DecisionTable` 的纯内存读写。
//!
//! owner 声明：决策表数据结构与容量纪律归本文件；建单/问询流程归
//! `super::approval`，共享状态一律经 [`AppStateParts`] 读态。本文件不持有
//! 锁——`Arc<Mutex<DecisionTable>>` 由 `AppState` 承载。

use {
    super::AppStateParts,
    crate::approval::PENDING_TTL_SECS,
    std::{collections::HashMap, time::Instant},
};

/// 异步 `202` 决策三态。后台 waiter 落定后按 `pending_key` 落表，
/// 重试请求先消费此表：批准 → 取凭据，拒绝/超时 → `403`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialDecision {
    Approved,
    Denied,
    TimedOut,
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
    /// 满表仅余 `InFlight`——新键无票，SHALL NOT 伪造 `202 + E_PENDING`。
    Saturated,
}

#[derive(Debug)]
pub(crate) enum DecisionEntry {
    InFlight {
        event_id: Option<String>,
    },
    Decided {
        decision: CredentialDecision,
        created: Instant,
    },
}

/// 审批决策表（键 = `pending_key`），由 `AppState` 以
/// `Arc<Mutex<DecisionTable>>` 承载（进程级 `static` 已移除）。容量约束仅作用于终态：
/// `begin` 满表时先驱逐终态 `Decided`（按 `created` 升序，同刻以 key 字典序 tie-break）
/// 腾位，仅余 `InFlight` 时返回 `BeginOutcome::Saturated`（调用点映射
/// `429 + Retry-After: 60`，不插入、不伪造 `202`），`InFlight` 永不驱逐；`resolve`
/// 落定终态同受驱逐约束，无可驱逐终态时记 warn 并递增 `overflow_count`
/// （`approval_decision_overflow_total`）。
#[derive(Debug)]
pub struct DecisionTable {
    entries: HashMap<String, DecisionEntry>,
    max_entries: usize,
    overflow_count: u64,
}

pub(crate) const DECISION_TABLE_MAX_ENTRIES: usize = 4096;

impl Default for DecisionTable {
    fn default() -> Self { Self::with_max_entries(DECISION_TABLE_MAX_ENTRIES) }
}

impl DecisionTable {
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            overflow_count: 0,
        }
    }

    /// 清扫过期已决条目（一次性消费语义的兜底）。
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.entries.retain(|_, e| match e {
            DecisionEntry::InFlight { .. } => true,
            DecisionEntry::Decided { created, .. } => {
                now.duration_since(*created).as_secs() < PENDING_TTL_SECS
            }
        });
    }

    /// 占位入口。顺序为 `sweep(now)` → 满表时循环驱逐最早终态 `Decided`
    /// 腾位 → 满表且仅余 `InFlight` 时饱和拒绝（不插入、不驱逐在途）；同键在途仍
    /// [`BeginOutcome::Busy`]，同键终态仍只读 [`BeginOutcome::Decided`]。
    pub(crate) fn begin(&mut self, key: &str) -> BeginOutcome {
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

    /// 终态显式消费。`begin` 只读，动作成功/终态返回后由调用方消费；
    /// 动作失败时保留已批准态，使同一请求重试仍可按已批准执行。
    pub(crate) fn consume(&mut self, key: &str) -> bool { self.entries.remove(key).is_some() }

    pub(crate) fn set_event_id(&mut self, key: &str, event_id: &str) {
        if let Some(DecisionEntry::InFlight { event_id: slot }) = self.entries.get_mut(key) {
            *slot = Some(event_id.to_string());
        }
    }

    pub(crate) fn cancel(&mut self, key: &str) { self.entries.remove(key); }

    /// 驱逐 `created` 最早的终态 `Decided`（同刻以 key 字典序 tie-break）；
    /// 仅余 `InFlight` 时返回 `false`（在途永不驱逐）。
    pub(crate) fn evict_oldest_decided(&mut self) -> bool {
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

    /// 软上限驱逐——循环驱逐终态 `Decided` 至不超上限；驱逐尽仍超限
    /// （仅余 `InFlight`）时不驱逐、记 warn 并递增 `overflow_count`。
    pub(crate) fn enforce_soft_cap(&mut self) {
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
    pub(crate) fn resolve(&mut self, key: &str, decision: Option<bool>) {
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
    pub(crate) fn slot(&self, key: &str) -> Option<DecisionSlot> {
        self.entries.get(key).map(|e| match e {
            DecisionEntry::InFlight { .. } => DecisionSlot::Pending,
            DecisionEntry::Decided { decision, .. } => match decision {
                CredentialDecision::Approved => DecisionSlot::Approved,
                CredentialDecision::Denied => DecisionSlot::Denied,
                CredentialDecision::TimedOut => DecisionSlot::TimedOut,
            },
        })
    }

    /// 条目快照（只读；测试断言容量纪律用）。
    #[cfg(test)]
    pub(crate) fn entries(&self) -> &std::collections::HashMap<String, DecisionEntry> {
        &self.entries
    }

    /// 软上限溢出累计（只读观测）——`/_admin/metrics` 暴露为
    /// `approval_decision_overflow_total`；`InFlight` 超限且无可驱逐终态时递增。
    pub fn overflow_count(&self) -> u64 { self.overflow_count }

    /// 当前条目数（只读观测）——`/_admin/metrics` 暴露为
    /// `decision_table_size`，使软上限占用状态可观测（含暂时超限的 `InFlight`）。
    pub fn entry_count(&self) -> usize { self.entries.len() }

    /// 该 `pending_key` 是否存在任意条目（`InFlight` 或 `Decided`）。
    /// 供审批幂等重试的限流豁免判定：只回答「有无」，不区分状态、不消费。
    /// 调用方 SHALL 先 [`Self::sweep`]——`begin` 与
    /// [`credential_decision_exists`] 均如此——否则已过期的终态仍会答 true。
    pub(crate) fn has_entry(&self, key: &str) -> bool { self.entries.contains_key(key) }
}

/// 后台 waiter 落定（`None` = 超时按拒绝）——经受管状态决策表写入终态。
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
        .map(|table| table.entry_count())
        .unwrap_or(0)
}

/// 该 `pending_key` 是否存在任意决策表条目（`InFlight` 或 `Decided`）——供审批
/// 幂等重试的限流豁免判定。加锁失败按「无条目」处理（不 panic、不跨 `.await` 持锁）。
///
/// 取锁后先 [`DecisionTable::sweep`] 再 [`DecisionTable::has_entry`]，与 `begin`
/// 的清扫保持同一判据：终态 `Decided` 只在 `PENDING_TTL_SECS` 后仍保留于表内（一次性
/// 消费语义的兜底），若不先清扫，这条已过期条目会让紧接着的 `begin()` 之前的限流
/// 判定答 true 而跳过 2s 限流，随后 `begin()` 自行清扫并为一个全新票占位——即新票
/// 绕过了限流。单次取锁、不跨 `.await`。
pub(crate) fn credential_decision_exists(state: &impl AppStateParts, key: &str) -> bool {
    state.decisions().lock().ok().is_some_and(|mut table| {
        table.sweep(Instant::now());
        table.has_entry(key)
    })
}
