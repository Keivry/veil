//! D1 审批收敛：三文件分工（本文件存单据 + 问询网关 trait）。
//!
//! - 本文件：`PendingApprovals` 待审单据存储（`Mutex<HashMap>`，`PENDING_TTL_SECS` 60s 孤儿上限）+
//!   `ApprovalGateway` 问询网关 trait（`ask`/`ask_audit` + 300s/90s 分表超时）。
//! - `service::credential::approval`：`approval_dual_mode` 双模（默认 202 抛单建单即返；
//!   `CREDENTIAL_BLOCK_WAIT=1` 时 300s 阻塞等 reaction；审计问询走 `AUDIT_TIMEOUT` 90s 口径）。
//! - `service::matrix`：`MatrixBranch` 五业务分支（Unlock/Register/HashChange/Credential/Audit
//!     + Unknown 兜底）流转，凭据 300s / 审计 90s 分表超时，`ORPHAN_SWEEP_SECS` 60s 孤儿清扫，
//!       `spawn_sync_loop` 常驻同步。
//!
//! D1 保活二选一锁定：流内保活唯一实现为 `service::audit_hold::RequestKeepalive`
//! （`handler::llm::pump` 经 `spawn_gated` 接线，间隔消费 `service::sse::KEEPALIVE_INTERVAL`
//! 10s）；管理面 SSE 60s ping（`service::admin::sse::SSE_PING_INTERVAL`）+ 5min 强制重连
//! 分属不同链路，差异有意。`KeepaliveTracker`（时间戳自检形态，生产零接线）已删，不再立项。
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct PendingRecord {
    pub key: String,
    pub reason: String,
    pub created_ms: u128,
}

impl PendingRecord {
    pub fn new(key: &str, reason: &str) -> Self {
        Self {
            key: key.to_string(),
            reason: reason.to_string(),
            created_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingApprovals {
    inner: Mutex<HashMap<String, PendingRecord>>,
}

/// 孤儿 pending 存活上限（秒）；超限由清扫器回收，保证内存有界。
pub const PENDING_TTL_SECS: u64 = 60;

impl PendingApprovals {
    pub fn insert(&self, record: PendingRecord) {
        self.inner
            .lock()
            .map(|mut g| g.insert(record.key.clone(), record))
            .ok();
    }

    pub fn get(&self, key: &str) -> Option<PendingRecord> {
        self.inner.lock().ok()?.get(key).cloned()
    }

    pub fn remove(&self, key: &str) { self.inner.lock().map(|mut g| g.remove(key)).ok(); }

    /// 全清：`lock` 语义配套，清空未决审批 + pending 表（口令缓存/KeePass 会话由网关侧接线清理）。
    pub fn clear_all(&self) -> usize {
        self.inner
            .lock()
            .map(|mut g| {
                let n = g.len();
                g.clear();
                n
            })
            .unwrap_or(0)
    }

    pub fn len(&self) -> usize { self.inner.lock().map(|g| g.len()).unwrap_or(0) }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn sweep_expired(&self) -> usize {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let ttl_ms = u128::from(PENDING_TTL_SECS) * 1000;
        self.inner
            .lock()
            .map(|mut g| {
                let before = g.len();
                g.retain(|_, r| now_ms.saturating_sub(r.created_ms) < ttl_ms);
                before - g.len()
            })
            .unwrap_or(0)
    }

    pub fn spawn_sweeper(self: &std::sync::Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(PENDING_TTL_SECS));
            loop {
                ticker.tick().await;
                me.sweep_expired();
            }
        })
    }
}

pub trait ApprovalGateway: Send + Sync + std::fmt::Debug {
    fn request_approval(&self, record: &PendingRecord) -> ApprovalOutcome;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Pending,
    Approved,
    Blocked,
}

#[derive(Debug, Default)]
pub struct NoopApproval;

impl ApprovalGateway for NoopApproval {
    fn request_approval(&self, _record: &PendingRecord) -> ApprovalOutcome {
        ApprovalOutcome::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_approval_stays_pending() {
        let gateway = NoopApproval;
        let record = PendingRecord::new("k", "hash_mismatch");
        assert_eq!(gateway.request_approval(&record), ApprovalOutcome::Pending);
    }

    #[test]
    fn pending_table_supports_lookup() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("k", "r"));
        assert_eq!(table.len(), 1);
        assert!(table.get("k").is_some());
    }

    #[test]
    fn expired_orphans_reclaimed_by_sweeper() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("fresh", "r"));
        let mut stale = PendingRecord::new("stale", "r");
        stale.created_ms = stale
            .created_ms
            .saturating_sub(u128::from(PENDING_TTL_SECS) * 1000 + 1);
        table.insert(stale);
        assert_eq!(table.len(), 2);
        assert_eq!(table.sweep_expired(), 1);
        assert!(table.get("fresh").is_some());
        assert!(table.get("stale").is_none());
        table.remove("fresh");
        assert!(table.is_empty());
    }

    #[test]
    fn clear_all_leaves_no_remainder() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("k1", "hash_mismatch"));
        table.insert(PendingRecord::new("k2", "auto_approve_none"));
        assert_eq!(table.clear_all(), 2);
        assert!(table.is_empty());
        assert_eq!(table.clear_all(), 0);
    }

    #[test]
    fn duplicate_key_insert_overwrites_idempotently() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("k", "hash_mismatch"));
        table.insert(PendingRecord::new("k", "auto_approve_none"));
        assert_eq!(table.len(), 1, "同 key 重复建单不得翻倍");
        assert_eq!(table.get("k").unwrap().reason, "auto_approve_none");
    }

    #[test]
    fn concurrent_unlock_same_key_single_record_without_deadlock() {
        use std::sync::Arc;
        let table = Arc::new(PendingApprovals::default());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let t = Arc::clone(&table);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    t.insert(PendingRecord::new("unlock-k", "hash_mismatch"));
                }
            }));
        }
        for h in handles {
            h.join().expect("并发插入不得死锁");
        }
        assert_eq!(table.len(), 1, "并发双解锁仅一次 Matrix ask 建单");
    }
}
