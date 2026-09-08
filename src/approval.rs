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
    fn 占位审批保持挂起() {
        let gateway = NoopApproval;
        let record = PendingRecord::new("k", "hash_mismatch");
        assert_eq!(gateway.request_approval(&record), ApprovalOutcome::Pending);
    }

    #[test]
    fn 挂起表可回查() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("k", "r"));
        assert_eq!(table.len(), 1);
        assert!(table.get("k").is_some());
    }

    #[test]
    fn 超期孤儿被清扫器回收() {
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
    fn 同key重复建单幂等覆盖() {
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("k", "hash_mismatch"));
        table.insert(PendingRecord::new("k", "auto_approve_none"));
        assert_eq!(table.len(), 1, "同 key 重复建单不得翻倍");
        assert_eq!(table.get("k").unwrap().reason, "auto_approve_none");
    }
}
