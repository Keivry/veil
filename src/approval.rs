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

    pub fn len(&self) -> usize { self.inner.lock().map(|g| g.len()).unwrap_or(0) }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
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
}
