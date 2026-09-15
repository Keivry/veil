//! D1 审批收敛：本文件承载待审单据存储（`PendingApprovals`）。
//!
//! H3.1 owner 锁定：单据存储（`PendingApprovals`）归本文件，双模执行
//! （`approval_dual_mode`）归 `service::credential::approval`，
//! 分支流转归 `service::matrix`；三处职责正交、互不垫片，新代码按此归属。
//!
//! - 本文件：`PendingApprovals` 待审单据存储（`Mutex<HashMap>`，`PENDING_TTL_SECS` 60s 孤儿上限）。
//! - `service::credential::approval`：`approval_dual_mode` 双模（默认 202 抛单建单即返；
//!   `CREDENTIAL_BLOCK_WAIT=1` 时 300s 阻塞等 reaction；审计问询走 `AUDIT_TIMEOUT` 90s 口径）。
//! - `service::matrix`：`MatrixBranch` 五业务分支（Unlock/Register/HashChange/Credential/Audit
//!     + Unknown 兜底）流转，凭据 300s / 审计 90s 分表超时，`ORPHAN_SWEEP_SECS` 60s 孤儿清扫，
//!       `spawn_sync_loop` 常驻同步。
//!
//! D1 保活二选一锁定：流内保活唯一实现为 `service::audit::RequestKeepalive`
//! （`service::audit::RequestKeepalive::spawn_gated` 接线于 `src/handler/llm/pump/spawn/setup.rs`，
//! 间隔消费 `service::sse::KEEPALIVE_INTERVAL`
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
    /// 本记录的清扫 TTL（秒，`AUTH-9`）：缺省 `PENDING_TTL_SECS`（60s，空闲/审计/解锁类）；
    /// 凭据/注册/哈希变更类阻塞票由建单侧以 300s 覆盖，使其不被 60s 空闲清扫误收。
    ttl_secs: u64,
}

impl PendingRecord {
    pub fn new(key: &str, reason: &str) -> Self { Self::with_ttl(key, reason, PENDING_TTL_SECS) }

    /// 指定清扫 TTL 的构造（`AUTH-9`）：凭据类阻塞票传 `300`，其余沿用 `PENDING_TTL_SECS`。
    pub fn with_ttl(key: &str, reason: &str, ttl_secs: u64) -> Self {
        Self {
            key: key.to_string(),
            reason: reason.to_string(),
            created_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            ttl_secs,
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingApprovals {
    inner: Mutex<HashMap<String, PendingRecord>>,
    sweeper_spawns: std::sync::atomic::AtomicUsize,
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

    /// `AUTH-9`：按记录自身 `ttl_secs` 清扫——凭据类阻塞票 300s，空闲/审计/解锁类 60s。
    pub fn sweep_expired(&self) -> usize {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        self.inner
            .lock()
            .map(|mut g| {
                let before = g.len();
                g.retain(|_, r| {
                    now_ms.saturating_sub(r.created_ms) < u128::from(r.ttl_secs) * 1000
                });
                before - g.len()
            })
            .unwrap_or(0)
    }

    /// F9/D9：清扫任务启动次数（可观测证据）。构造/建单/手工 sweep 均不启动任务，
    /// 仅显式 [`Self::spawn_sweeper`] 使其递增。
    #[cfg(test)]
    pub(crate) fn sweeper_spawn_count(&self) -> usize {
        self.sweeper_spawns
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn spawn_sweeper(self: &std::sync::Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.sweeper_spawns
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn credential_pending_survives_past_idle_ttl() {
        // AUTH-9：凭据阻塞票（300s TTL）不被 60s 空闲清扫回收。
        let table = PendingApprovals::default();
        let mut blocking = PendingRecord::with_ttl(
            "cred-key",
            "hash_mismatch",
            crate::service::matrix::CREDENTIAL_TIMEOUT_SECS,
        );
        blocking.created_ms = blocking
            .created_ms
            .saturating_sub(u128::from(PENDING_TTL_SECS) * 1000 + 1);
        table.insert(blocking);
        assert_eq!(table.sweep_expired(), 0, "凭据阻塞票不得被 60s 空闲清扫");
        assert_eq!(table.len(), 1, "票须保留至 300s 阻塞超时");
    }

    #[test]
    fn idle_orphan_swept_at_60s() {
        // AUTH-9：无等待者孤儿票按 60s 上限回收，内存有界。
        let table = PendingApprovals::default();
        let mut orphan = PendingRecord::new("idle-key", "unlock");
        orphan.created_ms = orphan
            .created_ms
            .saturating_sub(u128::from(PENDING_TTL_SECS) * 1000 + 1);
        table.insert(orphan);
        assert_eq!(table.sweep_expired(), 1, "空闲孤儿票 60s 须回收");
        assert!(table.is_empty());
    }

    #[test]
    fn init_no_sync_sweeper_observable() {
        // F9/D9：结构化断言——构造/建单/手工 sweep 不自启清扫任务，仅显式 spawn_sweeper 递增计数；
        // 并锁定生产 init 序（`src/main.rs`：先 AppState::new 构造，后显式 spawn_sweeper）。
        let table = PendingApprovals::default();
        table.insert(PendingRecord::new("sync", "hash_mismatch"));
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.sweeper_spawn_count(),
            0,
            "同步构造/建单不得启动清扫任务"
        );
        assert_eq!(table.sweep_expired(), 0, "同步 sweep 无任务依赖");
        assert_eq!(
            table.sweeper_spawn_count(),
            0,
            "手工 sweep 不得启动后台任务"
        );
        // 正向对照：显式 spawn_sweeper 方使计数可观测 +1（证明钩子有效，非空断言）。
        let rt = tokio::runtime::Runtime::new().expect("测试 runtime");
        let spawned = std::sync::Arc::new(PendingApprovals::default());
        let handle = {
            let _guard = rt.enter();
            spawned.spawn_sweeper()
        };
        assert_eq!(spawned.sweeper_spawn_count(), 1, "显式 spawn 须可观测");
        handle.abort();
        // F9：生产 init 路径结构断言——main 仅显式 spawn 清扫器，默认构造阶段不自启。
        let main_src = include_str!("main.rs");
        let constructed = main_src
            .find("AppState::new(config, outcome)")
            .expect("main 生产构造点");
        let spawned = main_src
            .find("state.approval.spawn_sweeper()")
            .expect("main 显式审批清扫任务启动点");
        assert!(constructed < spawned, "默认构造须先于显式 spawn_sweeper");
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
