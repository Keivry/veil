//! 会话作用域存储（veil-pii-conversation-cache D3）：LRU + 空闲 TTL，
//! 键为 D2 派生会话键、值为共享 `Arc<PiiScope>`。
//!
//! 容量 `PII_SCOPE_MAX_CONVERSATIONS`、空闲 TTL `PII_SCOPE_TTL_SECS`；单会话条目
//! 沿用 `PII_MAX_ENTRIES`（请求表 + 响应表各一份）。锁经 `lock_or_recover`，中毒
//! 恢复真实结果，绝不静默降级。淘汰确定性且仅致缓存失配（重新铸造 token）。

use {
    super::conversation_key::{ConversationKey, touch_order},
    crate::service::{llm_gateway::GatewayMetrics, lock_recover::lock_or_recover, pii::PiiScope},
    std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    },
};

/// 注入时钟：TTL 可测（生产恒 `Instant::now`）。
pub(crate) type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

struct Entry {
    scope: Arc<PiiScope>,
    last_used: Instant,
}

#[derive(Default)]
struct StoreInner {
    map: HashMap<String, Entry>,
    order: VecDeque<String>,
}

/// 会话键 → 共享 `Arc<PiiScope>` 的有界存储（LRU + 空闲 TTL）。
pub struct ConversationScopeStore {
    inner: Mutex<StoreInner>,
    capacity: usize,
    ttl: Duration,
    clock: Clock,
    metrics: Option<Arc<GatewayMetrics>>,
}

impl std::fmt::Debug for ConversationScopeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationScopeStore")
            .field("entries", &self.len())
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl ConversationScopeStore {
    /// 生产构造：容量/空闲 TTL 来自 `PII_SCOPE_MAX_CONVERSATIONS`/`PII_SCOPE_TTL_SECS`。
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self::with_clock(capacity, ttl, Arc::new(Instant::now))
    }

    pub(crate) fn with_clock(capacity: usize, ttl: Duration, clock: Clock) -> Self {
        Self {
            inner: Mutex::new(StoreInner::default()),
            capacity: capacity.max(1),
            ttl,
            clock,
            metrics: None,
        }
    }

    /// 装配期注入共享网关度量（D12 观测计数）；未注入时计数路径为无操作。
    pub fn with_metrics(mut self, metrics: Arc<GatewayMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// D12：记录一次会话条目复用（`get_or_insert` 命中）。
    fn record_reuse(&self) {
        if let Some(m) = &self.metrics {
            m.record_conversation_reuse();
        }
    }

    /// D12：记录淘汰条数（LRU 容量 + 空闲 TTL）；零条不写入。
    fn record_eviction(&self, n: u64) {
        if let Some(m) = &self.metrics {
            m.record_conversation_eviction(n);
        }
    }

    /// 原子 get-or-insert：命中返回既有共享 `Arc`（指针相等），未命中插入新 Scope。
    /// 同会话并发在途请求收敛到同一 `Arc`，同明文收敛到同一 token（`PiiScope` 内部锁）。
    pub fn get_or_insert(&self, key: &ConversationKey) -> Arc<PiiScope> {
        let now = (self.clock)();
        let mut inner = lock_or_recover(self.inner.lock());
        self.record_eviction(prune_expired(&mut inner, self.ttl, now));
        if let Some(entry) = inner.map.get_mut(key.as_str()) {
            let scope = entry.scope.clone();
            entry.last_used = now;
            touch_order(&mut inner.order, key.as_str());
            self.record_reuse();
            return scope;
        }
        let mut evicted = 0u64;
        while inner.map.len() >= self.capacity {
            match inner.order.pop_front() {
                Some(oldest) => {
                    inner.map.remove(&oldest);
                    evicted += 1;
                }
                None => break,
            }
        }
        self.record_eviction(evicted);
        let scope = Arc::new(PiiScope::new());
        inner.map.insert(
            key.as_str().to_string(),
            Entry {
                scope: scope.clone(),
                last_used: now,
            },
        );
        inner.order.push_back(key.as_str().to_string());
        scope
    }

    /// 当前条目数（先按时钟清理过期条目）。
    pub fn len(&self) -> usize {
        let now = (self.clock)();
        let mut inner = lock_or_recover(self.inner.lock());
        prune_expired(&mut inner, self.ttl, now);
        inner.map.len()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// 仅测试：在持有锁时 panic 以强制中毒，验证 [`lock_or_recover`] 恢复路径。
    #[cfg(test)]
    pub(crate) fn force_poison(&self) {
        let _guard = self.inner.lock();
        panic!("强制锁中毒（测试）");
    }
}

/// 清理过期条目（`now - last_used >= ttl`）：淘汰仅致缓存失配，重新铸造 token。
/// 返回实际淘汰条数（供 D12 观测计数；调用方决定是否记录）。
fn prune_expired(inner: &mut StoreInner, ttl: Duration, now: Instant) -> u64 {
    if inner.map.is_empty() {
        return 0;
    }
    let expired: Vec<String> = inner
        .map
        .iter()
        .filter(|(_, e)| {
            now.checked_duration_since(e.last_used)
                .is_some_and(|d| d >= ttl)
        })
        .map(|(k, _)| k.clone())
        .collect();
    let removed = expired.len() as u64;
    for k in expired {
        inner.map.remove(&k);
        if let Some(pos) = inner.order.iter().position(|v| v == &k) {
            inner.order.remove(pos);
        }
    }
    removed
}

#[cfg(test)]
#[path = "conversation_scope_tests.rs"]
mod conversation_scope_tests;
