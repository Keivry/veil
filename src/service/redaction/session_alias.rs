//! 会话别名表：把上游生成的标识路由到 veil 的 canonical 会话键。
//!
//! 键为 `HMAC(secret, "veil-alias-v1" || 0x1f || tenant_fingerprint || 0x1f ||
//! upstream_id)`，值为 canonical [`ConversationKey`]——上游标识原值绝不落表，
//! 跨租户因租户指纹分域而不可解析。
//!
//! 语义：**first-writer-wins**（冲突保留既有绑定并计数，绝不覆盖）、多对一
//! （同一 canonical 可挂多个上游标识，不拆分 `PiiScope`）、容量按**别名条目**计并
//! LRU 逐出。检查与插入在同一锁内原子完成，并发首轮不会产生脏绑定。

use {
    super::conversation_key::{ConversationKey, hmac_hex, touch_order},
    crate::service::{llm_gateway::GatewayMetrics, lock_recover::lock_or_recover},
    std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, Mutex},
    },
};

/// 别名键域串：与 `scoped_key` 的 `tenant || 0x1f || conversation` 域分离（纵深防御）。
const ALIAS_DOMAIN: &[u8] = b"veil-alias-v1";
/// 分量分隔符（与 `conversation_key` 同一字面量 `0x1f`）。
const SEPARATOR: &[u8] = b"\x1f";

/// `bind` 结果：首次绑定 / 幂等（同 canonical）/ 冲突（异 canonical，拒绝覆盖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// 首次绑定成功。
    Bound,
    /// 该上游 id 已绑定到同一 canonical（幂等，不计数）。
    AlreadyBound,
    /// 该上游 id 已绑定到不同 canonical；既有绑定保留，不覆盖。
    Conflict,
    /// 上游 id 为空：空操作（不绑定、不逐出、不解析）。
    Skipped,
}

#[derive(Default)]
struct AliasInner {
    map: HashMap<String, ConversationKey>,
    order: VecDeque<String>,
}

/// 上游标识 → canonical 会话键的进程内、租户分域有界映射。
pub struct SessionAliasMap {
    inner: Mutex<AliasInner>,
    capacity: usize,
    metrics: Option<Arc<GatewayMetrics>>,
}

/// 手工 `Debug`：别名键（HMAC hex）与 canonical 键不得经 `{:?}` 泄漏，仅暴露条目数。
impl std::fmt::Debug for SessionAliasMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionAliasMap")
            .field("entries", &self.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

/// 别名键：`HMAC(secret, ALIAS_DOMAIN || 0x1f || tenant_fp || 0x1f || upstream_id)`。
fn alias_key(secret: &[u8], tenant_fingerprint: &str, upstream_id: &str) -> String {
    hmac_hex(
        secret,
        &[
            ALIAS_DOMAIN,
            SEPARATOR,
            tenant_fingerprint.as_bytes(),
            SEPARATOR,
            upstream_id.as_bytes(),
        ],
    )
}

impl SessionAliasMap {
    /// 容量来自 `[session].alias_max_entries`（按别名条目计，`0` 归一为 `1`）。
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(AliasInner::default()),
            capacity: capacity.max(1),
            metrics: None,
        }
    }

    /// 装配期注入共享网关度量（观测计数）；未注入时计数路径为无操作。
    pub fn with_metrics(mut self, metrics: Arc<GatewayMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// 绑定上游标识到 canonical 键（原子检查+插入，first-writer-wins）。
    pub fn bind(
        &self,
        secret: &[u8],
        tenant_fingerprint: &str,
        upstream_id: &str,
        canonical: &ConversationKey,
    ) -> BindOutcome {
        let outcome = self.bind_silent(secret, tenant_fingerprint, upstream_id, canonical);
        if outcome == BindOutcome::Conflict {
            self.report_conflict();
        }
        outcome
    }

    /// 与 [`Self::bind`] 同语义，但不记录冲突指标/告警；供响应级去重后统一上报。
    pub fn bind_silent(
        &self,
        secret: &[u8],
        tenant_fingerprint: &str,
        upstream_id: &str,
        canonical: &ConversationKey,
    ) -> BindOutcome {
        if upstream_id.is_empty() {
            return BindOutcome::Skipped;
        }
        let key = alias_key(secret, tenant_fingerprint, upstream_id);
        let mut inner = lock_or_recover(self.inner.lock());

        if let Some(existing) = inner.map.get(&key) {
            if existing == canonical {
                // 幂等：重复帧/终端帧不重复计数，也不提升 LRU（不改变派生结果）。
                return BindOutcome::AlreadyBound;
            }
            return BindOutcome::Conflict;
        }

        if inner.map.len() >= self.capacity
            && let Some(oldest) = inner.order.pop_front()
        {
            inner.map.remove(&oldest);
            if let Some(metrics) = &self.metrics {
                metrics.record_session_alias_evict();
            }
        }
        touch_order(&mut inner.order, &key);
        inner.map.insert(key, canonical.clone());
        BindOutcome::Bound
    }

    /// 记录一次冲突（指标 + 告警）；调用方负责响应级去重。
    pub fn report_conflict(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_session_alias_conflict();
        }
        tracing::warn!("会话别名冲突：上游标识已绑定到不同会话键，保留既有绑定");
    }

    /// 解析上游标识 → canonical 键（命中提升 LRU 并计 `session_alias_hit`）。
    pub fn resolve(
        &self,
        secret: &[u8],
        tenant_fingerprint: &str,
        upstream_id: &str,
    ) -> Option<ConversationKey> {
        if upstream_id.is_empty() {
            return None;
        }
        let key = alias_key(secret, tenant_fingerprint, upstream_id);
        let mut inner = lock_or_recover(self.inner.lock());
        let found = inner.map.get(&key).cloned()?;
        touch_order(&mut inner.order, &key);
        if let Some(metrics) = &self.metrics {
            metrics.record_session_alias_hit();
        }
        Some(found)
    }

    /// 清空全部别名条目（`lock` 路径），返回被清空的条目数。
    pub fn clear(&self) -> usize {
        let mut inner = lock_or_recover(self.inner.lock());
        let cleared = inner.map.len();
        inner.map.clear();
        inner.order.clear();
        cleared
    }

    /// 当前别名条目数（有界断言用）。
    pub fn len(&self) -> usize { lock_or_recover(self.inner.lock()).map.len() }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

#[cfg(test)]
mod tests;
