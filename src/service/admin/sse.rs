//! 管理面 SSE 状态：并发守卫 + 建连过滤（handler 层 SSE 推送见
//! `handler::admin::admin_events_stream`）。

use {
    super::state::AdminState,
    std::{
        collections::HashMap,
        net::IpAddr,
        sync::{Arc, Mutex},
    },
};

/// SSE 并发上限/IP（并发维度；仅约束 `/_admin/events/stream` 同时在线数，
/// 与通用 10/min 速率限流正交，超限拒绝新连接且已建连接不受影响）。
pub const SSE_MAX_PER_IP: usize = 5;
/// SSE 保活 ping 间隔（60s）。
pub const SSE_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
/// A11/D10：SSE 流内 `event: metrics` 快照周期（15s）。
pub const SSE_METRICS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
/// SSE 强制重连（5min，服务端主动关闭）。
pub const SSE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300);

impl AdminState {
    /// SSE 并发守卫（5/IP）：调用方 MUST 持有至连接结束，`Drop` 自动释放；
    /// 满时返回 `None`（429）。禁止手动调 `release_sse_for`（双重释放会
    /// 错减他路计数；该方法仅保留作 `Drop` 内部语义的公开别名）。
    pub fn acquire_sse(&self, ip: IpAddr) -> Option<SseGuard> {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n >= SSE_MAX_PER_IP {
            return None;
        }
        guard.insert(ip, n + 1);
        Some(SseGuard {
            ip,
            slots: Arc::clone(&self.sse_count),
        })
    }

    /// 释放 SSE 计数（`SseGuard::drop` 内部语义的公开别名；调用方禁止在
    /// 持有守卫时手动调用，否则与 `Drop` 双重释放错减计数）。
    pub fn release_sse_for(&self, ip: IpAddr) {
        let mut guard = self.sse_count.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&ip);
        } else {
            guard.insert(ip, n - 1);
        }
    }

    /// 当前 IP 的 SSE 并发数（单测用）。
    #[cfg(test)]
    pub(crate) fn sse_current(&self, ip: IpAddr) -> usize {
        self.sse_count
            .lock()
            .map(|g| g.get(&ip).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// 订阅实时流。
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.broadcaster.subscribe()
    }
}

/// SSE 并发守卫：持有计数槽位，`Drop` 时自动释放（断连不泄漏）。
pub struct SseGuard {
    ip: IpAddr,
    slots: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl Drop for SseGuard {
    fn drop(&mut self) {
        let mut guard = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.get(&self.ip).copied().unwrap_or(0);
        if n <= 1 {
            guard.remove(&self.ip);
        } else {
            guard.insert(self.ip, n - 1);
        }
    }
}

/// SSE 建连过滤维度（`?model=&upstream=`；对标原仓建连参数绑定）。
/// 返回 `(model, upstream)`；空表示不过滤。`model` 按事件 `protocol` 子串匹配，
/// `upstream` 按事件摘要子串匹配（尽力过滤，形态不符的事件直通）。
#[derive(Debug, Clone, Default)]
pub struct SseFilter {
    pub model: Option<String>,
    pub upstream: Option<String>,
}

impl SseFilter {
    /// 从建连 query 解析过滤维度。
    pub fn from_query(query: &HashMap<String, String>) -> Self {
        Self {
            model: query.get("model").cloned().filter(|v| !v.is_empty()),
            upstream: query.get("upstream").cloned().filter(|v| !v.is_empty()),
        }
    }

    /// 事件 JSON 是否通过过滤（解析失败直通，不丢事件）。
    pub fn passes(&self, event_json: &str) -> bool {
        if self.model.is_none() && self.upstream.is_none() {
            return true;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(event_json) else {
            return true;
        };
        if let Some(m) = self.model.as_deref()
            && !v
                .get("protocol")
                .and_then(|p| p.as_str())
                .is_some_and(|p| p.contains(m))
        {
            return false;
        }
        if let Some(u) = self.upstream.as_deref()
            && !v
                .get("summary")
                .and_then(|s| s.as_str())
                .is_some_and(|s| s.contains(u))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::collections::HashMap};

    #[test]
    fn sse_filter_dimensions() {
        let q: HashMap<String, String> = HashMap::from([
            ("model".to_string(), "chat".to_string()),
            ("upstream".to_string(), "u1".to_string()),
        ]);
        let f = SseFilter::from_query(&q);
        assert!(f.passes(r#"{"protocol":"chat/completions","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"v1/responses","summary":"u1 ok"}"#));
        assert!(!f.passes(r#"{"protocol":"chat/completions","summary":"other"}"#));
        // 形态不符直通不丢事件。
        assert!(f.passes("not-json"));
        let empty = SseFilter::from_query(&HashMap::new());
        assert!(empty.passes(r#"{"protocol":"x"}"#));
    }
}
