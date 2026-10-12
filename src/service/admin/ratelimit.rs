//! 管理面限流纯逻辑：速率 10/min/IP + 豁免路径（429 响应构造归
//! `handler::admin::rate_limited`）。

use {
    super::{super::credential::AppStateParts, state::AdminState},
    std::{
        collections::HashMap,
        net::IpAddr,
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    },
};

/// 通用管理接口限流：10/min/IP（速率维度）。
/// 与 SSE `5/IP` 并发维度正交、独立计数，均为有意设计；
/// 收紧至此值系有意收敛，不视为回归。
pub const ADMIN_RATE_LIMIT: usize = 10;
/// 限流窗口（秒）。
pub const ADMIN_RATE_WINDOW_SECS: u64 = 60;
/// per-IP 限流状态硬上限（超上限按最久未用驱逐，防大量源 IP 无界增长）。
pub const ADMIN_RATE_MAX_ENTRIES: usize = 4096;
/// 周期清扫节拍（每 N 次限流检查执行一次过期条目清扫）。
const ADMIN_RATE_SWEEP_INTERVAL_OPS: u64 = 1024;
/// 周期清扫任务节拍（秒）：生产启动路径实际 spawn，与容量驱逐共同构成有界策略。
pub const ADMIN_RATE_SWEEP_SECS: u64 = 60;

/// 清除窗内无命中的过期条目，返回清理数（`decide_rate_limit` 阈值语义不变）。
fn sweep_expired_rate(
    rate: &mut HashMap<IpAddr, Vec<Instant>>,
    now: Instant,
    window: Duration,
) -> u64 {
    let before = rate.len();
    rate.retain(|_, hits| hits.iter().any(|t| now.duration_since(*t) < window));
    (before - rate.len()) as u64
}

/// 限流豁免路径清单（四条，仅声明/测试与文档用途，不被生产路径消费）：
/// `/_admin` 与 `/_admin/`（控制台壳，`router.rs` 两条注册指向同一 handler）、
/// `/_admin/health` 存活探针（前端刷新高频）、`/_admin/events/stream` 长连接
/// （按并发而非速率计量，唯一门是 `5/IP` 并发上限）。阈值数值不动
/// （`10/min` 仍约束 metrics/series/events 等数据接口），仅此四路不计数。
pub fn admin_rate_exempt_paths() -> [&'static str; 4] {
    [
        "/_admin",
        "/_admin/",
        "/_admin/health",
        "/_admin/events/stream",
    ]
}

/// 是否豁免限流（豁免集为上述四条路径）。
pub fn is_rate_exempt(path: &str) -> bool { admin_rate_exempt_paths().contains(&path) }

/// 纯函数限流判定（时钟注入）：按给定 `now` 剔除出窗命中、判阈值并返回
/// `Retry-After` 秒数；放行时把 `now` 记入 `hits`。生产语义与原内联逻辑逐字一致。
fn decide_rate_limit(
    hits: &mut Vec<Instant>,
    now: Instant,
    limit: usize,
    window: Duration,
) -> Result<(), u64> {
    hits.retain(|t| now.duration_since(*t) < window);
    if hits.len() >= limit {
        let oldest = hits.iter().min().copied().unwrap_or(now);
        let retry = window
            .saturating_sub(now.duration_since(oldest))
            .as_secs()
            .max(1);
        return Err(retry);
    }
    hits.push(now);
    Ok(())
}

impl AdminState {
    /// 通用限流（10/min/IP）：超限返回 `Retry-After` 秒数。
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), u64> { self.check_rate_with_evictions(ip).0 }

    /// 限流判定 + 有界管理。周期清扫过期条目，超硬上限按最久未用驱逐；
    /// 返回 `(判定结果, 本次驱逐数)`。阈值与 `Retry-After` 语义不变。
    pub fn check_rate_with_evictions(&self, ip: IpAddr) -> (Result<(), u64>, u64) {
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs(ADMIN_RATE_WINDOW_SECS);
        let mut evicted = 0u64;
        if self
            .rate_ops
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(ADMIN_RATE_SWEEP_INTERVAL_OPS)
        {
            evicted += sweep_expired_rate(&mut guard, now, window);
        }
        let decision = {
            let hits = guard.entry(ip).or_default();
            decide_rate_limit(hits, now, ADMIN_RATE_LIMIT, window)
        };
        if guard.len() > ADMIN_RATE_MAX_ENTRIES {
            evicted += sweep_expired_rate(&mut guard, now, window);
            evicted += evict_oldest_rate_entries(&mut guard, ip);
        }
        (decision, evicted)
    }

    /// 周期清扫入口：删除窗内无命中的过期条目，返回清理数。
    pub fn sweep_rate(&self, now: Instant) -> u64 {
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let window = Duration::from_secs(ADMIN_RATE_WINDOW_SECS);
        sweep_expired_rate(&mut guard, now, window)
    }

    /// 生产接线：spawn 周期清扫任务，按 TTL 清过期条目；
    /// 返回句柄供调用方持有（`main.rs` 持有至进程结束）。
    pub fn spawn_rate_sweeper(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // 首个 tick 立即到点，先消费，使清扫按完整周期起算。
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let cleaned = me.sweep_rate(Instant::now());
                if cleaned > 0 {
                    tracing::debug!(cleaned, "管理面限流周期清扫已删除过期条目");
                }
            }
        })
    }
}

/// 达硬上限时按「最久未用」驱逐（当前 IP 桶因刚写入 `now` 必为最新，不会自逐），
/// 返回驱逐数。
fn evict_oldest_rate_entries(rate: &mut HashMap<IpAddr, Vec<Instant>>, current: IpAddr) -> u64 {
    let mut evicted = 0u64;
    while rate.len() > ADMIN_RATE_MAX_ENTRIES {
        let victim = rate
            .iter()
            .filter(|(ip, _)| **ip != current)
            .min_by_key(|(_, hits)| hits.iter().max().copied())
            .map(|(ip, _)| *ip);
        match victim {
            Some(ip) => {
                rate.remove(&ip);
                evicted += 1;
            }
            None => break,
        }
    }
    evicted
}

/// 通用限流门（速率维度）：通过则计数 +1；超限返回 `Retry-After` 秒数
/// （响应构造归 handler 层，本层不 import axum）。
/// 与 SSE 并发计数相互独立（正交），本函数不触 `sse_count`。
pub(crate) fn check_admin_rate(state: &impl AppStateParts, ip: IpAddr) -> Option<u64> {
    let (decision, evicted) = state.admin_state().check_rate_with_evictions(ip);
    if evicted > 0 {
        tracing::warn!(
            evicted,
            cap = ADMIN_RATE_MAX_ENTRIES,
            "管理面限流状态超上限，已驱逐最久未用条目"
        );
        state.gateway_metrics().record_admin_rate_evicted(evicted);
    }
    decision.err()
}

#[cfg(test)]
mod tests;
