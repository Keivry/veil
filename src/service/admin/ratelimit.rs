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

/// 通用管理接口限流：10/min/IP（速率维度；spec `admin-ratelimit-contract`）。
/// 与 SSE `5/IP` 并发维度正交、独立计数，均为有意设计（design D4）；
/// 原仓约 60/min 豁免收紧至此值系有意收敛，不视为回归。
pub const ADMIN_RATE_LIMIT: usize = 10;
/// 限流窗口（秒）。
pub const ADMIN_RATE_WINDOW_SECS: u64 = 60;
/// per-IP 限流状态硬上限（RUN-2：超上限按最久未用驱逐，防大量源 IP 无界增长）。
pub const ADMIN_RATE_MAX_ENTRIES: usize = 4096;
/// 周期清扫节拍（每 N 次限流检查执行一次过期条目清扫）。
const ADMIN_RATE_SWEEP_INTERVAL_OPS: u64 = 1024;
/// 周期清扫任务节拍（秒，DCD-3）：生产启动路径实际 spawn，与容量驱逐共同构成有界策略。
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

/// 限流豁免路径：`/_admin/health` 为存活探针（前端刷新高频），豁免通用 10/min 限流。
/// 阈值数值不动（10/min 等接线维持），仅 health 不计数。
pub fn admin_rate_exempt_paths() -> [&'static str; 1] { ["/_admin/health"] }

/// 是否豁免限流（health 恒 true）。
pub fn is_rate_exempt(path: &str) -> bool { admin_rate_exempt_paths().contains(&path) }

/// 纯函数限流判定（G8.4 时钟注入）：按给定 `now` 剔除出窗命中、判阈值并返回
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

    /// RUN-2：限流判定 + 有界管理。周期清扫过期条目，超硬上限按最久未用驱逐；
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

    /// 生产接线（DCD-3）：spawn 周期清扫任务，按 TTL 清过期条目；
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
mod tests {
    use {
        super::{
            super::{
                sse::SSE_MAX_PER_IP,
                state::test_support::{test_admin_state, test_ip},
            },
            *,
        },
        std::{
            net::IpAddr,
            time::{Duration, Instant},
        },
    };

    #[test]
    fn rate_limit_counts_by_direct_peer_ip() {
        let st = test_admin_state();
        // 同一 IP 10 次放行，第 11 次 429。
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(test_ip()).is_ok());
        }
        let retry = st.check_rate(test_ip()).unwrap_err();
        assert!(
            (1..=ADMIN_RATE_WINDOW_SECS).contains(&retry),
            "第 11 次须 429 且 Retry-After 落在 1..=窗口秒数: {retry}"
        );
        // 超限后继续请求恒拒绝（不因再次调用被放行）。
        assert!(st.check_rate(test_ip()).is_err());
        // 不同 IP 不受影响（不读代理头：伪造 XFF 无法逃逸——本函数只收直连 IP）。
        assert!(st.check_rate(IpAddr::from([10, 0, 0, 2])).is_ok());
    }

    #[test]
    fn rate_limit_window_rollover_and_retry_after_value() {
        // G8.4：注入时钟（纯函数）精确断言阈值、Retry-After 取值与窗口滚动。
        let window = Duration::from_secs(ADMIN_RATE_WINDOW_SECS);
        let base = Instant::now();
        let mut hits: Vec<Instant> = Vec::new();
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(decide_rate_limit(&mut hits, base, ADMIN_RATE_LIMIT, window).is_ok());
        }
        assert_eq!(hits.len(), ADMIN_RATE_LIMIT, "窗口内命中须满阈值");
        // 同一 now 第 11 次拒绝：oldest 未老化，Retry-After 取满窗秒数。
        assert_eq!(
            decide_rate_limit(&mut hits, base, ADMIN_RATE_LIMIT, window).unwrap_err(),
            ADMIN_RATE_WINDOW_SECS,
            "同刻 oldest 无老化，Retry-After 取满窗"
        );
        // 出窗前一刻（59s）仍拒绝，Retry-After 精确收敛到 1s。
        let just_before = base + window - Duration::from_secs(1);
        assert_eq!(
            decide_rate_limit(&mut hits, just_before, ADMIN_RATE_LIMIT, window).unwrap_err(),
            1,
            "临近出窗 Retry-After 须收敛到 1"
        );
        // 满窗时刻 oldest 出窗，放行且仅保留新一轮命中。
        let rollover = base + window;
        assert!(decide_rate_limit(&mut hits, rollover, ADMIN_RATE_LIMIT, window).is_ok());
        assert_eq!(hits.len(), 1, "滚动后仅新一轮命中存留");
    }

    #[test]
    fn sse_max_five_per_ip_sixth_rejected() {
        let st = test_admin_state();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
            // 持有守卫期间计数递增（守卫 `Drop` 时自动释放，禁止手动释放）。
        }
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        assert!(st.acquire_sse(test_ip()).is_none());
        // 释放一路后可再建。
        drop(guards.pop());
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP - 1);
        assert!(st.acquire_sse(test_ip()).is_some());
        let _ = guards;
    }

    #[test]
    fn sse_over_limit_rejection_preserves_existing_connections() {
        let st = test_admin_state();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
        }
        // 第 6 条被拒。
        assert!(st.acquire_sse(test_ip()).is_none());
        // 前 5 条计数不受影响。
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        // 拒绝路径不触计数：再拒一次计数仍为 5。
        assert!(st.acquire_sse(test_ip()).is_none());
        assert_eq!(st.sse_current(test_ip()), SSE_MAX_PER_IP);
        drop(guards);
        // 守卫全部 `Drop` 后归零（断连不泄漏）。
        assert_eq!(st.sse_current(test_ip()), 0);
    }

    #[test]
    fn rate_and_concurrency_counters_are_orthogonal() {
        let st = test_admin_state();
        // 速率打满不影响并发配额。
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(test_ip()).is_ok());
        }
        let retry = st.check_rate(test_ip()).unwrap_err();
        assert!(
            (1..=ADMIN_RATE_WINDOW_SECS).contains(&retry),
            "速率超限须带有效 Retry-After: {retry}"
        );
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(test_ip()).unwrap());
        }
        assert!(st.acquire_sse(test_ip()).is_none());
        // 并发打满不影响他 IP 速率。
        assert!(st.check_rate(IpAddr::from([10, 0, 0, 9])).is_ok());
        // 释放本 IP 全部并发后归零，速率仍保持超限（独立窗口）。
        drop(guards);
        assert_eq!(st.sse_current(test_ip()), 0);
        assert!(st.check_rate(test_ip()).is_err());
    }

    #[test]
    fn health_exempt_from_rate_limit_thresholds_unchanged() {
        assert!(is_rate_exempt("/_admin/health"));
        assert!(!is_rate_exempt("/_admin/metrics"));
        assert!(!is_rate_exempt("/_admin/events/stream"));
        assert_eq!(ADMIN_RATE_LIMIT, 10);
        assert_eq!(ADMIN_RATE_WINDOW_SECS, 60);
    }

    #[test]
    fn sse_five_connection_cap_and_release() {
        let st = test_admin_state();
        let ip = test_ip();
        let mut guards = Vec::new();
        for _ in 0..SSE_MAX_PER_IP {
            guards.push(st.acquire_sse(ip).expect("5 并发内须放行"));
        }
        assert!(st.acquire_sse(ip).is_none(), "第 6 连接须拒绝");
        assert_eq!(st.sse_current(ip), SSE_MAX_PER_IP);
        drop(guards.pop());
        assert!(st.acquire_sse(ip).is_some(), "释放后须可再建");
    }

    #[test]
    fn admin_rate_map_bounded_under_many_ips() {
        let st = test_admin_state();
        for i in 0..(ADMIN_RATE_MAX_ENTRIES + 512) {
            let ip = IpAddr::from([
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ]);
            assert!(st.check_rate(ip).is_ok(), "新 IP 首次须放行");
        }
        let len = st.rate.lock().expect("限流锁无毒").len();
        assert!(len <= ADMIN_RATE_MAX_ENTRIES, "限流状态须有界: {len}");
        assert!(st.check_rate(test_ip()).is_ok(), "驱逐后其他 IP 仍可判定");
    }

    #[test]
    fn admin_rate_sweep_preserves_semantics() {
        let st = test_admin_state();
        let ip = test_ip();
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(ip).is_ok());
        }
        {
            let mut guard = st.rate.lock().expect("限流锁无毒");
            let stale = Instant::now() - Duration::from_secs(ADMIN_RATE_WINDOW_SECS + 1);
            guard.insert(IpAddr::from([10, 9, 9, 9]), vec![stale]);
        }
        assert!(st.sweep_rate(Instant::now()) >= 1, "过期条目须被清理");
        assert!(st.check_rate(ip).is_err(), "清扫后同 IP 仍按 10/min 拒绝");
        let retry = st.check_rate(ip).unwrap_err();
        assert!(
            (1..=ADMIN_RATE_WINDOW_SECS).contains(&retry),
            "Retry-After 取值不变: {retry}"
        );
        assert!(
            st.check_rate(IpAddr::from([10, 0, 0, 2])).is_ok(),
            "其他 IP 不受影响"
        );
    }

    #[tokio::test]
    async fn admin_rate_sweep_wired() {
        let st = std::sync::Arc::new(test_admin_state());
        {
            let mut guard = st.rate.lock().expect("限流锁无毒");
            let stale = Instant::now() - Duration::from_secs(ADMIN_RATE_WINDOW_SECS + 1);
            guard.insert(IpAddr::from([10, 8, 8, 8]), vec![stale]);
        }
        let handle = st.spawn_rate_sweeper(Duration::from_millis(20));
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            !st.rate
                .lock()
                .expect("限流锁无毒")
                .contains_key(&IpAddr::from([10, 8, 8, 8])),
            "周期清扫任务须删除过期条目"
        );
        handle.abort();
        // 生产接线：main.rs 实际 spawn 周期清扫（DCD-3）。
        let main_src = include_str!("../../../src/main.rs");
        assert!(
            main_src.contains("spawn_rate_sweeper"),
            "生产启动路径须接线周期清扫"
        );
    }
}
