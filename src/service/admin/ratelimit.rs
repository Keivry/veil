//! 管理面限流纯逻辑：速率 10/min/IP + 豁免路径（429 响应构造归
//! `handler::admin::rate_limited`）。

use {
    super::{super::credential::AppStateParts, state::AdminState},
    std::{
        net::IpAddr,
        time::{Duration, Instant},
    },
};

/// 通用管理接口限流：10/min/IP（速率维度；spec `admin-ratelimit-contract`）。
/// 与 SSE `5/IP` 并发维度正交、独立计数，均为有意设计（design D4）；
/// 原仓约 60/min 豁免收紧至此值系有意收敛，不视为回归。
pub const ADMIN_RATE_LIMIT: usize = 10;
/// 限流窗口（秒）。
pub const ADMIN_RATE_WINDOW_SECS: u64 = 60;

/// 限流豁免路径：`/_admin/health` 为存活探针（前端刷新高频），豁免通用 10/min 限流。
/// 阈值数值不动（10/min 等接线维持），仅 health 不计数。
pub fn admin_rate_exempt_paths() -> [&'static str; 1] { ["/_admin/health"] }

/// 是否豁免限流（health 恒 true）。
pub fn is_rate_exempt(path: &str) -> bool { admin_rate_exempt_paths().contains(&path) }

impl AdminState {
    /// 通用限流（10/min/IP）：超限返回 `Retry-After` 秒数。
    pub fn check_rate(&self, ip: IpAddr) -> Result<(), u64> {
        let mut guard = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs(ADMIN_RATE_WINDOW_SECS);
        let hits = guard.entry(ip).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= ADMIN_RATE_LIMIT {
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
}

/// 通用限流门（速率维度）：通过则计数 +1；超限返回 `Retry-After` 秒数
/// （响应构造归 handler 层，本层不 import axum）。
/// 与 SSE 并发计数相互独立（正交），本函数不触 `sse_count`。
pub(crate) fn check_admin_rate(state: &impl AppStateParts, ip: IpAddr) -> Option<u64> {
    state.admin_state().check_rate(ip).err()
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
        std::net::IpAddr,
    };

    #[test]
    fn rate_limit_counts_by_direct_peer_ip() {
        let st = test_admin_state();
        // 同一 IP 10 次放行，第 11 次 429。
        for _ in 0..ADMIN_RATE_LIMIT {
            assert!(st.check_rate(test_ip()).is_ok());
        }
        let retry = st.check_rate(test_ip()).unwrap_err();
        assert!(retry >= 1);
        // 不同 IP 不受影响（不读代理头：伪造 XFF 无法逃逸——本函数只收直连 IP）。
        assert!(st.check_rate(IpAddr::from([10, 0, 0, 2])).is_ok());
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
        assert!(st.check_rate(test_ip()).is_err());
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
}
