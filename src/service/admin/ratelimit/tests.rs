//! `admin::ratelimit` 单测（自 `ratelimit.rs` 外迁；测试名与断言不变）。

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
    // 注入时钟（纯函数）精确断言阈值、Retry-After 取值与窗口滚动。
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
fn exempt_paths_and_thresholds_unchanged() {
    // 四条豁免：控制台壳（含尾斜杠别名）、存活探针、SSE 长连接（各自高频/长驻，
    // 不占速率桶）。
    assert!(is_rate_exempt("/_admin"));
    assert!(is_rate_exempt("/_admin/"));
    assert!(is_rate_exempt("/_admin/health"));
    assert!(is_rate_exempt("/_admin/events/stream"));
    assert_eq!(admin_rate_exempt_paths().len(), 4);
    // 数据接口仍占桶。
    assert!(!is_rate_exempt("/_admin/metrics"));
    assert!(!is_rate_exempt("/_admin/series"));
    assert!(!is_rate_exempt("/_admin/events"));
    // 阈值数值不动。
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
    // 生产接线：main.rs 实际 spawn 周期清扫。
    let main_src = include_str!("../../../../src/main.rs");
    assert!(
        main_src.contains("spawn_rate_sweeper"),
        "生产启动路径须接线周期清扫"
    );
}
