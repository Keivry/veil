//! 网关度量与固定键原子计数（F-2/D-2 自 `mod.rs` 拆出；触 800 红线后按模块
//! 外迁模板拆分，结构/方法/注释逐字搬移、语义不变）。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// 固定键原子计数（H2/D2）：已知键编译期枚举，热路径无锁写入；未知键归 `other`
/// 桶并每进程仅告警一次（不静默丢失，也不无限刷屏）。
#[derive(Debug)]
struct KeyedCounters<const N: usize> {
    keys: [&'static str; N],
    counts: [AtomicU64; N],
    other: AtomicU64,
    other_warned: AtomicBool,
}

impl<const N: usize> KeyedCounters<N> {
    fn new(keys: [&'static str; N]) -> Self {
        Self {
            keys,
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            other: AtomicU64::new(0),
            other_warned: AtomicBool::new(false),
        }
    }

    fn record(&self, key: &str, n: u64) {
        if n == 0 {
            return;
        }
        match self.index_of(key) {
            Some(i) => {
                self.counts[i].fetch_add(n, Ordering::Relaxed);
            }
            None => {
                self.other.fetch_add(n, Ordering::Relaxed);
                if !self.other_warned.swap(true, Ordering::Relaxed) {
                    tracing::warn!(key = %key, "网关度量未知键归 other 桶（本进程仅提示一次）");
                }
            }
        }
    }

    fn get(&self, key: &str) -> u64 {
        match self.index_of(key) {
            Some(i) => self.counts[i].load(Ordering::Relaxed),
            None => self.other.load(Ordering::Relaxed),
        }
    }

    fn index_of(&self, key: &str) -> Option<usize> { self.keys.iter().position(|k| *k == key) }
}

pub(super) const LENIENT_TAIL_KEYS: [&str; 3] = ["chat/completions", "v1/messages", "v1/responses"];
pub(super) const TRUNCATED_MODE_KEYS: [&str; 3] =
    ["silent_discard", "open_ended", "synthesized_failed"];
pub(super) const HOP_DIR_KEYS: [&str; 2] = ["upstream", "downstream"];
pub(super) const CONV_MISSING_KEYS: [&str; 5] = [
    "failed",
    "block",
    "truncated",
    "nondialog-stream",
    "nonstream-block",
];

#[derive(Debug)]
pub struct GatewayMetrics {
    lenient: KeyedCounters<3>,
    truncated: KeyedCounters<3>,
    hop_filtered: KeyedCounters<2>,
    conv_missing: KeyedCounters<5>,
    sse_events: AtomicU64,
    /// P0-3.1/TSS-03：截断丢弃的残缺 tool 分片帧数。
    truncated_tool_dropped: AtomicU64,
    /// C11：超长 SSE 行截断丢弃的尾部字节数。
    truncated_line_dropped_bytes: AtomicU64,
    /// P0-4.2/F1：NonDialog 非对话臂透传次数（流量验证用）。
    nondialog_passthrough: AtomicU64,
    /// E5/D3：非流还原破裂重试仍失败、回退上游原文的次数。
    restore_fallback: AtomicU64,
    /// E8：Responses/Anthropic 终止判定 JSON 解析失败回退 contains 的次数。
    terminal_fallback: AtomicU64,
    /// RUN-2：管理面限流条目超上限被驱逐的累计次数。
    admin_rate_evicted: AtomicU64,
    /// RUN-4：上游响应体读取失败（`chunk()`/`bytes()` 报错）的累计次数。
    upstream_read_errors: AtomicU64,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self {
            lenient: KeyedCounters::new(LENIENT_TAIL_KEYS),
            truncated: KeyedCounters::new(TRUNCATED_MODE_KEYS),
            hop_filtered: KeyedCounters::new(HOP_DIR_KEYS),
            conv_missing: KeyedCounters::new(CONV_MISSING_KEYS),
            sse_events: AtomicU64::new(0),
            truncated_tool_dropped: AtomicU64::new(0),
            truncated_line_dropped_bytes: AtomicU64::new(0),
            nondialog_passthrough: AtomicU64::new(0),
            restore_fallback: AtomicU64::new(0),
            terminal_fallback: AtomicU64::new(0),
            admin_rate_evicted: AtomicU64::new(0),
            upstream_read_errors: AtomicU64::new(0),
        }
    }
}

impl GatewayMetrics {
    pub fn record_lenient(&self, tail: &str) { self.lenient.record(tail, 1); }

    pub fn lenient_count(&self, tail: &str) -> u64 { self.lenient.get(tail) }

    pub fn record_truncated(&self, mode: &str) { self.truncated.record(mode, 1); }

    #[cfg(test)]
    pub(crate) fn truncated_count(&self, mode: &str) -> u64 { self.truncated.get(mode) }

    pub fn add_sse_event(&self) { self.sse_events.fetch_add(1, Ordering::Relaxed); }

    pub fn sse_event_total(&self) -> u64 { self.sse_events.load(Ordering::Relaxed) }

    pub fn record_hop_filtered(&self, dir: &str, count: u64) {
        self.hop_filtered.record(dir, count);
    }

    // DCD-5（9.1）：本方法仅测试引用，但集成测试 `tests/http_e2e_nondialog_passthrough.rs`
    // 以非 `cfg(test)` 构建链接本库并直接调用；降级 `#[cfg(test)] pub(crate)` 会破坏
    // 该 e2e 编译，故暂保留 `pub`（待 e2e 访问面改造后再收敛）。
    pub fn hop_filtered_count(&self, dir: &str) -> u64 { self.hop_filtered.get(dir) }

    pub fn record_conv_missing(&self, reason: &str) { self.conv_missing.record(reason, 1); }

    #[cfg(test)]
    pub(crate) fn conv_missing_count(&self, reason: &str) -> u64 { self.conv_missing.get(reason) }

    pub fn record_truncated_tool_dropped(&self, n: u64) {
        self.truncated_tool_dropped.fetch_add(n, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn truncated_tool_dropped_count(&self) -> u64 {
        self.truncated_tool_dropped.load(Ordering::Relaxed)
    }

    pub fn record_truncated_line_dropped_bytes(&self, n: u64) {
        self.truncated_line_dropped_bytes
            .fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_nondialog_passthrough(&self) {
        self.nondialog_passthrough.fetch_add(1, Ordering::Relaxed);
    }

    // DCD-5（9.1）：同 `hop_filtered_count`——集成测试 `tests/http_e2e_nondialog_passthrough.rs`
    // 以非 `cfg(test)` 构建链接本库并直接调用，暂保留 `pub`。
    pub fn nondialog_passthrough_count(&self) -> u64 {
        self.nondialog_passthrough.load(Ordering::Relaxed)
    }

    pub fn record_terminal_fallback(&self) {
        self.terminal_fallback.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn terminal_fallback_count(&self) -> u64 {
        self.terminal_fallback.load(Ordering::Relaxed)
    }

    pub fn record_restore_fallback(&self) { self.restore_fallback.fetch_add(1, Ordering::Relaxed); }

    #[cfg(test)]
    pub(crate) fn restore_fallback_count(&self) -> u64 {
        self.restore_fallback.load(Ordering::Relaxed)
    }

    pub fn record_admin_rate_evicted(&self, n: u64) {
        self.admin_rate_evicted.fetch_add(n, Ordering::Relaxed);
    }

    pub fn admin_rate_evicted_count(&self) -> u64 {
        self.admin_rate_evicted.load(Ordering::Relaxed)
    }

    pub fn record_upstream_read_error(&self) {
        self.upstream_read_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream_read_error_count(&self) -> u64 {
        self.upstream_read_errors.load(Ordering::Relaxed)
    }
}
