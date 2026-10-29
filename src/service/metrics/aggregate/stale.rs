//! 桶边界版本不符行的跳过计数与一次性告警（自 `aggregate.rs` 拆出以守 800 行红线）。

use {
    super::LATENCY_BOUNDS_VERSION,
    std::sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

/// 边界版本不符的持久行跳过计数（进程级累计 + 一次性 `warn!`）。
static STALE_BUCKETS_ROWS: AtomicU64 = AtomicU64::new(0);
/// 一次性告警闸门（每进程只报一次，避免每次查询刷屏）。
static STALE_BUCKETS_WARNED: AtomicBool = AtomicBool::new(false);

/// 记一行「边界版本不符」并恰好在首行时 `warn!` 汇报一次累计跳过行数。
///
/// 老行的计数/token/附属列仍然可用，只有 12 桶不可重解释，故这里只跳过桶贡献，
/// 不做删除也不做换算（换算会按新边界编造不存在的分布）。
pub(super) fn note_stale_bucket_row(window: &str, protocol: &str, row_version: i64) {
    let total = STALE_BUCKETS_ROWS.fetch_add(1, Ordering::Relaxed) + 1;
    if !STALE_BUCKETS_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            current = LATENCY_BOUNDS_VERSION,
            window,
            protocol,
            row_version,
            skipped_rows = total,
            "指标行桶边界版本不符，延迟桶贡献按零计（计数仍求和；升级后延迟分布随窗口滚动重新填充）"
        );
    }
}

/// 边界版本不符的持久行累计跳过数（测试断言用）。
#[cfg(test)]
pub(crate) fn stale_bucket_rows_total() -> u64 { STALE_BUCKETS_ROWS.load(Ordering::Relaxed) }
