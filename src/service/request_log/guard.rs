//! 流式请求的「恰好一行」守卫：`Arc<Mutex<Option<RequestRow>>>`。
//!
//! 流式请求的完成点在 `spawn` 出去的泵任务里，`gateway_serve` 只返回响应头，
//! 故用可克隆守卫在派生任务中落行（design §1.2）：
//!
//! - [`StreamGuard::finish`] 按终态补全后取走 `Option<RequestRow>`，**至多一次生效**
//!   （幂等）：多个克隆各调一次只写一行；
//! - `Drop`：若行仍未被取走（客户端中途断开、泵任务被中止），把 `aborted` 计数 +1
//!   **并**经守卫持有的 `Weak<RequestLog>` 补写一行 `error_kind = "client_aborted"`。 写入走
//!   `record`（零 I/O，只入队），不阻塞、不 panic；`Weak` 升级失败时只计数。

use {
    super::store::{RequestLog, RequestRow, cache_input_tokens, now_secs},
    crate::service::{llm_gateway::Usage, lock_recover::lock_or_recover},
    std::sync::{
        Arc,
        Mutex,
        Weak,
        atomic::{AtomicU64, Ordering},
    },
};

/// 客户端中途断开（未 finish）时补写行的错误分类。
pub const CLIENT_ABORTED_KIND: &str = "client_aborted";

/// 流式终态数据：由泵任务在真终态处一次性填充，交 [`StreamGuard::finish`] 记账。
///
/// 与 group 4 的 `Outcome` 解耦——后者是网关侧的分支枚举，本结构只承载**落库字段**。
#[derive(Debug, Clone, Default)]
pub struct StreamOutcome<'a> {
    /// 上游/合成状态码（成功 `200`、fetch 失败 `502`）。
    pub status: Option<u16>,
    /// `upstream_unreachable` 等终态分类。
    pub error_kind: Option<&'a str>,
    /// Chat `chatcmpl-…` / Responses `resp_…`。
    pub upstream_id: Option<&'a str>,
    pub finish_reason: Option<&'a str>,
    /// `silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`。
    pub truncated_mode: Option<&'a str>,
    pub usage: Option<&'a Usage>,
    /// 测量耗时（省略则保留行内原值）。
    pub latency_ms: Option<u64>,
    /// 是否计入 metrics（取 `record_chat*` 的返回值）。
    pub counted_metrics: Option<bool>,
}

impl StreamOutcome<'_> {
    /// 把终态写进行（仅覆盖有值字段；`cache_input_tokens` 随之重算）。
    fn apply(&self, row: &mut RequestRow) {
        if let Some(status) = self.status {
            row.status = Some(status);
        }
        if let Some(kind) = self.error_kind {
            row.error_kind = Some(kind.to_string());
        }
        if let Some(id) = self.upstream_id {
            row.upstream_id = Some(id.to_string());
        }
        if let Some(reason) = self.finish_reason {
            row.finish_reason = Some(reason.to_string());
        }
        if let Some(mode) = self.truncated_mode {
            row.truncated_mode = Some(mode.to_string());
        }
        if let Some(latency) = self.latency_ms {
            row.latency_ms = latency;
        }
        if let Some(counted) = self.counted_metrics {
            row.counted_metrics = counted;
        }
        if let Some(usage) = self.usage {
            row.prompt_tokens = usage.prompt_tokens;
            row.completion_tokens = usage.completion_tokens;
            row.total_tokens = usage.total_tokens;
            row.cached_read = usage.cached_read;
            row.cached_write = usage.cached_write;
            row.cache_input_tokens = cache_input_tokens(
                &row.protocol,
                usage.prompt_tokens,
                usage.cached_read,
                usage.cached_write,
            );
        }
    }
}

/// 流式落行守卫（可克隆；`finish` 幂等）。
#[derive(Clone)]
pub struct StreamGuard {
    inner: Arc<Mutex<Option<RequestRow>>>,
    /// 进程级 `aborted` 计数（与 [`super::store::RequestLog`] 共享同一原子）。
    aborted: Arc<AtomicU64>,
    /// 补写中断行用的弱引用（不延长 `RequestLog` 生命周期）。
    log: Weak<RequestLog>,
}

impl std::fmt::Debug for StreamGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamGuard")
            .field("finished", &self.is_finished())
            .finish()
    }
}

impl StreamGuard {
    /// 以完整行新建守卫（自带私有 `aborted` 计数与无存储的弱引用；仅供单测直调守卫）。
    pub fn new(row: RequestRow) -> Self {
        Self::with_log(row, Arc::new(AtomicU64::new(0)), Weak::new())
    }

    /// 生产装配点：共享 `aborted` 计数并持日志实例的弱引用（`Drop` 补写中断行）。
    pub fn with_log(row: RequestRow, aborted: Arc<AtomicU64>, log: Weak<RequestLog>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(row))),
            aborted,
            log,
        }
    }

    /// 已完成（行已被取走）。
    pub fn is_finished(&self) -> bool { lock_or_recover(self.inner.lock()).is_none() }

    /// 补全终态并取走待写行：`apply` 只对**首个**调用者执行，返回 `Some(row)` 供调用方
    /// 唯一的 `request_log.record(...)` 写入，其余调用者与 `Drop` 均得 `None`。
    pub fn finish(&self, outcome: &StreamOutcome<'_>) -> Option<RequestRow> {
        let mut slot = lock_or_recover(self.inner.lock());
        let row = slot.as_mut()?;
        outcome.apply(row);
        slot.take()
    }

    /// 放弃计数（`/_admin/metrics` 的 `requests_aborted` 来源）。
    pub fn aborted_count(&self) -> u64 { self.aborted.load(Ordering::Relaxed) }

    /// 取走未完成的待写行（`Drop` 专用：命中即 `finish` 从未生效）。
    fn take_unfinished(&self) -> Option<RequestRow> { lock_or_recover(self.inner.lock()).take() }
}

/// 中断行补全：保留请求级字段，清状态并以「行创建时刻 → 当前」折算延迟。
fn client_aborted_row(mut row: RequestRow) -> RequestRow {
    let now = now_secs();
    row.error_kind = Some(CLIENT_ABORTED_KIND.to_string());
    row.status = None;
    row.latency_ms = u64::try_from(now.saturating_sub(row.ts_secs))
        .unwrap_or(0)
        .saturating_mul(1_000);
    row
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }
        let Some(row) = self.take_unfinished() else {
            return;
        };
        self.aborted.fetch_add(1, Ordering::Relaxed);
        match self.log.upgrade() {
            Some(log) => log.record(client_aborted_row(row)),
            None => {
                tracing::warn!(
                    "流式请求行未被 finish 落库，且日志存储已释放（只计 aborted，不写行）"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
