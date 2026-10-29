//! 请求日志存储：`llm_requests` 行 + `request_model_rollup` 投影 + 有界写队列。
//!
//! 与 `MetricsStore` 同库（`data_dir/metrics.sqlite`，WAL + `0600`），但**不共用**
//! 表与刷盘周期：本模块每 2s（或累计 ≥ [`FLUSH_BATCH_ROWS`] 行）单事务批量写，
//! 关闭路径由 `flush_blocking` 兜底（design §2/§3）。
//!
//! 关键约束：
//! - `record` 零 I/O，队列满丢**最旧**并计 `dropped`（不阻塞转发）；
//! - `counted_metrics=1` 的行是「与 KPI `requests` 同集合」的唯一桥接， `request_model_rollup`
//!   **只**由这群行聚合（design §2/§7.3）；
//! - 保留期：`llm_requests` 按 `retention_days`（`0` = 不清理）删除； rollup 随窗口数驱逐（`d` 32 /
//!   `h` 170 / `m` 13）。
//!
//! 所有 sqlite 访问各自 `open_wal`（无长连接，与既有 metrics 存储同模式）；
//! 生产路径禁止 `unwrap`/`expect`，失败一律 `anyhow::Result` 或计数。

use {
    super::guard::StreamGuard,
    crate::{
        fs_perm::{ensure_0600, open_wal},
        service::lock_recover::lock_or_recover,
    },
    rusqlite::types::Value,
    std::{
        collections::{HashMap, VecDeque},
        path::{Path, PathBuf},
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    },
};

mod schema;

use schema::{INSERT_SQL, ensure_tables};

/// 待写队列容量（满则丢最旧；design §3）。
pub const REQUEST_QUEUE_CAP: usize = 4096;
/// 单批最大行数（驱动提前触发条件）。
pub const FLUSH_BATCH_ROWS: usize = 64;
/// 默认刷盘周期（design §3：2s）。
pub const FLUSH_INTERVAL_SECS: u64 = 2;
/// 保留期清理周期（design §3：60s）。
pub const PURGE_INTERVAL_SECS: u64 = 60;
/// 查询页大小默认值（与 `/_admin/requests` 契约一致）。
pub const DEFAULT_LIMIT: usize = 50;
/// 查询页大小上限（canonical「具体限制表」）。
pub const MAX_LIMIT: usize = 200;
/// 分页偏移上限（超过由调用方回 400）。
pub const MAX_OFFSET: usize = 10_000;
/// `session` 前缀过滤最少字符数（不足由调用方回 400）。
pub const MIN_SESSION_PREFIX_CHARS: usize = 4;
/// rollup 保留窗数（design §2：`d` 32 / `h` 170 / `m` 13）。
///
/// 有意不复用 `metrics::aggregate` 的内部常量：那组常量的 `m` 当前为 1（group 6
/// 才改 13），而本表按 design §2 从第一天起就要答 1h 范围，故本地独立声明并在
/// group 6 收敛语义（两侧窗口键口径一致，数值仍是 32/170/13）。
const ROLLUP_KEEP: [(&str, usize); 3] = [("d", 32), ("h", 170), ("m", 13)];
/// 一天秒数（保留期与窗口折算单一来源）。
const SECS_PER_DAY: i64 = 86_400;

/// 一次 LLM 请求的落库行（design §2 全列）。
#[derive(Debug, Clone, Default)]
pub struct RequestRow {
    /// epoch 秒。
    pub ts_secs: i64,
    pub request_id: String,
    /// 协议线级标签（`chat` / `anthropic` / `responses` / `passthrough`）。
    pub protocol: String,
    pub model: String,
    /// `host:port`（无路径/查询串）。
    pub upstream: Option<String>,
    pub ingress_port: Option<u16>,
    pub stream: bool,
    /// `!is_passthrough(protocol)`。
    pub is_chat: bool,
    /// 该行是否计入 metrics `requests`（与 `record_chat*` 返回值同源）。
    pub counted_metrics: bool,
    pub status: Option<u16>,
    pub error_kind: Option<String>,
    pub latency_ms: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_read: u64,
    pub cached_write: u64,
    /// 输入缓存命中率分母（见 [`cache_input_tokens`]）。
    pub cache_input_tokens: u64,
    pub session_id: Option<String>,
    /// `SessionSource::as_str()`。
    pub session_source: String,
    /// `SessionScope::as_str()`。
    pub session_scope: String,
    pub upstream_id: Option<String>,
    pub finish_reason: Option<String>,
    pub truncated_mode: Option<String>,
    /// 脱敏后摘要（`[redaction].enabled=false` 时恒 `None`）。
    pub req_summary: Option<String>,
    /// 首 token 时延（毫秒）：请求起始 → 首个**生成 token**（内容或推理）真正下行。
    /// **流式专属**：非流请求无逐 token 时间轴，恒 `None`（见
    /// `handler/llm/pump/ttft.rs::carries_output_token` 与 `handler/llm/trace.rs`）。
    pub ttft_ms: Option<u32>,
    /// 输出 tokens/秒（`[首个生成 token .. 流结束]` 窗口内），保留一位小数；
    /// 随 `ttft_ms` 不可测（含非流）时为 `None`。
    pub tps: Option<f64>,
}

/// 状态类别过滤（`2xx|4xx|5xx|error`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    S2xx,
    S4xx,
    S5xx,
    /// 无状态（中断/未落上游）或 `>= 400`。
    Error,
}

impl StatusClass {
    /// 解析查询参数取值；非法值 `None`（调用方回 `400`）。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "2xx" => Some(Self::S2xx),
            "4xx" => Some(Self::S4xx),
            "5xx" => Some(Self::S5xx),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// `/_admin/requests` 过滤条件（`None` 表示不限）。
#[derive(Debug, Clone, Default)]
pub struct RequestFilter {
    /// 范围下界（epoch 秒，含）；`None` = 全部保留期。
    pub range_start_ts: Option<i64>,
    pub model: Option<String>,
    pub protocol: Option<String>,
    pub status_class: Option<StatusClass>,
    /// `session_id` 前缀（大小写敏感，最少 [`MIN_SESSION_PREFIX_CHARS`] 字符）。
    pub session_prefix: Option<String>,
    /// `Some(SessionScope::Session|User)` 过滤；`None` = any。
    pub scope: Option<super::session::SessionScope>,
    /// 仅保留真实 LLM 请求（`is_chat = 1`）；默认 `false` = 不限。
    pub llm_only: bool,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl RequestFilter {
    /// 收敛后的页大小（1..=[`MAX_LIMIT`]，默认 [`DEFAULT_LIMIT`]）。
    pub fn limit(&self) -> usize { self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) }

    pub fn offset(&self) -> usize { self.offset.unwrap_or(0) }
}

/// 查询结果页（`sum_*`/`earliest_ts` 与 `rows` 同 WHERE）。
#[derive(Debug, Clone, Default)]
pub struct RequestPage {
    pub total: u64,
    pub rows: Vec<RequestRow>,
    pub sum_cached_read: u64,
    pub sum_cache_input_tokens: u64,
    /// 同 WHERE 范围内最早 `ts_secs`（无行则 `None`）。
    ///
    /// 该值受业务过滤（model/status/session/scope）影响，**不得**用作「保留期
    /// 可回答下界」——只用它算覆盖时长会把「过滤后只剩近期行」误判为数据部分缺失。
    pub earliest_ts: Option<i64>,
    /// 仅按时间下界（`range_start_ts`）过滤后的最早 `ts_secs`（无行则 `None`）。
    ///
    /// 这是 `coverage_secs`/`partial` 的正确口径：业务过滤只影响返回行与
    /// `earliest_ts`，不得让覆盖率缩水。
    pub retention_earliest_ts: Option<i64>,
}

/// 请求日志存储（同库不同表；队列 + 计数 + 刷盘）。
pub struct RequestLog {
    pending: Mutex<VecDeque<RequestRow>>,
    dropped: AtomicU64,
    /// 写库失败后回灌队列的累计批次数（观测用；行本身不丢）。
    write_failures: AtomicU64,
    /// `StreamGuard::Drop` 共享同一计数（`Arc` 以便跨派生任务累加）。
    aborted: Arc<AtomicU64>,
    /// 积压达 [`FLUSH_BATCH_ROWS`] 时提前唤醒驱动（design §3「2s 或 ≥64 行」）。
    wake: Arc<tokio::sync::Notify>,
    db_path: PathBuf,
    retention_days: u64,
    enabled: bool,
}

impl std::fmt::Debug for RequestLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestLog")
            .field("db_path", &self.db_path)
            .field("enabled", &self.enabled)
            .field("retention_days", &self.retention_days)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .field(
                "write_failures",
                &self.write_failures.load(Ordering::Relaxed),
            )
            .field("aborted", &self.aborted.load(Ordering::Relaxed))
            .finish()
    }
}

impl RequestLog {
    /// 新建（不触盘，表在首次 flush/查询时确保）。
    pub fn new(db_path: PathBuf, enabled: bool, retention_days: u64) -> Self {
        Self {
            pending: Mutex::new(VecDeque::with_capacity(FLUSH_BATCH_ROWS)),
            dropped: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
            aborted: Arc::new(AtomicU64::new(0)),
            wake: Arc::new(tokio::sync::Notify::new()),
            db_path,
            retention_days,
            enabled,
        }
    }

    /// 关闭态构造（`record` 直接丢弃，不判定 `dropped`）。
    pub fn disabled(db_path: PathBuf) -> Self { Self::new(db_path, false, 0) }

    pub fn enabled(&self) -> bool { self.enabled }

    pub fn retention_days(&self) -> u64 { self.retention_days }

    pub fn db_path(&self) -> &Path { &self.db_path }

    /// 队列溢出累计丢弃数（`data.metrics.requests_dropped`）。
    pub fn dropped_total(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }

    /// 写库失败并回灌队列的累计批次数（行不丢，仅观测）。
    pub fn write_failures_total(&self) -> u64 { self.write_failures.load(Ordering::Relaxed) }

    /// 未 finish 的流式请求累计数（`data.metrics.requests_aborted`）。
    pub fn aborted_total(&self) -> u64 { self.aborted.load(Ordering::Relaxed) }

    /// 队列当前长度（测试断言缓冲/丢弃语义）。
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { lock_or_recover(self.pending.lock()).len() }

    /// 队列当前 `request_id` 序列（测试断言回灌保序）。
    #[cfg(test)]
    pub(crate) fn pending_ids(&self) -> Vec<String> {
        lock_or_recover(self.pending.lock())
            .iter()
            .map(|r| r.request_id.clone())
            .collect()
    }

    /// 为流式请求建守卫（共享本实例的 `aborted` 计数，并持 `Weak` 以便
    /// `Drop` 时把中断行写回队列）。
    pub fn stream_guard(self: &Arc<Self>, row: RequestRow) -> StreamGuard {
        StreamGuard::with_log(row, Arc::clone(&self.aborted), Arc::downgrade(self))
    }

    /// 入队（零 I/O）：满 [`REQUEST_QUEUE_CAP`] 时丢最旧并计 `dropped`。
    /// 积压达阈值时 `Notify::notify_one`（非阻塞，无接收者亦不等待）。
    pub fn record(&self, row: RequestRow) {
        if !self.enabled {
            return;
        }
        let len = self.push_back(row);
        if len >= FLUSH_BATCH_ROWS {
            self.wake.notify_one();
        }
    }

    /// 追加一行并按容量淘汰最旧；返回追加后的长度。
    fn push_back(&self, row: RequestRow) -> usize {
        let mut queue = lock_or_recover(self.pending.lock());
        while queue.len() >= REQUEST_QUEUE_CAP {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(row);
        queue.len()
    }

    /// 把失败批次按原顺序放回队首（`push_front` 逆序回灌即得原序）。
    fn requeue_front(&self, rows: Vec<RequestRow>) {
        let mut queue = lock_or_recover(self.pending.lock());
        for row in rows.into_iter().rev() {
            if queue.len() >= REQUEST_QUEUE_CAP {
                // 回灌不得撑破容量：宁可计 `dropped` 也不无界增长。
                self.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            queue.push_front(row);
        }
    }

    /// 同步排空 + 写库 + 保留期清理（关闭路径与单测入口）。
    ///
    /// 先写后丢：写失败时整批回灌队首并计 `write_failures`，错误照常返回
    /// （关闭路径据此 `warn`，但行仍在队列里等下次刷盘）。
    pub fn flush_blocking(&self) -> anyhow::Result<()> { self.flush_with_purge(true) }

    fn flush_with_purge(&self, purge: bool) -> anyhow::Result<()> {
        let rows = self.drain();
        if let Err(err) = write_batch_blocking(&self.db_path, &rows) {
            self.write_failures.fetch_add(1, Ordering::Relaxed);
            self.requeue_front(rows);
            return Err(err);
        }
        if purge {
            purge_blocking(&self.db_path, self.retention_days)?;
        }
        Ok(())
    }

    /// 周期刷盘驱动：`interval` 到点或积压 ≥ [`FLUSH_BATCH_ROWS`] 时排空写库；
    /// 保留期清理按 [`PURGE_INTERVAL_SECS`] 独立计时。
    ///
    /// rusqlite 全为阻塞 I/O，故写库与清理都进 `spawn_blocking`（不占用异步
    /// 工作线程）；失败只 `warn`（转发路径零影响）。
    pub fn spawn_flush_driver(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            let mut last_purge = Instant::now();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = me.wake.notified() => {}
                }
                let flush_target = Arc::clone(&me);
                match tokio::task::spawn_blocking(move || flush_target.flush_with_purge(false))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::warn!("请求日志刷盘失败（转发不受影响）: {err:#}");
                    }
                    Err(err) => {
                        tracing::warn!("请求日志刷盘任务异常终止: {err}");
                    }
                }
                if last_purge.elapsed() >= Duration::from_secs(PURGE_INTERVAL_SECS) {
                    last_purge = Instant::now();
                    let purge_target = Arc::clone(&me);
                    let purge = tokio::task::spawn_blocking(move || {
                        purge_blocking(&purge_target.db_path, purge_target.retention_days)
                    })
                    .await;
                    match purge {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::warn!("请求日志保留期清理失败: {err:#}");
                        }
                        Err(err) => {
                            tracing::warn!("请求日志保留期清理任务异常终止: {err}");
                        }
                    }
                }
            }
        })
    }

    /// 排空队列（锁内只做 `mem::take`，不在持锁时写库）。
    fn drain(&self) -> Vec<RequestRow> {
        let mut queue = lock_or_recover(self.pending.lock());
        queue.drain(..).collect()
    }

    /// 分页过滤查询（同 WHERE 聚合 `sum_*` 与 `earliest_ts`）。
    ///
    /// `offset > `[`MAX_OFFSET`] 属调用方错误（`400`）；此处同判以防御内部误用。
    pub fn query(&self, filter: &RequestFilter) -> anyhow::Result<RequestPage> {
        if filter.offset() > MAX_OFFSET {
            anyhow::bail!("offset 超过上限 {MAX_OFFSET}");
        }
        query_blocking(&self.db_path, filter)
    }

    /// 范围模型分布：读 `request_model_rollup`（`counted_metrics=1` 投影）。
    ///
    /// `gran` 由调用方按范围显式给出（`'m'` = 5min、`'h'` = 1h、`'d'` = 1day），
    /// **不得**由 `now - start_ts` 反推：范围起点对齐后会把细粒度误降为粗粒度。
    /// `start_ts` 按该粒度向下取整为起始窗口序号。
    pub fn per_model_counts(
        &self,
        start_ts: i64,
        gran: char,
    ) -> anyhow::Result<Vec<(String, u64)>> {
        per_model_blocking(&self.db_path, start_ts, gran)
    }
}

/// 输入缓存命中率分母（design §5）：Chat/Responses 的 `prompt_tokens` 已含缓存，
/// Anthropic 的 `input_tokens` **不含**缓存读写，故须加回。
pub fn cache_input_tokens(protocol: &str, prompt: u64, cached_read: u64, cached_write: u64) -> u64 {
    match protocol.to_ascii_lowercase().as_str() {
        "anthropic" | "v1/messages" => prompt
            .saturating_add(cached_read)
            .saturating_add(cached_write),
        _ => prompt,
    }
}

/// 输出速率（tokens/秒），保留一位小数。
///
/// 窗口取「首 token 之后」：`latency_ms - ttft_ms`。**口径自洽**：`ttft_ms` 定格在
/// 首个**生成 token**（内容或推理，见 `handler/llm/pump/ttft.rs::carries_output_token`），
/// 故窗口是 `[首个生成 token .. 流结束]`；分子 `completion_tokens` 也是全部生成 token
/// （含推理 token），两端口径一致，不因首 token 是推理而低估速率。
/// 不可测时返回 `None`——无输出 token（`completion_tokens == 0`）、未记录首 token
/// 时延（含非流请求，其 TTFT/TPS 恒 `None`）、或窗口为 0/负值。
pub fn tokens_per_sec(
    completion_tokens: u64,
    latency_ms: u64,
    ttft_ms: Option<u32>,
) -> Option<f64> {
    let ttft = ttft_ms?;
    if completion_tokens == 0 || latency_ms <= u64::from(ttft) {
        return None;
    }
    let window_secs = (latency_ms - u64::from(ttft)) as f64 / 1_000.0;
    Some((completion_tokens as f64 / window_secs * 10.0).round() / 10.0)
}

const ROLLUP_UPSERT_SQL: &str = "INSERT INTO request_model_rollup(\
     granularity, window, protocol, model, count, prompt, completion, total, cached_read, \
     cached_write, cache_input)\
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)\
     ON CONFLICT(granularity, window, protocol, model) DO UPDATE SET \
     count=count+excluded.count, prompt=prompt+excluded.prompt, \
     completion=completion+excluded.completion, total=total+excluded.total, \
     cached_read=cached_read+excluded.cached_read, \
     cached_write=cached_write+excluded.cached_write, \
     cache_input=cache_input+excluded.cache_input";

/// rollup 单键累计（`(granularity, window, protocol, model)`）。
#[derive(Debug, Clone, Default)]
struct RollupAgg {
    count: u64,
    prompt: u64,
    completion: u64,
    total: u64,
    cached_read: u64,
    cached_write: u64,
    cache_input: u64,
}

/// 三粒度窗口键（与 `metrics::aggregate::{day,hour,five_min}_key` 同口径）。
fn window_keys(ts_secs: i64) -> [(&'static str, String); 3] {
    [
        ("d", format!("d{}", ts_secs.div_euclid(SECS_PER_DAY))),
        ("h", format!("h{}", ts_secs.div_euclid(3_600))),
        ("m", format!("m{}", ts_secs.div_euclid(300))),
    ]
}

/// 仅 `counted_metrics=1` 的行参与 rollup 聚合（与 KPI `requests` 同集合）。
fn aggregate_rollup(rows: &[RequestRow]) -> HashMap<(String, String, String, String), RollupAgg> {
    let mut out: HashMap<(String, String, String, String), RollupAgg> = HashMap::new();
    for row in rows.iter().filter(|r| r.counted_metrics) {
        for (gran, window) in window_keys(row.ts_secs) {
            let key = (
                gran.to_string(),
                window,
                row.protocol.clone(),
                row.model.clone(),
            );
            let agg = out.entry(key).or_default();
            agg.count += 1;
            agg.prompt += row.prompt_tokens;
            agg.completion += row.completion_tokens;
            agg.total += row.total_tokens;
            agg.cached_read += row.cached_read;
            agg.cached_write += row.cached_write;
            agg.cache_input += row.cache_input_tokens;
        }
    }
    out
}

/// 单事务写：`llm_requests` 批量 INSERT + `request_model_rollup` 累加 UPSERT。
fn write_batch_blocking(db_path: &Path, rows: &[RequestRow]) -> anyhow::Result<()> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    if rows.is_empty() {
        ensure_0600(db_path);
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(INSERT_SQL)?;
        for row in rows {
            stmt.execute(rusqlite::params![
                row.ts_secs,
                row.request_id,
                row.protocol,
                row.model,
                row.upstream,
                row.ingress_port.map(i64::from),
                row.stream as i64,
                row.is_chat as i64,
                row.counted_metrics as i64,
                row.status.map(i64::from),
                row.error_kind,
                row.latency_ms as i64,
                row.prompt_tokens as i64,
                row.completion_tokens as i64,
                row.total_tokens as i64,
                row.cached_read as i64,
                row.cached_write as i64,
                row.cache_input_tokens as i64,
                row.session_id,
                row.session_source,
                row.session_scope,
                row.upstream_id,
                row.finish_reason,
                row.truncated_mode,
                row.req_summary,
                row.ttft_ms.map(i64::from),
                row.tps,
            ])?;
        }
    }
    {
        let mut stmt = tx.prepare(ROLLUP_UPSERT_SQL)?;
        for ((gran, window, protocol, model), agg) in aggregate_rollup(rows) {
            stmt.execute(rusqlite::params![
                gran,
                window,
                protocol,
                model,
                agg.count as i64,
                agg.prompt as i64,
                agg.completion as i64,
                agg.total as i64,
                agg.cached_read as i64,
                agg.cached_write as i64,
                agg.cache_input as i64,
            ])?;
        }
    }
    tx.commit()?;
    ensure_0600(db_path);
    Ok(())
}

/// 保留期清理：`llm_requests` 按天数（`0` = 跳过），rollup 按窗口数驱逐。
fn purge_blocking(db_path: &Path, retention_days: u64) -> anyhow::Result<()> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    if retention_days > 0 {
        let retention_secs = i64::try_from(retention_days)
            .unwrap_or(i64::MAX)
            .saturating_mul(SECS_PER_DAY);
        let cutoff = now_secs().saturating_sub(retention_secs);
        conn.execute("DELETE FROM llm_requests WHERE ts_secs < ?1", [cutoff])?;
    }
    for (gran, keep) in ROLLUP_KEEP {
        // 窗口键为 `d{n}`/`h{n}`/`m{n}`：按整数序（跨位 `m9` < `m10`）驱逐最旧。
        conn.execute(
            "DELETE FROM request_model_rollup WHERE granularity = ?1 AND window NOT IN \
             (SELECT window FROM request_model_rollup WHERE granularity = ?1 GROUP BY window \
              ORDER BY CAST(substr(window, 2) AS INTEGER) DESC LIMIT ?2)",
            rusqlite::params![gran, keep as i64],
        )?;
    }
    ensure_0600(db_path);
    Ok(())
}

/// 当前 epoch 秒（保留期截止与守卫补写行的时间基准单一来源）。
pub(super) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `session_id LIKE ?` 的前缀模式（转义 `%`/`_`/`\`，免通配注入）。
fn like_prefix(prefix: &str) -> String {
    let mut escaped = String::with_capacity(prefix.len() + 2);
    for ch in prefix.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push('%');
    escaped
}

/// 按过滤条件拼 WHERE 与参数（`total`/`sum_*`/行查询共用）。
fn build_where(filter: &RequestFilter) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    if let Some(ts) = filter.range_start_ts {
        clauses.push("ts_secs >= ?".to_string());
        values.push(Value::Integer(ts));
    }
    if let Some(model) = filter.model.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("model = ?".to_string());
        values.push(Value::Text(model.to_string()));
    }
    if let Some(protocol) = filter.protocol.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("protocol = ?".to_string());
        values.push(Value::Text(protocol.to_string()));
    }
    match filter.status_class {
        Some(StatusClass::S2xx) => clauses.push("status >= 200 AND status < 300".to_string()),
        Some(StatusClass::S4xx) => clauses.push("status >= 400 AND status < 500".to_string()),
        Some(StatusClass::S5xx) => clauses.push("status >= 500 AND status < 600".to_string()),
        Some(StatusClass::Error) => {
            clauses.push("(status IS NULL OR status >= 400)".to_string());
        }
        None => {}
    }
    if let Some(prefix) = filter.session_prefix.as_deref().filter(|v| !v.is_empty()) {
        clauses.push("session_id LIKE ? ESCAPE '\\'".to_string());
        values.push(Value::Text(like_prefix(prefix)));
    }
    if let Some(scope) = filter.scope {
        clauses.push("session_scope = ?".to_string());
        values.push(Value::Text(scope.as_str().to_string()));
    }
    // 非 LLM 记录为 `is_chat = 0`（`passthrough` 与非对话 `count_tokens` 均属此列），
    // 故按判别位过滤，不得改用 `protocol != 'passthrough'`。
    if filter.llm_only {
        clauses.push("is_chat = 1".to_string());
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    (where_sql, values)
}

fn query_blocking(db_path: &Path, filter: &RequestFilter) -> anyhow::Result<RequestPage> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let (where_sql, mut values) = build_where(filter);
    let mut stmt = conn.prepare(&format!(
        "SELECT COUNT(*), COALESCE(SUM(cached_read), 0), \
         COALESCE(SUM(cache_input_tokens), 0), MIN(ts_secs) FROM llm_requests{where_sql}"
    ))?;
    let (total, sum_cached_read, sum_cache_input_tokens, earliest_ts): (
        i64,
        i64,
        i64,
        Option<i64>,
    ) = stmt.query_row(rusqlite::params_from_iter(values.iter()), |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
    })?;
    drop(stmt);
    let retention_earliest_ts = retention_earliest_blocking(&conn, filter.range_start_ts)?;

    values.push(Value::Integer(filter.limit() as i64));
    values.push(Value::Integer(filter.offset() as i64));
    let mut stmt = conn.prepare(&format!(
        "SELECT ts_secs, request_id, protocol, model, upstream, ingress_port, stream, is_chat, \
         counted_metrics, status, error_kind, latency_ms, prompt_tokens, completion_tokens, \
         total_tokens, cached_read, cached_write, cache_input_tokens, session_id, \
         session_source, session_scope, upstream_id, finish_reason, truncated_mode, req_summary, \
         ttft_ms, tps \
         FROM llm_requests{where_sql} ORDER BY ts_secs DESC, id DESC LIMIT ? OFFSET ?"
    ))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(values.iter()), row_from_sql)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(RequestPage {
        total: total.max(0) as u64,
        rows,
        sum_cached_read: sum_cached_read.max(0) as u64,
        sum_cache_input_tokens: sum_cache_input_tokens.max(0) as u64,
        earliest_ts,
        retention_earliest_ts,
    })
}

/// 只按时间下界取最早 `ts_secs`（业务过滤不参与，供覆盖率口径使用）。
fn retention_earliest_blocking(
    conn: &rusqlite::Connection,
    range_start_ts: Option<i64>,
) -> anyhow::Result<Option<i64>> {
    Ok(match range_start_ts {
        Some(ts) => conn.query_row(
            "SELECT MIN(ts_secs) FROM llm_requests WHERE ts_secs >= ?1",
            [ts],
            |r| r.get(0),
        )?,
        None => conn.query_row("SELECT MIN(ts_secs) FROM llm_requests", [], |r| r.get(0))?,
    })
}

/// sqlite 行 → [`RequestRow`]（列序与 `query_blocking` 的 SELECT 严格一致）。
fn row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestRow> {
    Ok(RequestRow {
        ts_secs: row.get(0)?,
        request_id: row.get(1)?,
        protocol: row.get(2)?,
        model: row.get(3)?,
        upstream: row.get(4)?,
        ingress_port: row
            .get::<_, Option<i64>>(5)?
            .and_then(|v| u16::try_from(v).ok()),
        stream: row.get::<_, i64>(6)? != 0,
        is_chat: row.get::<_, i64>(7)? != 0,
        counted_metrics: row.get::<_, i64>(8)? != 0,
        status: row
            .get::<_, Option<i64>>(9)?
            .and_then(|v| u16::try_from(v).ok()),
        error_kind: row.get(10)?,
        latency_ms: row.get::<_, i64>(11)?.max(0) as u64,
        prompt_tokens: row.get::<_, i64>(12)?.max(0) as u64,
        completion_tokens: row.get::<_, i64>(13)?.max(0) as u64,
        total_tokens: row.get::<_, i64>(14)?.max(0) as u64,
        cached_read: row.get::<_, i64>(15)?.max(0) as u64,
        cached_write: row.get::<_, i64>(16)?.max(0) as u64,
        cache_input_tokens: row.get::<_, i64>(17)?.max(0) as u64,
        session_id: row.get(18)?,
        session_source: row.get(19)?,
        session_scope: row.get(20)?,
        upstream_id: row.get(21)?,
        finish_reason: row.get(22)?,
        truncated_mode: row.get(23)?,
        req_summary: row.get(24)?,
        ttft_ms: row
            .get::<_, Option<i64>>(25)?
            .and_then(|v| u32::try_from(v).ok()),
        tps: row.get(26)?,
    })
}

/// 粒度字符 → (`rollup` 粒度键, 窗口跨度秒)；非法取值返回 `None`。
///
/// `m` 为 5min 窗（与 [`window_keys`] 的 `m` 键口径一致），`h` 为 1h，`d` 为 1day。
fn gran_span(gran: char) -> Option<(&'static str, i64)> {
    match gran {
        'm' => Some(("m", 300)),
        'h' => Some(("h", 3_600)),
        'd' => Some(("d", SECS_PER_DAY)),
        _ => None,
    }
}

fn per_model_blocking(
    db_path: &Path,
    start_ts: i64,
    gran: char,
) -> anyhow::Result<Vec<(String, u64)>> {
    let Some((granularity, span_secs)) = gran_span(gran) else {
        anyhow::bail!("非法 rollup 粒度 {gran:?}（只支持 'm'|'h'|'d'）");
    };
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let start_window = start_ts.div_euclid(span_secs);
    let mut stmt = conn.prepare(
        "SELECT model, SUM(count) FROM request_model_rollup \
         WHERE granularity = ?1 AND CAST(substr(window, 2) AS INTEGER) >= ?2 \
         GROUP BY model ORDER BY SUM(count) DESC, model ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![granularity, start_window], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests;
