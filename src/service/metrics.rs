//! §7.1 指标聚合 + §7.3 摘要脱敏 + §7.4 PII 值级掩码采样。
//!
//! 口径对标原仓 `_metrics.py`（内存环 10k + sqlite 日/小时聚合）：
//! - 内存环 10k（最近 10k 样本）+ `daily` 保留 30 天 + `hourly` 保留 7 天 + `five_min` 覆盖式
//!   UPSERT（只留最新窗口，重复 flush 覆盖不翻倍）；
//! - 计数仅含对话端点（`is_chat_tail` 为真，非对话直接跳过）；
//! - 延迟 12 桶直方图近似 p95；`is_precise` 为真表示精确计数可直接对账，
//!   为假表示近似仅趋势参考（内存-only 降级时为假）；
//! - `truncated_mode` 三态（`silent_discard`/`open_ended`/`synthesized_failed`） 按 mode
//!   分标签计数，三态之外不落指标并记告警；
//! - 非流式 usage 与流式同口径计入（`responses` 单层 `response.usage` + Anthropic `message.usage`
//!   由网关 `extract_usage_nonstream` 产出，此处只做 聚合口径不断言网关，见 TODO(§7)）；
//! - 写库一律 `spawn_blocking(rusqlite WAL)`，文件 0600（复用 `fs_perm` 单源，不直调私有函数）；
//!   PII 值级采样落盘走有界 `broadcast` 后台批量刷盘，同步入口永不直写。
//!
//! 接线状态（§7 落点已接线）：`record_chat` 已由 `handler/llm` 接线
//! （非流 `nonstream::serve_nonstream` + 流泵 `pump::spawn_stream_pump` 收尾）；审计 hold 事件
//! `push_event` 由网关调用方按需接线（见 `service::admin::AdminState::push_event`）。

use {
    super::llm_gateway::{Protocol, Usage},
    crate::fs_perm::{ensure_0600, open_wal},
    std::{
        collections::{HashMap, VecDeque},
        path::{Path, PathBuf},
        sync::{
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    },
};

/// 内存环容量（最近 10k 样本）。
pub const RING_CAP: usize = 10_000;
/// 延迟桶边界（毫秒），对标原仓 12 桶 Python 边界；11 条边界 → 12 桶（含上溢桶）。
pub const LATENCY_BOUNDS_MS: [u64; 11] = [10, 25, 50, 100, 200, 400, 800, 1500, 3000, 5000, 10000];
/// 延迟桶数（硬性 12）。
pub const LATENCY_BUCKETS: usize = 12;
/// `truncated_mode` 唯一三态（他值不落指标）。
pub const TRUNCATED_MODES: [&str; 3] = ["silent_discard", "open_ended", "synthesized_failed"];
/// `daily` 保留天数。
pub const DAILY_RETENTION_DAYS: i64 = 30;
/// `hourly` 保留天数。
pub const HOURLY_RETENTION_DAYS: i64 = 7;
/// PII 采样落盘滚动天数。
pub const PII_SAMPLE_RETENTION_DAYS: i64 = 7;
/// 摘要截断默认上限（字符）。
pub const SUMMARY_MAX_CHARS: usize = 1000;

/// 延迟值落桶（0..12）。
pub fn bucket_index(latency_ms: u64) -> usize {
    LATENCY_BOUNDS_MS
        .iter()
        .position(|&b| latency_ms <= b)
        .unwrap_or(LATENCY_BUCKETS - 1)
}

/// 12 桶近似 p95：首个累积 ≥95% 所在桶的桶中位 `(lower+upper)/2`（对标原仓口径）；
/// 上溢桶返回最后边界（无上界，中位无定义）。
pub fn p95_approx(buckets: &[u64; LATENCY_BUCKETS]) -> u64 {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return 0;
    }
    let threshold = ((total as f64) * 0.95).ceil() as u64;
    let mut acc = 0u64;
    for (i, &c) in buckets.iter().enumerate() {
        acc += c;
        if acc >= threshold {
            let upper = LATENCY_BOUNDS_MS.get(i).copied().unwrap_or(u64::MAX);
            if upper == u64::MAX {
                return LATENCY_BOUNDS_MS[LATENCY_BOUNDS_MS.len() - 1];
            }
            let lower = if i == 0 { 0 } else { LATENCY_BOUNDS_MS[i - 1] };
            return (lower + upper) / 2;
        }
    }
    LATENCY_BOUNDS_MS[LATENCY_BOUNDS_MS.len() - 1]
}

/// 精确性双条件（对标原仓）：`窗口覆盖 ≥3600s && 样本 ≥100` 才标精确，否则近似标 `≈`。
pub fn is_precise_for_window(coverage_secs: u64, samples: u64) -> bool {
    coverage_secs >= 3600 && samples >= 100
}

/// 单个请求样本（仅对话端点）。
#[derive(Debug, Clone)]
pub struct MetricSample {
    pub ts_secs: i64,
    pub protocol: String,
    pub latency_ms: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_read: u64,
    pub cached_write: u64,
    pub unknown: u64,
    pub truncated_mode: Option<String>,
    pub is_precise: bool,
}

/// 扩展 usage（对标原仓 `cached_read/cached_write/unknown` 三列）。
/// `Usage` 结构体归属网关模块（禁触），本结构为指标侧加法口径。
#[derive(Debug, Clone, Default)]
pub struct ExtendedUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_read: u64,
    pub cached_write: u64,
    pub unknown: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Granularity {
    Daily,
    Hourly,
    FiveMin,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AggKey {
    granularity: Granularity,
    window: String,
    protocol: String,
}

#[derive(Debug, Clone, Default)]
struct WindowAgg {
    count: u64,
    prompt: u64,
    completion: u64,
    total: u64,
    cached_read: u64,
    cached_write: u64,
    unknown: u64,
    pii_hits: u64,
    cred_hits: u64,
    audit_blocks: u64,
    buckets: [u64; LATENCY_BUCKETS],
    t_silent: u64,
    t_open: u64,
    t_synth: u64,
}

fn day_key(ts_secs: i64) -> String {
    // UTC 日键（不引入 chrono 重依赖，用整数天）。
    let days = ts_secs.div_euclid(86_400);
    format!("d{days}")
}

fn hour_key(ts_secs: i64) -> String {
    let hours = ts_secs.div_euclid(3_600);
    format!("h{hours}")
}

fn five_min_key(ts_secs: i64) -> String {
    let w = ts_secs.div_euclid(300);
    format!("m{w}")
}

/// 指标聚合存储：内存环 + 窗口累计（覆盖式）+ sqlite 落盘。
pub struct MetricsStore {
    ring: Mutex<VecDeque<MetricSample>>,
    aggs: Mutex<HashMap<AggKey, WindowAgg>>,
    db_path: PathBuf,
    dropped: AtomicU64,
}

impl std::fmt::Debug for MetricsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsStore")
            .field("db_path", &self.db_path)
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish()
    }
}

impl MetricsStore {
    /// 新建（同步构造不碰磁盘，表在首次 flush/查询时确保）。
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(RING_CAP)),
            aggs: Mutex::new(HashMap::new()),
            db_path,
            dropped: AtomicU64::new(0),
        }
    }

    /// 记录一次对话端点观测（基础口径，扩展列置零；签名兼容版）。
    pub fn record_chat(
        &self,
        protocol: Protocol,
        latency_ms: u64,
        usage: Option<&Usage>,
        truncated_mode: Option<&str>,
        is_precise: bool,
        ts_secs: i64,
    ) -> bool {
        let ext = usage.map(|u| ExtendedUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
            ..ExtendedUsage::default()
        });
        self.record_chat_extended(
            protocol,
            latency_ms,
            ext.as_ref(),
            truncated_mode,
            is_precise,
            ts_secs,
        )
    }

    /// 记录一次对话端点观测（扩展口径：含 `cached_read/write/unknown`）。
    pub fn record_chat_extended(
        &self,
        protocol: Protocol,
        latency_ms: u64,
        usage: Option<&ExtendedUsage>,
        truncated_mode: Option<&str>,
        is_precise: bool,
        ts_secs: i64,
    ) -> bool {
        if protocol == Protocol::NonDialog {
            return false;
        }
        let truncated = match truncated_mode {
            Some(m) if TRUNCATED_MODES.contains(&m) => Some(m.to_string()),
            Some(bad) => {
                tracing::warn!(mode = %bad, "truncated_mode 非法值不落指标");
                None
            }
            None => None,
        };
        let proto = protocol.as_tail().to_string();
        let ext = usage.cloned().unwrap_or_default();
        let sample = MetricSample {
            ts_secs,
            protocol: proto.clone(),
            latency_ms,
            prompt_tokens: ext.prompt_tokens,
            completion_tokens: ext.completion_tokens,
            total_tokens: ext.total_tokens,
            cached_read: ext.cached_read,
            cached_write: ext.cached_write,
            unknown: ext.unknown,
            truncated_mode: truncated.clone(),
            is_precise,
        };
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() >= RING_CAP {
                ring.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            ring.push_back(sample);
        }
        if let Ok(mut aggs) = self.aggs.lock() {
            for (g, key) in [
                (Granularity::Daily, day_key(ts_secs)),
                (Granularity::Hourly, hour_key(ts_secs)),
                (Granularity::FiveMin, five_min_key(ts_secs)),
            ] {
                let entry = aggs
                    .entry(AggKey {
                        granularity: g,
                        window: key,
                        protocol: proto.clone(),
                    })
                    .or_default();
                entry.count += 1;
                entry.prompt += ext.prompt_tokens;
                entry.completion += ext.completion_tokens;
                entry.total += ext.total_tokens;
                entry.cached_read += ext.cached_read;
                entry.cached_write += ext.cached_write;
                entry.unknown += ext.unknown;
                entry.buckets[bucket_index(latency_ms)] += 1;
                match truncated.as_deref() {
                    Some("silent_discard") => entry.t_silent += 1,
                    Some("open_ended") => entry.t_open += 1,
                    Some("synthesized_failed") => entry.t_synth += 1,
                    _ => {}
                }
            }
        }
        true
    }

    /// 当前环长度（单测/快照用）。
    pub fn ring_len(&self) -> usize { self.ring.lock().map(|r| r.len()).unwrap_or(0) }

    /// 环满丢弃计数（`mpsc(512)` 背压语义的内存环对应物，只计数不阻塞）。
    pub fn dropped_total(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }

    /// 快照（`/_admin/metrics` 口径）：聚合内存环 + 窗口累计。
    pub fn snapshot(&self) -> MetricsSnapshot {
        let (mut count, mut prompt, mut completion, mut total) = (0u64, 0u64, 0u64, 0u64);
        let (mut cached_read, mut cached_write, mut unknown) = (0u64, 0u64, 0u64);
        let mut buckets = [0u64; LATENCY_BUCKETS];
        let mut t_silent = 0u64;
        let mut t_open = 0u64;
        let mut t_synth = 0u64;
        let mut per_protocol: HashMap<String, u64> = HashMap::new();
        let mut precise_true = 0u64;
        let mut precise_total = 0u64;
        let (mut min_ts, mut max_ts) = (i64::MAX, i64::MIN);
        if let Ok(ring) = self.ring.lock() {
            for s in ring.iter() {
                count += 1;
                if s.ts_secs < min_ts {
                    min_ts = s.ts_secs;
                }
                if s.ts_secs > max_ts {
                    max_ts = s.ts_secs;
                }
                prompt += s.prompt_tokens;
                completion += s.completion_tokens;
                total += s.total_tokens;
                cached_read += s.cached_read;
                cached_write += s.cached_write;
                unknown += s.unknown;
                buckets[bucket_index(s.latency_ms)] += 1;
                *per_protocol.entry(s.protocol.clone()).or_insert(0) += 1;
                precise_total += 1;
                if s.is_precise {
                    precise_true += 1;
                }
                match s.truncated_mode.as_deref() {
                    Some("silent_discard") => t_silent += 1,
                    Some("open_ended") => t_open += 1,
                    Some("synthesized_failed") => t_synth += 1,
                    _ => {}
                }
            }
        }
        MetricsSnapshot {
            requests: count,
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
            cached_read,
            cached_write,
            unknown,
            latency_buckets: buckets,
            p95_ms: p95_approx(&buckets),
            per_protocol,
            truncated_silent_discard: t_silent,
            truncated_open_ended: t_open,
            truncated_synthesized_failed: t_synth,
            // 精确性双条件（窗口覆盖 ≥3600s 且样本 ≥100）叠加降级样本一票否决。
            is_precise: {
                let coverage = if count == 0 {
                    0
                } else {
                    (max_ts - min_ts).max(0) as u64
                };
                is_precise_for_window(coverage, count)
                    && precise_total > 0
                    && precise_true == precise_total
            },
            ring_len: count as usize,
            dropped: self.dropped_total(),
        }
    }

    /// 覆盖式刷盘同步镜像（仅单测用；生产一律走异步 [`flush`](MetricsStore::flush)）。
    #[cfg(test)]
    pub fn flush_to_sqlite_blocking(&self) -> anyhow::Result<()> {
        let snapshot: Vec<(AggKey, WindowAgg)> = self
            .aggs
            .lock()
            .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        flush_aggs_blocking(&self.db_path, &snapshot)?;
        purge_retention_blocking(&self.db_path)?;
        Ok(())
    }

    /// 异步刷盘：快照拷贝后下沉 `spawn_blocking`，绝不在 async 直调 rusqlite。
    pub async fn flush(&self) -> anyhow::Result<()> {
        let snapshot: Vec<(AggKey, WindowAgg)> = self
            .aggs
            .lock()
            .map(|g| g.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            flush_aggs_blocking(&db_path, &snapshot)?;
            purge_retention_blocking(&db_path)
        })
        .await
        .map_err(|e| anyhow::anyhow!("metrics 刷盘任务异常: {e}"))?
    }

    /// 附属计数（pii/cred/audit 三列，日/小时口径）：网关侧审计与脱敏事件回填。
    /// 与 `record_chat` 独立累积，flush 时同窗合并（覆盖式 UPSERT）。
    pub fn record_aux_counts(
        &self,
        protocol: Protocol,
        ts_secs: i64,
        pii_hits: u64,
        cred_hits: u64,
        audit_blocks: u64,
    ) {
        if protocol == Protocol::NonDialog {
            return;
        }
        let proto = protocol.as_tail().to_string();
        if let Ok(mut aggs) = self.aggs.lock() {
            for (g, key) in [
                (Granularity::Daily, day_key(ts_secs)),
                (Granularity::Hourly, hour_key(ts_secs)),
                (Granularity::FiveMin, five_min_key(ts_secs)),
            ] {
                let entry = aggs
                    .entry(AggKey {
                        granularity: g,
                        window: key,
                        protocol: proto.clone(),
                    })
                    .or_default();
                entry.pii_hits += pii_hits;
                entry.cred_hits += cred_hits;
                entry.audit_blocks += audit_blocks;
            }
        }
    }

    /// 重启回填：从 sqlite 读回各粒度聚合，恢复内存窗口累计（覆盖式，不翻倍）。
    pub async fn backfill_from_sqlite(&self) -> anyhow::Result<usize> {
        let db_path = self.db_path.clone();
        let rows = tokio::task::spawn_blocking(move || backfill_rows_blocking(&db_path))
            .await
            .map_err(|e| anyhow::anyhow!("metrics 回填任务异常: {e}"))??;
        let n = rows.len();
        if let Ok(mut aggs) = self.aggs.lock() {
            for (key, agg) in rows {
                aggs.insert(key, agg);
            }
        }
        Ok(n)
    }

    /// 时序查询（`/_admin/series` 口径）：读 sqlite 聚合表。
    pub async fn query_series(
        &self,
        granularity: &str,
        since_window: Option<String>,
        protocol: Option<String>,
    ) -> anyhow::Result<Vec<SeriesPoint>> {
        let db_path = self.db_path.clone();
        let gran = granularity.to_string();
        let since = since_window.clone();
        let proto = protocol.clone();
        tokio::task::spawn_blocking(move || {
            query_series_blocking(&db_path, &gran, since.as_deref(), proto.as_deref())
        })
        .await
        .map_err(|e| anyhow::anyhow!("series 查询任务异常: {e}"))?
    }
}

/// 快照（`/_admin/metrics` 响应体 Schalke）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_read: u64,
    pub cached_write: u64,
    pub unknown: u64,
    pub latency_buckets: [u64; LATENCY_BUCKETS],
    pub p95_ms: u64,
    pub per_protocol: HashMap<String, u64>,
    pub truncated_silent_discard: u64,
    pub truncated_open_ended: u64,
    pub truncated_synthesized_failed: u64,
    pub is_precise: bool,
    pub ring_len: usize,
    pub dropped: u64,
}

/// 时序点（`/_admin/series` 行）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeriesPoint {
    pub window: String,
    pub protocol: String,
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_read: u64,
    pub cached_write: u64,
    pub unknown: u64,
    pub pii_hits: u64,
    pub cred_hits: u64,
    pub audit_blocks: u64,
    pub truncated_silent_discard: u64,
    pub truncated_open_ended: u64,
    pub truncated_synthesized_failed: u64,
}

/// WAL 截断检查点（TRUNCATE）：刷盘后 best-effort 调用，把 `-wal` 合并回主库并截断，
/// 防 `-wal` 常驻膨胀。返回 `(busy, checkpointed)`；调用方失败只 warn 不中断刷盘。
pub fn wal_checkpoint_truncate(db_path: &Path) -> anyhow::Result<(u32, u32)> {
    let conn = open_wal(db_path)?;
    let (busy, checkpointed): (u32, u32) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    Ok((busy, checkpointed))
}

fn ensure_tables(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metrics_daily(
            window TEXT NOT NULL, protocol TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cached_read INTEGER NOT NULL DEFAULT 0,
            cached_write INTEGER NOT NULL DEFAULT 0,
            unknown INTEGER NOT NULL DEFAULT 0,
            pii_hits INTEGER NOT NULL DEFAULT 0,
            cred_hits INTEGER NOT NULL DEFAULT 0,
            audit_blocks INTEGER NOT NULL DEFAULT 0,
            t_silent INTEGER NOT NULL DEFAULT 0,
            t_open INTEGER NOT NULL DEFAULT 0,
            t_synth INTEGER NOT NULL DEFAULT 0,
            buckets TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(window, protocol));
         CREATE TABLE IF NOT EXISTS metrics_hourly(
            window TEXT NOT NULL, protocol TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cached_read INTEGER NOT NULL DEFAULT 0,
            cached_write INTEGER NOT NULL DEFAULT 0,
            unknown INTEGER NOT NULL DEFAULT 0,
            pii_hits INTEGER NOT NULL DEFAULT 0,
            cred_hits INTEGER NOT NULL DEFAULT 0,
            audit_blocks INTEGER NOT NULL DEFAULT 0,
            t_silent INTEGER NOT NULL DEFAULT 0,
            t_open INTEGER NOT NULL DEFAULT 0,
            t_synth INTEGER NOT NULL DEFAULT 0,
            buckets TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(window, protocol));
         CREATE TABLE IF NOT EXISTS metrics_five_min(
            window TEXT NOT NULL, protocol TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
            cached_read INTEGER NOT NULL DEFAULT 0,
            cached_write INTEGER NOT NULL DEFAULT 0,
            unknown INTEGER NOT NULL DEFAULT 0,
            pii_hits INTEGER NOT NULL DEFAULT 0,
            cred_hits INTEGER NOT NULL DEFAULT 0,
            audit_blocks INTEGER NOT NULL DEFAULT 0,
            t_silent INTEGER NOT NULL DEFAULT 0,
            t_open INTEGER NOT NULL DEFAULT 0,
            t_synth INTEGER NOT NULL DEFAULT 0,
            buckets TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(window, protocol));",
    )?;
    // 存量库兼容：旧表缺新列时补列（双写兼容视图对等，旧大盘不断链）。
    for table in ["metrics_daily", "metrics_hourly", "metrics_five_min"] {
        for col in [
            "cached_read",
            "cached_write",
            "unknown",
            "pii_hits",
            "cred_hits",
            "audit_blocks",
        ] {
            let _ = conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"),
                [],
            );
        }
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pii_value_samples(
            hash TEXT PRIMARY KEY, kind TEXT NOT NULL,
            mask TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1,
            first_seen INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER NOT NULL DEFAULT 0);",
    )?;
    Ok(())
}

fn buckets_encode(b: &[u64; LATENCY_BUCKETS]) -> String {
    b.iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// 覆盖式 UPSERT（`excluded.*` 全覆盖，重复 flush 不翻倍）。
fn flush_aggs_blocking(db_path: &Path, aggs: &[(AggKey, WindowAgg)]) -> anyhow::Result<()> {
    if aggs.is_empty() {
        let conn = open_wal(db_path)?;
        ensure_tables(&conn)?;
        ensure_0600(db_path);
        return Ok(());
    }
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    for (key, agg) in aggs {
        let table = match key.granularity {
            Granularity::Daily => "metrics_daily",
            Granularity::Hourly => "metrics_hourly",
            Granularity::FiveMin => "metrics_five_min",
        };
        let sql = format!(
            "INSERT INTO {table}(window, protocol, requests, prompt_tokens, completion_tokens, \
             total_tokens, cached_read, cached_write, unknown, pii_hits, cred_hits, audit_blocks, \
             t_silent, t_open, t_synth, buckets) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16) \
             ON CONFLICT(window, protocol) DO UPDATE SET \
             requests=excluded.requests, prompt_tokens=excluded.prompt_tokens, \
             completion_tokens=excluded.completion_tokens, total_tokens=excluded.total_tokens, \
             cached_read=excluded.cached_read, cached_write=excluded.cached_write, \
             unknown=excluded.unknown, pii_hits=excluded.pii_hits, cred_hits=excluded.cred_hits, \
             audit_blocks=excluded.audit_blocks, \
             t_silent=excluded.t_silent, t_open=excluded.t_open, t_synth=excluded.t_synth, \
             buckets=excluded.buckets"
        );
        conn.execute(
            &sql,
            rusqlite::params![
                key.window,
                key.protocol,
                agg.count as i64,
                agg.prompt as i64,
                agg.completion as i64,
                agg.total as i64,
                agg.cached_read as i64,
                agg.cached_write as i64,
                agg.unknown as i64,
                agg.pii_hits as i64,
                agg.cred_hits as i64,
                agg.audit_blocks as i64,
                agg.t_silent as i64,
                agg.t_open as i64,
                agg.t_synth as i64,
                buckets_encode(&agg.buckets),
            ],
        )?;
    }
    // `five_min` 只留最新窗口（每 protocol 最大 window）。
    conn.execute_batch(
        "DELETE FROM metrics_five_min WHERE (protocol, window) NOT IN \
         (SELECT protocol, MAX(window) FROM metrics_five_min GROUP BY protocol);",
    )?;
    ensure_0600(db_path);
    drop(conn);
    if let Err(err) = wal_checkpoint_truncate(db_path) {
        tracing::warn!("wal_checkpoint(TRUNCATE) 失败（刷盘不受影响）: {err:#}");
    }
    Ok(())
}

fn purge_retention_blocking(db_path: &Path) -> anyhow::Result<()> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    // 窗口键为 `d{days}` / `h{hours}` / `m{win}` 整数序，字符串比较需转整数；
    // 保守策略：按行数裁剪（daily 保留 32 窗×协议，hourly 保留 7*24+2 窗×协议）。
    conn.execute_batch(
        "DELETE FROM metrics_daily WHERE window NOT IN \
         (SELECT window FROM metrics_daily GROUP BY window ORDER BY window DESC LIMIT 32); \
         DELETE FROM metrics_hourly WHERE window NOT IN \
         (SELECT window FROM metrics_hourly GROUP BY window ORDER BY window DESC LIMIT 170);",
    )?;
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        - PII_SAMPLE_RETENTION_DAYS * 86_400;
    conn.execute(
        "DELETE FROM pii_value_samples WHERE last_seen < ?1",
        [cutoff],
    )?;
    ensure_0600(db_path);
    Ok(())
}

fn query_series_blocking(
    db_path: &Path,
    granularity: &str,
    since: Option<&str>,
    protocol: Option<&str>,
) -> anyhow::Result<Vec<SeriesPoint>> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let table = match granularity {
        "daily" => "metrics_daily",
        "five_min" | "5min" => "metrics_five_min",
        _ => "metrics_hourly",
    };
    let mut sql = format!(
        "SELECT window, protocol, requests, prompt_tokens, completion_tokens,\
         total_tokens, cached_read, cached_write, unknown, pii_hits, cred_hits, audit_blocks, \
         t_silent, t_open, t_synth FROM {table} WHERE 1=1"
    );
    if since.is_some() {
        sql.push_str(" AND window >= ?");
    }
    if protocol.is_some() {
        sql.push_str(" AND protocol = ?");
    }
    sql.push_str(" ORDER BY window ASC LIMIT 500");
    let mut stmt = conn.prepare(&sql)?;
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(s) = since {
        params.push(Box::new(s.to_string()));
    }
    if let Some(p) = protocol {
        params.push(Box::new(p.to_string()));
    }
    let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(refs.as_slice(), |row| {
        Ok(SeriesPoint {
            window: row.get(0)?,
            protocol: row.get(1)?,
            requests: row.get::<_, i64>(2)? as u64,
            prompt_tokens: row.get::<_, i64>(3)? as u64,
            completion_tokens: row.get::<_, i64>(4)? as u64,
            total_tokens: row.get::<_, i64>(5)? as u64,
            cached_read: row.get::<_, i64>(6)? as u64,
            cached_write: row.get::<_, i64>(7)? as u64,
            unknown: row.get::<_, i64>(8)? as u64,
            pii_hits: row.get::<_, i64>(9)? as u64,
            cred_hits: row.get::<_, i64>(10)? as u64,
            audit_blocks: row.get::<_, i64>(11)? as u64,
            truncated_silent_discard: row.get::<_, i64>(12)? as u64,
            truncated_open_ended: row.get::<_, i64>(13)? as u64,
            truncated_synthesized_failed: row.get::<_, i64>(14)? as u64,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// 重启回填行读取：三粒度表全量读回内存聚合（flush 覆盖式语义，重启不丢窗）。
fn backfill_rows_blocking(db_path: &Path) -> anyhow::Result<Vec<(AggKey, WindowAgg)>> {
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let mut out = Vec::new();
    for (gran, table) in [
        (Granularity::Daily, "metrics_daily"),
        (Granularity::Hourly, "metrics_hourly"),
        (Granularity::FiveMin, "metrics_five_min"),
    ] {
        let mut stmt = conn.prepare(&format!(
            "SELECT window, protocol, requests, prompt_tokens, completion_tokens, total_tokens, \
             cached_read, cached_write, unknown, pii_hits, cred_hits, audit_blocks, \
             t_silent, t_open, t_synth, buckets FROM {table}"
        ))?;
        let rows = stmt.query_map([], |row| {
            let buckets_s: String = row.get(15)?;
            let mut buckets = [0u64; LATENCY_BUCKETS];
            for (i, part) in buckets_s.split(',').enumerate().take(LATENCY_BUCKETS) {
                buckets[i] = part.trim().parse().unwrap_or(0);
            }
            Ok((
                AggKey {
                    granularity: gran,
                    window: row.get(0)?,
                    protocol: row.get(1)?,
                },
                WindowAgg {
                    count: row.get::<_, i64>(2)? as u64,
                    prompt: row.get::<_, i64>(3)? as u64,
                    completion: row.get::<_, i64>(4)? as u64,
                    total: row.get::<_, i64>(5)? as u64,
                    cached_read: row.get::<_, i64>(6)? as u64,
                    cached_write: row.get::<_, i64>(7)? as u64,
                    unknown: row.get::<_, i64>(8)? as u64,
                    pii_hits: row.get::<_, i64>(9)? as u64,
                    cred_hits: row.get::<_, i64>(10)? as u64,
                    audit_blocks: row.get::<_, i64>(11)? as u64,
                    t_silent: row.get::<_, i64>(12)? as u64,
                    t_open: row.get::<_, i64>(13)? as u64,
                    t_synth: row.get::<_, i64>(14)? as u64,
                    buckets,
                },
            ))
        })?;
        for r in rows {
            out.push(r?);
        }
    }
    Ok(out)
}

// ── §7.3 摘要脱敏单一路径：redact → truncate ──────────────────────────────

/// 秘密 JSON 键形态（`{"password":"hunter2"}` 落盘须为脱敏后）。
/// 对标原仓 `_SECRET_PATTERNS`：覆盖常见键名 + JSON 冒号形态。
fn secret_key_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)("?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"?\s*[:=]\s*"?)[^",}\s][^",}]*"#,
        )
        .expect("secret 正则恒合法")
    })
}

fn sk_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{8,}").expect("sk 正则恒合法")
    })
}

fn email_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
            .expect("email 正则恒合法")
    })
}

fn placeholder_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"__VG_CRED_[0-9A-Za-z_]*__?|__PII_[0-9A-Za-z_]*__?")
            .expect("占位符正则恒合法")
    })
}

/// 摘要脱敏（单一路径）：先脱敏后截断。
///
/// 顺序硬性 `redact → truncate`：`__PII__`/`__VG_CRED__`/`sk-`/email/秘密键值
/// → `[REDACTED:*]`，控制字符（`\x00-\x1f` 除 `\t\n`）剥离防伪造条目。
pub fn redact_summary(text: &str) -> String {
    // 控制字符先剥离（防伪造条目），保留 \t \n。
    let cleaned: String = text
        .chars()
        .filter(|&c| !c.is_control() || c == '\t' || c == '\n')
        .collect();
    let s = placeholder_re().replace_all(&cleaned, "[REDACTED:placeholder]");
    let s = sk_re().replace_all(&s, "[REDACTED:api_key]");
    let s = email_re().replace_all(&s, "[REDACTED:email]");
    // JSON 键形态：保留键名与分隔符，只脱敏值部（`$1` 为键+分隔符捕获组）。
    let s = secret_key_re().replace_all(&s, "$1[REDACTED:secret]");
    s.into_owned()
}

/// UTF-8 半字符保护截断（按字符数，不切分 `char` 边界）。
pub fn truncate_utf8(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars).collect();
    format!("{kept}…[truncated]")
}

/// 摘要单一路径：`redact → truncate`。
pub fn summarize(text: &str, max_chars: usize) -> String {
    truncate_utf8(&redact_summary(text), max_chars)
}

// ── §7.4 PII 值级掩码采样 ──────────────────────────────────────────────────

/// PII 采样开关（`Config` 口径，默认关闭）：
/// `pii_value_sample_enabled` 开启，`pii_value_sample_persist=false` 只记内存不落盘，
/// `pii_value_sample_hmac_key` 置位时用 HMAC-SHA256 计 hash，未设退化为普通
/// SHA256（低熵 PII 可被字典枚举，仅趋势参考——文档声明风险，见 [`PiiValueSampler::hash_value`]）。
/// 启动期由 `Config` 解析，热重载不支持；请求路径 MUST NOT 直读进程环境。
#[derive(Debug, Clone)]
pub struct PiiSamplerConfig {
    pub enabled: bool,
    pub persist: bool,
    pub hmac_key: Option<String>,
}

impl PiiSamplerConfig {
    /// 从 `Config` 构造（启动期唯一入口）。
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            enabled: config.pii_value_sample_enabled,
            persist: config.pii_value_sample_persist,
            hmac_key: config.pii_value_sample_hmac_key.clone(),
        }
    }

    #[cfg(test)]
    fn for_test(enabled: bool, persist: bool, hmac_key: Option<String>) -> Self {
        Self {
            enabled,
            persist,
            hmac_key,
        }
    }

    /// 无盐告警谓词：采样开启且未配 HMAC 时 hash 退化为无盐 SHA256，
    /// 低熵 PII 可被离线字典枚举，启动期须 warn（生产必须配置）。
    pub fn needs_hmac_warn(&self) -> bool {
        self.enabled && self.hmac_key.as_deref().unwrap_or("").is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SampleView {
    pub hash: String,
    pub kind: String,
    pub mask: String,
    pub hits: u64,
}

#[derive(Debug, Default)]
struct SamplerCounts {
    sampled: u64,
    skipped_disabled: u64,
    skipped_non_chat: u64,
    dropped_full: u64,
}

/// 采样落盘队列容量（有界通道背压：满时丢最老计 `dropped`，与指标环同语义）。
pub const SAMPLE_QUEUE_CAP: usize = 512;
/// 采样落盘行（掩码 + hash，不含明文）。
#[derive(Debug, Clone)]
struct SampleRow {
    hash: String,
    kind: String,
    mask: String,
    seen: i64,
}

/// PII 值级掩码采样：掩码当场生成，明文不出作用域（函数返回前丢弃）。
/// 落盘经有界 `broadcast` 后台任务批量写库，`sample()` 同步入口只做内存合并 + 非阻塞发送，
/// 永不在转发热路径同步写 sqlite（通道采 `broadcast` 而非 `mpsc`：`mpsc` 发送侧无驱逐 API，
/// 满时只能丢最新；`broadcast` 滞后即丢最老并经 `Lagged(n)` 上报精确丢数）。
/// 满队列丢最老计 `dropped_full`，可经 [`dropped_total`](PiiValueSampler::dropped_total) 查询。
pub struct PiiValueSampler {
    cfg: PiiSamplerConfig,
    counts: std::sync::Arc<Mutex<SamplerCounts>>,
    recent: Mutex<VecDeque<SampleView>>,
    tx: tokio::sync::broadcast::Sender<SampleRow>,
}

impl std::fmt::Debug for PiiValueSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiValueSampler")
            .field("enabled", &self.cfg.enabled)
            .field("persist", &self.cfg.persist)
            .field("hmac_configured", &self.cfg.hmac_key.is_some())
            .finish()
    }
}

impl PiiValueSampler {
    /// 新建（`db_path` 与 metrics 共库 `pii_value_samples` 表）。
    /// 落盘驱动：`persist` 开启且处于 tokio 运行时内时起后台任务批量刷盘；
    /// 同步单测（无运行时）下不行驱动，行滞留队列由 [`pending_len`](PiiValueSampler::pending_len)
    /// 可查。
    pub fn new(cfg: PiiSamplerConfig, db_path: PathBuf) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(SAMPLE_QUEUE_CAP);
        let counts = std::sync::Arc::new(Mutex::new(SamplerCounts::default()));
        if cfg.persist && tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(sample_flush_driver(
                _rx,
                db_path.clone(),
                std::sync::Arc::clone(&counts),
            ));
        }
        // 无运行时（同步单测）：`_rx` 随作用域析构，队列关闭；此形态下不启用
        // persist 落盘，误发一律计 `dropped`（可查），见
        // [`dropped_total`](PiiValueSampler::dropped_total)。
        Self {
            cfg,
            counts,
            recent: Mutex::new(VecDeque::with_capacity(256)),
            tx,
        }
    }

    /// 值级掩码（当场生成）：首字符 + `***` + 末字符，超短值全掩码。
    /// 输入明文仅在本函数栈上存活，返回后调用方须立即丢弃。
    pub fn sample_mask(value: &str) -> String {
        let chars: Vec<char> = value.chars().collect();
        if chars.len() <= 2 {
            return "***".to_string();
        }
        format!("{}***{}", chars[0], chars[chars.len() - 1])
    }

    /// hash 口径：置位 `HMAC_KEY` 用 HMAC-SHA256，否则退化 SHA256。
    ///
    /// ⚠️ 风险声明：未设 `PII_VALUE_SAMPLE_HMAC_KEY` 时为无盐 SHA256，
    /// 低熵 PII（手机号段等）可被离线字典枚举，此时 hash 仅趋势参考，
    /// 不得直接对账；生产环境必须配置 `HMAC_KEY`。
    pub fn hash_value(&self, value: &str) -> String {
        if let Some(key) = self.cfg.hmac_key.as_deref() {
            use hmac::{KeyInit as _, Mac as _};
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())
                .expect("HMAC key 恒可载入");
            mac.update(value.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        } else {
            crate::auth::sha256_hex(value.as_bytes())
        }
    }

    /// 采样入口：仅 `is_chat_tail` 触发；关闭时仅计数不落采样。
    /// 返回 `(mask, hash)`，明文不存储、不出作用域。
    pub fn sample(&self, kind: &str, value: &str, is_chat_tail: bool) -> Option<(String, String)> {
        if !is_chat_tail {
            if let Ok(mut c) = self.counts.lock() {
                c.skipped_non_chat += 1;
            }
            return None;
        }
        if !self.cfg.enabled {
            if let Ok(mut c) = self.counts.lock() {
                c.skipped_disabled += 1;
            }
            return None;
        }
        if value.is_empty() {
            return None;
        }
        // 掩码当场生成，明文不出本作用域。
        let mask = Self::sample_mask(value);
        let hash = self.hash_value(value);
        if let Ok(mut c) = self.counts.lock() {
            c.sampled += 1;
        }
        let view = SampleView {
            hash: hash.clone(),
            kind: kind.to_string(),
            mask: mask.clone(),
            hits: 1,
        };
        if let Ok(mut r) = self.recent.lock() {
            if r.len() >= 256 {
                r.pop_front();
            }
            // 同 hash 合并 hits（内存 TopN 口径）。
            if let Some(exist) = r.iter_mut().find(|v| v.hash == hash) {
                exist.hits += 1;
            } else {
                r.push_back(view);
            }
        }
        if self.cfg.persist {
            let row = SampleRow {
                hash: hash.clone(),
                kind: kind.to_string(),
                mask: mask.clone(),
                seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            };
            // 同步入口永不阻塞：`broadcast` 发送恒即时返回（无接收端/满队列均不等待）；
            // 无驱动（同步单测）发送失败计 dropped，满队列丢最老由驱动经 Lagged 计数。
            if self.tx.send(row).is_err()
                && let Ok(mut c) = self.counts.lock()
            {
                c.dropped_full += 1;
            }
        }
        Some((mask, hash))
    }

    /// hover 展示掩码 TopN（按 hits 降序，不含明文）。
    pub fn top_n(&self, n: usize) -> Vec<SampleView> {
        let mut v: Vec<SampleView> = self
            .recent
            .lock()
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default();
        v.sort_by_key(|v| std::cmp::Reverse(v.hits));
        v.truncate(n);
        v
    }

    /// 计数口径（关闭时仅计数验收用）。
    pub fn stats(&self) -> (u64, u64, u64) {
        self.counts
            .lock()
            .map(|c| (c.sampled, c.skipped_disabled, c.skipped_non_chat))
            .unwrap_or_default()
    }

    /// 满队列丢最老计数（含无驱动发送失败；与指标环 `dropped` 同语义可查）。
    pub fn dropped_total(&self) -> u64 { self.counts.lock().map(|c| c.dropped_full).unwrap_or(0) }

    /// 队列滞留行数（单测断言落盘前缓冲用）。
    #[cfg(test)]
    fn pending_len(&self) -> usize { self.tx.len() }
}

/// 采样批量落盘（驱动经 `spawn_blocking` 调用，禁 async 直调）：单连接单事务
/// UPSERT 全批，冲突 hash 合并 hits；失败由驱动吞掉（采样为趋势参考，不进主错链）。
fn persist_sample_batch(db_path: &Path, batch: &[SampleRow]) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO pii_value_samples(hash, kind, mask, hits, first_seen, last_seen)\
             VALUES (?1,?2,?3,1,?4,?4)\
             ON CONFLICT(hash) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen, mask=excluded.mask",
        )?;
        for row in batch {
            stmt.execute(rusqlite::params![row.hash, row.kind, row.mask, row.seen])?;
        }
    }
    tx.commit()?;
    ensure_0600(db_path);
    Ok(())
}

/// 采样后台刷盘驱动：收首行后排空批量，经 `spawn_blocking` 写库；
/// 滞后（满队列丢最老）按 `Lagged(n)` 计入共享 `dropped`；发送端全弃后退出。
async fn sample_flush_driver(
    mut rx: tokio::sync::broadcast::Receiver<SampleRow>,
    db_path: PathBuf,
    counts: std::sync::Arc<Mutex<SamplerCounts>>,
) {
    loop {
        let first = match rx.recv().await {
            Ok(row) => row,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                if let Ok(mut c) = counts.lock() {
                    c.dropped_full += n;
                }
                continue;
            }
        };
        let mut batch = vec![first];
        while batch.len() < 256 {
            match rx.try_recv() {
                Ok(row) => batch.push(row),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                    if let Ok(mut c) = counts.lock() {
                        c.dropped_full += n;
                    }
                }
            }
        }
        let db = db_path.clone();
        let _ = tokio::task::spawn_blocking(move || persist_sample_batch(&db, &batch)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("veil-metrics-test-{}-{}", std::process::id(), name));
        std::fs::create_dir_all(&dir).ok();
        dir.join("metrics.sqlite")
    }

    fn usage(p: u64, c: u64, t: u64) -> Usage {
        Usage {
            prompt_tokens: p,
            completion_tokens: c,
            total_tokens: t,
        }
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn memory_ring_capped_with_drop_count() {
        let store = MetricsStore::new(tmp_db("ring"));
        for i in 0..(RING_CAP + 5) {
            store.record_chat(Protocol::Chat, 10, None, None, true, now() + i as i64);
        }
        assert_eq!(store.ring_len(), RING_CAP);
        assert_eq!(store.dropped_total(), 5);
    }

    #[test]
    fn wal_checkpoint_truncate_runs() {
        let db = tmp_db("checkpoint");
        let _ = std::fs::remove_file(&db);
        let conn = open_wal(&db).expect("WAL 库须可建");
        conn.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('a');")
            .expect("写入须成功");
        drop(conn);
        let (busy, _done) = wal_checkpoint_truncate(&db).expect("检查点须可执行");
        assert_eq!(busy, 0, "单连接无竞争时不得 busy");
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(db.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(db.with_extension("sqlite-shm"));
    }

    #[test]
    fn only_dialog_endpoints_counted_non_dialog_skipped() {
        let store = MetricsStore::new(tmp_db("nondialog"));
        assert!(!store.record_chat(Protocol::NonDialog, 10, None, None, true, now()));
        assert!(store.record_chat(Protocol::Chat, 10, None, None, true, now()));
        let snap = store.snapshot();
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.per_protocol.get("non-dialog"), None);
        assert!(snap.per_protocol.contains_key("chat/completions"));
        // `other` 桶不再混入非对话：全量即对话快照一致。
        assert_eq!(snap.ring_len, 1);
    }

    #[test]
    fn latency_12_buckets_match_legacy_bounds() {
        assert_eq!(
            LATENCY_BOUNDS_MS,
            [10, 25, 50, 100, 200, 400, 800, 1500, 3000, 5000, 10000]
        );
        assert_eq!(LATENCY_BUCKETS, 12);
        assert_eq!(bucket_index(3), 0);
        assert_eq!(bucket_index(10_000), 10);
        assert_eq!(bucket_index(99_999), 11);
    }

    #[test]
    fn p95_bucket_midpoint_approximation() {
        let mut buckets = [0u64; LATENCY_BUCKETS];
        for _ in 0..95 {
            buckets[bucket_index(8)] += 1;
        }
        for _ in 0..5 {
            buckets[bucket_index(9000)] += 1;
        }
        // 95% 落 [0,10] 桶，中位 5。
        assert_eq!(p95_approx(&buckets), 5);
        assert_eq!(p95_approx(&[0u64; LATENCY_BUCKETS]), 0);
        // [800,1500) 桶中位 (800+1500)/2=1150。
        let mut b2 = [0u64; LATENCY_BUCKETS];
        b2[bucket_index(1000)] = 100;
        assert_eq!(p95_approx(&b2), 1150);
    }

    #[test]
    fn is_precise_requires_window_and_samples() {
        assert!(!is_precise_for_window(3600, 99));
        assert!(!is_precise_for_window(3599, 100));
        assert!(is_precise_for_window(3600, 100));
        let store = MetricsStore::new(tmp_db("precise"));
        // 少样本低覆盖一律近似（标≈）。
        store.record_chat(Protocol::Chat, 5, None, None, true, now());
        assert!(!store.snapshot().is_precise);
        // 100 样本跨 3600s 全精确 → 精确。
        let base = now() - 4000;
        for i in 0..100 {
            store.record_chat(Protocol::Chat, 5, None, None, true, base + i * 40);
        }
        assert!(store.snapshot().is_precise);
        // 混入降级样本 → 近似。
        store.record_chat(Protocol::Chat, 5, None, None, false, base + 4100);
        assert!(!store.snapshot().is_precise);
    }

    #[test]
    fn truncated_three_modes_split_by_label_invalid_ignored() {
        let store = MetricsStore::new(tmp_db("trunc"));
        store.record_chat(
            Protocol::Responses,
            5,
            None,
            Some("silent_discard"),
            true,
            now(),
        );
        store.record_chat(
            Protocol::Responses,
            5,
            None,
            Some("open_ended"),
            true,
            now(),
        );
        store.record_chat(
            Protocol::Responses,
            5,
            None,
            Some("synthesized_failed"),
            true,
            now(),
        );
        store.record_chat(
            Protocol::Responses,
            5,
            None,
            Some("bogus_mode"),
            true,
            now(),
        );
        let snap = store.snapshot();
        assert_eq!(snap.truncated_silent_discard, 1);
        assert_eq!(snap.truncated_open_ended, 1);
        assert_eq!(snap.truncated_synthesized_failed, 1);
        assert_eq!(snap.requests, 4);
    }

    #[test]
    fn extended_usage_columns_with_aux_backfill() {
        let db = tmp_db("ext-usage");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat_extended(
            Protocol::Chat,
            20,
            Some(&ExtendedUsage {
                prompt_tokens: 1,
                completion_tokens: 2,
                total_tokens: 3,
                cached_read: 40,
                cached_write: 5,
                unknown: 1,
            }),
            None,
            true,
            ts,
        );
        store.record_aux_counts(Protocol::Chat, ts, 7, 3, 2);
        let snap = store.snapshot();
        assert_eq!(snap.cached_read, 40);
        assert_eq!(snap.cached_write, 5);
        assert_eq!(snap.unknown, 1);
    }

    #[tokio::test]
    async fn aux_columns_persist_query_and_restart_backfill() {
        let db = tmp_db("aux-flush");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat(Protocol::Chat, 12, Some(&usage(1, 2, 3)), None, true, ts);
        store.record_aux_counts(Protocol::Chat, ts, 7, 3, 2);
        store.flush().await.unwrap();
        let pts = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].pii_hits, 7);
        assert_eq!(pts[0].cred_hits, 3);
        assert_eq!(pts[0].audit_blocks, 2);
        // 重启回填：新 store 读旧库恢复窗口累计。
        let store2 = MetricsStore::new(db.clone());
        let n = store2.backfill_from_sqlite().await.unwrap();
        assert!(n >= 3, "三粒度至少各一窗: {n}");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn nonstream_usage_recorded_with_stream_caliber() {
        use super::super::llm_gateway::extract_usage_nonstream;
        let store = MetricsStore::new(tmp_db("usage"));
        // responses 单层 response.usage。
        let resp = serde_json::json!({"response": {"usage": {"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}}});
        let u = extract_usage_nonstream(Protocol::Responses, &resp).unwrap();
        store.record_chat(Protocol::Responses, 20, Some(&u), None, true, now());
        // anthropic message.usage 嵌套。
        let anth = serde_json::json!({"message": {"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}});
        let u2 = extract_usage_nonstream(Protocol::Anthropic, &anth).unwrap();
        store.record_chat(Protocol::Anthropic, 30, Some(&u2), None, true, now());
        let snap = store.snapshot();
        assert_eq!(snap.total_tokens, 11);
        assert_eq!(snap.prompt_tokens, 5);
    }

    #[tokio::test]
    async fn overwrite_upsert_no_double_count_restart_consistent() {
        let db = tmp_db("upsert");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat(Protocol::Chat, 12, Some(&usage(1, 2, 3)), None, true, ts);
        store.flush().await.unwrap();
        // 重复 flush 不翻倍。
        store.flush().await.unwrap();
        let pts = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].requests, 1);
        assert_eq!(pts[0].total_tokens, 3);
        // 重启后同库口径一致（新 store 读旧库）。
        let store2 = MetricsStore::new(db.clone());
        let pts2 = store2
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert_eq!(pts2.len(), 1);
        assert_eq!(pts2[0].requests, 1);
        // 1h/24h 口径：hourly 同窗可见。
        let h = store.query_series("hourly", None, None).await.unwrap();
        assert!(!h.is_empty());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn summarize_redacts_through_single_path() {
        // JSON 键形态落盘为脱敏后。
        let out = summarize(r#"{"password":"hunter2"}"#, 1000);
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("[REDACTED:secret]"), "{out}");
        // sk- / email / 占位符三类。
        let out2 = summarize(
            "key sk-abcDEF1234567890 mail a@b.com ph __PII_1_ab12cd34__ cr __VG_CRED_000001__",
            1000,
        );
        assert!(!out2.contains("sk-abcDEF"), "{out2}");
        assert!(!out2.contains("a@b.com"), "{out2}");
        assert!(!out2.contains("__PII_"), "{out2}");
        assert!(!out2.contains("__VG_CRED_"), "{out2}");
        // 控制字符不产生伪造条目。
        let out3 = summarize("a\x00b\x1fc", 1000);
        assert!(!out3.contains('\x00') && !out3.contains('\x1f'));
        // UTF-8 半字符保护：截断不切分 char。
        let cn = "中文摘要".repeat(500);
        let t = summarize(&cn, 10);
        assert!(t.chars().count() <= 24, "{t}");
        assert!(std::str::from_utf8(t.as_bytes()).is_ok());
    }

    #[test]
    fn pii_sampling_disabled_counts_only() {
        let cfg = PiiSamplerConfig::for_test(false, true, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-off"));
        assert!(s.sample("phone", "13812345678", true).is_none());
        let (sampled, disabled, _) = s.stats();
        assert_eq!((sampled, disabled), (0, 1));
        assert!(s.top_n(10).is_empty());
    }

    #[test]
    fn pii_sampling_enabled_masks_top_n_with_hmac() {
        let cfg =
            PiiSamplerConfig::for_test(true, false, Some("test-hmac-key-0123456789".to_string()));
        let s = PiiValueSampler::new(cfg, tmp_db("pii-on"));
        // 非 chat 不触发。
        assert!(s.sample("phone", "13812345678", false).is_none());
        let (_, _, non_chat) = s.stats();
        assert_eq!(non_chat, 1);
        let (mask, hash) = s.sample("phone", "13812345678", true).unwrap();
        // 掩码当场生成，明文不出作用域：mask/hash 均不含明文。
        assert!(!mask.contains("13812345678") && !hash.contains("13812345678"));
        assert!(mask.starts_with('1') && mask.ends_with('8') && mask.contains("***"));
        // HMAC 口径可复算。
        use hmac::{KeyInit as _, Mac as _};
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test-hmac-key-0123456789").unwrap();
        mac.update(b"13812345678");
        assert_eq!(hash, hex::encode(mac.finalize().into_bytes()));
        // TopN hover 展示掩码。
        s.sample("phone", "13812345678", true);
        let top = s.top_n(5);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].hits, 2);
        assert!(!top[0].mask.contains("13812345678"));
    }

    #[test]
    fn pii_sampling_without_hmac_falls_back_to_sha256() {
        let cfg = PiiSamplerConfig::for_test(true, false, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-degrade"));
        let (_, hash) = s.sample("email", "a@b.com", true).unwrap();
        assert_eq!(hash, crate::auth::sha256_hex(b"a@b.com"));
    }

    #[tokio::test]
    async fn series_four_windows_cross_day_approx_sum_query() {
        let db = tmp_db("series-sem");
        let _ = std::fs::remove_file(&db);
        let day10 = 86_400 * 10 + 100;
        let day11 = 86_400 * 11 + 100;
        let store = MetricsStore::new(db.clone());
        store.record_chat(Protocol::Chat, 8, Some(&usage(1, 2, 3)), None, true, day10);
        store.record_chat(
            Protocol::Chat,
            9,
            Some(&usage(4, 5, 9)),
            None,
            true,
            day10 + 60,
        );
        store.record_chat(
            Protocol::Chat,
            9000,
            Some(&usage(0, 0, 0)),
            None,
            true,
            day11,
        );
        store.flush().await.unwrap();
        let daily = store.query_series("daily", None, None).await.unwrap();
        assert_eq!(daily.len(), 2);
        assert!(daily[0].window < daily[1].window);
        let same_day: u64 = daily
            .iter()
            .filter(|p| p.requests == 2)
            .map(|p| p.total_tokens)
            .sum();
        assert_eq!(same_day, 12);
        let hourly = store.query_series("hourly", None, None).await.unwrap();
        assert!(hourly.len() >= 2);
        let five = store.query_series("five_min", None, None).await.unwrap();
        assert!(!five.is_empty());
        let snap = store.snapshot();
        assert_eq!(snap.requests, 3);
        assert_eq!(snap.total_tokens, 12);
        assert_eq!(snap.p95_ms, p95_approx(&snap.latency_buckets));
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test]
    async fn series_since_and_protocol_filter_semantics() {
        let db = tmp_db("series-filter");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat(Protocol::Chat, 10, Some(&usage(1, 1, 2)), None, true, ts);
        store.record_chat(
            Protocol::Responses,
            10,
            Some(&usage(2, 2, 4)),
            None,
            true,
            ts,
        );
        store.flush().await.unwrap();
        let chat_only = store
            .query_series("daily", None, Some("chat/completions".to_string()))
            .await
            .unwrap();
        assert!(chat_only.iter().all(|p| p.protocol == "chat/completions"));
        assert_eq!(chat_only.iter().map(|p| p.requests).sum::<u64>(), 1);
        let all = store.query_series("daily", None, None).await.unwrap();
        assert!(all.iter().map(|p| p.requests).sum::<u64>() >= 2);
        let since_far = "d99999999".to_string();
        let empty = store
            .query_series("daily", Some(since_far), None)
            .await
            .unwrap();
        assert!(empty.is_empty());
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn pii_value_mask_merge_and_count_query() {
        let cfg = PiiSamplerConfig::for_test(true, false, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-query"));
        let (m1, h1) = s.sample("phone", "13812345678", true).unwrap();
        assert!(m1.starts_with('1') && m1.ends_with('8'));
        s.sample("phone", "13812345678", true);
        s.sample("email", "a@b.com", true);
        let top = s.top_n(5);
        assert_eq!(top.iter().find(|v| v.hash == h1).unwrap().hits, 2);
        assert_eq!(top.len(), 2);
        let (sampled, disabled, non_chat) = s.stats();
        assert_eq!((sampled, disabled, non_chat), (3, 0, 0));
        assert!(s.sample("phone", "13812345678", false).is_none());
        assert_eq!(PiiValueSampler::sample_mask("ab"), "***");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sampling_background_flush_persists() {
        let db = tmp_db("pii-flush");
        let _ = std::fs::remove_file(&db);
        let cfg = PiiSamplerConfig::for_test(true, true, None);
        let s = PiiValueSampler::new(cfg, db.clone());
        let (mask, hash) = s.sample("phone", "13812345678", true).unwrap();
        assert!(mask.contains("***"));
        // 后台驱动批量落盘：轮询等行落库（让出后驱动运行，2s 内必达）。
        let mut rows = 0;
        for _ in 0..200 {
            if let Ok(conn) = open_wal(&db) {
                rows = conn
                    .query_row(
                        "SELECT COUNT(*) FROM pii_value_samples WHERE hash=?1",
                        [hash.clone()],
                        |r| r.get::<_, i64>(0),
                    )
                    .unwrap_or(0);
                if rows >= 1 {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(rows, 1, "后台 flush 须把采样行写入 pii_value_samples");
        assert_eq!(s.dropped_total(), 0);
        let _ = std::fs::remove_file(&db);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sampling_full_queue_drops_oldest_queryable() {
        let db = tmp_db("pii-full");
        let _ = std::fs::remove_file(&db);
        let cfg = PiiSamplerConfig::for_test(true, true, None);
        let s = PiiValueSampler::new(cfg, db.clone());
        // 同步紧循环无让出点：单线程运行时驱动不得交错，512 缓冲 + 10 滞后精确可复算。
        for i in 0..(SAMPLE_QUEUE_CAP + 10) {
            let v = format!("1380000{i:04}");
            let _ = s.sample("phone", &v, true);
        }
        assert_eq!(s.pending_len(), SAMPLE_QUEUE_CAP);
        // 让出后驱动排空：滞后 10 计 dropped，512 行落库。
        for _ in 0..200 {
            if s.dropped_total() >= 10 && s.pending_len() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(s.dropped_total(), 10, "满队列须丢最老 10 行并计数");
        assert_eq!(s.pending_len(), 0);
        let conn = open_wal(&db).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, SAMPLE_QUEUE_CAP as i64);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn sampling_config_from_struct_not_env() {
        use std::collections::HashMap;
        let base: HashMap<String, String> = HashMap::from([
            (
                "HOMESERVER".to_string(),
                "https://matrix.example.com".to_string(),
            ),
            ("ROOM_ID".to_string(), "!r:example.com".to_string()),
            ("MATRIX_ACCESS_TOKEN".to_string(), "syt_x".to_string()),
            (
                "OBSERVABILITY_ADMIN_TOKEN".to_string(),
                "observability-admin-token-0123456789".to_string(),
            ),
        ]);
        let cfg = PiiSamplerConfig::from_config(&crate::config::Config::load_from(&base).unwrap());
        assert!(!cfg.enabled && cfg.persist && cfg.hmac_key.is_none());
        let mut env = base;
        env.insert("PII_VALUE_SAMPLE_ENABLED".to_string(), "1".to_string());
        env.insert("PII_VALUE_SAMPLE_PERSIST".to_string(), "0".to_string());
        env.insert(
            "PII_VALUE_SAMPLE_HMAC_KEY".to_string(),
            "k-0123456789".to_string(),
        );
        let cfg = PiiSamplerConfig::from_config(&crate::config::Config::load_from(&env).unwrap());
        assert!(cfg.enabled && !cfg.persist);
        assert_eq!(cfg.hmac_key.as_deref(), Some("k-0123456789"));
    }

    #[test]
    fn unsalted_sampling_warns_predicate() {
        assert!(PiiSamplerConfig::for_test(true, true, None).needs_hmac_warn());
        assert!(PiiSamplerConfig::for_test(true, true, Some(String::new())).needs_hmac_warn());
        assert!(!PiiSamplerConfig::for_test(true, true, Some("k".to_string())).needs_hmac_warn());
        assert!(!PiiSamplerConfig::for_test(false, true, None).needs_hmac_warn());
        assert!(!PiiSamplerConfig::for_test(false, false, None).needs_hmac_warn());
    }

    #[test]
    fn model_approximation_caliber_and_window_check() {
        assert!(is_precise_for_window(3600, 100));
        assert!(is_precise_for_window(86400, 1000));
        assert!(!is_precise_for_window(3599, 100), "覆盖不足须标近似");
        assert!(!is_precise_for_window(3600, 99), "样本不足须标近似");
        assert!(!is_precise_for_window(0, 0));
    }

    #[test]
    fn sampling_master_switch_off_means_zero_persist() {
        let cfg = PiiSamplerConfig::for_test(false, true, None);
        let s = PiiValueSampler::new(cfg, tmp_db("sample-off"));
        assert!(s.sample("phone", "13812345678", true).is_none());
        assert!(s.sample("phone", "13812345678", true).is_none());
        let (sampled, disabled, _) = s.stats();
        assert_eq!((sampled, disabled), (0, 2), "关闭时只记跳过不采样");
        assert!(s.top_n(5).is_empty(), "零落盘：无样本可查");
    }
}
