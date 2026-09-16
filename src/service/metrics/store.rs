//! 指标存储：`MetricsStore` 记录/刷盘 + sqlite 落盘/回填 + 采样落盘驱动。
//!
//! 聚合类型（`AggKey`/`WindowAgg`/`Granularity`）与纯函数归属
//! `super::aggregate`；快照/时序查询方法以独立 `impl MetricsStore`
//! 块置于该模块（同 crate 多 impl 块），本文件保留记录与落盘。

use {
    super::{
        super::llm_gateway::{Protocol, is_passthrough},
        aggregate::{
            AggKey,
            ExtendedChatRecord,
            ExtendedUsage,
            Granularity,
            MetricSample,
            WindowAgg,
            bucket_index,
            normalize_model,
        },
        sample::{SampleRow, SamplerCounts},
    },
    crate::fs_perm::{ensure_0600, open_wal},
    std::{
        collections::{HashMap, VecDeque},
        path::{Path, PathBuf},
        sync::{
            Arc,
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    },
};

/// 指标周期刷盘间隔（秒，D1）：与既有 `RateTable::SWEEP_SECS`/`PENDING_TTL_SECS`
/// 同为 60，写入放大可控；关闭路径另有一次最终刷盘。
pub const METRICS_FLUSH_INTERVAL_SECS: u64 = 60;

/// 指标聚合存储：内存环 + 窗口累计（覆盖式）+ sqlite 落盘。
pub struct MetricsStore {
    pub(crate) ring: Mutex<VecDeque<MetricSample>>,
    pub(crate) aggs: Mutex<HashMap<AggKey, WindowAgg>>,
    pub(crate) db_path: PathBuf,
    pub(crate) dropped: AtomicU64,
    /// `aggs` 有界驱逐累计计数（retention + LRU，可观测）。
    pub(crate) aggs_evicted: AtomicU64,
    /// `aggs` 最近更新序号（LRU 驱逐依据）。
    pub(crate) agg_tick: AtomicU64,
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
            ring: Mutex::new(VecDeque::with_capacity(super::aggregate::RING_CAP)),
            aggs: Mutex::new(HashMap::new()),
            db_path,
            dropped: AtomicU64::new(0),
            aggs_evicted: AtomicU64::new(0),
            agg_tick: AtomicU64::new(0),
        }
    }

    /// 记录一次对话端点观测（基础口径，扩展列置零；签名兼容版）。
    /// `model` 为上游回显模型名（归一后分桶；缺失传空串归 `unknown_model`）。
    pub fn record_chat(&self, rec: super::aggregate::ChatRecord<'_>) -> bool {
        let ext = rec.usage.map(|u| ExtendedUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
            cached_read: u.cached_read,
            cached_write: u.cached_write,
            ..ExtendedUsage::default()
        });
        self.record_chat_extended(ExtendedChatRecord {
            protocol: rec.protocol,
            model: rec.model,
            latency_ms: rec.latency_ms,
            usage: ext.as_ref(),
            truncated_mode: rec.truncated_mode,
            is_precise: rec.is_precise,
            ts_secs: rec.ts_secs,
        })
    }

    /// 记录一次对话端点观测（扩展口径：含 `cached_read/write/unknown`）。
    pub fn record_chat_extended(&self, rec: ExtendedChatRecord<'_>) -> bool {
        let ExtendedChatRecord {
            protocol,
            model,
            latency_ms,
            usage,
            truncated_mode,
            is_precise,
            ts_secs,
        } = rec;
        if is_passthrough(protocol) {
            return false;
        }
        let truncated = match truncated_mode {
            Some(m) if super::aggregate::TRUNCATED_MODES.contains(&m) => Some(m.to_string()),
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
            model: normalize_model(model),
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
            if ring.len() >= super::aggregate::RING_CAP {
                ring.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            ring.push_back(sample);
        }
        if let Ok(mut aggs) = self.aggs.lock() {
            let mut any_new = false;
            for (g, key) in [
                (Granularity::Daily, super::aggregate::day_key(ts_secs)),
                (Granularity::Hourly, super::aggregate::hour_key(ts_secs)),
                (
                    Granularity::FiveMin,
                    super::aggregate::five_min_key(ts_secs),
                ),
            ] {
                let agg_key = AggKey {
                    granularity: g,
                    window: key,
                    protocol: proto.clone(),
                };
                if !aggs.contains_key(&agg_key) {
                    any_new = true;
                }
                let entry = aggs.entry(agg_key).or_default();
                entry.count += 1;
                entry.prompt += ext.prompt_tokens;
                entry.completion += ext.completion_tokens;
                entry.total += ext.total_tokens;
                entry.cached_read += ext.cached_read;
                entry.cached_write += ext.cached_write;
                entry.unknown += ext.unknown;
                entry.buckets[bucket_index(latency_ms)] += 1;
                entry.updated = self.agg_tick.fetch_add(1, Ordering::Relaxed);
                match truncated.as_deref() {
                    Some("silent_discard") => entry.t_silent += 1,
                    Some("open_ended") => entry.t_open += 1,
                    Some("synthesized_failed") => entry.t_synth += 1,
                    Some("upstream_error") => entry.t_upstream_error += 1,
                    _ => {}
                }
            }
            if any_new {
                super::aggregate::enforce_agg_bounds(&mut aggs, &self.aggs_evicted);
            }
        }
        true
    }

    /// 当前环长度（`DCD-5`：仅测试引用，`#[cfg(test)]` 收编；快照走 `ring_len` 字段）。
    #[cfg(test)]
    pub(crate) fn ring_len(&self) -> usize { self.ring.lock().map(|r| r.len()).unwrap_or(0) }

    /// 环满丢弃计数（`mpsc(512)` 背压语义的内存环对应物，只计数不阻塞）。
    /// `DCD-5`/`OPS-1`：保留 `pub`——`snapshot()` 生产引用，经 `/_admin/metrics` 暴露。
    pub fn dropped_total(&self) -> u64 { self.dropped.load(Ordering::Relaxed) }

    /// `aggs` 有界驱逐累计计数（retention + LRU，可观测）。
    /// `DCD-5`/`OPS-1`：保留 `pub`——`snapshot()` 生产引用，经 `/_admin/metrics` 暴露。
    pub fn aggs_evicted_total(&self) -> u64 { self.aggs_evicted.load(Ordering::Relaxed) }

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

    /// 周期刷盘驱动（RUN-1/D1）：每 `interval` 调 [`flush`](MetricsStore::flush)，
    /// 失败仅 `warn` 不退出（指标降级为内存累计，接口照常服务）；返回句柄供调用方持有。
    pub fn spawn_flush_driver(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // 首个 tick 立即到点，先消费，使刷盘按完整周期起算。
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(err) = me.flush().await {
                    tracing::warn!("指标周期刷盘失败（服务继续，内存累计）: {err:#}");
                }
            }
        })
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
        if is_passthrough(protocol) {
            return;
        }
        let proto = protocol.as_tail().to_string();
        if let Ok(mut aggs) = self.aggs.lock() {
            let mut any_new = false;
            for (g, key) in [
                (Granularity::Daily, super::aggregate::day_key(ts_secs)),
                (Granularity::Hourly, super::aggregate::hour_key(ts_secs)),
                (
                    Granularity::FiveMin,
                    super::aggregate::five_min_key(ts_secs),
                ),
            ] {
                let agg_key = AggKey {
                    granularity: g,
                    window: key,
                    protocol: proto.clone(),
                };
                if !aggs.contains_key(&agg_key) {
                    any_new = true;
                }
                let entry = aggs.entry(agg_key).or_default();
                entry.pii_hits += pii_hits;
                entry.cred_hits += cred_hits;
                entry.audit_blocks += audit_blocks;
                entry.updated = self.agg_tick.fetch_add(1, Ordering::Relaxed);
            }
            if any_new {
                super::aggregate::enforce_agg_bounds(&mut aggs, &self.aggs_evicted);
            }
        }
    }
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

pub(crate) fn ensure_tables(conn: &rusqlite::Connection) -> anyhow::Result<()> {
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
            t_upstream_error INTEGER NOT NULL DEFAULT 0,
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
            t_upstream_error INTEGER NOT NULL DEFAULT 0,
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
            t_upstream_error INTEGER NOT NULL DEFAULT 0,
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
            "t_upstream_error",
        ] {
            let _ = conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"),
                [],
            );
        }
    }
    ensure_pii_value_samples_table(conn)?;
    Ok(())
}

/// 采样表复合键迁移（M5）：旧表主键为单 `hash`，新表为 `(day, upstream, kind, hash)`。
/// 存量旧表直接重建（采样为趋势参考，7 天滚动可重建；启动日志声明，见 warn）。
fn ensure_pii_value_samples_table(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='pii_value_samples'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    if table_exists {
        let has_day: bool = conn
            .prepare("PRAGMA table_info(pii_value_samples)")
            .map(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(1))
                    .map(|rows| rows.flatten().any(|name| name == "day"))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if !has_day {
            conn.execute_batch("DROP TABLE pii_value_samples;")?;
            tracing::warn!(
                "pii_value_samples 旧单键表已重建为复合键 (day,upstream,kind,hash)，历史采样行已清理（7天滚动可重建）"
            );
        }
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pii_value_samples(
            day TEXT NOT NULL, upstream TEXT NOT NULL, kind TEXT NOT NULL, hash TEXT NOT NULL,
            mask TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1,
            first_seen INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(day, upstream, kind, hash));",
    )?;
    Ok(())
}

fn buckets_encode(b: &[u64; super::aggregate::LATENCY_BUCKETS]) -> String {
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
             t_silent, t_open, t_synth, t_upstream_error, buckets) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17) \
             ON CONFLICT(window, protocol) DO UPDATE SET \
             requests=excluded.requests, prompt_tokens=excluded.prompt_tokens, \
             completion_tokens=excluded.completion_tokens, total_tokens=excluded.total_tokens, \
             cached_read=excluded.cached_read, cached_write=excluded.cached_write, \
             unknown=excluded.unknown, pii_hits=excluded.pii_hits, cred_hits=excluded.cred_hits, \
             audit_blocks=excluded.audit_blocks, \
             t_silent=excluded.t_silent, t_open=excluded.t_open, t_synth=excluded.t_synth, \
             t_upstream_error=excluded.t_upstream_error, buckets=excluded.buckets"
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
                agg.t_upstream_error as i64,
                buckets_encode(&agg.buckets),
            ],
        )?;
    }
    // `five_min` 只留最新窗口（每 protocol 最大 window，按整数序比较）。
    conn.execute_batch(
        "DELETE FROM metrics_five_min WHERE rowid NOT IN \
         (SELECT m.rowid FROM metrics_five_min AS m WHERE CAST(substr(m.window, 2) AS INTEGER) = \
          (SELECT MAX(CAST(substr(x.window, 2) AS INTEGER)) FROM metrics_five_min AS x \
           WHERE x.protocol = m.protocol));",
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
    // 窗口键为 `d{days}` / `h{hours}` / `m{win}`：按整数序（`window_ord` 同口径）比较，
    // 避免字符串在位数进位处（如 `h9` vs `h10`）排序失真；保留窗数与内存侧一致。
    conn.execute_batch(
        "DELETE FROM metrics_daily WHERE window NOT IN \
         (SELECT window FROM metrics_daily GROUP BY window \
          ORDER BY CAST(substr(window, 2) AS INTEGER) DESC LIMIT 32); \
         DELETE FROM metrics_hourly WHERE window NOT IN \
         (SELECT window FROM metrics_hourly GROUP BY window \
          ORDER BY CAST(substr(window, 2) AS INTEGER) DESC LIMIT 170);",
    )?;
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        - super::aggregate::PII_SAMPLE_RETENTION_DAYS * 86_400;
    conn.execute(
        "DELETE FROM pii_value_samples WHERE last_seen < ?1",
        [cutoff],
    )?;
    ensure_0600(db_path);
    Ok(())
}

/// 采样批量落盘（驱动经 `spawn_blocking` 调用，禁 async 直调）：单连接单事务
/// UPSERT 全批，冲突复合键合并 hits；失败由驱动吞掉（采样为趋势参考，不进主错链）。
pub(crate) fn persist_sample_batch(db_path: &Path, batch: &[SampleRow]) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let conn = open_wal(db_path)?;
    ensure_tables(&conn)?;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO pii_value_samples(day, upstream, kind, hash, mask, hits, first_seen, last_seen)\
             VALUES (?1,?2,?3,?4,?5,1,?6,?6)\
             ON CONFLICT(day, upstream, kind, hash) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen, mask=excluded.mask",
        )?;
        for row in batch {
            stmt.execute(rusqlite::params![
                row.day,
                row.upstream,
                row.kind,
                row.hash,
                row.mask,
                row.seen
            ])?;
        }
    }
    tx.commit()?;
    ensure_0600(db_path);
    Ok(())
}

/// 采样后台刷盘驱动：收首行后排空批量，经 `spawn_blocking` 写库；
/// 滞后（满队列丢最老）按 `Lagged(n)` 计入共享 `dropped`；发送端全弃后退出。
pub(crate) async fn sample_flush_driver(
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
mod tests;

#[cfg(test)]
mod migration_tests;

#[cfg(test)]
mod reliability_tests;
