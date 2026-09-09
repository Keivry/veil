//! 指标存储：`MetricsStore` 记录/刷盘 + sqlite 落盘/回填 + 采样落盘驱动。
//!
//! 聚合类型（`AggKey`/`WindowAgg`/`Granularity`）与纯函数归属
//! `super::aggregate`；快照/时序查询方法以独立 `impl MetricsStore`
//! 块置于该模块（同 crate 多 impl 块），本文件保留记录与落盘。

use {
    super::{
        super::llm_gateway::Protocol,
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
            Mutex,
            atomic::{AtomicU64, Ordering},
        },
    },
};

/// 指标聚合存储：内存环 + 窗口累计（覆盖式）+ sqlite 落盘。
pub struct MetricsStore {
    pub(crate) ring: Mutex<VecDeque<MetricSample>>,
    pub(crate) aggs: Mutex<HashMap<AggKey, WindowAgg>>,
    pub(crate) db_path: PathBuf,
    pub(crate) dropped: AtomicU64,
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
        if protocol == Protocol::NonDialog {
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
            for (g, key) in [
                (Granularity::Daily, super::aggregate::day_key(ts_secs)),
                (Granularity::Hourly, super::aggregate::hour_key(ts_secs)),
                (
                    Granularity::FiveMin,
                    super::aggregate::five_min_key(ts_secs),
                ),
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
                (Granularity::Daily, super::aggregate::day_key(ts_secs)),
                (Granularity::Hourly, super::aggregate::hour_key(ts_secs)),
                (
                    Granularity::FiveMin,
                    super::aggregate::five_min_key(ts_secs),
                ),
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
mod tests {
    use {
        super::{
            super::{
                aggregate::{ExtendedUsage, p95_approx},
                summarize::test_support::{chat_rec, ext_rec, now, tmp_db, usage},
            },
            *,
        },
        crate::service::llm_gateway::Protocol,
    };

    #[test]
    fn memory_ring_capped_with_drop_count() {
        let store = MetricsStore::new(tmp_db("ring"));
        for i in 0..(super::super::aggregate::RING_CAP + 5) {
            store.record_chat(chat_rec(
                Protocol::Chat,
                "",
                10,
                None,
                None,
                true,
                now() + i as i64,
            ));
        }
        assert_eq!(store.ring_len(), super::super::aggregate::RING_CAP);
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
        assert!(!store.record_chat(chat_rec(
            Protocol::NonDialog,
            "",
            10,
            None,
            None,
            true,
            now()
        )));
        assert!(store.record_chat(chat_rec(Protocol::Chat, "", 10, None, None, true, now())));
        let snap = store.snapshot();
        assert_eq!(snap.requests, 1);
        assert_eq!(snap.per_protocol.get("non-dialog"), None);
        assert!(snap.per_protocol.contains_key("chat/completions"));
        // `other` 桶不再混入非对话：全量即对话快照一致。
        assert_eq!(snap.ring_len, 1);
    }

    #[test]
    fn extended_usage_columns_with_aux_backfill() {
        let db = tmp_db("ext-usage");
        let _ = std::fs::remove_file(&db);
        let ts = now();
        let store = MetricsStore::new(db.clone());
        store.record_chat_extended(ext_rec(
            Protocol::Chat,
            "",
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
        ));
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
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            12,
            Some(&usage(1, 2, 3)),
            None,
            true,
            ts,
        ));
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
        use crate::service::llm_gateway::extract_usage_nonstream;
        let store = MetricsStore::new(tmp_db("usage"));
        // responses 单层 response.usage。
        let resp = serde_json::json!({"response": {"usage": {"prompt_tokens": 4, "completion_tokens": 5, "total_tokens": 9}}});
        let u = extract_usage_nonstream(Protocol::Responses, &resp).unwrap();
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            20,
            Some(&u),
            None,
            true,
            now(),
        ));
        // anthropic message.usage 嵌套。
        let anth = serde_json::json!({"message": {"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}});
        let u2 = extract_usage_nonstream(Protocol::Anthropic, &anth).unwrap();
        store.record_chat(chat_rec(
            Protocol::Anthropic,
            "",
            30,
            Some(&u2),
            None,
            true,
            now(),
        ));
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
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            12,
            Some(&usage(1, 2, 3)),
            None,
            true,
            ts,
        ));
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

    #[tokio::test]
    async fn series_four_windows_cross_day_approx_sum_query() {
        let db = tmp_db("series-sem");
        let _ = std::fs::remove_file(&db);
        let day10 = 86_400 * 10 + 100;
        let day11 = 86_400 * 11 + 100;
        let store = MetricsStore::new(db.clone());
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            8,
            Some(&usage(1, 2, 3)),
            None,
            true,
            day10,
        ));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            9,
            Some(&usage(4, 5, 9)),
            None,
            true,
            day10 + 60,
        ));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            9000,
            Some(&usage(0, 0, 0)),
            None,
            true,
            day11,
        ));
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

    #[test]
    fn model_approximation_caliber_and_window_check() {
        assert!(super::super::aggregate::is_precise_for_window(3600, 100));
        assert!(super::super::aggregate::is_precise_for_window(86400, 1000));
        assert!(
            !super::super::aggregate::is_precise_for_window(3599, 100),
            "覆盖不足须标近似"
        );
        assert!(
            !super::super::aggregate::is_precise_for_window(3600, 99),
            "样本不足须标近似"
        );
        assert!(!super::super::aggregate::is_precise_for_window(0, 0));
    }
}
