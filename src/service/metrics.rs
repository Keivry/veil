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
//! - 写库一律 `spawn_blocking(rusqlite WAL)`，文件 0600（复用 §1 口径，不直调 §1 私有函数）。
//!
//! TODO(§7): 网关落点接入（`handler.rs gateway_serve` 内 `record_chat` 调用 +
//! 审计 hold 事件 `push_event`）待 §5§6 并行施工完成后补线，此处只提供聚合口径。

use {
    super::llm_gateway::{Protocol, Usage},
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
/// 延迟桶边界（毫秒），11 条边界 → 12 桶（含上溢桶）。
pub const LATENCY_BOUNDS_MS: [u64; 11] = [5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000];
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

/// 12 桶近似 p95：返回累积 ≥95% 所在桶的上界（上溢桶返回最后边界）。
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
            return LATENCY_BOUNDS_MS.get(i).copied().unwrap_or(u64::MAX);
        }
    }
    LATENCY_BOUNDS_MS[LATENCY_BOUNDS_MS.len() - 1]
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
    pub truncated_mode: Option<String>,
    pub is_precise: bool,
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

    /// 记录一次对话端点观测。非对话（`Protocol::NonDialog`）直接跳过返回 `false`。
    ///
    /// `truncated_mode` 仅三态落标签，他值忽略并记告警，不失败。
    /// `is_precise` 由调用方按 `sqlite_ok` 传入（降级内存-only 时为假）。
    pub fn record_chat(
        &self,
        protocol: Protocol,
        latency_ms: u64,
        usage: Option<&Usage>,
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
        let (prompt, completion, total) = match usage {
            Some(u) => (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            None => (0, 0, 0),
        };
        let sample = MetricSample {
            ts_secs,
            protocol: proto.clone(),
            latency_ms,
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: total,
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
                entry.prompt += prompt;
                entry.completion += completion;
                entry.total += total;
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
        let mut buckets = [0u64; LATENCY_BUCKETS];
        let mut t_silent = 0u64;
        let mut t_open = 0u64;
        let mut t_synth = 0u64;
        let mut per_protocol: HashMap<String, u64> = HashMap::new();
        let mut precise_true = 0u64;
        let mut precise_total = 0u64;
        if let Ok(ring) = self.ring.lock() {
            for s in ring.iter() {
                count += 1;
                prompt += s.prompt_tokens;
                completion += s.completion_tokens;
                total += s.total_tokens;
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
            latency_buckets: buckets,
            p95_ms: p95_approx(&buckets),
            per_protocol,
            truncated_silent_discard: t_silent,
            truncated_open_ended: t_open,
            truncated_synthesized_failed: t_synth,
            // 全精确才标精确（降级期混入近似即为假，仅趋势参考）。
            is_precise: precise_total > 0 && precise_true == precise_total,
            ring_len: count as usize,
            dropped: self.dropped_total(),
        }
    }

    /// 覆盖式刷盘（`spawn_blocking` 外层由调用方包，见 [`flush`]）。
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
    pub truncated_silent_discard: u64,
    pub truncated_open_ended: u64,
    pub truncated_synthesized_failed: u64,
}

fn connect_wal(db_path: &Path) -> anyhow::Result<rusqlite::Connection> {
    if let Some(parent) = db_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let conn = rusqlite::Connection::open(db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;",
    )?;
    Ok(conn)
}

fn ensure_tables(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS metrics_daily(
            window TEXT NOT NULL, protocol TEXT NOT NULL,
            requests INTEGER NOT NULL DEFAULT 0,
            prompt_tokens INTEGER NOT NULL DEFAULT 0,
            completion_tokens INTEGER NOT NULL DEFAULT 0,
            total_tokens INTEGER NOT NULL DEFAULT 0,
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
            t_silent INTEGER NOT NULL DEFAULT 0,
            t_open INTEGER NOT NULL DEFAULT 0,
            t_synth INTEGER NOT NULL DEFAULT 0,
            buckets TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(window, protocol));
         CREATE TABLE IF NOT EXISTS pii_value_samples(
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
        let conn = connect_wal(db_path)?;
        ensure_tables(&conn)?;
        chmod_0600(db_path);
        return Ok(());
    }
    let conn = connect_wal(db_path)?;
    ensure_tables(&conn)?;
    for (key, agg) in aggs {
        let table = match key.granularity {
            Granularity::Daily => "metrics_daily",
            Granularity::Hourly => "metrics_hourly",
            Granularity::FiveMin => "metrics_five_min",
        };
        let sql = format!(
            "INSERT INTO {table}(window, protocol, requests, prompt_tokens, completion_tokens, \
             total_tokens, t_silent, t_open, t_synth, buckets) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) \
             ON CONFLICT(window, protocol) DO UPDATE SET \
             requests=excluded.requests, prompt_tokens=excluded.prompt_tokens, \
             completion_tokens=excluded.completion_tokens, total_tokens=excluded.total_tokens, \
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
    chmod_0600(db_path);
    Ok(())
}

fn purge_retention_blocking(db_path: &Path) -> anyhow::Result<()> {
    let conn = connect_wal(db_path)?;
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
    chmod_0600(db_path);
    Ok(())
}

fn query_series_blocking(
    db_path: &Path,
    granularity: &str,
    since: Option<&str>,
    protocol: Option<&str>,
) -> anyhow::Result<Vec<SeriesPoint>> {
    let conn = connect_wal(db_path)?;
    ensure_tables(&conn)?;
    let table = match granularity {
        "daily" => "metrics_daily",
        "five_min" | "5min" => "metrics_five_min",
        _ => "metrics_hourly",
    };
    let mut sql = format!(
        "SELECT window, protocol, requests, prompt_tokens, completion_tokens,\
         total_tokens, t_silent, t_open, t_synth FROM {table} WHERE 1=1"
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
            truncated_silent_discard: row.get::<_, i64>(6)? as u64,
            truncated_open_ended: row.get::<_, i64>(7)? as u64,
            truncated_synthesized_failed: row.get::<_, i64>(8)? as u64,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn chmod_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if !path.exists() {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    for suffix in ["-wal", "-shm"] {
        let mut sibling = path.as_os_str().to_owned();
        sibling.push(suffix);
        let p = Path::new(&sibling);
        if p.exists() {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
        }
    }
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
}

/// PII 值级掩码采样：掩码当场生成，明文不出作用域（函数返回前丢弃）。
pub struct PiiValueSampler {
    cfg: PiiSamplerConfig,
    db_path: PathBuf,
    counts: Mutex<SamplerCounts>,
    recent: Mutex<VecDeque<SampleView>>,
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
    pub fn new(cfg: PiiSamplerConfig, db_path: PathBuf) -> Self {
        Self {
            cfg,
            db_path,
            counts: Mutex::new(SamplerCounts::default()),
            recent: Mutex::new(VecDeque::with_capacity(256)),
        }
    }

    /// 值级掩码（当场生成）：首字符 + `***` + 末字符，超短值全掩码。
    /// 输入明文仅在本函数栈上存活，返回后调用方须立即丢弃。
    pub fn mask_value(value: &str) -> String {
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
        let mask = Self::mask_value(value);
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
            let db_path = self.db_path.clone();
            let hash_c = hash.clone();
            let kind_c = kind.to_string();
            let mask_c = mask.clone();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            // 同步落盘经 blocking 任务？此处为同步 API（§3 调用路径），用
            // `spawn_blocking` 需 async；采样为低频后台路径，允许短暂直写
            // （调用方在后台任务中触发，不阻塞转发主路径）。
            if let Ok(conn) = connect_wal(&db_path) {
                let _ = ensure_tables(&conn);
                let _ = conn.execute(
                    "INSERT INTO pii_value_samples(hash, kind, mask, hits, first_seen, last_seen)\
                     VALUES (?1,?2,?3,1,?4,?4)\
                     ON CONFLICT(hash) DO UPDATE SET hits=hits+1, last_seen=excluded.last_seen, mask=excluded.mask",
                    rusqlite::params![hash_c, kind_c, mask_c, now],
                );
                chmod_0600(&db_path);
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
    fn 内存环10k封顶且丢弃计数() {
        let store = MetricsStore::new(tmp_db("ring"));
        for i in 0..(RING_CAP + 5) {
            store.record_chat(Protocol::Chat, 10, None, None, true, now() + i as i64);
        }
        assert_eq!(store.ring_len(), RING_CAP);
        assert_eq!(store.dropped_total(), 5);
    }

    #[test]
    fn 仅对话端点计数非对话跳过() {
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
    fn 延迟12桶p95近似() {
        assert_eq!(bucket_index(3), 0);
        assert_eq!(bucket_index(10_000), 10);
        assert_eq!(bucket_index(99_999), 11);
        let mut buckets = [0u64; LATENCY_BUCKETS];
        for _ in 0..95 {
            buckets[bucket_index(8)] += 1;
        }
        for _ in 0..5 {
            buckets[bucket_index(9000)] += 1;
        }
        // 95% 落在 10ms 桶。
        assert_eq!(p95_approx(&buckets), 10);
        assert_eq!(p95_approx(&[0u64; LATENCY_BUCKETS]), 0);
    }

    #[test]
    fn is_precise标记精确与近似() {
        let store = MetricsStore::new(tmp_db("precise"));
        store.record_chat(Protocol::Chat, 5, None, None, true, now());
        assert!(store.snapshot().is_precise);
        store.record_chat(Protocol::Chat, 5, None, None, false, now());
        assert!(!store.snapshot().is_precise);
    }

    #[test]
    fn truncated三态分标签非法值不落() {
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
    fn 非流式usage同流式口径计入() {
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
    async fn 覆盖upsert不翻倍与重启口径一致() {
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
    fn 摘要脱敏单一路径() {
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
    fn pii采样关闭仅计数() {
        let cfg = PiiSamplerConfig::for_test(false, true, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-off"));
        assert!(s.sample("phone", "13812345678", true).is_none());
        let (sampled, disabled, _) = s.stats();
        assert_eq!((sampled, disabled), (0, 1));
        assert!(s.top_n(10).is_empty());
    }

    #[test]
    fn pii采样开启掩码top_n与hmac口径() {
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
    fn pii采样未设hmac退化sha256() {
        let cfg = PiiSamplerConfig::for_test(true, false, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-degrade"));
        let (_, hash) = s.sample("email", "a@b.com", true).unwrap();
        assert_eq!(hash, crate::auth::sha256_hex(b"a@b.com"));
    }

    #[test]
    fn 采样配置取自配置结构体而非进程环境() {
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
}
