//! 指标聚合：记录束类型 + 窗口键 + 快照/时序查询（`impl MetricsStore` 独立块）。

use {
    super::{
        super::llm_gateway::{Protocol, Usage},
        store::MetricsStore,
    },
    crate::fs_perm::open_wal,
    std::{collections::HashMap, path::Path},
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
/// 模型名归一上限（字符，对标 Python `unknown_model` 回退口径的防注入截断）。
pub const MODEL_MAX_CHARS: usize = 128;
/// 摘要截断默认上限（字符）。
/// R4 裁决：与 `audit::AUDIT_SUMMARY_TRUNCATE_CHARS`（4096，审计 JSONL 行预算）
/// 并存——1000 供管理面事件摘要（SSE/查询面小体量），4096 供审计日志行；
/// 两面体量与消费者不同，统一任一值都会改变对端输出，故保留双常量并注释差异。
pub const SUMMARY_MAX_CHARS: usize = 1000;

/// 模型名归一（C13）：去控制字符 + 截断 128 字符；空归 `unknown_model`
/// （与 Python 模型分桶回退一致，防属性注入/超长破坏聚合键）。
pub fn normalize_model(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MODEL_MAX_CHARS)
        .collect();
    if cleaned.is_empty() {
        "unknown_model".to_string()
    } else {
        cleaned
    }
}

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
    /// C13 模型分桶键（归一后：去控制字符+截断128，空为 `unknown_model`）。
    pub model: String,
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

/// 对话观测参数束（C13：模型分桶后位置参数超 clippy 7 参上限，成束传参）。
#[derive(Debug, Clone, Copy)]
pub struct ChatRecord<'a> {
    pub protocol: Protocol,
    /// 上游回显模型名（归一后分桶；缺失传空串归 `unknown_model`）。
    pub model: &'a str,
    pub latency_ms: u64,
    pub usage: Option<&'a Usage>,
    pub truncated_mode: Option<&'a str>,
    pub is_precise: bool,
    pub ts_secs: i64,
}

/// 扩展对话观测参数束（`cached_read/write/unknown` 列，见 [`ExtendedUsage`]）。
#[derive(Debug, Clone, Copy)]
pub struct ExtendedChatRecord<'a> {
    pub protocol: Protocol,
    pub model: &'a str,
    pub latency_ms: u64,
    pub usage: Option<&'a ExtendedUsage>,
    pub truncated_mode: Option<&'a str>,
    pub is_precise: bool,
    pub ts_secs: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Granularity {
    Daily,
    Hourly,
    FiveMin,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct AggKey {
    pub(crate) granularity: Granularity,
    pub(crate) window: String,
    pub(crate) protocol: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct WindowAgg {
    pub(crate) count: u64,
    pub(crate) prompt: u64,
    pub(crate) completion: u64,
    pub(crate) total: u64,
    pub(crate) cached_read: u64,
    pub(crate) cached_write: u64,
    pub(crate) unknown: u64,
    pub(crate) pii_hits: u64,
    pub(crate) cred_hits: u64,
    pub(crate) audit_blocks: u64,
    pub(crate) buckets: [u64; LATENCY_BUCKETS],
    pub(crate) t_silent: u64,
    pub(crate) t_open: u64,
    pub(crate) t_synth: u64,
}

pub(crate) fn day_key(ts_secs: i64) -> String {
    // UTC 日键（不引入 chrono 重依赖，用整数天）。
    let days = ts_secs.div_euclid(86_400);
    format!("d{days}")
}

pub(crate) fn hour_key(ts_secs: i64) -> String {
    let hours = ts_secs.div_euclid(3_600);
    format!("h{hours}")
}

pub(crate) fn five_min_key(ts_secs: i64) -> String {
    let w = ts_secs.div_euclid(300);
    format!("m{w}")
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
    /// C13 模型分桶计数（环聚合；持久聚合仍按协议键，见 `AggKey`）。
    pub per_model: HashMap<String, u64>,
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

impl MetricsStore {
    /// 快照（`/_admin/metrics` 口径）：聚合内存环 + 窗口累计。
    pub fn snapshot(&self) -> MetricsSnapshot {
        let (mut count, mut prompt, mut completion, mut total) = (0u64, 0u64, 0u64, 0u64);
        let (mut cached_read, mut cached_write, mut unknown) = (0u64, 0u64, 0u64);
        let mut buckets = [0u64; LATENCY_BUCKETS];
        let mut t_silent = 0u64;
        let mut t_open = 0u64;
        let mut t_synth = 0u64;
        let mut per_protocol: HashMap<String, u64> = HashMap::new();
        let mut per_model: HashMap<String, u64> = HashMap::new();
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
                *per_model.entry(s.model.clone()).or_insert(0) += 1;
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
            per_model,
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

fn query_series_blocking(
    db_path: &Path,
    granularity: &str,
    since: Option<&str>,
    protocol: Option<&str>,
) -> anyhow::Result<Vec<SeriesPoint>> {
    let conn = open_wal(db_path)?;
    super::store::ensure_tables(&conn)?;
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
    super::store::ensure_tables(&conn)?;
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

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{
                store::MetricsStore,
                summarize::test_support::{chat_rec, ext_rec, now, tmp_db, usage},
            },
            *,
        },
        crate::service::llm_gateway::Protocol,
    };

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
        store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
        assert!(!store.snapshot().is_precise);
        // 100 样本跨 3600s 全精确 → 精确。
        let base = now() - 4000;
        for i in 0..100 {
            store.record_chat(chat_rec(
                Protocol::Chat,
                "",
                5,
                None,
                None,
                true,
                base + i * 40,
            ));
        }
        assert!(store.snapshot().is_precise);
        // 混入降级样本 → 近似。
        store.record_chat(chat_rec(
            Protocol::Chat,
            "",
            5,
            None,
            None,
            false,
            base + 4100,
        ));
        assert!(!store.snapshot().is_precise);
    }

    #[test]
    fn truncated_three_modes_split_by_label_invalid_ignored() {
        let store = MetricsStore::new(tmp_db("trunc"));
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            5,
            None,
            Some("silent_discard"),
            true,
            now(),
        ));
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            5,
            None,
            Some("open_ended"),
            true,
            now(),
        ));
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            5,
            None,
            Some("synthesized_failed"),
            true,
            now(),
        ));
        store.record_chat(chat_rec(
            Protocol::Responses,
            "",
            5,
            None,
            Some("bogus_mode"),
            true,
            now(),
        ));
        let snap = store.snapshot();
        assert_eq!(snap.truncated_silent_discard, 1);
        assert_eq!(snap.truncated_open_ended, 1);
        assert_eq!(snap.truncated_synthesized_failed, 1);
        assert_eq!(snap.requests, 4);
    }

    #[test]
    fn b5_model_at_sign_passthrough_and_edges() {
        // B5.2：`:@` 形态按普通字符保留通过；空归 unknown；超长截断；控制字符剥离。
        assert_eq!(normalize_model("org:proj@gpt-4o"), "org:proj@gpt-4o");
        assert_eq!(normalize_model("a:b@c"), "a:b@c");
        assert_eq!(normalize_model(""), "unknown_model");
        assert_eq!(
            normalize_model(&"m".repeat(200)).chars().count(),
            MODEL_MAX_CHARS
        );
        assert_eq!(normalize_model("\u{0}ab\n"), "ab");
        let store = MetricsStore::new(tmp_db("b5-atmodel"));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "org:proj@gpt-4o",
            5,
            None,
            None,
            true,
            now(),
        ));
        store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
        store.record_chat(chat_rec(
            Protocol::Chat,
            &"m".repeat(200),
            5,
            None,
            None,
            true,
            now(),
        ));
        let snap = store.snapshot();
        assert_eq!(snap.per_model.get("org:proj@gpt-4o"), Some(&1));
        assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
        assert_eq!(snap.requests, 3);
    }

    #[test]
    fn record_chat_buckets_by_normalized_model() {
        // C13：`record_chat` 按归一化 model 分桶（截断128+去控制字符）；
        // 阻断体回显断言见 `block_inject` 单测。
        assert_eq!(normalize_model("gpt-4o"), "gpt-4o");
        assert_eq!(normalize_model(""), "unknown_model");
        assert_eq!(normalize_model("   "), "   ", "空白非控制字符，保留");
        assert_eq!(normalize_model("\u{0}ab\n"), "ab");
        assert_eq!(
            normalize_model(&"m".repeat(200)).chars().count(),
            MODEL_MAX_CHARS
        );
        let store = MetricsStore::new(tmp_db("model-bucket"));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "gpt-4o",
            5,
            None,
            None,
            true,
            now(),
        ));
        store.record_chat(chat_rec(
            Protocol::Chat,
            "gpt-4o",
            5,
            None,
            None,
            true,
            now(),
        ));
        store.record_chat(chat_rec(Protocol::Chat, "", 5, None, None, true, now()));
        let snap = store.snapshot();
        assert_eq!(snap.per_model.get("gpt-4o"), Some(&2));
        assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
        assert_eq!(snap.requests, 3);
    }

    /// T9 可观测联动回补：model 分桶/协议联动/三粒度桶数与空桶稀疏/24h 近似口径/since 过滤。
    mod observability_parity_tests {
        use {
            super::{ExtendedUsage, chat_rec, ext_rec, now, tmp_db, usage},
            crate::service::{llm_gateway::Protocol, metrics::MetricsStore},
        };

        #[test]
        fn t9_model_linkage_snapshot_buckets() {
            let store = MetricsStore::new(tmp_db("obs-model"));
            let ts = now();
            for _ in 0..2 {
                store.record_chat(chat_rec(
                    Protocol::Chat,
                    "gpt-4o",
                    10,
                    Some(&usage(10, 5, 15)),
                    None,
                    true,
                    ts,
                ));
            }
            store.record_chat(chat_rec(
                Protocol::Chat,
                "gpt-4o-mini",
                10,
                Some(&usage(1, 1, 2)),
                None,
                true,
                ts,
            ));
            store.record_chat(chat_rec(
                Protocol::Chat,
                "",
                10,
                Some(&usage(1, 1, 2)),
                None,
                true,
                ts,
            ));
            let snap = store.snapshot();
            assert_eq!(snap.per_model.get("gpt-4o"), Some(&2));
            assert_eq!(snap.per_model.get("gpt-4o-mini"), Some(&1));
            assert_eq!(snap.per_model.get("unknown_model"), Some(&1));
            assert_eq!(snap.per_protocol.get("chat/completions"), Some(&4));
            assert_eq!(snap.total_tokens, 15 * 2 + 2 + 2);
        }

        #[test]
        fn t9_protocol_linkage_series_rows_split() {
            let db = tmp_db("obs-proto");
            let _ = std::fs::remove_file(&db);
            let store = MetricsStore::new(db.clone());
            let ts = now();
            store.record_chat(chat_rec(
                Protocol::Chat,
                "m",
                10,
                Some(&usage(1, 1, 2)),
                None,
                true,
                ts,
            ));
            store.record_chat(chat_rec(
                Protocol::Anthropic,
                "m",
                10,
                Some(&usage(1, 1, 2)),
                None,
                true,
                ts,
            ));
            let snap = store.snapshot();
            assert_eq!(snap.per_protocol.get("chat/completions"), Some(&1));
            assert_eq!(snap.per_protocol.get("v1/messages"), Some(&1));
            let _ = std::fs::remove_file(&db);
        }

        #[tokio::test]
        async fn t9_three_granularities_exact_counts() {
            let db = tmp_db("obs-gran");
            let _ = std::fs::remove_file(&db);
            let store = MetricsStore::new(db.clone());
            let ts = now();
            for _ in 0..5 {
                store.record_chat(chat_rec(
                    Protocol::Chat,
                    "m",
                    100,
                    Some(&usage(10, 5, 15)),
                    None,
                    true,
                    ts,
                ));
            }
            store.record_aux_counts(Protocol::Chat, ts, 1, 0, 0);
            store.flush().await.unwrap();
            for gran in ["daily", "hourly", "five_min"] {
                let pts = store
                    .query_series(gran, None, Some("chat/completions".to_string()))
                    .await
                    .unwrap();
                let total: u64 = pts.iter().map(|p| p.requests).sum();
                assert_eq!(total, 5, "{gran} 粒度 requests 须精确求和");
                assert_eq!(pts.iter().map(|p| p.prompt_tokens).sum::<u64>(), 50);
                assert_eq!(pts.iter().map(|p| p.pii_hits).sum::<u64>(), 1);
            }
            let _ = std::fs::remove_file(&db);
        }

        #[tokio::test]
        async fn t9_empty_store_sparse_no_zero_fill() {
            let db = tmp_db("obs-empty");
            let _ = std::fs::remove_file(&db);
            let store = MetricsStore::new(db.clone());
            let pts = store.query_series("hourly", None, None).await.unwrap();
            assert!(pts.is_empty(), "空库稀疏无行（与原仓补零桶差异有意）");
            let _ = std::fs::remove_file(&db);
        }

        #[tokio::test]
        async fn t9_since_window_filters_old() {
            let db = tmp_db("obs-since");
            let _ = std::fs::remove_file(&db);
            let store = MetricsStore::new(db.clone());
            let ts = now();
            store.record_chat(chat_rec(
                Protocol::Chat,
                "m",
                10,
                Some(&usage(1, 1, 2)),
                None,
                true,
                ts,
            ));
            store.flush().await.unwrap();
            let all = store
                .query_series("daily", Some("d0".to_string()), None)
                .await
                .unwrap();
            assert!(!all.is_empty());
            let future = store
                .query_series("daily", Some("d999999999".to_string()), None)
                .await
                .unwrap();
            assert!(future.is_empty(), "未来 since 须过滤全部旧窗");
            let _ = std::fs::remove_file(&db);
        }

        #[tokio::test]
        async fn t9_cached_columns_linkage() {
            let db = tmp_db("obs-cache");
            let _ = std::fs::remove_file(&db);
            let store = MetricsStore::new(db.clone());
            let ts = now();
            let ext = ExtendedUsage {
                prompt_tokens: 100,
                completion_tokens: 20,
                total_tokens: 120,
                cached_read: 30,
                cached_write: 0,
                ..Default::default()
            };
            store.record_chat_extended(ext_rec(
                Protocol::Chat,
                "m",
                10,
                Some(&ext),
                None,
                true,
                ts,
            ));
            store.flush().await.unwrap();
            let pts = store
                .query_series("daily", None, Some("chat/completions".to_string()))
                .await
                .unwrap();
            assert_eq!(pts.iter().map(|p| p.cached_read).sum::<u64>(), 30);
            let _ = std::fs::remove_file(&db);
        }
    }
}
