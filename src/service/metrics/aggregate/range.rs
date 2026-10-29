//! `range=1h|24h|7d|30d` 语义：范围解析、窗口下界折算与范围快照。
//!
//! `1h` 优先由内存环按 `ts_secs` 秒级过滤 requests/token/延迟分布，pii/cred/audit
//! 四项附属计数改由 `five_min` 窗口补齐（环样本不带这些列），故
//! `boundary_slack_secs=300`；环未覆盖满 1 小时时整体退回 `five_min` 窗口对齐求和
//! （同样 `boundary_slack_secs=300`、`partial=true`）。`24h`/`7d`/`30d` 一律按映射
//! 粒度窗口求和。

use {
    super::{
        super::store::MetricsStore,
        Granularity,
        LATENCY_BOUNDS_VERSION,
        MetricsSnapshot,
        WindowAgg,
        bucket_index,
        day_key,
        five_min_key,
        hour_key,
        p95_approx,
        p95_saturated,
        window_ord,
    },
    std::collections::HashMap,
};

/// 合法 `range` 取值（错误消息与校验共用，顺序即规范顺序）。
pub const RANGE_LABELS: [&str; 4] = ["1h", "24h", "7d", "30d"];

/// 范围映射的聚合粒度（与 `admin::compat_granularity_for_range` 的名称一一对应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RangeGranularity {
    FiveMin,
    Hourly,
    Daily,
}

impl RangeGranularity {
    /// 粒度跨度（秒）：窗口对齐误差上界与窗口起点折算的分母。
    pub const fn span_secs(self) -> u64 {
        match self {
            Self::FiveMin => 300,
            Self::Hourly => 3_600,
            Self::Daily => 86_400,
        }
    }

    /// 对应内存/落盘聚合的粒度枚举。
    pub(crate) const fn aggs_granularity(self) -> Granularity {
        match self {
            Self::FiveMin => Granularity::FiveMin,
            Self::Hourly => Granularity::Hourly,
            Self::Daily => Granularity::Daily,
        }
    }

    /// `/_admin/series?granularity=` 的取值形态。
    pub const fn series_name(self) -> &'static str {
        match self {
            Self::FiveMin => "five_min",
            Self::Hourly => "hourly",
            Self::Daily => "daily",
        }
    }

    fn from_series_name(name: &str) -> Option<Self> {
        match name {
            "five_min" | "5min" => Some(Self::FiveMin),
            "hourly" => Some(Self::Hourly),
            "daily" => Some(Self::Daily),
            _ => None,
        }
    }

    /// 包含 `ts_secs` 的窗口键（`d{days}`/`h{hours}`/`m{win}`）。
    pub fn window_key(self, ts_secs: i64) -> String {
        match self {
            Self::FiveMin => five_min_key(ts_secs),
            Self::Hourly => hour_key(ts_secs),
            Self::Daily => day_key(ts_secs),
        }
    }

    /// 包含 `ts_secs` 的窗口起点（epoch 秒）。
    pub fn window_start(self, ts_secs: i64) -> i64 {
        let span = self.span_secs() as i64;
        ts_secs.div_euclid(span) * span
    }
}

/// 解析后的范围：跨度 + 聚合粒度 + 1h 档的窗口兜底粒度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeSpec {
    pub span_secs: i64,
    pub granularity: RangeGranularity,
    /// 仅 `1h` 档为 `Some(FiveMin)`（环覆盖不足时改用该粒度窗口求和）。
    pub fallback_granularity: Option<RangeGranularity>,
}

impl RangeSpec {
    /// 解析 `1h|24h|7d|30d`（大小写不敏感、容忍首尾空白）；其余取值 `Err`，
    /// 由调用方映射为 `400 + E_BAD_REQUEST`。
    ///
    /// `Err(())` 是有意的契约：解析失败只有「非法取值」一种原因，调用方统一转
    /// `400 + E_BAD_REQUEST`，不携带错误细节（与 `compat_granularity_for_range`
    /// 的 `Option` 语义等价）。
    #[allow(clippy::result_unit_err)]
    pub fn parse(raw: &str) -> Result<Self, ()> {
        let normalized = raw.trim().to_ascii_lowercase();
        let span_secs = match normalized.as_str() {
            "1h" => 3_600,
            "24h" => 86_400,
            "7d" => 7 * 86_400,
            "30d" => 30 * 86_400,
            _ => return Err(()),
        };
        // 粒度映射复用管理面兼容表，避免与 `events` 侧出现第二份口径。
        let granularity = RangeGranularity::from_series_name(
            crate::service::admin::events::compat_granularity_for_range(&normalized).ok_or(())?,
        )
        .ok_or(())?;
        Ok(Self {
            span_secs,
            granularity,
            fallback_granularity: (granularity == RangeGranularity::FiveMin)
                .then_some(RangeGranularity::FiveMin),
        })
    }

    /// 规范化后的范围标签（与请求取值同形，供响应回显）。
    pub fn label(&self) -> &'static str {
        match self.span_secs {
            3_600 => "1h",
            86_400 => "24h",
            604_800 => "7d",
            _ => "30d",
        }
    }

    /// `1h` 档允许走内存环秒级路径；其余档位只有窗口聚合。
    pub fn allows_ring(&self) -> bool { self.span_secs <= 3_600 }

    /// 窗口求和所用的粒度（`1h` 取兜底粒度 `five_min`，其余取映射粒度）。
    pub fn agg_granularity(&self) -> RangeGranularity {
        self.fallback_granularity.unwrap_or(self.granularity)
    }

    /// 请求日志 rollup 的粒度字符（`'m'|'h'|'d'`），由范围显式决定。
    ///
    /// 不得由 `now - start_ts` 反推：对齐后的起点会把 1h/24h 推到更粗的粒度。
    pub const fn rollup_granularity(self) -> char {
        match self.granularity {
            RangeGranularity::FiveMin => 'm',
            RangeGranularity::Hourly => 'h',
            RangeGranularity::Daily => 'd',
        }
    }

    /// 范围的秒级下界（`now - span`）。
    pub fn range_start(&self, now_secs: i64) -> i64 { now_secs - self.span_secs }
}

/// 范围起点的窗口键（`[dhm]<整数>`），供 `/_admin/series` 折算 `since`。
pub fn series_since_for_range(range: RangeSpec, now_secs: i64) -> String {
    range
        .agg_granularity()
        .window_key(range.range_start(now_secs))
}

/// 范围内求和结果：窗口累计 + 协议分布 + 最早可用时间 + 样本精确性。
#[derive(Debug, Default)]
struct RangeSum {
    agg: WindowAgg,
    per_protocol: HashMap<String, u64>,
    /// 该路径可回答数据的最早时间（ring 最早样本 / 最早保留窗口起点）。
    earliest_available: Option<i64>,
    all_precise: bool,
}

impl RangeSum {
    fn new(all_precise: bool) -> Self {
        Self {
            all_precise,
            ..Self::default()
        }
    }

    fn note_available(&mut self, ts: i64) {
        self.earliest_available = Some(self.earliest_available.map_or(ts, |e| e.min(ts)));
    }

    fn accumulate(&mut self, src: &WindowAgg) {
        let dst = &mut self.agg;
        dst.count += src.count;
        dst.prompt += src.prompt;
        dst.completion += src.completion;
        dst.total += src.total;
        dst.cached_read += src.cached_read;
        dst.cached_write += src.cached_write;
        dst.unknown += src.unknown;
        dst.pii_hits += src.pii_hits;
        dst.pii_miss += src.pii_miss;
        dst.cred_hits += src.cred_hits;
        dst.audit_blocks += src.audit_blocks;
        dst.t_silent += src.t_silent;
        dst.t_open += src.t_open;
        dst.t_synth += src.t_synth;
        dst.t_upstream_error += src.t_upstream_error;
        // 边界版本不符的窗口（升级前落盘的数据）只贡献计数，桶按零计：
        // 旧桶下标对应的是旧边界，叠加进当前桶会让分布与 p95 失真。
        if src.bucket_bounds_version == LATENCY_BOUNDS_VERSION {
            for (to, from) in dst.buckets.iter_mut().zip(src.buckets.iter()) {
                *to += *from;
            }
        }
    }
}

impl MetricsStore {
    /// 按范围快照（`/_admin/metrics?range=` 与 SSE `metrics` 同口径）。
    pub fn snapshot_in_range(
        &self,
        range: RangeSpec,
        now_secs: i64,
        per_model: Option<&[(String, u64)]>,
    ) -> MetricsSnapshot {
        let span = range.span_secs;
        let range_start = range.range_start(now_secs);
        let ring_path = range.allows_ring() && self.ring_covers(now_secs, span);
        let (sum, granularity) = if ring_path {
            let mut sum = self.ring_range_sum(range_start);
            // 环样本只有请求逐条指标，pii/cred/audit 四项附属计数只落窗口聚合；
            // 在与兜底路径相同的 `five_min` 对齐下界上补齐（1h 档两路径同口径）。
            let (pii_hits, pii_miss, cred_hits, audit_blocks) = self.aggs_aux_counts(window_ord(
                &RangeGranularity::FiveMin.window_key(range_start),
            ));
            sum.agg.pii_hits = pii_hits;
            sum.agg.pii_miss = pii_miss;
            sum.agg.cred_hits = cred_hits;
            sum.agg.audit_blocks = audit_blocks;
            (sum, None)
        } else {
            let granularity = range.agg_granularity();
            let since_window = granularity.window_key(range_start);
            let sum =
                self.aggs_range_sum(granularity.aggs_granularity(), window_ord(&since_window));
            (sum, Some(granularity))
        };
        let samples = sum.agg.count;
        let ring_len = self.ring.lock().map(|r| r.len()).unwrap_or(0);
        let coverage_secs = sum.earliest_available.map_or(0, |earliest| {
            u64::try_from(now_secs - range_start.max(earliest)).unwrap_or(0)
        });
        // 环路径 requests/token 为秒级，附属计数为 5min 窗口口径，slack 取较大者。
        let boundary_slack_secs = if ring_path {
            RangeGranularity::FiveMin.span_secs()
        } else {
            granularity.map_or(0, |g| g.span_secs())
        };
        // 1h 环未覆盖满整段时退回窗口兜底，精度必然降级（即便窗口条数够）。
        let fallback_degraded = range.allows_ring() && !ring_path;
        let partial = coverage_secs < span as u64 || fallback_degraded;
        // 窗口路径看不到逐样本 `is_precise`，只有保留窗口完整覆盖整段才算精确。
        let all_samples_precise = if ring_path {
            sum.all_precise
        } else {
            coverage_secs >= span as u64
        };
        // `partial` 与 `is_precise` 互斥：降级口径不得宣称可对账。
        let is_precise = !partial
            && span >= 3_600
            && samples >= 100
            && coverage_secs >= span as u64
            && all_samples_precise;
        let mut per_model_map: HashMap<String, u64> = HashMap::new();
        // rollup 不可用（无投影，或投影为空但确有请求）时用环样本兜底，
        // 避免「KPI 有计数、分布为空」；兜底口径必须标 partial。
        let per_model_partial = match per_model {
            Some(rows) if !rows.is_empty() => {
                for (model, count) in rows {
                    *per_model_map.entry(model.clone()).or_insert(0) += *count;
                }
                false
            }
            None => {
                self.ring_per_model(range_start, &mut per_model_map);
                true
            }
            Some(_) => {
                if samples > 0 {
                    self.ring_per_model(range_start, &mut per_model_map);
                }
                samples > 0
            }
        };
        MetricsSnapshot {
            requests: samples,
            prompt_tokens: sum.agg.prompt,
            completion_tokens: sum.agg.completion,
            total_tokens: sum.agg.total,
            cached_read: sum.agg.cached_read,
            cached_write: sum.agg.cached_write,
            unknown: sum.agg.unknown,
            pii_hits: sum.agg.pii_hits,
            pii_miss: sum.agg.pii_miss,
            cred_hits: sum.agg.cred_hits,
            latency_buckets: sum.agg.buckets,
            p95_ms: p95_approx(&sum.agg.buckets),
            p95_saturated: p95_saturated(&sum.agg.buckets),
            per_protocol: sum.per_protocol,
            per_model: per_model_map,
            truncated_silent_discard: sum.agg.t_silent,
            truncated_open_ended: sum.agg.t_open,
            truncated_synthesized_failed: sum.agg.t_synth,
            truncated_upstream_error: sum.agg.t_upstream_error,
            is_precise,
            ring_len,
            dropped: self.dropped_total(),
            aggs_evicted: self.aggs_evicted_total(),
            range: Some(range.label().to_string()),
            since_ts: Some(match granularity {
                Some(g) => g.window_start(range_start),
                None => range_start,
            }),
            coverage_secs,
            partial,
            boundary_slack_secs,
            per_model_partial,
            requests_dropped: 0,
            requests_aborted: 0,
        }
    }

    /// 环内最早样本是否已到达 `now - span`（覆盖满整段）。
    fn ring_covers(&self, now_secs: i64, span_secs: i64) -> bool {
        let Ok(ring) = self.ring.lock() else {
            return false;
        };
        ring.iter()
            .map(|s| s.ts_secs)
            .min()
            .is_some_and(|earliest| earliest <= now_secs - span_secs)
    }

    fn ring_range_sum(&self, since_ts: i64) -> RangeSum {
        let mut sum = RangeSum::new(true);
        let Ok(ring) = self.ring.lock() else {
            return sum;
        };
        for s in ring.iter() {
            sum.note_available(s.ts_secs);
            if s.ts_secs < since_ts {
                continue;
            }
            let agg = &mut sum.agg;
            agg.count += 1;
            agg.prompt += s.prompt_tokens;
            agg.completion += s.completion_tokens;
            agg.total += s.total_tokens;
            agg.cached_read += s.cached_read;
            agg.cached_write += s.cached_write;
            agg.unknown += s.unknown;
            agg.buckets[bucket_index(s.latency_ms)] += 1;
            *sum.per_protocol.entry(s.protocol.clone()).or_insert(0) += 1;
            match s.truncated_mode.as_deref() {
                Some("silent_discard") => agg.t_silent += 1,
                Some("open_ended") => agg.t_open += 1,
                Some("synthesized_failed") => agg.t_synth += 1,
                Some("upstream_error") => agg.t_upstream_error += 1,
                _ => {}
            }
            sum.all_precise = sum.all_precise && s.is_precise;
        }
        sum
    }

    fn aggs_range_sum(&self, granularity: Granularity, since_ord: i64) -> RangeSum {
        let mut sum = RangeSum::new(true);
        let Ok(aggs) = self.aggs.lock() else {
            return sum;
        };
        let span = granularity.span_secs() as i64;
        for (key, agg) in aggs.iter() {
            if key.granularity != granularity {
                continue;
            }
            let ord = window_ord(&key.window);
            sum.note_available(ord.saturating_mul(span));
            if ord < since_ord {
                continue;
            }
            sum.accumulate(agg);
            *sum.per_protocol.entry(key.protocol.clone()).or_insert(0) += agg.count;
        }
        sum
    }

    /// `five_min` 窗口附属计数求和（`since_ord` 为对齐窗口序号）：
    /// 返回 `(pii_hits, pii_miss, cred_hits, audit_blocks)`。
    fn aggs_aux_counts(&self, since_ord: i64) -> (u64, u64, u64, u64) {
        let mut aux = (0u64, 0u64, 0u64, 0u64);
        let Ok(aggs) = self.aggs.lock() else {
            return aux;
        };
        for (key, agg) in aggs.iter() {
            if key.granularity != Granularity::FiveMin || window_ord(&key.window) < since_ord {
                continue;
            }
            aux.0 += agg.pii_hits;
            aux.1 += agg.pii_miss;
            aux.2 += agg.cred_hits;
            aux.3 += agg.audit_blocks;
        }
        aux
    }

    /// 环内 `since_ts` 之后的模型分桶计数（rollup 不可用时的降级分布）。
    fn ring_per_model(&self, since_ts: i64, out: &mut HashMap<String, u64>) {
        let Ok(ring) = self.ring.lock() else {
            return;
        };
        for s in ring.iter().filter(|s| s.ts_secs >= since_ts) {
            *out.entry(s.model.clone()).or_insert(0) += 1;
        }
    }
}

#[cfg(test)]
mod tests;
