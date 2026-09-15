//! PII 值级掩码采样：掩码/哈希口径 + 内存 TopN + 采样器。

use std::{collections::VecDeque, path::PathBuf, sync::Mutex};

/// 采样日键（M5，对标原仓 `pii_value_agg.day=%Y-%m-%d` UTC）：整数天转公历日期
/// （Hinnant 天数转民用日期算法，不引入 chrono 重依赖）。
pub(crate) fn sampler_day(ts_secs: i64) -> String {
    let z = ts_secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

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
    /// `DCD-5`：仅测试引用（启动 warn 未接线），`#[cfg(test)]` 收编；接生产时移除收编。
    #[cfg(test)]
    pub(crate) fn needs_hmac_warn(&self) -> bool {
        self.enabled && self.hmac_key.as_deref().unwrap_or("").is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SampleView {
    pub hash: String,
    pub kind: String,
    pub mask: String,
    pub hits: u64,
    /// 去重键成分：同值跨上游不合并（与落盘复合键 `(day,upstream,kind,hash)` 对齐）。
    pub upstream: String,
}

#[derive(Debug, Default)]
pub(crate) struct SamplerCounts {
    pub(crate) sampled: u64,
    pub(crate) skipped_disabled: u64,
    pub(crate) skipped_non_chat: u64,
    pub(crate) dropped_full: u64,
}

/// 采样落盘队列容量（有界通道背压：满时丢最老计 `dropped`，与指标环同语义）。
pub const SAMPLE_QUEUE_CAP: usize = 512;
/// 采样落盘行（掩码 + hash，不含明文；`day/upstream` 参与复合键）。
#[derive(Debug, Clone)]
pub(crate) struct SampleRow {
    pub(crate) day: String,
    pub(crate) upstream: String,
    pub(crate) hash: String,
    pub(crate) kind: String,
    pub(crate) mask: String,
    pub(crate) seen: i64,
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
            tokio::spawn(super::store::sample_flush_driver(
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

    /// 值级掩码（当场生成，对标原仓 `mask_pii_value(kind, value)`）：
    /// phone 前3后4、email `***@***.suffix`（不透首字符防侧信道）、bank 仅后4、
    /// ipv4 前两段保留、ipv6/api_key 前4后4（短值降级）、other 前3后3（短值首末）。
    /// 空值返回 `***`（M4，调用方 `sample` 负责计数）；64 截断见函数尾（M3）。
    /// 输入明文仅在本函数栈上存活，返回后调用方须立即丢弃。
    pub fn sample_mask(kind: &str, value: &str) -> String {
        if value.is_empty() {
            return "***".to_string();
        }
        let chars: Vec<char> = value.chars().collect();
        let n = chars.len();
        let first = |m: usize| -> String { chars.iter().take(m).collect() };
        let last = |m: usize| -> String { chars.iter().skip(n.saturating_sub(m)).collect() };
        // 短值通用形态：`len<6` 时首字符 + `****` + 末字符（`len<2` 全掩码）。
        let short = || -> String {
            if n >= 2 {
                format!("{}****{}", chars[0], chars[n - 1])
            } else {
                "***".to_string()
            }
        };
        let raw = match kind.to_ascii_lowercase().as_str() {
            "phone" => {
                if n >= 7 {
                    format!("{}****{}", first(3), last(4))
                } else if n < 6 {
                    short()
                } else {
                    format!("{}****{}", first(3), last(3))
                }
            }
            "email" => {
                if let Some(at) = value.find('@') {
                    // 不透 local/domain 首字符：统一 `***@***.suffix`。
                    let domain = &value[at + 1..];
                    if let Some(dot) = domain.rfind('.') {
                        let suffix = &domain[dot + 1..];
                        if suffix.is_empty() {
                            "***@***".to_string()
                        } else {
                            format!("***@***.{suffix}")
                        }
                    } else {
                        "***@***".to_string()
                    }
                } else if n < 6 {
                    short()
                } else {
                    format!("{}****{}", first(3), last(3))
                }
            }
            "bank" | "bank_card" => {
                if n >= 4 {
                    // 仅后 4（BIN 不保留）。
                    format!("**** **** **** {}", last(4))
                } else {
                    short()
                }
            }
            "ipv4" => {
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() == 4 {
                    format!("{}.{}.**.**", parts[0], parts[1])
                } else if n >= 8 {
                    format!("{}****{}", first(4), last(4))
                } else {
                    short()
                }
            }
            "ipv6" | "api_key" => {
                if n < 6 {
                    short()
                } else if n >= 8 {
                    format!("{}****{}", first(4), last(4))
                } else {
                    format!("{}****{}", first(3), last(3))
                }
            }
            _ => {
                if n < 6 {
                    if n <= 1 {
                        "***".to_string()
                    } else {
                        format!("{}****{}", chars[0], chars[n - 1])
                    }
                } else {
                    format!("{}****{}", first(3), last(3))
                }
            }
        };
        Self::truncate_mask(raw)
    }

    /// 掩码 64 上限（M3，对标原仓 `masked[:64]`）：按字符边界硬截断，不附加后缀。
    /// 有意偏离 design“复用 `truncate_utf8`”：后者追加 `…[truncated]` 会使长度超出 64，
    /// 违反 spec“掩码恒 `<= 64` 字符”；此处须严格封顶。
    fn truncate_mask(raw: String) -> String {
        if raw.chars().count() <= 64 {
            raw
        } else {
            raw.chars().take(64).collect()
        }
    }

    /// hash 口径：置位 `HMAC_KEY` 用 HMAC-SHA256，否则退化 SHA256；恒取 hex 前 16 字符
    /// （对标原仓 `_pii_value_hash(...)[:16]`，去重/落盘/展示键以 16hex 对齐）。
    ///
    /// ⚠️ 风险声明：未设 `PII_VALUE_SAMPLE_HMAC_KEY` 时为无盐 SHA256，
    /// 低熵 PII（手机号段等）可被离线字典枚举，此时 hash 仅趋势参考，
    /// 不得直接对账；生产环境必须配置 `HMAC_KEY`。
    pub fn hash_value(&self, value: &str) -> String {
        let full = if let Some(key) = self.cfg.hmac_key.as_deref() {
            use hmac::{KeyInit as _, Mac as _};
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())
                .expect("HMAC key 恒可载入");
            mac.update(value.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        } else {
            crate::auth::sha256_hex(value.as_bytes())
        };
        full[..16].to_string()
    }

    /// 采样入口：仅 `is_chat_tail` 触发；关闭时仅计数不落采样。
    /// `upstream` 为网关上下文的上游标识，参与内存去重与落盘复合键；
    /// 调用方 MUST 透传真实上游（禁止空串占位）。
    /// 返回 `(mask, hash)`，明文不存储、不出作用域。
    pub fn sample(
        &self,
        kind: &str,
        value: &str,
        is_chat_tail: bool,
        upstream: &str,
    ) -> Option<(String, String)> {
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
        // 空值计入采样（M4，对标原仓 `mask('other','') == '***'`）：掩码 `***`，hash 照常计算。
        let mask = Self::sample_mask(kind, value);
        let hash = self.hash_value(value);
        if let Ok(mut c) = self.counts.lock() {
            c.sampled += 1;
        }
        let view = SampleView {
            hash: hash.clone(),
            kind: kind.to_string(),
            mask: mask.clone(),
            hits: 1,
            upstream: upstream.to_string(),
        };
        if let Ok(mut r) = self.recent.lock() {
            if r.len() >= 256 {
                r.pop_front();
            }
            // 复合键去重（M5）：同 hash 不同 kind 或不同 upstream 不合并 hits。
            if let Some(exist) = r
                .iter_mut()
                .find(|v| v.hash == hash && v.kind == kind && v.upstream == upstream)
            {
                exist.hits += 1;
            } else {
                r.push_back(view);
            }
        }
        if self.cfg.persist {
            let seen = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let row = SampleRow {
                day: sampler_day(seen),
                upstream: upstream.to_string(),
                hash: hash.clone(),
                kind: kind.to_string(),
                mask: mask.clone(),
                seen,
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
    /// `DCD-5`/`OPS-1`：保留 `pub`——`admin_metrics_body` 生产引用，经 `/_admin/metrics` 暴露。
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
    /// `DCD-5`：仅测试引用，`#[cfg(test)]` 收编。
    #[cfg(test)]
    pub(crate) fn stats(&self) -> (u64, u64, u64) {
        self.counts
            .lock()
            .map(|c| (c.sampled, c.skipped_disabled, c.skipped_non_chat))
            .unwrap_or_default()
    }

    /// 满队列丢最老计数（含无驱动发送失败；与指标环 `dropped` 同语义可查）。
    /// `DCD-5`：仅测试引用，`#[cfg(test)]` 收编。
    #[cfg(test)]
    pub(crate) fn dropped_total(&self) -> u64 {
        self.counts.lock().map(|c| c.dropped_full).unwrap_or(0)
    }

    /// 队列滞留行数（单测断言落盘前缓冲用）。
    #[cfg(test)]
    fn pending_len(&self) -> usize { self.tx.len() }
}

#[cfg(test)]
mod tests;
