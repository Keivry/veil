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

#[cfg(test)]
mod tests {
    use {
        super::{
            super::{
                store::{ensure_tables, persist_sample_batch},
                summarize::test_support::tmp_db,
            },
            *,
        },
        crate::fs_perm::open_wal,
    };

    #[test]
    fn pii_sampling_disabled_counts_only() {
        let cfg = PiiSamplerConfig::for_test(false, true, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-off"));
        assert!(s.sample("phone", "13812345678", true, "").is_none());
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
        assert!(s.sample("phone", "13812345678", false, "").is_none());
        let (_, _, non_chat) = s.stats();
        assert_eq!(non_chat, 1);
        let (mask, hash) = s.sample("phone", "13812345678", true, "").unwrap();
        // 掩码当场生成，明文不出作用域：mask/hash 均不含明文。
        assert!(!mask.contains("13812345678") && !hash.contains("13812345678"));
        assert!(mask.starts_with('1') && mask.ends_with('8') && mask.contains("***"));
        // HMAC 口径可复算（16hex：完整 HMAC-SHA256 hex 前 16 字符）。
        use hmac::{KeyInit as _, Mac as _};
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test-hmac-key-0123456789").unwrap();
        mac.update(b"13812345678");
        let full = hex::encode(mac.finalize().into_bytes());
        assert_eq!(hash, full[..16]);
        // TopN hover 展示掩码。
        s.sample("phone", "13812345678", true, "");
        let top = s.top_n(5);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].hits, 2);
        assert!(!top[0].mask.contains("13812345678"));
    }

    #[test]
    fn sample_mask_varies_by_kind() {
        use super::PiiValueSampler as S;
        // 对标原仓 `pii_value_samples_test.py::TestMaskPiiValue` 向量。
        assert_eq!(S::sample_mask("phone", "13812348000"), "138****8000");
        assert_eq!(
            S::sample_mask("phone", "__PII_82_8f6a798b__"),
            "__P****8b__"
        );
        assert_eq!(S::sample_mask("email", "user@example.com"), "***@***.com");
        assert_eq!(S::sample_mask("email", "user@domain"), "***@***");
        assert_eq!(
            S::sample_mask("bank", "6225880123456789"),
            "**** **** **** 6789"
        );
        assert_eq!(
            S::sample_mask("bank_card", "6225880123456789"),
            "**** **** **** 6789"
        );
        assert_eq!(S::sample_mask("ipv4", "192.168.1.10"), "192.168.**.**");
        assert!(S::sample_mask("ipv6", "2001:db8::1").contains("****"));
        assert_eq!(S::sample_mask("api_key", "abcd1234"), "abcd****1234");
        assert_eq!(S::sample_mask("api_key", "abc12"), "a****2");
        assert_eq!(S::sample_mask("other", "hello_world"), "hel****rld");
        assert_eq!(S::sample_mask("other", ""), "***");
        // 同一明文不同 kind 掩码分叉（M1 核心断言）。
        assert_ne!(
            S::sample_mask("phone", "13812348000"),
            S::sample_mask("other", "13812348000")
        );
    }

    #[test]
    fn pii_sampling_without_hmac_falls_back_to_sha256() {
        let cfg = PiiSamplerConfig::for_test(true, false, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-degrade"));
        let (_, hash) = s.sample("email", "a@b.com", true, "").unwrap();
        let full = crate::auth::sha256_hex(b"a@b.com");
        assert_eq!(hash, full[..16]);
    }

    #[test]
    fn hash_value_is_16hex_keyed_and_degraded() {
        let is_hex16 = |h: &str| h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit());
        // 无 key 退化 SHA256[:16]。
        let plain = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("hash-plain"),
        );
        let h_plain = plain.hash_value("__PII_7_12345678__");
        assert!(is_hex16(&h_plain));
        // 有 key 时 HMAC[:16]，与无盐不同且同 key 同值稳定。
        let keyed = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, Some("test-salt-123".to_string())),
            tmp_db("hash-hmac"),
        );
        let h_hmac = keyed.hash_value("__PII_7_12345678__");
        assert!(is_hex16(&h_hmac));
        assert_ne!(h_hmac, h_plain);
        assert_eq!(keyed.hash_value("__PII_7_12345678__"), h_hmac);
    }

    #[test]
    fn mask_truncates_at_64_chars_utf8_safe() {
        use super::PiiValueSampler as S;
        // 100 字符 email：掩码恒 `<= 64` 字符（M3 场景）。
        let long_email = format!("{}@b.com", "a".repeat(100));
        let masked = S::sample_mask("email", &long_email);
        assert!(masked.chars().count() <= 64, "{masked}");
        // CJK 长值：按字符边界截断，不断裂 `char`。
        let masked = S::sample_mask("other", &"中".repeat(100));
        assert!(masked.chars().count() <= 64);
        assert!(std::str::from_utf8(masked.as_bytes()).is_ok());
        // 短掩码原样保留。
        assert_eq!(S::sample_mask("phone", "13812348000"), "138****8000");
    }

    #[test]
    fn empty_value_samples_as_stars_and_counts() {
        // M4 场景：空串采样为 `***` 并计数，永不跳过为 `None`。
        let s = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("empty-sample"),
        );
        let (mask, hash) = s.sample("other", "", true, "").unwrap();
        assert_eq!(mask, "***");
        assert_eq!(hash.len(), 16);
        let (sampled, ..) = s.stats();
        assert_eq!(sampled, 1);
        assert_eq!(s.top_n(5).len(), 1);
    }

    #[test]
    fn top_n_orders_by_hits_and_truncates() {
        // Top5 口径：6 个不同值按频次 6..1 采样，Top3 按 hits 降序且截断。
        let s = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("topn"),
        );
        let values = [
            "13800000001",
            "13800000002",
            "13800000003",
            "13800000004",
            "13800000005",
            "13800000006",
        ];
        for (i, v) in values.iter().enumerate() {
            for _ in 0..(6 - i) {
                s.sample("phone", v, true, "").unwrap();
            }
        }
        let top3 = s.top_n(3);
        assert_eq!(top3.len(), 3);
        assert_eq!((top3[0].hits, top3[1].hits, top3[2].hits), (6, 5, 4));
        assert_eq!(s.top_n(10).len(), 6);
        // 非对话不采样且计入 `skipped_non_chat`。
        assert!(s.sample("phone", values[0], false, "").is_none());
        let (.., non_chat) = s.stats();
        assert_eq!(non_chat, 1);
    }

    #[test]
    fn concurrent_sampling_is_isolated_and_lossless() {
        // 并发隔离（对标原仓 `test_concurrency_isolation`）：8 线程各采 25 个不同值，
        // 计数 200 且条目无丢失无合并。
        use std::sync::Arc;
        let s = Arc::new(PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("concurrent"),
        ));
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    for i in 0..25 {
                        let v = format!("139{t:02}{i:04}");
                        s.sample("phone", &v, true, "").unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("采样线程恒成功");
        }
        let (sampled, ..) = s.stats();
        assert_eq!(sampled, 200);
        assert_eq!(s.top_n(500).len(), 200);
    }

    #[test]
    fn same_plaintext_different_kinds_do_not_merge() {
        // M5 场景：同明文以 phone 与 bank 各采样一次 → 两条独立条目，hits 互不干扰。
        let s = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("cross-kind"),
        );
        let value = "13812348000";
        let (_, h_phone) = s.sample("phone", value, true, "").unwrap();
        let (_, h_bank) = s.sample("bank", value, true, "").unwrap();
        assert_eq!(h_phone, h_bank, "同明文 hash 相同，去重须靠 kind 区分");
        s.sample("phone", value, true, "");
        let top = s.top_n(5);
        assert_eq!(top.len(), 2);
        let phone = top.iter().find(|v| v.kind == "phone").unwrap();
        let bank = top.iter().find(|v| v.kind == "bank").unwrap();
        assert_eq!((phone.hits, bank.hits), (2, 1));
    }

    #[test]
    fn same_value_cross_upstream_does_not_merge() {
        // 同 kind 同明文分属两上游 → 两条独立条目，hits 互不干扰。
        let s = PiiValueSampler::new(
            PiiSamplerConfig::for_test(true, false, None),
            tmp_db("cross-upstream"),
        );
        let value = "13812348000";
        let (_, h_a) = s.sample("phone", value, true, "https://a.example").unwrap();
        let (_, h_b) = s.sample("phone", value, true, "https://b.example").unwrap();
        assert_eq!(h_a, h_b, "同明文 hash 相同，去重须靠 upstream 区分");
        s.sample("phone", value, true, "https://a.example");
        let top = s.top_n(5);
        assert_eq!(top.len(), 2);
        let a = top
            .iter()
            .find(|v| v.upstream == "https://a.example")
            .unwrap();
        let b = top
            .iter()
            .find(|v| v.upstream == "https://b.example")
            .unwrap();
        assert_eq!((a.hits, b.hits), (2, 1));
    }

    #[test]
    fn persist_upsert_keys_on_day_upstream_kind_hash() {
        // SQL 层：同 hash 不同 kind 落两行；同四元组重复落库合并 hits。
        let db = tmp_db("composite-upsert");
        let _ = std::fs::remove_file(&db);
        let row = |kind: &str| SampleRow {
            day: "2026-09-09".to_string(),
            upstream: String::new(),
            hash: "0123456789abcdef".to_string(),
            kind: kind.to_string(),
            mask: "***".to_string(),
            seen: 1,
        };
        persist_sample_batch(&db, &[row("phone"), row("bank"), row("phone")]).unwrap();
        let conn = open_wal(&db).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 2);
        let hits: i64 = conn
            .query_row(
                "SELECT hits FROM pii_value_samples WHERE day='2026-09-09' AND kind='phone'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(hits, 2);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn legacy_single_key_table_rebuilds_to_composite() {
        // 迁移场景：存量单键旧表在 ensure_tables 后重建为复合键表，旧行清理。
        let db = tmp_db("legacy-migrate");
        let _ = std::fs::remove_file(&db);
        let conn = open_wal(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE pii_value_samples(hash TEXT PRIMARY KEY, kind TEXT NOT NULL,\
             mask TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1,\
             first_seen INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0);\
             INSERT INTO pii_value_samples(hash,kind,mask,hits,first_seen,last_seen)\
             VALUES ('aa','phone','***',1,0,0);",
        )
        .unwrap();
        drop(conn);
        let conn = open_wal(&db).unwrap();
        ensure_tables(&conn).unwrap();
        let has_day: bool = conn
            .prepare("PRAGMA table_info(pii_value_samples)")
            .map(|mut stmt| {
                stmt.query_map([], |row| row.get::<_, String>(1))
                    .map(|rows| rows.flatten().any(|name| name == "day"))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        assert!(has_day);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
        drop(conn);
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn pii_value_mask_merge_and_count_query() {
        let cfg = PiiSamplerConfig::for_test(true, false, None);
        let s = PiiValueSampler::new(cfg, tmp_db("pii-query"));
        let (m1, h1) = s.sample("phone", "13812345678", true, "").unwrap();
        assert!(m1.starts_with('1') && m1.ends_with('8'));
        s.sample("phone", "13812345678", true, "");
        s.sample("email", "a@b.com", true, "");
        let top = s.top_n(5);
        assert_eq!(top.iter().find(|v| v.hash == h1).unwrap().hits, 2);
        assert_eq!(top.len(), 2);
        let (sampled, disabled, non_chat) = s.stats();
        assert_eq!((sampled, disabled, non_chat), (3, 0, 0));
        assert!(s.sample("phone", "13812345678", false, "").is_none());
        assert_eq!(PiiValueSampler::sample_mask("other", "ab"), "a****b");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sampling_background_flush_persists() {
        let db = tmp_db("pii-flush");
        let _ = std::fs::remove_file(&db);
        let cfg = PiiSamplerConfig::for_test(true, true, None);
        let s = PiiValueSampler::new(cfg, db.clone());
        let (mask, hash) = s.sample("phone", "13812345678", true, "").unwrap();
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
            let _ = s.sample("phone", &v, true, "");
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
        // 通道见底不等于落库完成（`spawn_blocking` 批量写仍在途）：轮询等行落库（2s 内必达）。
        let mut rows = 0;
        for _ in 0..200 {
            if let Ok(conn) = open_wal(&db) {
                rows = conn
                    .query_row("SELECT COUNT(*) FROM pii_value_samples", [], |r| {
                        r.get::<_, i64>(0)
                    })
                    .unwrap_or(0);
                if rows >= SAMPLE_QUEUE_CAP as i64 {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
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
    fn sampling_master_switch_off_means_zero_persist() {
        let cfg = PiiSamplerConfig::for_test(false, true, None);
        let s = PiiValueSampler::new(cfg, tmp_db("sample-off"));
        assert!(s.sample("phone", "13812345678", true, "").is_none());
        assert!(s.sample("phone", "13812345678", true, "").is_none());
        let (sampled, disabled, _) = s.stats();
        assert_eq!((sampled, disabled), (0, 2), "关闭时只记跳过不采样");
        assert!(s.top_n(5).is_empty(), "零落盘：无样本可查");
    }
}
