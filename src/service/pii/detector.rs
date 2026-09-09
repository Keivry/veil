//! PII 检测器：内置 recognizer 原语 + 校验 LRU + `PiiDetector` 核心扫描。
//!
//! 口径对标原仓 `_pii.py` 与 `_token.py`：7 recognizer（手机/身份证GB校验位/
//! 银行卡Luhn/邮箱/IPv4/IPv6/API key 最小长度16）合成为单一联合正则一次扫描；
//! 中文与 CJK 边界用 lookaround 表达，MUST NOT 用 `\b`。token 形态
//! `__PII_<seq>_<rand8>__`。全局 PII LRU（`moka 0.12`）仅缓存确定性校验结论，
//! 不缓存任何明文↔token 映射，请求级映射永不跨请求互见。
//!
//! 原仓七类对照（D8 映射表，本仓 7 名恒 7，缺失类：无）：
//!
//! | 原仓 `_BUILTIN_PATTERNS` | 本仓 `BUILTIN_NAMES` | 备注 |
//! |:--------------------------|:---------------------|:-----|
//! | phone（手机号） | `phone` | 含 +86 冠码与中文紧贴，GB 口径同字 |
//! | id_card（身份证） | `id_card` | GB 校验位复核，非法位不命中 |
//! | bank_card（银行卡） | `bank_card` | Luhn 复核，非法号不命中 |
//! | email（邮箱） | `email` | 联合正则命名组同字 |
//! | ipv4 | `ipv4` | 保留/公网划分见 `reserved_allowlist_exempted` |
//! | ipv6 | `ipv6` | 同上 |
//! | api_key（密钥） | `api_key` | sk-/gh[pous]_/AKIA 前缀，最小长度 16 |

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Mutex,
        OnceLock,
        RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// PII 占位符前缀。
pub const PII_TOKEN_PREFIX: &str = "__PII_";
/// 请求/响应单表上限（真 LRU，与凭据 5000 区分）。
pub const PII_MAX_ENTRIES: usize = 1000;
/// 自定义正则单次扫描预算（毫秒）。
pub const RE_DOS_BUDGET_MS: u64 = 100;
/// 自定义正则连续超时停用阈值。
pub const RE_DOS_STRIKES: u32 = 3;
/// 全局校验结论 LRU 容量。
pub const VALIDATION_CACHE_CAP: u64 = 4096;

/// 7 内置 recognizer 名（与自定义重名拒绝加载；D8 互锁：长度恒 7 见 `builtin_names_len_locked`）。
pub const BUILTIN_NAMES: [&str; 7] = [
    "email",
    "phone",
    "id_card",
    "bank_card",
    "ipv4",
    "ipv6",
    "api_key",
];

/// 命中位置：`(kind, value, start, end)`，`start/end` 为字节下标。
pub type PiiHit = (String, String, usize, usize);

/// 内置联合正则：命名捕获组区分类型，全部 lookaround 边界（无 `\b`）。
/// 与原仓 `_BUILTIN_PATTERNS` 同字（排序：银行卡排手机号之后，长值优先由仲裁保证）。
const COMBINED_PATTERN: &str = concat!(
    r"(?P<email>(?<![0-9A-Za-z_.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![0-9A-Za-z_.-]))",
    r"|(?P<phone>(?<![\d])(?:\+?86[\- ]?)?1[3-9]\d{9}(?!\d))",
    r"|(?P<id_card>(?<![\d])\d{17}[\dXx](?!\d))",
    r"|(?P<bank_card>(?<![\d])(?:(?:62|60|3[47])\d{11,17}|[45]\d{12,18})(?!\d))",
    r"|(?P<ipv4>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d]))",
    r"|(?P<ipv6>(?<![0-9A-Za-z:.])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*)(?![0-9A-Za-z:.])",
    r"|(?P<api_key>(?<![0-9A-Za-z-])(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|gh[pous]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})(?![0-9A-Za-z-]))",
);

pub(crate) fn combined_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| fancy_regex::Regex::new(COMBINED_PATTERN).expect("内置联合正则恒合法"))
}

pub(crate) fn pii_token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("PII token 正则恒合法"))
}

/// 宽松形态（fuzzy 还原用）：对标 Python `IGNORECASE` 语义，大小写变体均可回查；
/// 序号回查另作独立开关（`restore_with_fuzzy(fuzzy)` 参数），两者正交。
pub(crate) fn pii_loose_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)__PII_\d+_[^_\s]{1,16}__").expect("PII 宽松正则恒合法")
    })
}

/// 凭据完整形态（PII 值注册拒绝用，避免双 token 串扰）。
pub(crate) fn cred_token_shape_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__VG_CRED_\d{4,}__").expect("凭据形态正则恒合法"))
}

/// base64 data URL 排除（命中区间不做 PII 检测）。
pub(crate) fn data_url_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"data:image/[^;]+;base64,[A-Za-z0-9+/=\s]+")
            .expect("data URL 正则恒合法")
    })
}

/// URL 查询参数数值上下文（银行卡防误报：`?id=622588...` 订单号不判卡）。
pub(crate) fn url_query_param_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)[?&](?:id|order|sn|amount|uid|tid|no|num|count|page|limit|offset|ts|time|date|price|total|code2?)\s*=\s*\d{10,}",
        )
        .expect("URL 参数正则恒合法")
    })
}

pub(crate) fn protected_token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"__VG_CRED_\d{4,}__|__PII_\d+_[0-9a-fA-F]{8}__")
            .expect("占位符保护正则恒合法")
    })
}

/// Luhn 校验（银行卡）。
pub fn luhn_ok(digits: &str) -> bool {
    let mut total: u32 = 0;
    for (i, ch) in digits.chars().rev().enumerate() {
        let Some(mut d) = ch.to_digit(10) else {
            return false;
        };
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        total += d;
    }
    !digits.is_empty() && total.is_multiple_of(10)
}

const ID_WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const ID_CHECKS: &[u8; 11] = b"10X98765432";

/// 大陆身份证 GB 11643 校验位验证。
pub fn id_card_ok(value: &str) -> bool {
    if value.len() != 18 || !value[..17].chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let total: u32 = value[..17]
        .chars()
        .zip(ID_WEIGHTS)
        .map(|(c, w)| (c as u32 - 48) * w)
        .sum();
    value[17..]
        .chars()
        .next()
        .is_some_and(|c| c.to_ascii_uppercase() == ID_CHECKS[(total % 11) as usize] as char)
}

/// 归一化 IPv4 前导零（`192.168.001.001` → `192.168.1.1`），仅用于判定。
pub fn normalize_ipv4_leading_zeros(value: &str) -> String {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return value.to_string();
    }
    parts
        .iter()
        .map(|p| p.trim_start_matches('0'))
        .map(|p| if p.is_empty() { "0" } else { p })
        .collect::<Vec<_>>()
        .join(".")
}

/// 正则粗筛后的精确校验：仅合法 IPv4 视为命中（0-255 逐段）。
pub fn is_valid_ipv4(value: &str) -> bool {
    normalize_ipv4_leading_zeros(value)
        .parse::<std::net::Ipv4Addr>()
        .is_ok()
}

/// 正则粗筛后的精确校验：仅合法 IPv6 视为命中。
pub fn is_valid_ipv6(value: &str) -> bool { value.parse::<std::net::Ipv6Addr>().is_ok() }

/// 按 kind 六分支掩码（对标原仓 `mask_pii_value`；超长统一截断 64）。
/// phone/email/bank_card/ipv4/ipv6+api_key/other 六分支定制，空值返回 `***`。
pub fn mask_pii_value(kind: &str, value: &str) -> String {
    if value.is_empty() {
        return "***".to_string();
    }
    let short = |v: &str| -> String {
        let chars: Vec<char> = v.chars().collect();
        if chars.len() < 2 {
            "***".to_string()
        } else if chars.len() < 6 {
            format!("{}****{}", chars[0], chars[chars.len() - 1])
        } else {
            format!(
                "{}****{}",
                chars[..3].iter().collect::<String>(),
                chars[chars.len() - 3..].iter().collect::<String>()
            )
        }
    };
    let masked = match kind.to_lowercase().as_str() {
        "phone" => {
            let chars: Vec<char> = value.chars().collect();
            if chars.len() >= 7 {
                format!(
                    "{}****{}",
                    chars[..3].iter().collect::<String>(),
                    chars[chars.len() - 4..].iter().collect::<String>()
                )
            } else {
                short(value)
            }
        }
        "email" => match value.split_once('@') {
            Some((_, domain)) if domain.contains('.') => {
                let suffix = domain.rsplit('.').next().unwrap_or("");
                if suffix.is_empty() {
                    "***@***".to_string()
                } else {
                    format!("***@***.{suffix}")
                }
            }
            _ => short(value),
        },
        "bank_card" | "bankcard" | "id_card" => {
            let chars: Vec<char> = value.chars().collect();
            if chars.len() >= 4 {
                format!(
                    "**** **** **** {}",
                    chars[chars.len() - 4..].iter().collect::<String>()
                )
            } else {
                short(value)
            }
        }
        "ipv4" => {
            let parts: Vec<&str> = value.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.**.**", parts[0], parts[1])
            } else {
                short(value)
            }
        }
        "ipv6" | "api_key" | "apikey" => {
            let chars: Vec<char> = value.chars().collect();
            if chars.len() >= 8 {
                format!(
                    "{}****{}",
                    chars[..4].iter().collect::<String>(),
                    chars[chars.len() - 4..].iter().collect::<String>()
                )
            } else {
                short(value)
            }
        }
        _ => short(value),
    };
    if masked.chars().count() > 64 {
        masked.chars().take(64).collect()
    } else {
        masked
    }
}

pub(crate) fn strip_ip_trailing(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';', ')', ']', '}'])
}

/// 保留豁免判定：私有/保留/回环/链路本地/组播/CGNAT/文档/未指定均豁免，
/// 仅公网全局可路由地址视为 PII。含尾点/冒号精确前缀处理：
/// 判定前统一剥句末标点、IPv6 转小写；`fc`/`fd` 仅冒号形态豁免，
/// 裸 `10`/`fcfake` 等子串不豁免（标准库解析天然保证精确性）。
pub fn is_reserved_ip(value: &str, kind: &str) -> bool {
    // 保留前缀兜底先行：标准库漏判的 IANA 特殊段按前缀豁免。
    if is_keep_prefix_ip(value, kind) {
        return true;
    }
    if kind == "ipv4" {
        let v = normalize_ipv4_leading_zeros(strip_ip_trailing(value));
        let Ok(ip) = v.parse::<std::net::Ipv4Addr>() else {
            return false;
        };
        if ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_documentation()
            || ip.octets()[0] >= 240
        {
            return true;
        }
        // CGNAT 100.64.0.0/10（标准库未单列，显式覆盖）。
        let o = ip.octets();
        if o[0] == 100 && o[1] & 0xC0 == 0x40 {
            return true;
        }
        // IPv4 映射/兼容段兜底：0/8、240/4 已被 is_unspecified/is_reserved 覆盖。
        return false;
    }
    if kind == "ipv6" {
        let v = strip_ip_trailing(value).to_ascii_lowercase();
        if v.is_empty() {
            return false;
        }
        let Ok(ip) = v.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_unique_local()
            || ip.is_unicast_link_local()
        {
            return true;
        }
        // 文档前缀 2001:db8::/32。
        if ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8 {
            return true;
        }
        return false;
    }
    false
}

/// 保留前缀兜底（`ip_network` 对等）：标准库未单列的 IANA 特殊段显式覆盖。
/// 仅合法解析形态才做前缀豁免（非法串不豁免，仅豁免方向）。
pub fn is_keep_prefix_ip(value: &str, kind: &str) -> bool {
    if kind == "ipv4" {
        let v = normalize_ipv4_leading_zeros(strip_ip_trailing(value)).to_lowercase();
        // 仅合法 IPv4 形态才做前缀豁免（`999.1.1.1`/`fcfake` 类不豁免）。
        if v.parse::<std::net::Ipv4Addr>().is_err() {
            return false;
        }
        const KEEP: &[&str] = &[
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.2",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
            "169.254.",
            "100.64.",
            "100.65.",
            "192.0.0.",
            "192.0.2.",
            "198.51.100.",
            "203.0.113.",
            "198.18.",
            "198.19.",
            "224.",
            "225.",
            "226.",
            "227.",
            "228.",
            "229.",
            "230.",
            "231.",
            "232.",
            "233.",
            "234.",
            "235.",
            "236.",
            "237.",
            "238.",
            "239.",
            "240.",
            "0.",
        ];
        if v.starts_with("172.2") {
            // 172.16/12 精确：172.16–172.31。
            if let Some(second) = v.split('.').nth(1).and_then(|s| s.parse::<u8>().ok())
                && (16..=31).contains(&second)
            {
                return true;
            }
            return false;
        }
        return KEEP.iter().any(|p| v.starts_with(p));
    }
    if kind == "ipv6" {
        let v = strip_ip_trailing(value).to_ascii_lowercase();
        // 仅合法 IPv6 形态才做前缀豁免（裸 `fcfake` 类子串不豁免）。
        if v.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        const KEEP6: &[&str] = &[
            "::1",
            "::",
            "fe80:",
            "fe9",
            "fea",
            "feb",
            "fc",
            "fd",
            "ff02",
            "2001:db8:",
            "64:ff9b:",
        ];
        return KEEP6.iter().any(|p| v.starts_with(p));
    }
    false
}
/// 全局校验结论 LRU：`moka 0.12` 显式 LRU 策略 `future::Cache`，
/// 仅用于 PII 确定性校验（不存明文↔token 映射）。
#[derive(Debug, Clone)]
struct ValidationCache {
    cache: moka::future::Cache<String, bool>,
}

impl ValidationCache {
    fn global() -> &'static Self {
        static CACHE: OnceLock<ValidationCache> = OnceLock::new();
        CACHE.get_or_init(|| ValidationCache {
            cache: moka::future::Cache::builder()
                .max_capacity(VALIDATION_CACHE_CAP)
                .eviction_policy(moka::policy::EvictionPolicy::lru())
                .time_to_live(Duration::from_secs(600))
                .build(),
        })
    }

    async fn check(&self, key: &str, compute: impl FnOnce() -> bool) -> bool {
        if let Some(v) = self.cache.get(key).await {
            return v;
        }
        let v = compute();
        self.cache.insert(key.to_string(), v).await;
        v
    }
}

pub(crate) async fn cached_luhn(digits: &str) -> bool {
    let key = format!("luhn:{digits}");
    ValidationCache::global()
        .check(&key, || luhn_ok(digits))
        .await
}

pub(crate) async fn cached_id_ok(value: &str) -> bool {
    let key = format!("id:{value}");
    ValidationCache::global()
        .check(&key, || id_card_ok(value))
        .await
}

pub(crate) async fn cached_reserved(value: &str, kind: &str) -> bool {
    let key = format!("rsv:{kind}:{value}");
    ValidationCache::global()
        .check(&key, || is_reserved_ip(value, kind))
        .await
}

/// PII 检测器：内置联合正则 + 自定义正则 + 字典 recognizer。
/// 扫描可并发调用；自定义正则走 `spawn_blocking` 独立执行 + 100ms 超时守卫。
#[derive(Debug, Default)]
pub struct PiiDetector {
    pub(crate) custom: RwLock<Vec<(String, fancy_regex::Regex, String)>>,
    pub(crate) custom_names: RwLock<HashSet<String>>,
    pub(crate) strikes: Mutex<HashMap<String, u32>>,
    pub(crate) disabled: Mutex<HashSet<String>>,
    pub(crate) dict: RwLock<Vec<(String, String)>>,
    pub(crate) dict_re: RwLock<Option<regex::Regex>>,
    pub(crate) hardening: AtomicBool,
}

/// 强化复核（`PII_DETECTION_HARDENING`）：数字类命中两侧紧贴 ASCII 字母数字
/// 一律丢弃（防粘连误报），IPv4 另拒前导零段（八进制歧义）；邮箱/IPv6 保持原口径。
fn hardened_keep(kind: &str, text: &str, s: usize, e: usize) -> bool {
    match kind {
        "phone" | "id_card" | "bank_card" | "api_key" => {
            let ascii_alnum = |c: char| c.is_ascii_alphanumeric();
            if text[..s].chars().next_back().is_some_and(ascii_alnum) {
                return false;
            }
            if text[e..].chars().next().is_some_and(ascii_alnum) {
                return false;
            }
            true
        }
        "ipv4" => {
            let ascii_alnum = |c: char| c.is_ascii_alphanumeric();
            if text[..s].chars().next_back().is_some_and(ascii_alnum) {
                return false;
            }
            if text[e..].chars().next().is_some_and(ascii_alnum) {
                return false;
            }
            text[s..e]
                .split('.')
                .all(|part| part.len() <= 1 || !part.as_bytes().starts_with(b"0"))
        }
        _ => true,
    }
}

impl PiiDetector {
    /// 新建空检测器（自定义规则与字典经 load_* 注入）。
    pub fn new() -> Self { Self::default() }

    /// 检测强化开关（`PII_DETECTION_HARDENING`）：开启后内置命中做严格边界复核。
    pub fn set_hardening(&self, on: bool) { self.hardening.store(on, Ordering::Relaxed); }

    /// 是否处于强化模式。
    pub fn hardening(&self) -> bool { self.hardening.load(Ordering::Relaxed) }

    /// 全量扫描（异步）：内置联合一次扫描 + 自定义 ReDoS 守卫 + 字典独立扫描。
    pub async fn scan_spans(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let mut hits = super::chunk::scan_builtin(text, credential_p2t).await;
        hits.extend(self.scan_custom(text, credential_p2t).await);
        hits.extend(self.scan_dict_sync(text, credential_p2t));
        if self.hardening() {
            hits.retain(|(kind, _, s, e)| hardened_keep(kind, text, *s, *e));
        }
        hits
    }

    /// 全量扫描（同步叶回调版）：内置 + 字典；自定义经预扫快照在叶外处理。
    pub fn scan_spans_sync(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let mut hits = super::chunk::scan_builtin_sync(text, credential_p2t);
        hits.extend(self.scan_dict_sync(text, credential_p2t));
        if self.hardening() {
            hits.retain(|(kind, _, s, e)| hardened_keep(kind, text, *s, *e));
        }
        hits
    }
}

/// 跨子模块测试共享（其它子模块测试经
/// `crate::service::pii::detector::test_support` 复用）。
#[cfg(test)]
pub(crate) mod test_support {
    use {
        super::{PiiDetector, PiiHit},
        std::collections::HashMap,
    };

    pub(crate) fn detector() -> PiiDetector { PiiDetector::new() }

    pub(crate) fn empty_cred() -> HashMap<String, String> { HashMap::new() }

    pub(crate) fn kinds(hits: &[PiiHit]) -> Vec<&str> {
        hits.iter().map(|h| h.0.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        test_support::{detector, empty_cred, kinds},
    };

    #[test]
    fn builtin_names_len_locked() {
        assert_eq!(
            BUILTIN_NAMES.len(),
            7,
            "D8 互锁：内置 recognizer 名恒为 7（email/phone/id_card/bank_card/ipv4/ipv6/api_key）"
        );
        for name in [
            "email",
            "phone",
            "id_card",
            "bank_card",
            "ipv4",
            "ipv6",
            "api_key",
        ] {
            assert!(BUILTIN_NAMES.contains(&name), "缺失内置名: {name}");
        }
    }

    #[tokio::test]
    async fn six_recognizer_kinds_match() {
        let d = detector();
        // 手机号（含 +86 冠码与中文紧贴）。
        let hits = d.scan_spans("联系13812345678处理", &empty_cred()).await;
        assert!(
            kinds(&hits).contains(&"phone"),
            "手机号紧贴中文应命中: {hits:?}"
        );
        // 邮箱。
        let hits = d
            .scan_spans("邮箱 test.user@example.com 结束", &empty_cred())
            .await;
        assert!(kinds(&hits).contains(&"email"));
        // 身份证（GB 校验位合法：11010519491231002X 为经典合法号）。
        let hits = d
            .scan_spans("身份证11010519491231002X", &empty_cred())
            .await;
        assert!(
            kinds(&hits).contains(&"id_card"),
            "合法身份证应命中: {hits:?}"
        );
        // 身份证（校验位非法不替换）。
        let hits = d
            .scan_spans("身份证110105194912310021", &empty_cred())
            .await;
        assert!(
            !kinds(&hits).contains(&"id_card"),
            "非法身份证不得命中: {hits:?}"
        );
        // 银行卡（Luhn 合法：6225880123456789 需校验，改用经典测试号 4532015112830366）。
        let hits = d.scan_spans("卡号4532015112830366", &empty_cred()).await;
        assert!(
            kinds(&hits).contains(&"bank_card"),
            "合法卡号应命中: {hits:?}"
        );
        // 银行卡（Luhn 非法不替换）。
        let hits = d.scan_spans("卡号4532015112830367", &empty_cred()).await;
        assert!(!kinds(&hits).contains(&"bank_card"));
        // 公网 IPv4。
        let hits = d.scan_spans("访问 8.8.8.8 获取", &empty_cred()).await;
        assert!(kinds(&hits).contains(&"ipv4"));
        // 公网 IPv6。
        let hits = d
            .scan_spans("地址 2001:4860:4860::8888 可达", &empty_cred())
            .await;
        assert!(kinds(&hits).contains(&"ipv6"), "公网 IPv6 应命中: {hits:?}");
        // API key（sk- 前缀 + 最小 16 字符）。
        let hits = d
            .scan_spans("密钥 sk-abcdefgh12345678 结束", &empty_cred())
            .await;
        assert!(kinds(&hits).contains(&"api_key"));
        // API key 过短不命中。
        let hits = d.scan_spans("密钥 sk-abc 结束", &empty_cred()).await;
        assert!(!kinds(&hits).contains(&"api_key"));
    }

    #[tokio::test]
    async fn reserved_allowlist_exempted() {
        let d = detector();
        for ip in [
            "10.0.0.1",
            "192.168.1.100",
            "172.16.5.4",
            "127.0.0.1",
            "169.254.10.20",
            "224.0.0.1",
            "192.0.2.1",
            "100.64.0.1",
        ] {
            let hits = d
                .scan_spans(&format!("地址 {ip} 结束"), &empty_cred())
                .await;
            assert!(
                !kinds(&hits).contains(&"ipv4"),
                "保留 {ip} 应豁免: {hits:?}"
            );
        }
        for ip in ["::1", "fe80::1", "2001:db8::1", "ff02::1"] {
            let hits = d
                .scan_spans(&format!("地址 {ip} 结束"), &empty_cred())
                .await;
            assert!(
                !kinds(&hits).contains(&"ipv6"),
                "保留 {ip} 应豁免: {hits:?}"
            );
        }
        // 句末英文句号不吞没公网判定（core 剥离后仍命中，句号保留在原文）。
        let hits = d.scan_spans("Visit 8.8.8.8.", &empty_cred()).await;
        assert!(
            kinds(&hits).contains(&"ipv4"),
            "句末公网 IPv4 应命中: {hits:?}"
        );
        // 裸前缀子串不豁免：`fcfake` 不是保留地址。
        assert!(!is_reserved_ip("fcfake", "ipv6"));
    }

    #[test]
    fn hardening_drops_attached_and_leading_zero_ipv4() {
        // 默认关闭：粘连手机号仍命中（历史口径不变）。
        let plain = detector();
        assert!(!plain.hardening());
        let hits = plain.scan_spans_sync("x13812345678y", &empty_cred());
        assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
        // 开启后：两侧 ASCII 粘连丢弃，独立出现仍命中。
        let hard = detector();
        hard.set_hardening(true);
        assert!(hard.hardening());
        let hits = hard.scan_spans_sync("x13812345678y", &empty_cred());
        assert!(!kinds(&hits).contains(&"phone"), "{hits:?}");
        let hits = hard.scan_spans_sync("联系 13812345678 处理", &empty_cred());
        assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
        // 前导零 IPv4：关闭命中，开启丢弃；正常公网 IP 两侧一致命中。
        assert!(
            kinds(&plain.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred()))
                .contains(&"ipv4")
        );
        let hits = hard.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred());
        assert!(!kinds(&hits).contains(&"ipv4"), "{hits:?}");
        let hits = hard.scan_spans_sync("访问 8.8.8.8 获取", &empty_cred());
        assert!(kinds(&hits).contains(&"ipv4"), "{hits:?}");
    }

    #[test]
    fn mask_six_branch_shapes_correct() {
        assert_eq!(mask_pii_value("phone", "13812345678"), "138****5678");
        assert_eq!(mask_pii_value("email", "a@b.com"), "***@***.com");
        assert_eq!(
            mask_pii_value("bank_card", "4532015112830366"),
            "**** **** **** 0366"
        );
        assert_eq!(mask_pii_value("ipv4", "8.8.8.8"), "8.8.**.**");
        assert_eq!(
            mask_pii_value("ipv6", "2001:4860:4860::8888"),
            "2001****8888"
        );
        assert_eq!(
            mask_pii_value("api_key", "sk-abcdefgh12345678"),
            "sk-a****5678"
        );
        assert_eq!(mask_pii_value("other", "abcdef"), "abc****def");
        assert_eq!(mask_pii_value("phone", ""), "***");
    }

    #[test]
    fn keep_prefix_covers_special_ranges() {
        assert!(is_keep_prefix_ip("10.1.2.3", "ipv4"));
        assert!(is_keep_prefix_ip("100.64.0.1", "ipv4"));
        assert!(is_keep_prefix_ip("192.0.2.1", "ipv4"));
        assert!(is_keep_prefix_ip("fc00::1", "ipv6"));
        assert!(!is_keep_prefix_ip("8.8.8.8", "ipv4"));
        assert!(!is_keep_prefix_ip("2001:4860:4860::8888", "ipv6"));
        assert!(is_reserved_ip("100.64.0.1", "ipv4"));
    }

    #[test]
    fn b4_mixed_forms_regression() {
        // B4.1/B4.2 回归：时间戳混合、前导零归一、订单号规则、CJK/URL编码边缘。
        assert_eq!(normalize_ipv4_leading_zeros("010.000.000.001"), "10.0.0.1");
        assert_eq!(
            normalize_ipv4_leading_zeros("192.168.001.001"),
            "192.168.1.1"
        );
        let d = detector();
        // 时间戳与公网 IPv6 混合：时间戳不误杀，公网 IPv6 仍命中。
        let hits = d.scan_spans_sync("会议12:34:56，网关2001:4860:4860::8888在线", &empty_cred());
        assert!(kinds(&hits).contains(&"ipv6"), "{hits:?}");
        assert!(hits.iter().all(|h| h.1 != "12:34:56"), "{hits:?}");
        // 前导零公网 IPv4 按归一口径命中（默认非硬化；010 打头归一后落 10/8 保留段故用 8 打头）。
        let hits = d.scan_spans_sync("访问 8.008.008.008 获取", &empty_cred());
        assert!(kinds(&hits).contains(&"ipv4"), "{hits:?}");
        // URL 订单号按豁免规则处理（不判卡），裸卡号仍命中。
        let hits = d.scan_spans_sync(
            "https://pay.example.com/order?id=4532015112830366 支付",
            &empty_cred(),
        );
        assert!(hits.iter().all(|h| h.0 != "bank_card"), "{hits:?}");
        let hits = d.scan_spans_sync("卡号 4532015112830366 扣款", &empty_cred());
        assert!(hits.iter().any(|h| h.0 == "bank_card"), "{hits:?}");
        // URL 编码形态不误判、不崩溃。
        let hits = d.scan_spans_sync("https://x.example.com/?id=%34%35%33%32 支付", &empty_cred());
        assert!(hits.iter().all(|h| h.0 != "bank_card"), "{hits:?}");
        // 中英混排不断字误杀。
        let hits = d.scan_spans_sync("Contact联系13812345678Done处理", &empty_cred());
        assert!(kinds(&hits).contains(&"phone"), "{hits:?}");
        // 纯 CJK 无敏感零命中。
        let hits = d.scan_spans_sync("中文测试文本不含敏感信息", &empty_cred());
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn ipv6_timestamp_not_ipv6_and_uncompressed_requires_8_groups() {
        // 01-03: 典型 HH:MM:SS 时间戳恒非法（RFC4291 无 `::` 须 8 组）。
        assert!(!is_valid_ipv6("12:34:56"), "时分秒不得判 IPv6");
        assert!(!is_valid_ipv6("23:59:59"), "时分秒不得判 IPv6");
        assert!(!is_valid_ipv6("00:00:00"), "全零时间戳不得判 IPv6");
        // 04: 7 组无缩写非法。
        assert!(!is_valid_ipv6("1:2:3:4:5:6:7"), "无::须足 8 组");
        // 05: 9 组非法。
        assert!(!is_valid_ipv6("1:2:3:4:5:6:7:8:9"), "超 8 组非法");
        // 06: 8 组无缩写合法（公网可路由，后续扫描应命中）。
        assert!(is_valid_ipv6("1:2:3:4:5:6:7:8"));
        assert!(!is_reserved_ip("1:2:3:4:5:6:7:8", "ipv6"));
        // 07: 全写公网合法。
        assert!(is_valid_ipv6("2001:4860:4860:0:0:0:0:8888"));
        // 08: 压缩形态合法。
        assert!(is_valid_ipv6("2001:4860:4860::8888"));
        // 09-11: 回环/链路本地/文档合法但保留豁免。
        assert!(is_valid_ipv6("::1"));
        assert!(is_reserved_ip("::1", "ipv6"));
        assert!(is_valid_ipv6("fe80::1"));
        assert!(is_reserved_ip("fe80::1", "ipv6"));
        assert!(is_valid_ipv6("2001:db8::1"));
        assert!(is_reserved_ip("2001:db8::1", "ipv6"));
        // 12: 非十六进制非法。
        assert!(!is_valid_ipv6("gggg::1"), "非法十六进制不得判 IPv6");
        // 13: 带毫秒时间戳非法。
        assert!(!is_valid_ipv6("12:34:56.789"), "毫秒时间戳不得判 IPv6");
        // 14: ISO 日期时间中的时间段扫描不得出 ipv6。
        let hits =
            super::super::chunk::scan_builtin_sync("2024-01-01T12:34:56 上线", &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "ipv6"),
            "日期时间不得检出 ipv6: {hits:?}"
        );
        // 15: 纯时间句子扫描不得出 ipv6。
        let hits = super::super::chunk::scan_builtin_sync("会议 12:34:56 开始", &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "ipv6"),
            "时间戳不得检出 ipv6: {hits:?}"
        );
        // 16: 全写公网扫描命中且值完整（大小写均可）。
        let hits =
            super::super::chunk::scan_builtin_sync("地址 1:2:3:4:5:6:7:8 结束", &empty_cred());
        assert!(
            hits.iter()
                .any(|h| h.0 == "ipv6" && h.1 == "1:2:3:4:5:6:7:8"),
            "全写公网须命中: {hits:?}"
        );
        let hits = super::super::chunk::scan_builtin_sync(
            "地址 ABCD:EF01:2345:6789:ABCD:EF01:2345:6789 结束",
            &empty_cred(),
        );
        assert!(
            hits.iter().any(|h| h.0 == "ipv6"),
            "大写全写须命中: {hits:?}"
        );
        // 17: 尾部双冒号（`2001:db8::`）合法但文档段保留豁免，与 `2001:db8::1` 同口径。
        assert!(is_valid_ipv6("2001:db8::"));
        assert!(is_reserved_ip("2001:db8::", "ipv6"));
        let hits = super::super::chunk::scan_builtin_sync("地址 2001:db8:: 结束", &empty_cred());
        assert!(
            hits.iter().all(|h| h.0 != "ipv6"),
            "文档段豁免：尾部双冒号文档地址不得检出: {hits:?}"
        );
    }
}
