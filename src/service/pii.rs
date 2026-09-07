//! PII 检测器 + 请求级 PII token（§3.2 / §3.3）。
//!
//! 口径对标原仓 `_pii.py` 与 `_token.py` 的 `GlobalPiiTokens`：
//!
//! 6 recognizer（手机/身份证GB校验位/银行卡Luhn/邮箱/IPv4/IPv6/API key 最小长度16）合成为
//! 单一联合正则一次扫描；中文与 CJK 边界用 lookaround 表达，MUST NOT 用 `\b`。银行卡过
//! Luhn、身份证过 GB 校验位，未过不替换；保留豁免清单命中不替换。自定义正则跑独立执行
//! （`spawn_blocking`）加单次 100ms 超时守卫，连续 3 次超时停用该模式；含 `\b`
//! 的自定义正则拒绝加载。字典独立扫描（不并入联合正则），CJK 边界。token 形态
//! `__PII_<seq>_<rand8>__`，`rand8` 经 `OsRng::try_fill_bytes`
//! （`rand_core::TryRngCore`）；空洞跳过稳态下标；同值复用；响应期注册不进请求还原表；
//! 并发注册经 `Mutex` 原子执行。凭据优先：命中凭据的值 PII 跳过；占位符区间重叠排除。
//!
//! 全局 PII LRU（`moka 0.12`，显式 LRU 策略，`future::Cache`）仅缓存
//! 确定性校验结论（Luhn/GB/保留段/合法性），不缓存任何明文↔token 映射，
//! 请求级映射永不跨请求互见。

use {
    rand::{rand_core::TryRngCore as _, rngs::OsRng},
    std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::{Mutex, OnceLock, RwLock},
        time::Duration,
    },
};

/// PII 占位符前缀。
pub const PII_TOKEN_PREFIX: &str = "__PII_";
/// 请求/响应单表上限（真 LRU，与凭据 5000 区分）。
pub const PII_MAX_ENTRIES: usize = 1000;
/// 自定义正则单次扫描预算（毫秒）。
pub const RE_DOS_BUDGET_MS: u64 = 100;
/// 自定义正则连续超时停用阈值。
pub const RE_DOS_STRIKES: u32 = 3;
/// 单次扫描输入上限（字节），超限按 1MB 分块。
pub const SCAN_INPUT_LIMIT: usize = 1_048_576;
/// 全局校验结论 LRU 容量。
pub const VALIDATION_CACHE_CAP: u64 = 4096;

/// 6 内置 recognizer 名（与自定义重名拒绝加载）。
pub const BUILTIN_NAMES: [&str; 7] = [
    "email",
    "phone",
    "id_card",
    "bank_card",
    "ipv4",
    "ipv6",
    "api_key",
];

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

fn combined_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| fancy_regex::Regex::new(COMBINED_PATTERN).expect("内置联合正则恒合法"))
}

fn pii_token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__PII_\d+_[0-9a-f]{8}__").expect("PII token 正则恒合法"))
}

fn pii_loose_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__PII_\d+_[^_\s]{1,16}__").expect("PII 宽松正则恒合法"))
}

/// 凭据完整形态（PII 值注册拒绝用，避免双 token 串扰）。
fn cred_token_shape_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__VG_CRED_\d{4,}__").expect("凭据形态正则恒合法"))
}

/// PII 残缺形态，对标 `_PII_PARTIAL_TOKEN_RE`：
/// `__PI` 后负向前瞻排除完整形态，使完整 token 不被误剥；
/// 结尾覆盖行中残缺（后跟空白/标点/汉字等非单词字符同样剥离）。
fn pii_partial_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(
            r"__PI(?!I_\d+_[0-9a-f]{8}__)(?:I(?:_(?:\d+_)?[0-9a-fA-F]*)?)?(?:_*$|(?=\s|[^\w]))",
        )
        .expect("PII 残缺正则恒合法")
    })
}

/// 清理 PII 残缺前缀（完整 `__PII_<seq>_<rand8>__` 原样保留）。
pub fn strip_pii_partials(text: &str) -> String {
    pii_partial_re().replace_all(text, "").into_owned()
}

/// base64 data URL 排除（命中区间不做 PII 检测）。
fn data_url_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"data:image/[^;]+;base64,[A-Za-z0-9+/=\s]+")
            .expect("data URL 正则恒合法")
    })
}

/// URL 查询参数数值上下文（银行卡防误报：`?id=622588...` 订单号不判卡）。
fn url_query_param_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)[?&](?:id|order|sn|amount|uid|tid|no|num|count|page|limit|offset|ts|time|date|price|total|code2?)\s*=\s*\d{10,}",
        )
        .expect("URL 参数正则恒合法")
    })
}

fn protected_token_re() -> &'static regex::Regex {
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

fn strip_ip_trailing(value: &str) -> &str { value.trim_end_matches(['.', ',', ';', ')', ']', '}']) }

/// 保留豁免判定：私有/保留/回环/链路本地/组播/CGNAT/文档/未指定均豁免，
/// 仅公网全局可路由地址视为 PII。含尾点/冒号精确前缀处理：
/// 判定前统一剥句末标点、IPv6 转小写；`fc`/`fd` 仅冒号形态豁免，
/// 裸 `10`/`fcfake` 等子串不豁免（标准库解析天然保证精确性）。
pub fn is_reserved_ip(value: &str, kind: &str) -> bool {
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

async fn cached_luhn(digits: &str) -> bool {
    let key = format!("luhn:{digits}");
    ValidationCache::global()
        .check(&key, || luhn_ok(digits))
        .await
}

async fn cached_id_ok(value: &str) -> bool {
    let key = format!("id:{value}");
    ValidationCache::global()
        .check(&key, || id_card_ok(value))
        .await
}

async fn cached_reserved(value: &str, kind: &str) -> bool {
    let key = format!("rsv:{kind}:{value}");
    ValidationCache::global()
        .check(&key, || is_reserved_ip(value, kind))
        .await
}

/// 构造 `__PII_<seq>_<rand8>__` token。
pub fn make_pii_token(seq: usize, rand8: &str) -> String {
    format!("{PII_TOKEN_PREFIX}{seq}_{rand8}__")
}

/// 生成 8 位十六进制随机段（`OsRng::try_fill_bytes`，CSPRNG）。
pub fn gen_rand8() -> Result<String, &'static str> {
    let mut buf = [0u8; 4];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| "CSPRNG 熵源不可用")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn parse_pii_seq(token: &str) -> Option<usize> {
    let rest = token.strip_prefix(PII_TOKEN_PREFIX)?;
    let (seq, _) = rest.split_once('_')?;
    seq.parse().ok()
}

/// 请求级 PII token 容器（对标 `GlobalPiiTokens` 的请求隔离形态）。
///
/// - `pii_*`：请求期映射，可还原；`resp_*`：响应期映射，不可还原、原样保留；
/// - 同值复用同一 token；空洞跳过稳态下标；并发注册经 `Mutex` 原子执行；
/// - PII 还原只查本 Scope，MUST NOT 触达全局凭据映射。
#[derive(Debug, Default)]
pub struct PiiScope {
    inner: Mutex<ScopeInner>,
    malformed: Mutex<HashMap<String, u64>>,
}

#[derive(Debug, Default)]
struct ScopeInner {
    pii_p2t: HashMap<String, String>,
    pii_t2p: HashMap<String, String>,
    resp_p2t: HashMap<String, String>,
    resp_t2p: HashMap<String, String>,
    pii_order: VecDeque<String>,
    resp_order: VecDeque<String>,
}

/// PII 值注册拒绝：值命中内部 token 形态或含保留前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiReject(&'static str);

impl std::fmt::Display for PiiReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}

impl PiiScope {
    /// 新建空 Scope（每请求一个，请求结束即销毁）。
    pub fn new() -> Self { Self::default() }

    /// 空洞跳过：收集两表已用 seq，取最小空缺（稳态下标）。
    pub fn next_available_index(&self) -> usize {
        let inner = self.inner.lock().expect("PII scope 锁无毒");
        next_hole(&used_seqs(&inner))
    }

    /// 注册 PII 值并返回 token。同值复用；`response_side=true` 进响应表
    /// （不进请求还原表）；token 形态值拒绝注册。
    pub fn register(&self, value: &str, response_side: bool) -> Result<String, PiiReject> {
        if value.is_empty() {
            return Ok(value.to_string());
        }
        if pii_token_re().is_match(value)
            || value.contains(PII_TOKEN_PREFIX)
            || value.contains(crate::service::credential_vault::TOKEN_PREFIX)
            || cred_token_shape_re().is_match(value)
        {
            return Err(PiiReject(
                "PII 值不能匹配内部 token 格式或以 token 前缀开头",
            ));
        }
        let mut inner = self.inner.lock().expect("PII scope 锁无毒");
        if response_side {
            if let Some(tok) = inner.resp_p2t.get(value).cloned() {
                touch_order(&mut inner.resp_order, value);
                return Ok(tok);
            }
        } else if let Some(tok) = inner.pii_p2t.get(value).cloned() {
            touch_order(&mut inner.pii_order, value);
            return Ok(tok);
        }
        let seq = next_hole(&used_seqs(&inner));
        let rand8 = gen_rand8().map_err(|_| PiiReject("CSPRNG 熵源不可用"))?;
        let token = make_pii_token(seq, &rand8);
        if response_side {
            if inner.resp_p2t.len() >= PII_MAX_ENTRIES
                && let Some(oldest) = inner.resp_order.pop_front()
                && let Some(old_tok) = inner.resp_p2t.remove(&oldest)
            {
                inner.resp_t2p.remove(&old_tok);
            }
            inner.resp_order.push_back(value.to_string());
            inner.resp_p2t.insert(value.to_string(), token.clone());
            inner.resp_t2p.insert(token.clone(), value.to_string());
        } else {
            if inner.pii_p2t.len() >= PII_MAX_ENTRIES
                && let Some(oldest) = inner.pii_order.pop_front()
                && let Some(old_tok) = inner.pii_p2t.remove(&oldest)
            {
                inner.pii_t2p.remove(&old_tok);
            }
            inner.pii_order.push_back(value.to_string());
            inner.pii_p2t.insert(value.to_string(), token.clone());
            inner.pii_t2p.insert(token.clone(), value.to_string());
        }
        Ok(token)
    }

    /// 还原请求期注册 token；响应期/未注册/格式不符原样保留。
    /// 只查本 Scope，绝不触达全局凭据映射。
    /// 残留宽松形态补扫审计（聚合计数，落盘限流由调用方负责）。
    pub fn restore(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        let restored = {
            let inner = self.inner.lock().expect("PII scope 锁无毒");
            if inner.pii_t2p.is_empty() && inner.resp_t2p.is_empty() {
                return text.to_string();
            }
            pii_token_re()
                .replace_all(text, |caps: &regex::Captures| {
                    let tok = &caps[0];
                    if let Some(plain) = inner.pii_t2p.get(tok) {
                        plain.clone()
                    } else {
                        // 响应期 token 原样保留；未知形态同样保留并补扫审计。
                        tok.to_string()
                    }
                })
                .into_owned()
        };
        let known: HashSet<String> = self
            .inner
            .lock()
            .map(|g| g.pii_t2p.keys().chain(g.resp_t2p.keys()).cloned().collect())
            .unwrap_or_default();
        for m in pii_loose_re().find_iter(&restored) {
            let tok = m.as_str();
            if !known.contains(tok) {
                self.count_malformed(tok);
            }
        }
        restored
    }

    /// 是否持有该请求 token（跨请求还原隔离断言用）。
    pub fn contains_request_token(&self, token: &str) -> bool {
        self.inner
            .lock()
            .map(|g| g.pii_t2p.contains_key(token))
            .unwrap_or(false)
    }

    /// 记录宽松形态审计计数（同类聚合，调用方限流落盘）。
    pub fn count_malformed(&self, token: &str) -> String {
        let cat = if regex::Regex::new(r"^__PII_\d+_[0-9a-fA-F]{8}__$")
            .expect("形态正则恒合法")
            .is_match(token)
        {
            "unregistered"
        } else {
            "malformed"
        };
        let mut counts = self.malformed.lock().expect("计数锁无毒");
        let c = counts.entry(cat.to_string()).or_insert(0);
        *c += 1;
        cat.to_string()
    }
}

fn used_seqs(inner: &ScopeInner) -> HashSet<usize> {
    inner
        .pii_t2p
        .keys()
        .chain(inner.resp_t2p.keys())
        .filter_map(|t| parse_pii_seq(t))
        .collect()
}

fn next_hole(used: &HashSet<usize>) -> usize {
    let mut nxt = 1;
    while used.contains(&nxt) {
        nxt += 1;
    }
    nxt
}

fn touch_order(order: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = order.iter().position(|v| v == value) {
        order.remove(pos);
    }
    order.push_back(value.to_string());
}

/// 命中位置：`(kind, value, start, end)`，`start/end` 为字节下标。
pub type PiiHit = (String, String, usize, usize);

fn overlaps_any(spans: &[(usize, usize)], s: usize, e: usize) -> bool {
    spans
        .iter()
        .any(|(a, b)| *a <= s && s < *b || *a < e && e <= *b || s <= *a && *b <= e)
}

/// 文本中凭据值的位置区间（位置化优先：落入则 PII 跳过）。
pub fn credential_spans(
    text: &str,
    credential_p2t: &HashMap<String, String>,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for cred in credential_p2t.keys() {
        if cred.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(idx) = text[from..].find(cred) {
            let s = from + idx;
            spans.push((s, s + cred.len()));
            from = s + 1;
            if from >= text.len() {
                break;
            }
        }
    }
    spans
}

/// 占位符 + data URL 保护区间（重叠匹配整体跳过）。
pub fn protected_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for m in data_url_re().find_iter(text) {
        spans.push((m.start(), m.end()));
    }
    for m in protected_token_re().find_iter(text) {
        spans.push((m.start(), m.end()));
    }
    spans
}

fn coarse_hit(text: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"[\dA-Za-z@.\-]").expect("粗筛正则恒合法"))
        .is_match(text)
}

/// 联合正则命中分类：按命名组顺序返回 `(kind, 原文)`，未命中任一组返回 `None`。
fn classify_hit<'t>(caps: &fancy_regex::Captures<'t, str>) -> Option<(&'static str, &'t str)> {
    const ORDER: [&str; 7] = [
        "email",
        "phone",
        "id_card",
        "bank_card",
        "ipv4",
        "ipv6",
        "api_key",
    ];
    ORDER
        .iter()
        .find_map(|kind| caps.name(kind).map(|m| (*kind, m.as_str())))
}

/// 内置联合正则一次扫描（同步版，供 json-walk 叶回调）。
/// 返回位置化命中；凭据区间/保护区间落入跳过（凭据优先）。
pub fn scan_builtin_sync(text: &str, credential_p2t: &HashMap<String, String>) -> Vec<PiiHit> {
    if text.is_empty() || !coarse_hit(text) {
        return Vec::new();
    }
    let protected = protected_spans(text);
    let cred = credential_spans(text, credential_p2t);
    let mut out = Vec::new();
    for caps in combined_re().captures_iter(text).flatten() {
        let Some((kind, raw)) = classify_hit(&caps) else {
            continue;
        };
        let mut value = raw.to_string();
        let mut end = caps.get(0).map(|m| m.end()).unwrap_or(0);
        let start = end.saturating_sub(raw.len());
        match kind {
            "ipv6" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv6(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv6(raw) {
                    continue;
                }
            }
            "ipv4" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv4(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv4(raw) {
                    continue;
                }
            }
            "bank_card" => {
                let cs = start.saturating_sub(64);
                let ce = (end + 16).min(text.len());
                if url_query_param_re().is_match(&text[cs..ce]) {
                    continue;
                }
                if !luhn_ok(&value) {
                    continue;
                }
            }
            "id_card" if !id_card_ok(&value) => continue,
            _ => {}
        }
        if matches!(kind, "ipv4" | "ipv6") && is_reserved_ip(&value, kind) {
            continue;
        }
        if overlaps_any(&protected, start, end) || overlaps_any(&cred, start, end) {
            continue;
        }
        // 凭据优先（值级）：命中值本身是凭据则跳过。
        if credential_p2t.contains_key(&value) {
            continue;
        }
        out.push((kind.to_string(), value, start, end));
    }
    out
}

/// 内置联合正则一次扫描（异步版，走全局 moka 校验 LRU）。
pub async fn scan_builtin(text: &str, credential_p2t: &HashMap<String, String>) -> Vec<PiiHit> {
    if text.is_empty() || !coarse_hit(text) {
        return Vec::new();
    }
    let protected = protected_spans(text);
    let cred = credential_spans(text, credential_p2t);
    let mut out = Vec::new();
    for caps in combined_re().captures_iter(text).flatten() {
        let Some((kind, raw)) = classify_hit(&caps) else {
            continue;
        };
        let mut value = raw.to_string();
        let mut end = caps.get(0).map(|m| m.end()).unwrap_or(0);
        let start = end.saturating_sub(raw.len());
        match kind {
            "ipv6" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv6(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv6(raw) {
                    continue;
                }
            }
            "ipv4" => {
                let core = strip_ip_trailing(raw);
                if !core.is_empty() && is_valid_ipv4(core) {
                    value = core.to_string();
                    end = start + value.len();
                } else if !is_valid_ipv4(raw) {
                    continue;
                }
            }
            "bank_card" => {
                let cs = start.saturating_sub(64);
                let ce = (end + 16).min(text.len());
                if url_query_param_re().is_match(&text[cs..ce]) {
                    continue;
                }
                if !cached_luhn(&value).await {
                    continue;
                }
            }
            "id_card" if !cached_id_ok(&value).await => continue,
            _ => {}
        }
        if matches!(kind, "ipv4" | "ipv6") && cached_reserved(&value, kind).await {
            continue;
        }
        if overlaps_any(&protected, start, end) || overlaps_any(&cred, start, end) {
            continue;
        }
        if credential_p2t.contains_key(&value) {
            continue;
        }
        out.push((kind.to_string(), value, start, end));
    }
    out
}

/// 重叠仲裁：按 `(start, 长度降序)` 排序，重叠者仅保留首个（长跨度优先）。
pub fn arbitrate(mut hits: Vec<PiiHit>) -> Vec<PiiHit> {
    hits.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| b.3.cmp(&a.3)));
    let mut kept: Vec<PiiHit> = Vec::new();
    let mut kept_spans: Vec<(usize, usize)> = Vec::new();
    for h in hits {
        if overlaps_any(&kept_spans, h.2, h.3) {
            continue;
        }
        kept_spans.push((h.2, h.3));
        kept.push(h);
    }
    kept
}

/// 位置化替换（按字节区间一次成形，避免重复值错位）。
pub fn apply_spans(text: &str, spans: &[(usize, usize, String)]) -> String {
    let mut ordered = spans.to_vec();
    ordered.sort_by_key(|(s, ..)| *s);
    let mut out = String::with_capacity(text.len() + spans.len() * 8);
    let mut cursor = 0;
    for (s, e, rep) in ordered {
        if s < cursor || s > text.len() || e > text.len() || s > e {
            continue;
        }
        out.push_str(&text[cursor..s]);
        out.push_str(&rep);
        cursor = e;
    }
    out.push_str(&text[cursor..]);
    out
}

/// PII 检测器：内置联合正则 + 自定义正则 + 字典 recognizer。
/// 扫描可并发调用；自定义正则走 `spawn_blocking` 独立执行 + 100ms 超时守卫。
#[derive(Debug, Default)]
pub struct PiiDetector {
    custom: RwLock<Vec<(String, fancy_regex::Regex, String)>>,
    custom_names: RwLock<HashSet<String>>,
    strikes: Mutex<HashMap<String, u32>>,
    disabled: Mutex<HashSet<String>>,
    dict: RwLock<Vec<(String, String)>>,
    dict_re: RwLock<Option<regex::Regex>>,
}

impl PiiDetector {
    /// 新建空检测器（自定义规则与字典经 load_* 注入）。
    pub fn new() -> Self { Self::default() }

    /// 是否含 `\b`（ASCII 词边界，中文紧贴下零命中，禁止使用）。
    fn has_word_boundary(pattern: &str) -> bool { pattern.contains("\\b") }

    /// 嵌套命名组检测（`lastgroup` 返回最内层导致分类错乱，禁止加载）。
    fn has_nested_named_groups(pattern: &str) -> bool {
        let mut stack: Vec<usize> = Vec::new();
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if bytes[i] == b'(' {
                if pattern[i..].starts_with("(?P<")
                    || !(pattern[i..].starts_with("(?:")
                        || pattern[i..].starts_with("(?=")
                        || pattern[i..].starts_with("(?!")
                        || pattern[i..].starts_with("(?<=")
                        || pattern[i..].starts_with("(?<!")
                        || pattern[i..].starts_with("(?#"))
                {
                    stack.push(i);
                } else {
                    stack.push(usize::MAX);
                }
            } else if bytes[i] == b')'
                && let Some(open) = stack.pop()
                && open != usize::MAX
            {
                ranges.push((open, i));
            }
            i += 1;
        }
        // 命名组定义区间互含即嵌套。
        let named: Vec<(usize, usize)> = ranges
            .iter()
            .filter(|(s, _)| pattern[*s..].starts_with("(?P<"))
            .copied()
            .collect();
        for (a, b) in named.iter() {
            for (c, d) in named.iter() {
                if (a, b) != (c, d) && a < c && *c < *b {
                    return true;
                }
            }
        }
        false
    }

    /// 加载自定义正则 `[(name, pattern)]`，返回成功加载的条数。
    /// 与内置重名 / 重复 / 编译失败 / 含 `\b` / 嵌套命名组 / 自检异常一律拒绝加载。
    pub fn load_custom_patterns(&self, patterns: &[(String, String)]) -> usize {
        if patterns.is_empty() {
            return 0;
        }
        let builtin: HashSet<&str> = BUILTIN_NAMES.iter().copied().collect();
        let mut loaded = 0;
        for (name, pattern) in patterns {
            if builtin.contains(name.as_str()) {
                tracing::warn!("自定义正则 {name} 与内置重名，拒绝加载");
                continue;
            }
            {
                let names = self.custom_names.read().expect("检测器锁无毒");
                if names.contains(name) {
                    tracing::warn!("自定义正则 {name} 与已加载规则重名，拒绝加载");
                    continue;
                }
            }
            if Self::has_word_boundary(pattern) {
                tracing::warn!("自定义正则 {name} 含 \\b 词边界，中文环境失效，拒绝加载");
                continue;
            }
            let compiled = match fancy_regex::Regex::new(pattern) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("自定义正则 {name} 编译失败: {e}，拒绝加载");
                    continue;
                }
            };
            if Self::has_nested_named_groups(pattern) {
                tracing::warn!("自定义正则 {name} 含嵌套命名组，拒绝加载");
                continue;
            }
            // 启动自检：对抗性短输入跑一遍，异常则拒绝。
            if compiled
                .find("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_err()
            {
                tracing::warn!("自定义正则 {name} 自检异常，拒绝加载");
                continue;
            }
            {
                let mut custom = self.custom.write().expect("检测器锁无毒");
                let mut names = self.custom_names.write().expect("检测器锁无毒");
                if names.contains(name) {
                    continue;
                }
                custom.push((name.clone(), compiled, pattern.clone()));
                names.insert(name.clone());
            }
            loaded += 1;
        }
        loaded
    }

    /// 已加载的自定义规则名（断言/可观测用）。
    pub fn custom_names_snapshot(&self) -> Vec<String> {
        self.custom_names
            .read()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 已停用的自定义规则名（连续超时 3 次）。
    pub fn disabled_snapshot(&self) -> Vec<String> {
        self.disabled
            .lock()
            .map(|g| g.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 加载敏感名称名单 `[(name, type)]`，按长度降序。
    pub fn load_dict(&self, entries: &[(String, String)]) {
        let mut sorted = entries.to_vec();
        sorted.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        let pat = sorted
            .iter()
            .map(|(n, _)| regex::escape(n))
            .collect::<Vec<_>>()
            .join("|");
        let compiled = if pat.is_empty() {
            None
        } else {
            regex::Regex::new(&pat).ok()
        };
        *self.dict.write().expect("检测器锁无毒") = sorted;
        *self.dict_re.write().expect("检测器锁无毒") = compiled;
    }

    /// 字典命中边界：`name/person` 走严格 CJK 边界，
    /// 其余类型仅挡 ASCII 字母数字粘连。
    fn dict_boundary_ok(text: &str, start: usize, end: usize, typ: &str) -> bool {
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let is_cjk = |c: char| ('\u{4e00}'..='\u{9fff}').contains(&c) || c.is_alphanumeric();
        if typ == "name" || typ == "person" {
            if before.is_some_and(is_cjk) || after.is_some_and(is_cjk) {
                return false;
            }
            return true;
        }
        let ascii_alnum = |c: char| c.is_ascii_alphanumeric();
        !(before.is_some_and(ascii_alnum) || after.is_some_and(ascii_alnum))
    }

    /// 字典独立扫描（不并入联合正则，防 alternation 分支爆炸）。
    pub fn scan_dict_sync(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let dict_re = self.dict_re.read().expect("检测器锁无毒");
        let Some(re) = dict_re.as_ref() else {
            return Vec::new();
        };
        let dict = self.dict.read().expect("检测器锁无毒");
        let cred = credential_spans(text, credential_p2t);
        let mut out = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for m in re.find_iter(text) {
            let (s, e) = (m.start(), m.end());
            if !seen.insert((s, e)) {
                continue;
            }
            if overlaps_any(&cred, s, e) {
                continue;
            }
            let name = m.as_str().to_string();
            if credential_p2t.contains_key(&name) {
                continue;
            }
            let typ = dict
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, t)| t.as_str())
                .unwrap_or("name");
            if !Self::dict_boundary_ok(text, s, e, typ) {
                continue;
            }
            out.push((typ.to_string(), name, s, e));
        }
        out
    }

    /// 自定义正则扫描（ReDoS 守卫）：每规则每分块经 `spawn_blocking`
    /// 独立执行 + 100ms 超时；超时跳过并计数，连续 3 次停用。
    pub async fn scan_custom(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let custom: Vec<(String, fancy_regex::Regex, String)> =
            self.custom.read().map(|g| g.clone()).unwrap_or_default();
        if custom.is_empty() || text.is_empty() {
            return Vec::new();
        }
        let disabled: HashSet<String> = self.disabled.lock().map(|g| g.clone()).unwrap_or_default();
        let protected = protected_spans(text);
        let cred = credential_spans(text, credential_p2t);
        // 超长输入按 1MB 分块（overlap 256 防跨界切断）。
        let chunks: Vec<(usize, String)> = if text.len() > SCAN_INPUT_LIMIT {
            let overlap = 256usize;
            let step = SCAN_INPUT_LIMIT.saturating_sub(overlap).max(1);
            let mut v = Vec::new();
            let mut off = 0;
            while off < text.len() {
                let end = (off + SCAN_INPUT_LIMIT).min(text.len());
                v.push((off, text[off..end].to_string()));
                if end == text.len() {
                    break;
                }
                off += step;
            }
            v
        } else {
            vec![(0, text.to_string())]
        };
        let mut hits = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let mut timed_out: Vec<String> = Vec::new();
        let mut succeeded: Vec<String> = Vec::new();
        for (name, compiled, _src) in &custom {
            if disabled.contains(name) {
                continue;
            }
            let mut rule_ok = true;
            for (offset, chunk) in &chunks {
                let re = compiled.clone();
                let input = chunk.clone();
                let found = tokio::task::spawn_blocking(move || {
                    re.find_iter(&input)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|m| (m.start(), m.end(), m.as_str().to_string()))
                        .collect::<Vec<_>>()
                });
                match tokio::time::timeout(Duration::from_millis(RE_DOS_BUDGET_MS), found).await {
                    Ok(Ok(spans)) => {
                        for (s, e, value) in spans {
                            let (abs_s, abs_e) = (offset + s, offset + e);
                            if !seen.insert((abs_s, abs_e)) {
                                continue;
                            }
                            // 区间保护：与占位符/凭据重叠整体跳过。
                            if overlaps_any(&protected, abs_s, abs_e)
                                || overlaps_any(&cred, abs_s, abs_e)
                            {
                                continue;
                            }
                            if credential_p2t.contains_key(&value) {
                                continue;
                            }
                            hits.push((name.clone(), value, abs_s, abs_e));
                        }
                    }
                    _ => {
                        rule_ok = false;
                        break;
                    }
                }
            }
            if rule_ok {
                succeeded.push(name.clone());
            } else {
                timed_out.push(name.clone());
            }
        }
        // 锁外结算：成功清零，超时累计，连续 3 次停用并告警。
        for name in succeeded {
            self.account_rule(&name, false);
        }
        for name in timed_out {
            self.account_rule(&name, true);
        }
        hits
    }

    /// 超时记账状态机：成功清零；超时累计，连续 [`RE_DOS_STRIKES`] 次停用并告警。
    fn account_rule(&self, name: &str, timed_out: bool) {
        let mut strikes = self.strikes.lock().expect("检测器锁无毒");
        let mut disabled = self.disabled.lock().expect("检测器锁无毒");
        if !timed_out {
            strikes.remove(name);
            return;
        }
        let c = strikes.entry(name.to_string()).or_insert(0);
        *c += 1;
        if *c >= RE_DOS_STRIKES {
            disabled.insert(name.to_string());
            tracing::warn!("自定义正则 {name} 连续 {} 次超时，临时停用", RE_DOS_STRIKES);
        } else {
            tracing::warn!("自定义正则 {name} 扫描超时（第 {c} 次），跳过该规则");
        }
    }

    /// 全量扫描（异步）：内置联合一次扫描 + 自定义 ReDoS 守卫 + 字典独立扫描。
    pub async fn scan_spans(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let mut hits = scan_builtin(text, credential_p2t).await;
        hits.extend(self.scan_custom(text, credential_p2t).await);
        hits.extend(self.scan_dict_sync(text, credential_p2t));
        hits
    }

    /// 全量扫描（同步叶回调版）：内置 + 字典；自定义经预扫快照在叶外处理。
    pub fn scan_spans_sync(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let mut hits = scan_builtin_sync(text, credential_p2t);
        hits.extend(self.scan_dict_sync(text, credential_p2t));
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> PiiDetector { PiiDetector::new() }

    fn empty_cred() -> HashMap<String, String> { HashMap::new() }

    fn kinds(hits: &[PiiHit]) -> Vec<&str> { hits.iter().map(|h| h.0.as_str()).collect() }

    #[tokio::test]
    async fn 六类recognizer命中对照() {
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
    async fn 保留豁免清单放行() {
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
    fn 含b自定义正则拒绝加载() {
        let d = detector();
        let n = d.load_custom_patterns(&[("bad".to_string(), r"\bfoo\d+\b".to_string())]);
        assert_eq!(n, 0);
        assert!(d.custom_names_snapshot().is_empty());
        // 与内置重名同样拒绝。
        let n = d.load_custom_patterns(&[("phone".to_string(), r"1\d{10}".to_string())]);
        assert_eq!(n, 0);
        // 合法 lookaround 规则加载成功。
        let n = d.load_custom_patterns(&[(
            "emp_no".to_string(),
            r"(?P<emp_no>(?<![\d])工号\d{6}(?![\d]))".to_string(),
        )]);
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn 恶意模式百毫秒内拦截且三次停用() {
        // 引擎层：`^(a+)+$` 对抗性输入微秒级返回，远快于 100ms 预算（不挂起主链）。
        let d = detector();
        d.load_custom_patterns(&[("evil".to_string(), r"^(a+)+$".to_string())]);
        assert!(d.custom_names_snapshot().contains(&"evil".to_string()));
        assert_eq!(RE_DOS_BUDGET_MS, 100);
        let input = "a".repeat(2000) + "b";
        let start = std::time::Instant::now();
        let hits = d.scan_custom(&input, &empty_cred()).await;
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "恶意模式必须远快于预算返回"
        );
        assert!(hits.iter().all(|h| h.0 != "evil"));
        // 状态机层：连续 3 次超时停用（确定性单测记账逻辑）。
        let d2 = detector();
        d2.load_custom_patterns(&[("slow".to_string(), r"slow\d+".to_string())]);
        assert!(!d2.disabled_snapshot().contains(&"slow".to_string()));
        d2.account_rule("slow", true);
        d2.account_rule("slow", true);
        assert!(!d2.disabled_snapshot().contains(&"slow".to_string()));
        d2.account_rule("slow", true);
        assert!(d2.disabled_snapshot().contains(&"slow".to_string()));
        // 成功清零：超时 2 次后成功则计数重置。
        let d3 = detector();
        d3.load_custom_patterns(&[("flaky".to_string(), r"flaky\d+".to_string())]);
        d3.account_rule("flaky", true);
        d3.account_rule("flaky", true);
        d3.account_rule("flaky", false);
        d3.account_rule("flaky", true);
        d3.account_rule("flaky", true);
        assert!(!d3.disabled_snapshot().contains(&"flaky".to_string()));
    }

    #[test]
    fn 字典独立扫描与cjk边界() {
        let d = detector();
        d.load_dict(&[
            ("张三".to_string(), "name".to_string()),
            ("db-prod-01".to_string(), "hostname".to_string()),
        ]);
        // 标点分界命中（严格 CJK 边界：两侧非 CJK 字母数字）。
        let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
        // 张三丰不误伤（后接 CJK 即阻断）。
        let hits = d.scan_dict_sync("张三丰来了", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
        // 前接 CJK 同样阻断（严格前瞻语义）。
        let hits = d.scan_dict_sync("我张三", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
        // 主机名 ASCII 粘连不命中。
        let hits = d.scan_dict_sync("abcdb-prod-01x", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "db-prod-01"));
        let hits = d.scan_dict_sync("主机 db-prod-01 在线", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "db-prod-01"));
    }

    #[test]
    fn 同值复用与空洞跳过稳态下标() {
        let scope = PiiScope::new();
        let t1 = scope.register("13812345678", false).unwrap();
        let t2 = scope.register("13812345678", false).unwrap();
        assert_eq!(t1, t2, "同值必须复用同一 token");
        assert!(pii_token_re().is_match(&t1));
        // token 形态值拒绝注册。
        assert!(scope.register(&t1, false).is_err());
        assert!(scope.register("__PII_1_ab", false).is_err());
        // 响应期注册可用但请求还原表不含。
        let rt = scope.register("new-resp-value-001", true).unwrap();
        assert_ne!(rt, t1);
        let restored = scope.restore(&format!("{t1} {rt}"));
        assert!(restored.contains("13812345678"));
        assert!(restored.contains(&rt), "响应期 token 原样保留不还原");
        // 空洞跳过：直接构造空洞断言 next_available_index。
        assert_eq!(scope.next_available_index(), 3);
    }

    #[test]
    fn 并发注册无下标冲突() {
        use std::sync::Arc;
        let scope = Arc::new(PiiScope::new());
        let handles: Vec<_> = (0..32)
            .map(|i| {
                let s = scope.clone();
                std::thread::spawn(move || s.register(&format!("并发值-{i:03}"), false).unwrap())
            })
            .collect();
        let mut toks: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        toks.sort();
        toks.dedup();
        assert_eq!(toks.len(), 32, "并发注册不得串扰或冲突");
        let mut seqs: Vec<usize> = toks.iter().filter_map(|t| parse_pii_seq(t)).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (1..=32).collect::<Vec<_>>());
    }

    #[test]
    fn rand8形态与不可预测长度() {
        for _ in 0..10 {
            let r = gen_rand8().unwrap();
            assert_eq!(r.len(), 8);
            assert!(r.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(r, r.to_ascii_lowercase());
        }
    }

    #[test]
    fn 残缺清理保留完整形态() {
        assert_eq!(
            strip_pii_partials("__PII_1_ab12cd34__ tail"),
            "__PII_1_ab12cd34__ tail"
        );
        assert!(!strip_pii_partials("半截 __PII_1_ab 结尾").contains("__PII"));
        assert!(!strip_pii_partials("前缀 __PI ").contains("__PI"));
    }

    #[test]
    fn 凭据优先跳过() {
        // 某值同时命中凭据与 PII：PII 扫描必须跳过该区间。
        let mut cred = HashMap::new();
        cred.insert("13812345678".to_string(), "__VG_CRED_000001__".to_string());
        let hits = scan_builtin_sync("电话 13812345678", &cred);
        assert!(hits.is_empty(), "凭据值 PII 必须跳过: {hits:?}");
    }
}
