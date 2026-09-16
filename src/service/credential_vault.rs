//! 凭据 token（§3.1）：`__VG_CRED_%06d__` 全局映射 +
//! 请求级作用域隔离 + 残缺清理 + 幻觉完整 token 剥离 + 凭据优先。
//!
//! H3.1 owner 声明：token 映射实体（`CredentialVault/TOKEN_PREFIX/MAX_TOKEN_ENTRIES`）
//! 归本文件；KeePass 查询与注册/吊销运维归 `service::credential::vault_ops`
//! （其经本文件做取值 token 化）；两处职责正交、互不垫片。
//!
//! 口径对标原仓 `_token.py`：`_make_token` 零填充 6 位序号、
//! `_register_secret` 复用与 `MAX_TOKEN_ENTRIES=5000` 有界 LRU、
//! `_redact` 按明文长度降序单次替换、`_strip_partials` 接全出口。

use {
    crate::service::lock_recover::lock_or_recover,
    std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
    },
};

/// 凭据占位符前缀。
pub const TOKEN_PREFIX: &str = "__VG_CRED_";
/// 凭据占位符后缀。
pub const TOKEN_SUFFIX: &str = "__";
/// 全局凭据映射上限（LRU 淘汰最久未用）。
pub const MAX_TOKEN_ENTRIES: usize = 5000;
/// 凭据最小长度（字符数），过短不注册直接透传。
pub const SECRET_MIN_LENGTH: usize = 4;
/// alternation 正则编译上限（D3）：超限/失败回退逐键替换，不 panic。
const REGEX_SIZE_LIMIT_BYTES: usize = 1 << 20;

/// 构造 `__VG_CRED_%06d__` token（序号溢出时自然增长位数）。
pub fn make_cred_token(n: u64) -> String { format!("{TOKEN_PREFIX}{n:06}{TOKEN_SUFFIX}") }

fn token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__VG_CRED_\d{4,}__").expect("凭据 token 正则恒合法"))
}

/// 凭据残缺形态（分片切断的前缀），对标 `_PARTIAL_TOKEN_RE`。
/// D7 收窄：仅确证占位符残缺形态（`__VG_` + 可选截断 `CRED` + 可选 `_数字`）
/// 且后随边界（空白/标点/串尾）时剥离；后续为合法单词字符的正文
/// （如 `__VG_CREDENTIALS`）一律不剥离。完整形态不受影响（还原先行）。
fn cred_partial_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(r"__VG_(?:C(?:R(?:E(?:D(?:_?\d*)?)?)?)?)?(?:_*$|(?=\s|[^\w]))")
            .expect("凭据残缺正则恒合法")
    })
}

/// 清理凭据残缺前缀（流分片切断的 `__VG_` / `__VG_CRED_000` 等半截形态）。
pub fn strip_cred_partials(text: &str) -> String {
    cred_partial_re().replace_all(text, "").into_owned()
}

/// 注册拒绝原因：值命中内部 token 形态或前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultReject(&'static str);

impl std::fmt::Display for VaultReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}

/// 明文→token 映射快照（B2/D2）：含预编译 alternation 正则；
/// 注册（`seq` 变化）时失效，每帧仅 Arc 克隆、不深克隆、不重建正则。
#[derive(Debug)]
pub struct P2tSnapshot {
    map: HashMap<String, String>,
    alternation: Option<regex::Regex>,
}

impl P2tSnapshot {
    fn build(map: &HashMap<String, String>) -> Self {
        Self {
            map: map.clone(),
            alternation: compile_alternation(map),
        }
    }

    /// 只读映射（PII 扫描/区间保护复用）。
    pub fn map(&self) -> &HashMap<String, String> { &self.map }

    /// 空快照（仅测试构造）。
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            map: HashMap::new(),
            alternation: None,
        }
    }

    /// 键是否存在。
    pub fn contains_key(&self, key: &str) -> bool { self.map.contains_key(key) }

    /// 映射是否为空。
    pub fn is_empty(&self) -> bool { self.map.is_empty() }

    /// 按快照替换（预编译正则；编译失败走逐键回退，输出一致）。
    pub fn redact(&self, text: &str) -> String { self.redact_tracked(text, &mut |_| {}) }

    /// 按快照替换并回传**实际产出**的 token（B3 minted-set 依据）：`on_minted`
    /// 仅在映射键真正发生替换时以替换值调用；未命中键与字面 token 均不产出。
    pub fn redact_tracked(&self, text: &str, on_minted: &mut dyn FnMut(&str)) -> String {
        match &self.alternation {
            Some(re) => re
                .replace_all(text, |caps: &regex::Captures| {
                    match self.map.get(&caps[0]) {
                        Some(tok) => {
                            on_minted(tok);
                            tok.clone()
                        }
                        None => caps[0].to_string(),
                    }
                })
                .into_owned(),
            None => {
                let mut out = text.to_string();
                for k in sorted_keys_desc(&self.map) {
                    if let Some(v) = self.map.get(k) {
                        if out.contains(k.as_str()) {
                            on_minted(v);
                        }
                        out = out.replace(k.as_str(), v);
                    }
                }
                out
            }
        }
    }
}

#[derive(Debug)]
struct P2tCache {
    generation: u64,
    snapshot: Arc<P2tSnapshot>,
}

/// alternation 正则编译/回退首次告警（异常路径，避免每帧日志刷屏）。
fn warn_alternation_fallback_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!("凭据 map alternation 正则编译超限/失败，已回退逐键替换（首次告警）");
    }
}

fn read_inner(lock: &RwLock<VaultInner>) -> RwLockReadGuard<'_, VaultInner> {
    lock_or_recover(lock.read())
}

fn write_inner(lock: &RwLock<VaultInner>) -> RwLockWriteGuard<'_, VaultInner> {
    lock_or_recover(lock.write())
}

fn sorted_keys_desc(map: &HashMap<String, String>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    keys
}

fn compile_alternation(map: &HashMap<String, String>) -> Option<regex::Regex> {
    if map.is_empty() {
        return None;
    }
    let pat = sorted_keys_desc(map)
        .iter()
        .map(|k| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");
    match regex::RegexBuilder::new(&pat)
        .size_limit(REGEX_SIZE_LIMIT_BYTES)
        .build()
    {
        Ok(re) => Some(re),
        Err(_) => {
            warn_alternation_fallback_once();
            None
        }
    }
}

/// 编译失败/超限回退：按键长降序逐键替换（仅异常路径付 O(k·n)）。
fn replace_per_key(text: &str, map: &HashMap<String, String>) -> String {
    let mut out = text.to_string();
    for k in sorted_keys_desc(map) {
        if let Some(v) = map.get(k) {
            out = out.replace(k.as_str(), v);
        }
    }
    out
}

/// 全局凭据映射：`RwLock<HashMap>` + 有界 LRU（上限 [`MAX_TOKEN_ENTRIES`]）。
/// 读多写少，`RwLock` 保证并发脱敏/还原原子执行不串扰。
#[derive(Debug, Default)]
pub struct CredentialVault {
    inner: RwLock<VaultInner>,
    /// X3/D4 复杂度回归观测（仅测试）：全量快照调用计数。
    #[cfg(test)]
    snapshot_calls: std::sync::atomic::AtomicUsize,
    /// B2/D2 复杂度回归观测（仅测试）：p2t 快照重建计数。
    #[cfg(test)]
    p2t_build_calls: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Default)]
struct VaultInner {
    pwd_to_token: HashMap<String, String>,
    token_to_pwd: HashMap<String, String>,
    /// LRU 顺序（队首最久），与 `pwd_to_token` 同步维护。
    order: VecDeque<String>,
    seq: u64,
    /// p2t 快照缓存：`generation == seq` 时命中；注册/逐出（seq 自增）即失效。
    p2t_cache: Option<P2tCache>,
}

impl CredentialVault {
    /// 新建空 vault（单测与生产状态构造均经此）。
    pub fn new() -> Self { Self::default() }

    /// 注册凭据明文，返回 token。已存在则复用并提升 LRU；
    /// 过短直接透传原值；命中 token 形态/前缀则拒绝。
    pub fn register(&self, value: &str) -> Result<String, VaultReject> {
        if value.chars().count() < SECRET_MIN_LENGTH {
            return Ok(value.to_string());
        }
        let mut inner = write_inner(&self.inner);
        if let Some(tok) = inner.pwd_to_token.get(value) {
            let tok = tok.clone();
            touch(&mut inner.order, value);
            return Ok(tok);
        }
        if token_re().is_match(value) || value.starts_with(TOKEN_PREFIX) {
            return Err(VaultReject(
                "密码值不能匹配内部 token 格式或以 token 前缀开头",
            ));
        }
        inner.seq += 1;
        let token = make_cred_token(inner.seq);
        if inner.pwd_to_token.len() >= MAX_TOKEN_ENTRIES
            && let Some(oldest) = inner.order.pop_front()
            && let Some(old_tok) = inner.pwd_to_token.remove(&oldest)
        {
            inner.token_to_pwd.remove(&old_tok);
        }
        inner.order.push_back(value.to_string());
        inner.pwd_to_token.insert(value.to_string(), token.clone());
        inner.token_to_pwd.insert(token.clone(), value.to_string());
        Ok(token)
    }

    /// 当前映射条数（可观测/断言用）。
    pub fn len(&self) -> usize { read_inner(&self.inner).pwd_to_token.len() }

    /// 映射是否为空。
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// 全清映射（`lock`/`forget` 语义配套），返回清理条数并废止快照缓存。
    pub fn clear(&self) -> usize {
        let mut inner = write_inner(&self.inner);
        let cleared = inner.pwd_to_token.len();
        inner.pwd_to_token.clear();
        inner.token_to_pwd.clear();
        inner.order.clear();
        inner.p2t_cache = None;
        inner.seq += 1;
        cleared
    }

    /// 明文→token 快照（PII 凭据优先判定用，不暴露可变引用）。
    #[cfg(test)]
    pub(crate) fn snapshot_p2t(&self) -> HashMap<String, String> {
        read_inner(&self.inner).pwd_to_token.clone()
    }

    /// token→明文快照（流式显式 mapping 缓存键用）。
    pub fn snapshot_t2p(&self) -> HashMap<String, String> {
        #[cfg(test)]
        self.snapshot_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        read_inner(&self.inner).token_to_pwd.clone()
    }

    /// p2t 快照（Arc，含预编译 alternation）：注册时失效、双检重建一次；
    /// 每帧仅 Arc 克隆，不深克隆映射、不重编译正则（B2/D2）。
    pub fn p2t_snapshot(&self) -> Arc<P2tSnapshot> {
        {
            let inner = read_inner(&self.inner);
            if let Some(cache) = &inner.p2t_cache
                && cache.generation == inner.seq
            {
                return cache.snapshot.clone();
            }
        }
        let mut inner = write_inner(&self.inner);
        if let Some(cache) = &inner.p2t_cache
            && cache.generation == inner.seq
        {
            return cache.snapshot.clone();
        }
        #[cfg(test)]
        self.p2t_build_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let snapshot = Arc::new(P2tSnapshot::build(&inner.pwd_to_token));
        inner.p2t_cache = Some(P2tCache {
            generation: inner.seq,
            snapshot: snapshot.clone(),
        });
        snapshot
    }

    /// 单 token 还原直查（X3/D4）：同一把读锁一次查表，不克隆全表、
    /// 不重建 alternation 正则；未注册返回 `None`（调用方自决回退）。
    /// 已注册 token 的结果与全量 `restore` 的同 token 子串一致。
    pub fn restore_one(&self, token: &str) -> Option<String> {
        read_inner(&self.inner).token_to_pwd.get(token).cloned()
    }

    /// 全量快照调用计数（仅测试可见；X3 复杂度回归断言用）。
    #[cfg(test)]
    pub fn snapshot_calls(&self) -> usize {
        self.snapshot_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// p2t 快照重建计数（仅测试；B2 复杂度回归断言用）。
    #[cfg(test)]
    pub fn p2t_build_calls(&self) -> usize {
        self.p2t_build_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 将 token 还原为凭据明文。
    pub fn restore(&self, text: &str) -> String { replace_all_by_map(text, &self.snapshot_t2p()) }

    /// 剥离未知完整凭据 token（模型幻觉/未知句柄）。
    /// `allowed` 为 `Some` 时仅保留「授权集合内 **且** 全局映射仍命中」的 token
    /// （B3 请求级授权：命中映射但非本请求产出者同幻觉剥离，未还原形态不透出下游）；
    /// `None` 保持旧口径（命中映射的一律保留，仅未注册形态剥离）。
    pub fn strip_hallucinated(&self, text: &str, allowed: Option<&HashSet<String>>) -> String {
        let guard = read_inner(&self.inner);
        token_re()
            .replace_all(text, |caps: &regex::Captures| {
                let tok = &caps[0];
                let keep = match allowed {
                    Some(set) => set.contains(tok) && guard.token_to_pwd.contains_key(tok),
                    None => guard.token_to_pwd.contains_key(tok),
                };
                if keep { tok.to_string() } else { String::new() }
            })
            .into_owned()
    }
}

fn touch(order: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = order.iter().position(|v| v == value) {
        order.remove(pos);
    }
    order.push_back(value.to_string());
}

/// 按 map 键长度降序单次 alternation 替换（X7 单一来源）：`restore` 传
/// token→明文（还原），`redact_with_map` 传明文→token（脱敏），方向差异由
/// 入参 map 承载；命中键替换为值，未命中保持原样。键经 `regex::escape`，
/// 等长键次序不影响结果（等长不同键互不为前缀）。
pub fn replace_all_by_map(text: &str, map: &HashMap<String, String>) -> String {
    replace_all_by_map_limited(text, map, REGEX_SIZE_LIMIT_BYTES)
}

/// 带显式大小上限的 alternation 替换（D3）：编译失败/超限回退逐键替换，不 panic。
fn replace_all_by_map_limited(
    text: &str,
    map: &HashMap<String, String>,
    size_limit: usize,
) -> String {
    if map.is_empty() {
        return text.to_string();
    }
    let pat = sorted_keys_desc(map)
        .iter()
        .map(|k| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");
    match regex::RegexBuilder::new(&pat)
        .size_limit(size_limit)
        .build()
    {
        Ok(re) => re
            .replace_all(text, |caps: &regex::Captures| {
                map.get(&caps[0])
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned(),
        Err(_) => {
            warn_alternation_fallback_once();
            replace_per_key(text, map)
        }
    }
}

/// 显式 mapping 的单次替换（长度降序），供请求级快照复用。
#[cfg(test)]
pub(crate) fn redact_with_map(text: &str, map: &HashMap<String, String>) -> String {
    replace_all_by_map(text, map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_zero_padded_six_digits() {
        assert_eq!(make_cred_token(1), "__VG_CRED_000001__");
        assert_eq!(make_cred_token(42), "__VG_CRED_000042__");
    }

    #[test]
    fn partial_prefix_stripped_without_leak() {
        for partial in [
            "__VG_C",
            "__VG_CRED",
            "__VG_CRED_",
            "__VG_CRED_000",
            "__VG_CRED_000001",
            "尾部残缺 __VG_CRED_12 ",
        ] {
            let cleaned = strip_cred_partials(partial);
            assert!(
                !cleaned.contains("__VG"),
                "残缺必须清理: {partial:?} -> {cleaned:?}"
            );
        }
        // 完整凭据形态同样被残缺清理剥离（与原仓 `_PARTIAL_TOKEN_RE` 同语义，
        // 故还原必须先行；PII 完整形态由前瞻排除得以保留）。
        assert_eq!(strip_cred_partials("__VG_CRED_000001__"), "");
    }

    #[test]
    fn hallucinated_token_stripped_while_real_restored() {
        let vault = CredentialVault::new();
        let tok = vault.register("s3cr3t-value").unwrap();
        let text = format!("real={tok} fake=__VG_CRED_999999__");
        let restored = vault.restore(&text);
        assert!(restored.contains("s3cr3t-value"));
        let cleaned = vault.strip_hallucinated(&restored, None);
        assert!(!cleaned.contains("__VG_CRED_999999__"));
        assert!(cleaned.contains("s3cr3t-value"));
    }

    #[test]
    fn longest_first_ordering_prevents_substring_collision() {
        let vault = CredentialVault::new();
        vault.register("abcd-1234-long").unwrap();
        vault.register("abcd").unwrap();
        let out = redact_with_map("值 abcd-1234-long 结束", &vault.snapshot_p2t());
        assert!(!out.contains("abcd-1234-long"));
        assert!(out.contains("__VG_CRED_"));
    }

    #[test]
    fn short_values_and_token_shapes_rejected() {
        let vault = CredentialVault::new();
        assert_eq!(vault.register("abc").unwrap(), "abc");
        assert!(vault.register("__VG_CRED_000001__").is_err());
        assert!(vault.register("__VG_CRED_xxx").is_err());
    }

    #[test]
    fn same_secret_maps_to_same_token_across_requests() {
        let vault = CredentialVault::new();
        let first = vault.register("跨请求秘密-xyz789").unwrap();
        let second = vault.register("跨请求秘密-xyz789").unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("__VG_CRED_"));
        assert_eq!(vault.len(), 1);
    }

    #[test]
    fn restore_one_matches_full_restore_per_token() {
        let vault = CredentialVault::new();
        let tok_a = vault.register("alpha-secret-001").unwrap();
        let tok_b = vault.register("beta-secret-002").unwrap();
        assert_eq!(
            vault.restore_one(&tok_a).as_deref(),
            Some("alpha-secret-001")
        );
        assert_eq!(
            vault.restore_one(&tok_b).as_deref(),
            Some("beta-secret-002")
        );
        // 与全量 restore 的同 token 子串一致。
        let full = vault.restore(&format!("a={tok_a} b={tok_b}"));
        assert_eq!(full, "a=alpha-secret-001 b=beta-secret-002");
        // 未注册/非 token 直查返回 None（不克隆全表、不猜测）。
        assert_eq!(vault.restore_one("__VG_CRED_999999__"), None);
        assert_eq!(vault.restore_one("plain-text"), None);
    }

    #[test]
    fn snapshot_maps_and_redact_with_map_reflect_registrations() {
        // D1.3：只读快照语义改走生产等价路径（`snapshot_p2t`/`snapshot_t2p` +
        // `redact_with_map`/`restore`）；旧 `VaultSnapshot` 类型（生产零引用）已删。
        let vault = CredentialVault::new();
        let token = vault.register("快照秘密-abc456").unwrap();
        let p2t = vault.snapshot_p2t();
        assert_eq!(p2t.len(), 1);
        let out = redact_with_map("正文含 快照秘密-abc456 结尾", &p2t);
        assert_eq!(out, format!("正文含 {token} 结尾"));
        assert_eq!(vault.restore(&out), "正文含 快照秘密-abc456 结尾");
        assert_eq!(vault.len(), 1);
        let fresh = vault.register("另一秘密-def000").unwrap();
        let p2t2 = vault.snapshot_p2t();
        assert_eq!(p2t2.len(), 2);
        assert!(redact_with_map("另一秘密-def000", &p2t2).contains(&fresh));
    }

    #[test]
    fn bounded_global_map_evicts_oldest_via_lru() {
        let vault = CredentialVault::new();
        assert_eq!(MAX_TOKEN_ENTRIES, 5000, "凭据表容量分表锁定");
        for i in 0..MAX_TOKEN_ENTRIES + 5 {
            vault.register(&format!("secret-value-{i:06}")).unwrap();
        }
        assert_eq!(vault.len(), MAX_TOKEN_ENTRIES);
        // 最早注册的已被淘汰。
        assert!(!vault.snapshot_p2t().contains_key("secret-value-000000"));
    }

    #[test]
    fn lru_hot_entry_retained_cold_evicted_first() {
        let vault = CredentialVault::new();
        for i in 0..MAX_TOKEN_ENTRIES {
            vault.register(&format!("secret-value-{i:06}")).unwrap();
        }
        // 触达最早条目提升为热点（复用提升 LRU），再溢出一条。
        vault.register("secret-value-000000").unwrap();
        vault.register("secret-overflow-000001").unwrap();
        let snap = vault.snapshot_p2t();
        assert_eq!(vault.len(), MAX_TOKEN_ENTRIES);
        assert!(
            snap.contains_key("secret-value-000000"),
            "热点须驻留而非按 FIFO 逐出"
        );
        assert!(
            !snap.contains_key("secret-value-000001"),
            "从未触达的次冷条目须先逐出"
        );
    }

    /// T12 并发回补：100 路注册隔离 + 同值复用（tokio JoinSet）。
    #[tokio::test]
    async fn t12_100_way_register_isolation_no_conflict() {
        use std::sync::Arc;
        let vault = Arc::new(CredentialVault::new());
        let mut set = tokio::task::JoinSet::new();
        for i in 0..100 {
            let v = vault.clone();
            set.spawn(async move { v.register(&format!("join-secret-{i:03}")).unwrap() });
        }
        let mut toks = Vec::new();
        while let Some(r) = set.join_next().await {
            toks.push(r.expect("任务须成功"));
        }
        toks.sort();
        toks.dedup();
        assert_eq!(toks.len(), 100, "100 并发注册不得冲突");
        assert_eq!(vault.len(), 100);
    }

    #[tokio::test]
    async fn t12_concurrent_duplicate_reuse_single_token() {
        use std::sync::Arc;
        let vault = Arc::new(CredentialVault::new());
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let v = vault.clone();
            set.spawn(async move { v.register("shared-secret-xyz").unwrap() });
        }
        let mut toks = Vec::new();
        while let Some(r) = set.join_next().await {
            toks.push(r.expect("任务须成功"));
        }
        toks.sort();
        toks.dedup();
        assert_eq!(toks.len(), 1, "同值并发须复用同一 token");
        assert_eq!(vault.len(), 1);
    }

    /// B2/D2：帧路径零全量快照、p2t 快照仅注册后重建一次（不随帧数增长）。
    #[tokio::test]
    async fn stream_frame_no_full_snapshot() {
        use crate::service::{pii::PiiDetector, redaction::Scope};
        let vault = CredentialVault::new();
        vault.register("frame-secret-001").unwrap();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let frame = r#"{"a":"frame-secret-001","b":"8.8.8.8"}"#;
        let t2p_before = vault.snapshot_calls();
        let p2t_before = vault.p2t_build_calls();
        for _ in 0..20 {
            let (restored, spans) = scope.restore_response_with_spans_json(&vault, frame);
            let _ = scope
                .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
                .await;
        }
        assert_eq!(
            vault.snapshot_calls() - t2p_before,
            0,
            "逐帧不得全量快照 t2p"
        );
        assert_eq!(
            vault.p2t_build_calls() - p2t_before,
            1,
            "p2t 快照仅首次重建，不随帧数增长"
        );
    }

    /// B2/D2：帧间注册新凭据后缓存失效，后续帧可还原新 token。
    #[tokio::test]
    async fn restore_after_register() {
        use crate::service::{pii::PiiDetector, redaction::Scope};
        let vault = CredentialVault::new();
        let scope = Scope::new();
        let first = vault.register("first-secret-001").unwrap();
        assert!(vault.p2t_snapshot().contains_key("first-secret-001"));
        let builds_before = vault.p2t_build_calls();
        let fresh = vault.register("fresh-secret-002").unwrap();
        // B3：两 token 均须经本请求脱敏实际产出方可还原。
        let _ = scope
            .redact_request(&vault, &PiiDetector::new(), "fresh-secret-002")
            .await;
        let (restored, _) = scope.restore_response_with_spans(&vault, &format!("值 {fresh} 结束"));
        assert_eq!(restored, "值 fresh-secret-002 结束");
        assert!(
            vault.p2t_snapshot().contains_key("fresh-secret-002"),
            "缓存失效重建后须含新凭据"
        );
        assert!(vault.p2t_build_calls() > builds_before, "注册后缓存须重建");
        let _ = scope
            .redact_request(&vault, &PiiDetector::new(), "first-secret-001")
            .await;
        let (restored_old, _) =
            scope.restore_response_with_spans(&vault, &format!("值 {first} 结束"));
        assert_eq!(restored_old, "值 first-secret-001 结束");
    }

    /// B2/D2：并发注册 + 还原无死锁/无 panic，结果与串行语义一致。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn restore_concurrent_register() {
        use {
            crate::service::{pii::PiiDetector, redaction::Scope},
            std::sync::Arc,
        };
        let vault = Arc::new(CredentialVault::new());
        let mut set = tokio::task::JoinSet::new();
        for i in 0..8 {
            let v = vault.clone();
            set.spawn(async move {
                let secret = format!("concurrent-secret-{i:03}");
                let token = v.register(&secret).unwrap();
                let scope = Scope::new();
                // B3：请求侧脱敏铸造 token。
                let _ = scope.redact_request(&v, &PiiDetector::new(), &secret).await;
                let (restored, _) = scope.restore_response_with_spans(&v, &format!("v {token}"));
                assert_eq!(restored, format!("v {secret}"));
            });
        }
        while let Some(r) = set.join_next().await {
            r.expect("并发任务不得 panic");
        }
        let snap = vault.p2t_snapshot();
        let all: String = (0..8)
            .map(|i| format!("concurrent-secret-{i:03} "))
            .collect();
        let masked = snap.redact(&all);
        for i in 0..8 {
            assert!(
                !masked.contains(&format!("concurrent-secret-{i:03}")),
                "注册值须可被收敛后的快照脱敏: {masked}"
            );
        }
    }

    /// B3/D3：锁中毒后 register/restore/strip_hallucinated 恢复可用、无 panic。
    #[test]
    fn vault_poison_recovery() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        let vault = CredentialVault::new();
        let tok = vault.register("poison-secret-001").unwrap();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = vault.inner.write().unwrap();
            panic!("注入锁中毒");
        }));
        assert_eq!(
            vault.restore_one(&tok).as_deref(),
            Some("poison-secret-001")
        );
        assert_eq!(vault.restore(&format!("v {tok}")), "v poison-secret-001");
        assert_eq!(
            vault.strip_hallucinated("x __VG_CRED_999999__ y", None),
            "x  y"
        );
        let tok2 = vault.register("poison-secret-002").unwrap();
        assert_eq!(
            vault.restore_one(&tok2).as_deref(),
            Some("poison-secret-002")
        );
        assert_eq!(vault.len(), 2);
        assert!(!vault.p2t_snapshot().is_empty());
    }

    /// B3/D3：正则编译失败/触顶回退逐键替换，输出正确且无 panic。
    #[test]
    fn alternation_fallback() {
        let mut map = HashMap::new();
        map.insert(
            "alpha-secret-value".to_string(),
            "__VG_CRED_000001__".to_string(),
        );
        map.insert(
            "beta-secret-value".to_string(),
            "__VG_CRED_000002__".to_string(),
        );
        let text = "a alpha-secret-value b beta-secret-value c";
        let limited = replace_all_by_map_limited(text, &map, 1);
        assert_eq!(limited, "a __VG_CRED_000001__ b __VG_CRED_000002__ c");
        assert_eq!(
            replace_all_by_map(text, &map),
            limited,
            "回退与常规路径输出须一致"
        );
    }

    /// B3/D3：正则规模上限复核——`MAX_TOKEN_ENTRIES` 映射编译成功或回退，
    /// 输出与逐键替换一致且无 panic。
    #[test]
    fn regex_size_ceiling_max_entries() {
        let map: HashMap<String, String> = (0..MAX_TOKEN_ENTRIES)
            .map(|i| {
                (
                    format!("ceiling-secret-{i:06}"),
                    make_cred_token(i as u64 + 1),
                )
            })
            .collect();
        let text = "前缀 ceiling-secret-000000 中 ceiling-secret-004999 后缀";
        let out = replace_all_by_map(text, &map);
        assert!(!out.contains("ceiling-secret-000000"), "{out}");
        assert!(!out.contains("ceiling-secret-004999"), "{out}");
        assert!(out.contains("__VG_CRED_000001__"), "{out}");
        assert!(out.contains("__VG_CRED_005000__"), "{out}");
        let mut expected = text.to_string();
        for key in sorted_keys_desc(&map) {
            if let Some(value) = map.get(key) {
                expected = expected.replace(key.as_str(), value);
            }
        }
        assert_eq!(out, expected, "上限规模输出须与逐键替换一致");
    }

    /// B2/D2：每帧快照计数与表规模解耦（大表与空表均为 0 增量）。
    #[tokio::test]
    async fn stream_restore_complexity() {
        use crate::service::{pii::PiiDetector, redaction::Scope};
        let vault = CredentialVault::new();
        for i in 0..MAX_TOKEN_ENTRIES - 1 {
            vault
                .register(&format!("complexity-secret-{i:06}"))
                .unwrap();
        }
        let token = vault.register("big-table-target-secret").unwrap();
        assert_eq!(vault.len(), MAX_TOKEN_ENTRIES, "须构造上限规模表");
        let scope = Scope::new();
        // B3：请求侧脱敏铸造 token（基线快照计数之前）。
        let _ = scope
            .redact_request(&vault, &PiiDetector::new(), "big-table-target-secret")
            .await;
        let frame = format!("{{\"k\":\"{token}\"}}");
        let before = vault.snapshot_calls();
        for _ in 0..20 {
            let (restored, _) = scope.restore_response_with_spans(&vault, &frame);
            assert!(restored.contains("big-table-target-secret"), "{restored}");
        }
        let big_table_delta = vault.snapshot_calls() - before;
        let empty = CredentialVault::new();
        let empty_scope = Scope::new();
        let before_empty = empty.snapshot_calls();
        for _ in 0..20 {
            let _ = empty_scope.restore_response_with_spans(&empty, &frame);
        }
        assert_eq!(big_table_delta, 0, "大表逐帧快照计数须为 0 增量");
        assert_eq!(
            empty.snapshot_calls() - before_empty,
            0,
            "空表逐帧快照计数须为 0 增量"
        );
    }
}
