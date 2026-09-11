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

use std::{
    collections::{HashMap, VecDeque},
    sync::{OnceLock, RwLock},
};

/// 凭据占位符前缀。
pub const TOKEN_PREFIX: &str = "__VG_CRED_";
/// 凭据占位符后缀。
pub const TOKEN_SUFFIX: &str = "__";
/// 全局凭据映射上限（LRU 淘汰最久未用）。
pub const MAX_TOKEN_ENTRIES: usize = 5000;
/// 凭据最小长度（字符数），过短不注册直接透传。
pub const SECRET_MIN_LENGTH: usize = 4;

/// 构造 `__VG_CRED_%06d__` token（序号溢出时自然增长位数）。
pub fn make_cred_token(n: u64) -> String { format!("{TOKEN_PREFIX}{n:06}{TOKEN_SUFFIX}") }

fn token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__VG_CRED_\d{4,}__").expect("凭据 token 正则恒合法"))
}

/// 凭据残缺形态（分片切断的前缀），对标 `_PARTIAL_TOKEN_RE`。
/// lookahead 版：完整形态不受影响（`\d` 段后无 `_*$`/边界则不匹配）。
fn cred_partial_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(r"__VG_C(?:R(?:E(?:D(?:_?\d*)?)?)?)?(?:_*$|(?=\s|[^\w]))")
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

/// 全局凭据映射：`RwLock<HashMap>` + 有界 LRU（上限 [`MAX_TOKEN_ENTRIES`]）。
/// 读多写少，`RwLock` 保证并发脱敏/还原原子执行不串扰。
#[derive(Debug, Default)]
pub struct CredentialVault {
    inner: RwLock<VaultInner>,
    /// X3/D4 复杂度回归观测（仅测试）：全量快照调用计数。
    #[cfg(test)]
    snapshot_calls: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Default)]
struct VaultInner {
    pwd_to_token: HashMap<String, String>,
    token_to_pwd: HashMap<String, String>,
    /// LRU 顺序（队首最久），与 `pwd_to_token` 同步维护。
    order: VecDeque<String>,
    seq: u64,
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
        let mut inner = self.inner.write().expect("凭据 vault 锁无毒");
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
    pub fn len(&self) -> usize { self.inner.read().map(|g| g.pwd_to_token.len()).unwrap_or(0) }

    /// 映射是否为空。
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// 明文→token 快照（PII 凭据优先判定用，不暴露可变引用）。
    pub fn snapshot_p2t(&self) -> HashMap<String, String> {
        self.inner
            .read()
            .map(|g| g.pwd_to_token.clone())
            .unwrap_or_default()
    }

    /// token→明文快照（流式显式 mapping 缓存键用）。
    pub fn snapshot_t2p(&self) -> HashMap<String, String> {
        #[cfg(test)]
        self.snapshot_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .read()
            .map(|g| g.token_to_pwd.clone())
            .unwrap_or_default()
    }

    /// 单 token 还原直查（X3/D4）：同一把读锁一次查表，不克隆全表、
    /// 不重建 alternation 正则；未注册返回 `None`（调用方自决回退）。
    /// 已注册 token 的结果与全量 `restore` 的同 token 子串一致。
    pub fn restore_one(&self, token: &str) -> Option<String> {
        self.inner.read().ok()?.token_to_pwd.get(token).cloned()
    }

    /// 全量快照调用计数（仅测试可见；X3 复杂度回归断言用）。
    #[cfg(test)]
    pub fn snapshot_calls(&self) -> usize {
        self.snapshot_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 将 token 还原为凭据明文。
    pub fn restore(&self, text: &str) -> String { replace_all_by_map(text, &self.snapshot_t2p()) }

    /// 剥离未知完整凭据 token（模型幻觉/未知句柄）。
    /// 已还原的真实 token 不会落此函数；命中映射的一律保留。
    pub fn strip_hallucinated(&self, text: &str) -> String {
        let guard = self.inner.read().expect("凭据 vault 锁无毒");
        token_re()
            .replace_all(text, |caps: &regex::Captures| {
                if guard.token_to_pwd.contains_key(&caps[0]) {
                    caps[0].to_string()
                } else {
                    String::new()
                }
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
    if map.is_empty() {
        return text.to_string();
    }
    let mut items: Vec<(&String, &String)> = map.iter().collect();
    items.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    let pat = items
        .iter()
        .map(|(k, _)| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");
    let re = regex::Regex::new(&pat).expect("转义后 map 键正则恒合法");
    re.replace_all(text, |caps: &regex::Captures| {
        map.get(&caps[0])
            .cloned()
            .unwrap_or_else(|| caps[0].to_string())
    })
    .into_owned()
}

/// 显式 mapping 的单次替换（长度降序），供请求级快照复用。
pub fn redact_with_map(text: &str, map: &HashMap<String, String>) -> String {
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
        let cleaned = vault.strip_hallucinated(&restored);
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
}
