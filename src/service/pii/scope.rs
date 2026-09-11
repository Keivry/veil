//! 请求级 PII token 容器：注册/还原/序号空洞复用/LRU 淘汰。

use {
    super::detector::{
        PII_MAX_ENTRIES,
        PII_TOKEN_PREFIX,
        cred_token_shape_re,
        pii_loose_re,
        pii_token_re,
    },
    rand::{rand_core::TryRngCore as _, rngs::OsRng},
    std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::{Mutex, MutexGuard, OnceLock, PoisonError},
    },
};

/// 锁中毒恢复（B3/D3）：`PoisonError::into_inner` 返回可用守卫，首次 warn。
fn warn_poison_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!("PII scope 锁中毒，已 PoisonError::into_inner 恢复（首次告警）");
    }
}

fn recover_mutex<T>(lock: std::sync::LockResult<MutexGuard<'_, T>>) -> MutexGuard<'_, T> {
    lock.unwrap_or_else(|e: PoisonError<_>| {
        warn_poison_once();
        e.into_inner()
    })
}

/// 宽松形态分类正则（字面量提升 `OnceLock`，消除每调用编译与 `.expect`）。
fn malformed_shape_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^__PII_\d+_[0-9a-fA-F]{8}__$").expect("PII 形态正则恒合法")
    })
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

pub(crate) fn parse_pii_seq(token: &str) -> Option<usize> {
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
    /// F5/D4 分配游标：下一个候选序号（1 起），与 `used_seqs` 配套均摊 O(1)。
    next_seq: usize,
    /// F5/D4 全部在用序号（请求/响应表共享序号空间；分配插入、淘汰移除）。
    used_seqs: HashSet<usize>,
    /// 分配探测步数（仅测试观测线性有界；生产零成本）。
    #[cfg(test)]
    scan_steps: usize,
}

impl ScopeInner {
    /// F5/D4：游标 + 已用集分配。自游标起找首个未用序号，越顶回卷；
    /// 全满时返回 `PII_MAX_ENTRIES + 1`（与旧 `next_hole` 全占语义一致，
    /// 紧随的 LRU 淘汰会把空洞重新释放）。
    fn alloc_seq(&mut self) -> usize {
        let start = self.next_seq.max(1);
        let mut seq = if start > PII_MAX_ENTRIES { 1 } else { start };
        seq = self.find_free_from(seq);
        if seq > PII_MAX_ENTRIES {
            seq = self.find_free_from(1);
        }
        self.next_seq = if seq >= PII_MAX_ENTRIES { 1 } else { seq + 1 };
        seq
    }

    fn find_free_from(&mut self, from: usize) -> usize {
        let mut seq = from;
        while seq <= PII_MAX_ENTRIES {
            self.note_probe();
            if !self.used_seqs.contains(&seq) {
                return seq;
            }
            seq += 1;
        }
        PII_MAX_ENTRIES + 1
    }

    /// 回收淘汰条目的序号（空洞复用来源）。
    fn release_seq(&mut self, token: &str) {
        if let Some(seq) = parse_pii_seq(token) {
            self.used_seqs.remove(&seq);
        }
    }

    #[cfg(test)]
    fn note_probe(&mut self) { self.scan_steps += 1; }

    #[cfg(not(test))]
    fn note_probe(&mut self) {}
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

    /// 空洞跳过：返回全序号空间最小空闲序号（仅测试口径；
    /// 分配本身走 [`ScopeInner::alloc_seq`] 游标，不做全量重建）。
    #[cfg(test)]
    fn next_available_index(&self) -> usize {
        let inner = recover_mutex(self.inner.lock());
        let mut seq = 1;
        while inner.used_seqs.contains(&seq) {
            seq += 1;
        }
        seq
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
        let mut inner = recover_mutex(self.inner.lock());
        if response_side {
            if let Some(tok) = inner.resp_p2t.get(value).cloned() {
                touch_order(&mut inner.resp_order, value);
                return Ok(tok);
            }
        } else if let Some(tok) = inner.pii_p2t.get(value).cloned() {
            touch_order(&mut inner.pii_order, value);
            return Ok(tok);
        }
        let seq = inner.alloc_seq();
        let rand8 = gen_rand8().map_err(|_| PiiReject("CSPRNG 熵源不可用"))?;
        let token = make_pii_token(seq, &rand8);
        if response_side {
            if inner.resp_p2t.len() >= PII_MAX_ENTRIES
                && let Some(oldest) = inner.resp_order.pop_front()
                && let Some(old_tok) = inner.resp_p2t.remove(&oldest)
            {
                inner.resp_t2p.remove(&old_tok);
                inner.release_seq(&old_tok);
            }
            inner.used_seqs.insert(seq);
            inner.resp_order.push_back(value.to_string());
            inner.resp_p2t.insert(value.to_string(), token.clone());
            inner.resp_t2p.insert(token.clone(), value.to_string());
        } else {
            if inner.pii_p2t.len() >= PII_MAX_ENTRIES
                && let Some(oldest) = inner.pii_order.pop_front()
                && let Some(old_tok) = inner.pii_p2t.remove(&oldest)
            {
                inner.pii_t2p.remove(&old_tok);
                inner.release_seq(&old_tok);
            }
            inner.used_seqs.insert(seq);
            inner.pii_order.push_back(value.to_string());
            inner.pii_p2t.insert(value.to_string(), token.clone());
            inner.pii_t2p.insert(token.clone(), value.to_string());
        }
        Ok(token)
    }

    /// 还原请求期注册 token；响应期/未注册/格式不符原样保留。
    /// 只查本 Scope，绝不触达全局凭据映射。
    /// 残留宽松形态补扫审计（聚合计数，落盘限流由调用方负责）。
    pub fn restore(&self, text: &str) -> String { self.restore_with_fuzzy(text, false) }

    /// 宽松还原：`fuzzy=false` 与 [`PiiScope::restore`] 一致；`fuzzy=true`
    /// （`PII_FUZZY_RESTORE`）时残留宽松形态按序号回查请求表，截断/改写后的
    /// token 仍可还原；响应表与未知序号一律原样保留。
    pub fn restore_with_fuzzy(&self, text: &str, fuzzy: bool) -> String {
        let restored = self.restore_exact(text);
        if !fuzzy {
            return restored;
        }
        let inner = recover_mutex(self.inner.lock());
        if inner.pii_t2p.is_empty() {
            return restored;
        }
        let known: HashSet<String> = inner
            .pii_t2p
            .keys()
            .chain(inner.resp_t2p.keys())
            .cloned()
            .collect();
        let seq_map: HashMap<usize, String> = inner
            .pii_t2p
            .iter()
            .filter_map(|(tok, plain)| parse_pii_seq(tok).map(|s| (s, plain.clone())))
            .collect();
        drop(inner);
        if seq_map.is_empty() {
            return restored;
        }
        pii_loose_re()
            .replace_all(&restored, |caps: &regex::Captures| {
                let tok = &caps[0];
                if known.contains(tok) {
                    return tok.to_string();
                }
                parse_pii_seq(tok)
                    .and_then(|s| seq_map.get(&s).cloned())
                    .unwrap_or_else(|| tok.to_string())
            })
            .into_owned()
    }

    /// 精确还原本体（`restore`/`restore_with_fuzzy` 共用）。
    fn restore_exact(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        let restored = {
            let inner = recover_mutex(self.inner.lock());
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
        let known: HashSet<String> = {
            let inner = recover_mutex(self.inner.lock());
            inner
                .pii_t2p
                .keys()
                .chain(inner.resp_t2p.keys())
                .cloned()
                .collect()
        };
        for m in pii_loose_re().find_iter(&restored) {
            let tok = m.as_str();
            if !known.contains(tok) {
                self.count_malformed(tok);
            }
        }
        restored
    }

    /// 是否持有该请求 token（跨请求还原隔离断言用）。
    /// 中毒恢复后返回真实结果，不得静默降级为「不包含」（B3/D3）。
    /// 仅测试口径（D1/hygiene-round5）：生产零调用，`#[cfg(test)]` 收编，
    /// 对齐 [`PiiScope::next_available_index`] 的既有处置，release 构建不含该符号。
    #[cfg(test)]
    fn contains_request_token(&self, token: &str) -> bool {
        recover_mutex(self.inner.lock()).pii_t2p.contains_key(token)
    }

    /// 记录宽松形态审计计数（同类聚合，调用方限流落盘）。
    pub fn count_malformed(&self, token: &str) -> String {
        let cat = if malformed_shape_re().is_match(token) {
            "unregistered"
        } else {
            "malformed"
        };
        let mut counts = recover_mutex(self.malformed.lock());
        let c = counts.entry(cat.to_string()).or_insert(0);
        *c += 1;
        cat.to_string()
    }
}

fn touch_order(order: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = order.iter().position(|v| v == value) {
        order.remove(pos);
    }
    order.push_back(value.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_len_under_800_or_split() {
        // 红线看护（口径=文件总行，含测试与注释，见 hygiene-round4 模板）：
        // 超 800 即失败，须按模板拆分，不得只改数字放行。
        const SELF_SRC: &str = include_str!("scope.rs");
        let lines = SELF_SRC.lines().count();
        assert!(
            lines <= 800,
            "scope.rs {lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
        );
    }

    #[test]
    fn same_value_reuse_and_gap_skip_stable_index() {
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
    fn concurrent_register_no_index_conflict() {
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
    fn rand8_shape_and_unpredictable_length() {
        for _ in 0..10 {
            let r = gen_rand8().unwrap();
            assert_eq!(r.len(), 8);
            assert!(r.bytes().all(|b| b.is_ascii_hexdigit()));
            assert_eq!(r, r.to_ascii_lowercase());
        }
    }

    #[test]
    fn loose_shape_audit_class_and_unknown_passthrough() {
        let scope = PiiScope::new();
        // 完整形态但未注册：归类 unregistered。
        assert_eq!(scope.count_malformed("__PII_9_ab12cd34__"), "unregistered");
        // 残缺/非法形态：归类 malformed。
        assert_eq!(scope.count_malformed("__PII_x__"), "malformed");
        assert_eq!(scope.count_malformed("__PII_1_ab"), "malformed");
        // 未知完整 token 还原时原样透传（不伪造明文）。
        let out = scope.restore("回拨 __PII_9_ab12cd34__ 结束");
        assert_eq!(
            out, "回拨 __PII_9_ab12cd34__ 结束",
            "未知 token 须透传: {out}"
        );
        // 已注册 token 仍精确还原，不受未知形态干扰。
        let tok = scope.register("13812345678", false).unwrap();
        let out = scope.restore(&format!("回拨 {tok} 与 __PII_9_ab12cd34__"));
        assert!(out.contains("13812345678"), "{out}");
        assert!(out.contains("__PII_9_ab12cd34__"), "{out}");
    }

    #[test]
    fn request_table_capacity_split_lru_eviction() {
        // 分表声明：请求/响应单表 1000，与凭据 5000 不在同一容量口径。
        assert_eq!(PII_MAX_ENTRIES, 1000);
        assert_eq!(crate::service::credential_vault::MAX_TOKEN_ENTRIES, 5000);
        assert_ne!(
            PII_MAX_ENTRIES,
            crate::service::credential_vault::MAX_TOKEN_ENTRIES
        );
        let scope = PiiScope::new();
        let first = scope.register("13812340000", false).unwrap();
        let mut last_tok = String::new();
        for i in 1..=(PII_MAX_ENTRIES as u32 + 4) {
            last_tok = scope.register(&format!("139{:08}", i), false).unwrap();
        }
        // 最久未用被淘汰，新值驻留；淘汰腾出的序号被复用（空洞跳过）。
        assert!(
            !scope.contains_request_token(&first),
            "最久条目须被 LRU 淘汰"
        );
        let newest = format!("139{:08}", PII_MAX_ENTRIES as u32 + 4);
        assert!(scope.contains_request_token(&last_tok));
        assert_eq!(
            scope.register(&newest, false).unwrap(),
            last_tok,
            "最新条目须驻留复用同一 token"
        );
        // 响应表独立：响应侧注册不进请求还原表（分表隔离）。
        let rt = scope.register("新增响应值-001", true).unwrap();
        assert!(!scope.contains_request_token(&rt));
        let restored = scope.restore(&format!("回 {rt}"));
        assert!(restored.contains(&rt), "响应 token 原样保留: {restored}");
    }

    #[test]
    fn b4_lru_hit_reuse_and_thousand_boundary() {
        // B4.3：缓存命中复用与容量 1000 边界行为。
        assert_eq!(PII_MAX_ENTRIES, 1000);
        let scope = PiiScope::new();
        // 命中复用：同值注册返回同一 token，还原一致。
        let a = scope.register("13812345678", false).unwrap();
        assert_eq!(scope.register("13812345678", false).unwrap(), a);
        assert!(scope.restore(&format!("回拨 {a}")).contains("13812345678"));
        // 首条 + 999 条 = 1000 满容量，下一序号为 1001。
        for i in 0..999 {
            scope.register(&format!("b4-val-{i:04}"), false).unwrap();
        }
        assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
        // 再注一条触发淘汰：最旧（首 token）被逐出，空洞 1 可复用。
        scope.register("b4-val-0999", false).unwrap();
        assert!(!scope.contains_request_token(&a), "最久条目须被淘汰");
        assert_eq!(scope.next_available_index(), 1);
    }

    #[test]
    fn f5_cursor_alloc_is_linear_no_full_rebuild() {
        // F5/D4：K 次顺序注册探测步数线性（游标分配），不随每次注册全量重建。
        let scope = PiiScope::new();
        const K: usize = PII_MAX_ENTRIES;
        for i in 0..K {
            scope.register(&format!("f5-linear-{i:04}"), false).unwrap();
        }
        let inner = recover_mutex(scope.inner.lock());
        assert_eq!(
            inner.scan_steps, K,
            "顺序分配每注册恰探测一次候选（实际 {}）；旧全量重建为 O(K^2)",
            inner.scan_steps
        );
    }

    #[test]
    fn f5_hole_reuse_after_eviction_no_conflict() {
        // F5：淘汰释放的序号被后续注册复用，且不与在用序号冲突。
        let scope = PiiScope::new();
        let first = scope.register("f5-first", false).unwrap();
        let first_seq = parse_pii_seq(&first).unwrap();
        for i in 0..PII_MAX_ENTRIES - 1 {
            scope.register(&format!("f5-fill-{i:04}"), false).unwrap();
        }
        scope.register("f5-overflow", false).unwrap();
        assert!(!scope.contains_request_token(&first), "最旧条目须被淘汰");
        let reused = scope.register("f5-reused", false).unwrap();
        assert_eq!(parse_pii_seq(&reused), Some(first_seq), "空洞须被复用");
        let inner = recover_mutex(scope.inner.lock());
        let all: Vec<usize> = inner
            .pii_t2p
            .keys()
            .chain(inner.resp_t2p.keys())
            .filter_map(|t| parse_pii_seq(t))
            .collect();
        let uniq: HashSet<usize> = all.iter().copied().collect();
        assert_eq!(uniq.len(), all.len(), "两表在用序号不得重复");
        assert_eq!(inner.used_seqs, uniq, "已用集须与表内容一致");
    }

    #[test]
    fn f5_upper_bound_unique_and_in_range() {
        // F5：单请求注册至 PII_MAX_ENTRIES，序号互不重复且落在 [1, PII_MAX_ENTRIES]。
        let scope = PiiScope::new();
        let mut seqs = Vec::new();
        for i in 0..PII_MAX_ENTRIES {
            let tok = scope.register(&format!("f5-bound-{i:04}"), false).unwrap();
            seqs.push(parse_pii_seq(&tok).unwrap());
        }
        assert_eq!(seqs.len(), PII_MAX_ENTRIES);
        let uniq: HashSet<usize> = seqs.iter().copied().collect();
        assert_eq!(uniq.len(), PII_MAX_ENTRIES, "序号不得重复");
        assert!(
            seqs.iter().all(|s| (1..=PII_MAX_ENTRIES).contains(s)),
            "序号须落在 [1, {PII_MAX_ENTRIES}]"
        );
    }

    #[test]
    fn fuzzy_case_insensitive_restore() {
        let scope = PiiScope::new();
        let token = scope.register("13812345678", false).unwrap();
        let seq: usize = token
            .strip_prefix("__PII_")
            .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
            .flatten()
            .unwrap();
        // 大写变体同样按序号回查（IGNORECASE 口径）。
        let upper = format!("__PII_{seq}_ZZZZABCD__");
        assert!(pii_loose_re().is_match(&upper), "宽松形态须忽略大小写");
        let restored = scope.restore_with_fuzzy(&format!("回拨 {upper}"), true);
        assert!(restored.contains("13812345678"), "{restored}");
    }

    /// B3/D3：锁中毒后隔离判定返回真实值、计数正常、注册/还原无 panic。
    #[test]
    fn pii_poison_recovery() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        let scope = PiiScope::new();
        let tok = scope.register("13812345678", false).unwrap();
        for poison in 0..2 {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if poison == 0 {
                    let _guard = scope.inner.lock().unwrap();
                    panic!("注入 inner 锁中毒");
                }
                let _guard = scope.malformed.lock().unwrap();
                panic!("注入 malformed 锁中毒");
            }));
        }
        assert!(
            scope.contains_request_token(&tok),
            "中毒后隔离判定须返回真实结果（不得静默 false）"
        );
        assert_eq!(scope.count_malformed("__PII_9_ab12cd34__"), "unregistered");
        assert_eq!(scope.count_malformed("__PII_x__"), "malformed");
        let tok2 = scope.register("13900000001", false).unwrap();
        assert!(scope.contains_request_token(&tok2));
        assert!(scope.restore(&tok2).contains("13900000001"));
    }
}

/// T7 vault 回补：空洞跳过/rand8 不可枚举/100 并发 gather/同值复用。
#[cfg(test)]
mod vault_parity_tests {
    use {
        super::{PII_MAX_ENTRIES, PiiScope, gen_rand8, parse_pii_seq, pii_token_re},
        std::sync::Arc,
    };

    fn rand8_of(token: &str) -> &str {
        let rest = token.strip_prefix("__PII_").expect("须为 PII token");
        rest.split('_')
            .nth(1)
            .expect("须含 rand8 段")
            .trim_end_matches('_')
    }

    #[test]
    fn t7_same_value_reuses_token_both_tables() {
        let scope = PiiScope::new();
        let a = scope.register("13812345678", false).unwrap();
        assert_eq!(scope.register("13812345678", false).unwrap(), a);
        let r = scope.register("resp-value-001", true).unwrap();
        assert_eq!(scope.register("resp-value-001", true).unwrap(), r);
        // 请求/响应表隔离：同值跨表 token 不同。
        let cross = scope.register("13812345678", true).unwrap();
        assert_ne!(cross, a);
    }

    #[test]
    fn t7_hole_reused_after_eviction() {
        let scope = PiiScope::new();
        assert_eq!(PII_MAX_ENTRIES, 1000, "请求/响应单表容量分表锁定");
        for i in 0..PII_MAX_ENTRIES {
            scope.register(&format!("hole-val-{i:04}"), false).unwrap();
        }
        assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
        scope.register("hole-val-overflow", false).unwrap();
        assert_eq!(scope.next_available_index(), 1, "淘汰最旧后空洞 1 须可复用");
        let reused = scope.register("hole-val-new", false).unwrap();
        assert_eq!(parse_pii_seq(&reused), Some(1), "新值须跳回空洞 1");
    }

    #[test]
    fn t7_write_pii_does_not_evict_resp_table() {
        let scope = PiiScope::new();
        let rt = scope.register("resp-keep-001", true).unwrap();
        for i in 0..PII_MAX_ENTRIES {
            scope.register(&format!("pii-fill-{i:04}"), false).unwrap();
        }
        scope.register("pii-overflow-001", false).unwrap();
        assert!(
            scope.restore(&rt).contains(&rt),
            "写请求表不得淘汰响应表，响应 token 须原样保留"
        );
    }

    #[test]
    fn t7_rand8_unenumerable_shape_and_entropy() {
        let scope = PiiScope::new();
        let mut tokens = Vec::new();
        for i in 0..10 {
            let tok = scope.register(&format!("13800000{i:03}"), false).unwrap();
            assert!(pii_token_re().is_match(&tok), "{tok}");
            tokens.push(tok);
        }
        assert_eq!(
            tokens
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            10
        );
        let rand8s: Vec<&str> = tokens.iter().map(|t| rand8_of(t)).collect();
        assert!(rand8s.iter().all(|r| r.len() == 8));
        assert!(
            rand8s
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 1
        );
        for _ in 0..10 {
            assert_eq!(gen_rand8().unwrap().len(), 8);
        }
    }

    #[test]
    fn b6_rand8_batch_unique_and_holes_ordered() {
        // B6.1：批量生成无碰撞、无可预测序列；连续空洞按序复用。
        let scope = PiiScope::new();
        let mut tokens = Vec::new();
        for i in 0..100 {
            let tok = scope.register(&format!("b6-batch-{i:03}"), false).unwrap();
            assert!(pii_token_re().is_match(&tok), "{tok}");
            tokens.push(tok);
        }
        assert_eq!(
            tokens
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            100,
            "批量 token 不得碰撞"
        );
        let rand8s: Vec<&str> = tokens.iter().map(|t| rand8_of(t)).collect();
        assert!(
            rand8s
                .iter()
                .all(|r| r.len() == 8 && r.chars().all(|c| c.is_ascii_hexdigit()))
        );
        assert!(
            rand8s
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                >= 95,
            "rand8 须无可预测序列"
        );
        // 连续空洞复用顺序：填满后溢出 1 条（淘汰 seq 1，空洞 1），后续新值依次取 1/2/3，
        // 每取一洞淘汰下一最旧（稳态下标口径）。
        for i in 100..PII_MAX_ENTRIES {
            scope.register(&format!("b6-fill-{i:04}"), false).unwrap();
        }
        assert_eq!(scope.next_available_index(), PII_MAX_ENTRIES + 1);
        scope.register("b6-overflow-0", false).unwrap();
        assert_eq!(scope.next_available_index(), 1);
        for (i, expect) in [1usize, 2, 3].iter().enumerate() {
            let tok = scope.register(&format!("b6-reuse-{i}"), false).unwrap();
            assert_eq!(parse_pii_seq(&tok), Some(*expect), "{tok}");
        }
    }

    #[test]
    fn b6_fuzzy_illegal_matrix_state_unchanged() {
        // B6.2：fuzzy 非法形态矩阵均被拒绝还原（原样保留），vault 状态不变。
        let scope = PiiScope::new();
        let tok = scope.register("13812345678", false).unwrap();
        for bad in [
            "__PII__",
            "__PII_x_",
            "__PII_999_zzzz__",
            "__VG_CRED_000001__",
            "not-a-token",
        ] {
            let out = scope.restore_with_fuzzy(&format!("回拨 {bad} 结束"), true);
            assert_eq!(out, format!("回拨 {bad} 结束"), "{bad}");
            assert!(!scope.contains_request_token(bad), "{bad}");
        }
        // 精确形态但未注册：非 fuzzy 下原样保留（fuzzy 下按序号回查为已知值，口径有意不同）。
        let unknown_exact = "__PII_1_ab12cd34__";
        assert_eq!(
            scope.restore_with_fuzzy(&format!("回拨 {unknown_exact}"), false),
            format!("回拨 {unknown_exact}")
        );
        // 非法输入不污染状态：已注册值仍精确还原。
        assert_eq!(scope.restore(&tok), "13812345678");
    }

    #[test]
    fn t7_response_side_token_not_restored() {
        let scope = PiiScope::new();
        let rt = scope.register("13900000001", true).unwrap();
        assert_eq!(scope.restore(&rt), rt);
        let qt = scope.register("13900000002", false).unwrap();
        assert_eq!(scope.restore(&qt), "13900000002");
    }

    #[tokio::test]
    async fn t7_100_way_join_set_no_conflict() {
        let scope = Arc::new(PiiScope::new());
        let mut set = tokio::task::JoinSet::new();
        for i in 0..100 {
            let s = scope.clone();
            set.spawn(async move { s.register(&format!("join-val-{i:03}"), false).unwrap() });
        }
        let mut toks = Vec::new();
        while let Some(r) = set.join_next().await {
            toks.push(r.expect("任务须成功"));
        }
        toks.sort();
        toks.dedup();
        assert_eq!(toks.len(), 100, "100 并发注册不得冲突");
        let mut seqs: Vec<usize> = toks.iter().filter_map(|t| parse_pii_seq(t)).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (1..=100).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn t7_concurrent_duplicate_reuse_single_token() {
        let scope = Arc::new(PiiScope::new());
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..100 {
            let s = scope.clone();
            set.spawn(async move { s.register("13812345678", false).unwrap() });
        }
        let mut toks = Vec::new();
        while let Some(r) = set.join_next().await {
            toks.push(r.expect("任务须成功"));
        }
        toks.sort();
        toks.dedup();
        assert_eq!(toks.len(), 1, "同值并发须复用同一 token");
        assert_eq!(scope.next_available_index(), 2);
    }
}
