//! 凭据 token：`__CRED_%06d__` 全局映射 +
//! 请求级作用域隔离 + 残缺清理 + 凭据优先。
//!
//! owner 声明：token 映射实体（`CredentialVault/TOKEN_PREFIX/MAX_TOKEN_ENTRIES`）
//! 归本文件；KeePass 查询与注册/吊销运维归 `service::credential::vault_ops`
//! （其经本文件做取值 token 化）；两处职责正交、互不垫片。
//!
//! 口径：token 零填充 6 位序号、
//! 同明文复用与 `MAX_TOKEN_ENTRIES=5000` 有界 LRU、
//! 按明文长度降序单次替换、`_strip_partials` 接全出口。

use {
    crate::service::lock_recover::lock_or_recover,
    std::{
        collections::{HashMap, VecDeque},
        sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard},
    },
};

/// 凭据占位符前缀。
pub const TOKEN_PREFIX: &str = "__CRED_";
/// 凭据占位符后缀。
pub const TOKEN_SUFFIX: &str = "__";
/// 全局凭据映射上限（LRU 淘汰最久未用）。
pub const MAX_TOKEN_ENTRIES: usize = 5000;
/// 凭据最小长度（字符数），过短不注册直接透传。
pub const SECRET_MIN_LENGTH: usize = 4;
/// alternation 正则编译上限：超限/失败回退为原文单次扫描替换，不 panic。
const REGEX_SIZE_LIMIT_BYTES: usize = 1 << 20;

/// 构造 `__CRED_%06d__` token（序号溢出时自然增长位数）。
pub fn make_cred_token(n: u64) -> String { format!("{TOKEN_PREFIX}{n:06}{TOKEN_SUFFIX}") }

fn token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"__CRED_\d{4,}__").expect("凭据 token 正则恒合法"))
}

/// 凭据残缺形态（分片切断的前缀），对标 `_PARTIAL_TOKEN_RE`。
/// 收窄口径：仅确证占位符残缺形态（`__C` + 可选续写 `RED` + 可选 `_数字`）
/// 且后随边界（空白/标点/串尾）时剥离；后续为合法单词字符的正文
/// （如 `__CREDENTIALS`）一律不剥离。完整形态 `__CRED_\d{4,}__` 由
/// 负向前瞻豁免（镜像 `strip_pii_partials`），使其原样透传、免于误剥。
///
/// 跨族闭合豁免：`__C` 的两条 `_` 若实为**前一完整 token 的闭合界定**
/// （前文恰为完整 PII `__PII_\d+_[0-9a-fA-F]{8}` 或完整 CRED `__CRED_\d{4,}`），
/// 则其后的 `__C`（如 `__PII_1_ab12cd34__C`）不得判为残缺——否则会腐蚀前一
/// 完整 token 并吞掉字面 `C`。故在 `__C` 前施加跨族负向后顾。
fn cred_partial_re() -> &'static fancy_regex::Regex {
    static RE: OnceLock<fancy_regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(
            r"(?<!__PII_\d+_[0-9a-fA-F]{8})(?<!__CRED_\d{4,})__C(?!RED_\d{4,}__)(?:R(?:E(?:D(?:_?\d*)?)?)?)?(?:_*$|(?=\s|[^\w]))",
        )
        .expect("凭据残缺正则恒合法")
    })
}

/// 清理凭据残缺前缀（流分片切断的 `__C` / `__CRED_000` 等半截形态）。
pub fn strip_cred_partials(text: &str) -> String {
    cred_partial_re().replace_all(text, "").into_owned()
}

/// 注册拒绝原因：值命中内部 token 形态或前缀。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultReject(&'static str);

impl std::fmt::Display for VaultReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(self.0) }
}

/// 明文→token 映射快照：含预编译 alternation 正则；
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

    /// 按快照替换（预编译正则；编译失败走原文单次扫描回退，输出逐字节一致）。
    pub fn redact(&self, text: &str) -> String { self.redact_tracked(text, &mut |_| {}) }

    /// 按快照替换并回传**实际产出**的 token（minted-set 依据）：`on_minted`
    /// 在**每个真正发生替换的出现点**以替换值调用（同键出现两次即回调两次，
    /// alternation 与单次扫描回退两条路径口径一致）；未命中键与字面 token 均不产出。
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
            None => replace_by_map_scan(
                text,
                &sorted_keys_desc(&self.map),
                &self.map,
                &mut |_key: &str, token: &str| on_minted(token),
            ),
        }
    }
}

#[derive(Debug)]
struct P2tCache {
    generation: u64,
    snapshot: Arc<P2tSnapshot>,
}

/// alternation 正则编译/回退首次告警（异常路径，避免每帧日志刷屏；口径要求
/// 回退记录告警）。经日志层输出：`main` 已装订阅者，默认 `warn` 级别下可见。
fn warn_alternation_fallback_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "警告: 凭据 map alternation 正则编译超限/失败，已回退原文单次扫描替换（首次告警）"
        );
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

/// 编译失败/超限回退的**单一**实现：对**原文**单次左→右扫描、不得重扫替换产物，依赖
/// `sorted_keys_desc` 的键长降序以保证与 alternation 路径的最长优先语义等价；命中回调
/// `on_match(key, value)` 一次并前进键长，未命中按当前字符 `len_utf8()` 前进；空映射原样返回。
fn replace_by_map_scan(
    text: &str,
    keys_desc: &[&String],
    map: &HashMap<String, String>,
    on_match: &mut dyn FnMut(&str, &str),
) -> String {
    if map.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        match keys_desc.iter().find(|k| rest.starts_with(k.as_str())) {
            Some(key) => {
                let value = map.get(key.as_str()).map_or(key.as_str(), String::as_str);
                on_match(key.as_str(), value);
                out.push_str(value);
                rest = &rest[key.len()..];
            }
            None => {
                let Some(ch) = rest.chars().next() else { break };
                out.push(ch);
                rest = &rest[ch.len_utf8()..];
            }
        }
    }
    out
}

/// 编译失败/超限回退：委托 [`replace_by_map_scan`]（仅异常路径付 O(k·n)）。
fn replace_per_key(text: &str, map: &HashMap<String, String>) -> String {
    replace_by_map_scan(text, &sorted_keys_desc(map), map, &mut |_, _| {})
}

/// 全局凭据映射：`RwLock<HashMap>` + 有界 LRU（上限 [`MAX_TOKEN_ENTRIES`]）。
/// 读多写少，`RwLock` 保证并发脱敏/还原原子执行不串扰。
#[derive(Debug, Default)]
pub struct CredentialVault {
    inner: RwLock<VaultInner>,
    /// 复杂度回归观测（仅测试）：全量快照调用计数。
    #[cfg(test)]
    snapshot_calls: std::sync::atomic::AtomicUsize,
    /// 复杂度回归观测（仅测试）：p2t 快照重建计数。
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
    /// 每帧仅 Arc 克隆，不深克隆映射、不重编译正则。
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

    /// 单 token 还原直查：同一把读锁一次查表，不克隆全表、
    /// 不重建 alternation 正则；未注册返回 `None`（调用方自决回退）。
    /// 已注册 token 的结果与全量 `restore` 的同 token 子串一致。
    pub fn restore_one(&self, token: &str) -> Option<String> {
        read_inner(&self.inner).token_to_pwd.get(token).cloned()
    }

    /// 全量快照调用计数（仅测试可见；复杂度回归断言用）。
    #[cfg(test)]
    pub fn snapshot_calls(&self) -> usize {
        self.snapshot_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// p2t 快照重建计数（仅测试；复杂度回归断言用）。
    #[cfg(test)]
    pub fn p2t_build_calls(&self) -> usize {
        self.p2t_build_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 将 token 还原为凭据明文。
    pub fn restore(&self, text: &str) -> String { replace_all_by_map(text, &self.snapshot_t2p()) }
}

fn touch(order: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = order.iter().position(|v| v == value) {
        order.remove(pos);
    }
    order.push_back(value.to_string());
}

/// 按 map 键长度降序单次 alternation 替换（单一来源）：`restore` 传
/// token→明文（还原），`redact_with_map` 传明文→token（脱敏），方向差异由
/// 入参 map 承载；命中键替换为值，未命中保持原样。键经 `regex::escape`，
/// 等长键次序不影响结果（等长不同键互不为前缀）。
pub fn replace_all_by_map(text: &str, map: &HashMap<String, String>) -> String {
    replace_all_by_map_limited(text, map, REGEX_SIZE_LIMIT_BYTES)
}

/// 带显式大小上限的 alternation 替换：编译失败/超限回退为原文单次扫描，不 panic。
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
mod tests;
