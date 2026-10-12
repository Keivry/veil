//! 请求级 PII token 容器：注册/还原/序号空洞复用/LRU 淘汰。

use {
    super::detector::{
        PII_MAX_ENTRIES,
        PII_TOKEN_PREFIX,
        cred_token_shape_re,
        pii_loose_re,
        pii_token_re,
    },
    crate::service::lock_recover::lock_or_recover,
    rand::{rand_core::TryRng as _, rngs::SysRng},
    std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::Mutex,
    },
};

/// 构造 `__PII_<seq>_<rand8>__` token。
pub fn make_pii_token(seq: usize, rand8: &str) -> String {
    format!("{PII_TOKEN_PREFIX}{seq}_{rand8}__")
}

/// 生成 8 位十六进制随机段（`SysRng::try_fill_bytes`，CSPRNG）。
pub fn gen_rand8() -> Result<String, &'static str> {
    let mut buf = [0u8; 4];
    SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| "CSPRNG 熵源不可用")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) fn parse_pii_seq(token: &str) -> Option<usize> {
    let rest = token.strip_prefix(PII_TOKEN_PREFIX)?;
    let (seq, _) = rest.split_once('_')?;
    seq.parse().ok()
}

/// 请求级 PII token 容器（请求隔离形态）。
///
/// - `pii_*`：请求期映射，可还原；
/// - 同值复用同一 token；空洞跳过稳态下标；并发注册经 `Mutex` 原子执行；
/// - PII 还原只查本 Scope，MUST NOT 触达全局凭据映射。
#[derive(Debug, Default)]
pub struct PiiScope {
    inner: Mutex<ScopeInner>,
    /// 仅测试：强制 `register` 走熵源故障分支（fail-closed 注入）。
    #[cfg(test)]
    force_entropy_failure: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Default)]
struct ScopeInner {
    pii_p2t: HashMap<String, String>,
    pii_t2p: HashMap<String, String>,
    pii_order: VecDeque<String>,
    /// 请求表分配游标：下一个候选序号（1 起），与 `req_used` 配套均摊 O(1)。
    req_next_seq: usize,
    /// 请求表在用序号（分配插入、淘汰移除）。
    req_used: HashSet<usize>,
    /// 分配探测步数（仅测试观测线性有界；生产零成本）。
    #[cfg(test)]
    scan_steps: usize,
}

impl ScopeInner {
    /// 游标 + 已用集分配：自游标起找首个未用序号，越顶回卷；
    /// 表全满时返回 `PII_MAX_ENTRIES + 1`（与旧 `next_hole` 全占语义一致，
    /// 紧随的 LRU 淘汰会把空洞重新释放）。
    fn alloc_seq(&mut self) -> usize {
        let max = PII_MAX_ENTRIES;
        let next = &mut self.req_next_seq;
        let used = &self.req_used;
        let start = (*next).max(1);
        let mut probes = 0usize;
        let mut find_free = |from: usize| -> usize {
            let mut seq = from;
            while seq <= max {
                probes += 1;
                if !used.contains(&seq) {
                    return seq;
                }
                seq += 1;
            }
            max + 1
        };
        let mut seq = find_free(if start > max { 1 } else { start });
        if seq > max {
            seq = find_free(1);
        }
        *next = if seq >= max { 1 } else { seq + 1 };
        #[cfg(test)]
        {
            self.scan_steps += probes;
        }
        #[cfg(not(test))]
        {
            let _ = probes;
        }
        seq
    }

    /// 回收淘汰条目的序号（空洞复用来源）。
    fn release_seq(&mut self, token: &str) {
        if let Some(seq) = parse_pii_seq(token) {
            self.req_used.remove(&seq);
        }
    }
}

/// PII 值注册失败分类：token 形态拒绝与熵源/内部故障 MUST NOT
/// 共用同一错误分支——前者静默跳过，后者 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiRegisterError {
    /// 值本身即内部 token 形态或含保留前缀（`__PII_`/`__CRED_`）→ 静默跳过。
    TokenShape,
    /// rand8 的 `SysRng` 熵源/内部生成不可用 → fail-closed。
    EntropyUnavailable,
}

impl std::fmt::Display for PiiRegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TokenShape => "PII 值不能匹配内部 token 格式或以 token 前缀开头",
            Self::EntropyUnavailable => "CSPRNG 熵源不可用",
        })
    }
}

impl PiiScope {
    /// 新建空 Scope（每请求一个，请求结束即销毁）。
    pub fn new() -> Self { Self::default() }

    /// 空洞跳过：返回**请求表**序号空间最小空闲序号（仅测试口径；
    /// 分配本身走 [`ScopeInner::alloc_seq`] 游标，不做全量重建）。
    #[cfg(test)]
    fn next_available_index(&self) -> usize {
        let inner = lock_or_recover(self.inner.lock());
        let mut seq = 1;
        while inner.req_used.contains(&seq) {
            seq += 1;
        }
        seq
    }

    /// 仅测试：强制 `register` 走熵源故障分支（fail-closed 注入）。
    #[cfg(test)]
    pub(crate) fn force_entropy_failure(&self, on: bool) {
        self.force_entropy_failure
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// 注册 PII 值并返回 token。同值复用；token 形态值拒绝注册。
    /// 失败分类见 [`PiiRegisterError`]：token 形态静默跳过，熵源故障 fail-closed。
    pub fn register(&self, value: &str) -> Result<String, PiiRegisterError> {
        self.register_tracked(value).map(|(token, _reused)| token)
    }

    /// 注册并返回 `(token, reused)`：`reused=true` 表示值**已在本表**（命中既有映射、
    /// 未新铸占位符）。复用判定与注册在**同一临界区**内完成，无「先查后插」竞态；
    /// 其余语义（拒绝分类/失败分类）与 [`PiiScope::register`] 完全一致。
    /// 空值恒返回 `(原值, true)`（非新铸、非复用命中点，仅透传）。
    pub fn register_tracked(&self, value: &str) -> Result<(String, bool), PiiRegisterError> {
        if value.is_empty() {
            return Ok((value.to_string(), true));
        }
        if pii_token_re().is_match(value)
            || value.contains(PII_TOKEN_PREFIX)
            || value.contains(crate::service::credential_vault::TOKEN_PREFIX)
            || cred_token_shape_re().is_match(value)
        {
            return Err(PiiRegisterError::TokenShape);
        }
        #[cfg(test)]
        if self
            .force_entropy_failure
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tracing::warn!("PII 令牌生成熵源不可用（测试注入），请求将 fail-closed");
            return Err(PiiRegisterError::EntropyUnavailable);
        }
        let mut inner = lock_or_recover(self.inner.lock());
        if let Some(tok) = inner.pii_p2t.get(value).cloned() {
            touch_order(&mut inner.pii_order, value);
            return Ok((tok, true));
        }
        let seq = inner.alloc_seq();
        let Ok(rand8) = gen_rand8() else {
            tracing::warn!("PII 令牌生成熵源不可用，请求将 fail-closed");
            return Err(PiiRegisterError::EntropyUnavailable);
        };
        let token = make_pii_token(seq, &rand8);
        if inner.pii_p2t.len() >= PII_MAX_ENTRIES
            && let Some(oldest) = inner.pii_order.pop_front()
            && let Some(old_tok) = inner.pii_p2t.remove(&oldest)
        {
            inner.pii_t2p.remove(&old_tok);
            inner.release_seq(&old_tok);
        }
        inner.req_used.insert(seq);
        inner.pii_order.push_back(value.to_string());
        inner.pii_p2t.insert(value.to_string(), token.clone());
        inner.pii_t2p.insert(token.clone(), value.to_string());
        Ok((token, false))
    }

    /// 还原请求期注册 token；响应期/未注册/格式不符原样保留。
    /// 只查本 Scope，绝不触达全局凭据映射。
    pub fn restore(&self, text: &str) -> String { self.restore_with_fuzzy(text, false) }

    /// 宽松还原：`fuzzy=false` 与 [`PiiScope::restore`] 一致；`fuzzy=true`
    /// （`PII_FUZZY_RESTORE`）时残留宽松形态按序号回查请求表，截断/改写后的
    /// token 仍可还原；未知序号一律原样保留。
    pub fn restore_with_fuzzy(&self, text: &str, fuzzy: bool) -> String {
        let restored = self.restore_exact_parts(text);
        if !fuzzy {
            return restored;
        }
        let (known, seq_map) = {
            let inner = lock_or_recover(self.inner.lock());
            if inner.pii_t2p.is_empty() {
                return restored;
            }
            let known: HashSet<String> = inner.pii_t2p.keys().cloned().collect();
            let seq_map: HashMap<usize, String> = inner
                .pii_t2p
                .iter()
                .filter_map(|(tok, plain)| parse_pii_seq(tok).map(|s| (s, plain.clone())))
                .collect();
            (known, seq_map)
        };
        if seq_map.is_empty() {
            return restored;
        }
        pii_loose_re()
            .replace_all(&restored, |caps: &regex::Captures| {
                let tok = &caps[0];
                if known.contains(tok) {
                    return tok.to_string();
                }
                match parse_pii_seq(tok).and_then(|s| seq_map.get(&s).cloned()) {
                    Some(plain) => plain,
                    None => tok.to_string(),
                }
            })
            .into_owned()
    }

    /// 精确还原本体（`restore`/`restore_with_fuzzy` 共用）：命中提升 LRU。
    fn restore_exact_parts(&self, text: &str) -> String {
        if text.is_empty() {
            return text.to_string();
        }
        let (restored, req_hits) = {
            let inner = lock_or_recover(self.inner.lock());
            if inner.pii_t2p.is_empty() {
                return text.to_string();
            }
            let mut req_hits: Vec<String> = Vec::new();
            let restored = pii_token_re()
                .replace_all(text, |caps: &regex::Captures| {
                    let tok = &caps[0];
                    if let Some(plain) = inner.pii_t2p.get(tok) {
                        req_hits.push(plain.clone());
                        plain.clone()
                    } else {
                        tok.to_string()
                    }
                })
                .into_owned();
            (restored, req_hits)
        };
        if !req_hits.is_empty() {
            let mut inner = lock_or_recover(self.inner.lock());
            for value in &req_hits {
                touch_order(&mut inner.pii_order, value);
            }
        }
        restored
    }

    /// 是否持有该请求 token（跨请求还原隔离断言用）。
    /// 中毒恢复后返回真实结果，不得静默降级为「不包含」。
    /// 仅测试口径：生产零调用，`#[cfg(test)]` 收编，
    /// 对齐 [`PiiScope::next_available_index`] 的既有处置，release 构建不含该符号。
    #[cfg(test)]
    fn contains_request_token(&self, token: &str) -> bool {
        lock_or_recover(self.inner.lock())
            .pii_t2p
            .contains_key(token)
    }

    /// 单会话作用域聚合上界断言用（仅测试）：请求表当前条目数。
    /// 不改变 token 语义，仅暴露只读计数。
    #[cfg(test)]
    pub(crate) fn table_sizes(&self) -> usize { lock_or_recover(self.inner.lock()).pii_p2t.len() }
}

fn touch_order(order: &mut VecDeque<String>, value: &str) {
    if let Some(pos) = order.iter().position(|v| v == value) {
        order.remove(pos);
    }
    order.push_back(value.to_string());
}

#[cfg(test)]
mod tests;
