//! 自定义规则与字典：三槽加载 + ReDoS 守卫扫描 + 字典独立扫描。
//!
//! H7/D7 锁序不变量：`account_rule` 内 **`strikes` 先于 `disabled`**（两把 std
//! `Mutex` 恒按此序获取，后续新增获取点须遵循）；审查清单真源见 design D7，
//! 源码扫描守护见 `service::declaration_lock::lock_order_invariants`。

use {
    super::{
        super::json_walk::SCAN_INPUT_LIMIT,
        chunk::{credential_spans, overlaps_any, protected_spans, split_chunks},
        detector::{BUILTIN_NAMES, PiiDetector, PiiHit, RE_DOS_BUDGET_MS, RE_DOS_STRIKES},
    },
    std::{
        collections::{HashMap, HashSet},
        sync::atomic::AtomicBool,
        time::Duration,
    },
};

/// T3/7.2 ReDoS 扫描墙钟绝对上界（毫秒）：对抗输入必须在
/// [`RE_DOS_BUDGET_MS`] 预算断言与连续三次禁用记账之外，以本明确绝对常量内返回
/// （独立兜底锁；公式：预算 100ms + 调度/阻塞池余量）。
pub const REDOS_WALL_CLOCK_CEILING_MS: u64 = 400;

/// 全局首次中毒告警位（进程级 once 语义）。
static POISON_WARNED: AtomicBool = AtomicBool::new(false);

/// P14/D1 锁中毒恢复：`PoisonError::into_inner` 返回可用守卫，首次恢复 warn 一次。
/// 与 `scope.rs::recover_mutex` 同形；泛型覆盖 `Mutex`/`RwLock` 全部守卫类型，
/// 中毒后按当前内存状态继续服务（`scan` 读当前映射，`load_*` 全量覆盖写自愈）。
fn warn_poison_once() -> bool { warn_poison_once_at(&POISON_WARNED) }

/// 可注入标志位的告警实现（测试隔离用；`warn_poison_once` 置位全局标志）。
fn warn_poison_once_at(flag: &AtomicBool) -> bool {
    let first = !flag.swap(true, std::sync::atomic::Ordering::Relaxed);
    if first {
        tracing::warn!("PII custom 检测器锁中毒，已 PoisonError::into_inner 恢复（首次告警）");
    }
    first
}

/// 锁访问统一入口：中毒即恢复并首次告警，绝不 panic。
fn recover<T>(lock: std::sync::LockResult<T>) -> T {
    lock.unwrap_or_else(|e: std::sync::PoisonError<T>| {
        warn_poison_once();
        e.into_inner()
    })
}

/// 按字符截断（hint cap 用，不按字节切 `CJK`）。
fn truncate_chars(s: &str, cap: usize) -> String { s.chars().take(cap).collect() }

/// 跳过 `pattern[start..]` 处的一个平衡圆括号组（含转义与字符类），
/// 返回组结束后下标；不平衡返回 `None`。用于跳过零宽断言与命名组前缀。
fn skip_group(pattern: &str, start: usize) -> Option<usize> {
    let bytes = pattern.as_bytes();
    if bytes.get(start) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b']' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// 从正则 `pattern` 保守提取起始字面前缀：跳过行首锚点/组前缀/零宽断言，
/// 收集字面段至首个元字符；转义标点计入字面，转义类（`\d` 等）终止。
/// 无可提取字面前缀返回空串（该规则退化为缝窗保护）。
fn regex_literal_prefix(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'^' => {
                if out.is_empty() {
                    i += 1;
                    continue;
                }
                break;
            }
            b'(' => {
                if !out.is_empty() {
                    break;
                }
                let rest = &pattern[i..];
                let next = if rest.starts_with("(?P<") {
                    rest.find('>').map(|p| i + p + 1)
                } else if rest.starts_with("(?:") {
                    Some(i + 3)
                } else if rest.starts_with("(?=")
                    || rest.starts_with("(?!")
                    || rest.starts_with("(?<=")
                    || rest.starts_with("(?<!")
                {
                    skip_group(pattern, i)
                } else if rest.starts_with("(?") {
                    None
                } else {
                    Some(i + 1)
                };
                match next {
                    Some(n) => {
                        i = n;
                        continue;
                    }
                    None => break,
                }
            }
            b'\\' => {
                let Some(next) = bytes.get(i + 1).copied() else {
                    break;
                };
                if next.is_ascii_alphanumeric() {
                    break;
                }
                out.push(next as char);
                i += 2;
                continue;
            }
            b'.' | b'*' | b'+' | b'?' | b'[' | b'{' | b'|' | b'$' | b')' => break,
            _ => {}
        }
        let ch = pattern[i..].chars().next().unwrap_or('\u{0}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

impl PiiDetector {
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
    /// 对标原仓口径：与内置重名 / 跨文件重名 / 编译失败 / 含 `\b` /
    /// 嵌套命名组 / 自检异常一律拒绝加载；内命名组与外层 name 失配允许
    /// （命中分类以外层 name 为准，原仓同口径，不因此拒载）。
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
                let names = recover(self.custom_names.read());
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
                let mut custom = recover(self.custom.write());
                let mut names = recover(self.custom_names.write());
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

    /// 三槽叠加加载：`PII_CUSTOM_RULES` 合并槽 + `PATTERNS` 分离槽 + `DICT` 名单槽
    /// 一次调用全部载入并叠加生效（各槽独立去重，跨槽同名不互斥）。
    /// 返回 `(正则条数, 字典条数)`。
    pub fn load_custom_all(
        &self,
        patterns: &[(String, String)],
        dict: &[(String, String)],
    ) -> (usize, usize) {
        let n = self.load_custom_patterns(patterns);
        self.load_dict(dict);
        let m = recover(self.dict.read()).len();
        (n, m)
    }

    /// 已加载的自定义规则名（断言/可观测用）。
    pub fn custom_names_snapshot(&self) -> Vec<String> {
        recover(self.custom_names.read()).iter().cloned().collect()
    }

    /// 已停用的自定义规则名（连续超时 3 次）。
    pub fn disabled_snapshot(&self) -> Vec<String> {
        recover(self.disabled.lock()).iter().cloned().collect()
    }

    /// P1/D2 跨帧前缀 hold 的 hint 集：自定义正则可提取字面前缀 + 字典全名，
    /// cap 64 字符、按长度降序去重；无可提取前缀的规则不产生 hint（退化为缝窗保护）。
    pub fn partial_prefix_hints(&self) -> Vec<String> {
        const CAP: usize = 64;
        let mut hints: Vec<String> = Vec::new();
        for (_, _, pattern) in recover(self.custom.read()).iter() {
            let prefix = regex_literal_prefix(pattern);
            if !prefix.is_empty() {
                hints.push(truncate_chars(&prefix, CAP));
            }
        }
        for (name, _) in recover(self.dict.read()).iter() {
            if !name.is_empty() {
                hints.push(truncate_chars(name, CAP));
            }
        }
        hints.sort_by(|a, b| {
            b.chars()
                .count()
                .cmp(&a.chars().count())
                .then_with(|| a.cmp(b))
        });
        hints.dedup();
        hints
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
        *recover(self.dict.write()) = sorted;
        *recover(self.dict_re.write()) = compiled;
    }

    /// 字典命中边界：对标 Python `_dict_boundary_ok`（硬化门控差异化）。
    /// `name/person` 在强化开时走严格 CJK 边界（双侧 CJK 表意 ∪ Unicode 字母数字），
    /// 关闭时退化为「before 仅 ASCII 字母数字、after 仅 CJK 表意文字」边界，
    /// 避免 `é`/`ñ` 等西文变音字母数字误拒（后接真正 CJK 仍阻断，保张三丰不误伤）；
    /// 其余类型仅挡 ASCII 字母数字粘连。
    fn dict_boundary_ok(text: &str, start: usize, end: usize, typ: &str, strict_cjk: bool) -> bool {
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let is_cjk_ideograph = |c: char| ('\u{4e00}'..='\u{9fff}').contains(&c);
        let is_alnum_or_cjk = |c: char| is_cjk_ideograph(c) || c.is_alphanumeric();
        if typ == "name" || typ == "person" {
            if strict_cjk {
                if before.is_some_and(is_alnum_or_cjk) || after.is_some_and(is_alnum_or_cjk) {
                    return false;
                }
                return true;
            }
            let ascii_before = before.is_some_and(|c| c.is_ascii() && c.is_alphanumeric());
            if ascii_before || after.is_some_and(is_cjk_ideograph) {
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
        let dict_re = recover(self.dict_re.read());
        let Some(re) = dict_re.as_ref() else {
            return Vec::new();
        };
        let dict = recover(self.dict.read());
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
            if !Self::dict_boundary_ok(text, s, e, typ, self.hardening()) {
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
        let custom: Vec<(String, fancy_regex::Regex, String)> = recover(self.custom.read()).clone();
        if custom.is_empty() || text.is_empty() {
            return Vec::new();
        }
        let disabled: HashSet<String> = recover(self.disabled.lock()).clone();
        let protected = protected_spans(text);
        let cred = credential_spans(text, credential_p2t);
        let chunks: Vec<(usize, String)> = split_chunks(text, SCAN_INPUT_LIMIT, 256);
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
    pub(crate) fn account_rule(&self, name: &str, timed_out: bool) {
        let mut strikes = recover(self.strikes.lock());
        let mut disabled = recover(self.disabled.lock());
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
}

#[cfg(test)]
mod tests;
