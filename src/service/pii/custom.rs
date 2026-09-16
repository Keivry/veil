//! 自定义规则与字典：三槽加载 + ReDoS 守卫扫描 + 字典独立扫描。
//!
//! H7/D7 锁序不变量：`account_rules_batch` 内 **`strikes` 先于 `disabled`**（两把 std
//! `Mutex` 恒按此序获取，后续新增获取点须遵循）；审查清单真源见 design D7，源码扫描守护
//! 见 `service::declaration_lock::lock_order_invariants`（按 `account_rule` 前缀定位函数体，
//! 故批量实现须定义在测试用薄封装之前）。

use {
    super::{
        super::json_walk::SCAN_INPUT_LIMIT,
        chunk::{credential_spans, overlaps_any, protected_spans, split_chunks},
        detector::{BUILTIN_NAMES, PiiDetector, PiiHit, RE_DOS_BUDGET_MS, RE_DOS_STRIKES},
    },
    crate::{
        config::custom_file::strip_yaml_quotes,
        service::lock_recover::lock_or_recover as recover,
    },
    std::{
        collections::{HashMap, HashSet},
        sync::Arc,
        time::Duration,
    },
};

/// T3/7.2 ReDoS 扫描墙钟绝对上界（毫秒）：对抗输入必须在
/// [`RE_DOS_BUDGET_MS`] 预算断言与连续三次禁用记账之外，以本明确绝对常量内返回
/// （独立兜底锁；公式：预算 100ms + 调度/阻塞池余量）。
#[cfg(test)]
pub(crate) const REDOS_WALL_CLOCK_CEILING_MS: u64 = 400;

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
                // ARH-4：唯一写点经 `Arc::make_mut`——无外部强引用时零拷贝原地 push，
                // 扫描期存在共享引用时按 CoW 克隆，只读共享语义不被破坏。
                Arc::make_mut(&mut custom).push((name.clone(), compiled, pattern.clone()));
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
    #[cfg(test)]
    pub(crate) fn custom_names_snapshot(&self) -> Vec<String> {
        recover(self.custom_names.read()).iter().cloned().collect()
    }

    /// 已停用的自定义规则名（连续超时 3 次）。
    pub fn disabled_snapshot(&self) -> Vec<String> {
        recover(self.disabled.lock()).iter().cloned().collect()
    }

    /// P1/D2 跨帧前缀 hold 的 hint 集：自定义正则可提取字面前缀 + 字典全名，
    /// 单条 cap 64 字符、**总条数上限 64**（去重后按长度降序保留前 64，对齐 Python
    /// `partial_prefix_hints` 总条数上限，见 `pii-parity-closeout` spec）；
    /// 无可提取前缀的规则不产生 hint（退化为缝窗保护）。
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
        hints.truncate(CAP);
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

    /// 自定义正则扫描（ReDoS 守卫）：整帧以**单次** `spawn_blocking` 批量扫描
    /// 全部规则与分块（规则集 `Arc` 只读共享，扫描路径仅 `Arc::clone`）；逐规则
    /// `find_iter` Err 经批量记账停用，聚合墙钟超时仅一条全局 warn（零命中不记账）；
    /// 与逐规则逐分块扫描结果等价。
    pub async fn scan_custom(
        &self,
        text: &str,
        credential_p2t: &HashMap<String, String>,
    ) -> Vec<PiiHit> {
        let rules: Arc<Vec<(String, fancy_regex::Regex, String)>> =
            Arc::clone(&*recover(self.custom.read()));
        if rules.is_empty() || text.is_empty() {
            return Vec::new();
        }
        let disabled: HashSet<String> = recover(self.disabled.lock()).clone();
        let protected = protected_spans(text);
        let cred = credential_spans(text, credential_p2t);
        let chunks: Vec<(usize, String)> = split_chunks(text, SCAN_INPUT_LIMIT, 256);
        // ARH-4（7.3）：规则集一次性移入单任务并只读共享（`Arc`），无每规则/每分块任务 churn。
        let scan_rules = Arc::clone(&rules);
        let scan_disabled = disabled.clone();
        let batch = tokio::task::spawn_blocking(move || {
            let mut found: Vec<(usize, usize, usize, String)> = Vec::new();
            let mut timed_out: Vec<usize> = Vec::new();
            for (ri, (name, compiled, _src)) in scan_rules.iter().enumerate() {
                if scan_disabled.contains(name) {
                    continue;
                }
                let mut rule_ok = true;
                for (offset, chunk) in &chunks {
                    match compiled.find_iter(chunk).collect::<Result<Vec<_>, _>>() {
                        Ok(spans) => {
                            for m in spans {
                                found.push((
                                    ri,
                                    offset + m.start(),
                                    offset + m.end(),
                                    m.as_str().to_string(),
                                ));
                            }
                        }
                        Err(_) => {
                            rule_ok = false;
                            break;
                        }
                    }
                }
                if !rule_ok {
                    timed_out.push(ri);
                }
            }
            (found, timed_out)
        });
        // 每规则一档 `RE_DOS_BUDGET_MS` 的聚合上界（真挂起才触发全局跳过：零命中且不记账）。
        let budget =
            Duration::from_millis(RE_DOS_BUDGET_MS).saturating_mul(rules.len().max(1) as u32);
        let (found, timed_out) = match tokio::time::timeout(budget, batch).await {
            Ok(Ok(out)) => out,
            // D3：聚合墙钟超时（或阻塞任务 panic）**SHALL NOT** 对任何规则记账——逐规则
            // 停用仅由 batch 内 `find_iter` Err 路径触发；此处仅一条全局 warn（含规则数
            // 与预算）并返回零命中。
            _ => {
                tracing::warn!(
                    "自定义正则聚合扫描超时或阻塞任务异常：规则数 {}、预算 {}ms，本帧返回零命中（不记账）",
                    rules.len(),
                    budget.as_millis()
                );
                return Vec::new();
            }
        };
        let timed_out_names: HashSet<&str> = timed_out
            .iter()
            .filter_map(|ri| rules.get(*ri))
            .map(|(n, ..)| n.as_str())
            .collect();
        let mut hits = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        for (ri, s, e, value) in found {
            if !seen.insert((s, e)) {
                continue;
            }
            // 区间保护：与占位符/凭据重叠整体跳过。
            if overlaps_any(&protected, s, e) || overlaps_any(&cred, s, e) {
                continue;
            }
            if credential_p2t.contains_key(&value) {
                continue;
            }
            let Some((name, ..)) = rules.get(ri) else {
                continue;
            };
            hits.push((name.clone(), value, s, e));
        }
        // ARH-4：锁外批量结算——单次获取 `strikes` → `disabled`；成功清零、超时累计、
        // 连续 3 次停用并告警，已停用者跳过。
        let outcomes: Vec<(&str, bool)> = rules
            .iter()
            .map(|(name, ..)| (name.as_str(), timed_out_names.contains(name.as_str())))
            .collect();
        self.account_rules_batch(&outcomes);
        hits
    }

    /// 批量超时记账（ARH-4）：单次获取 `strikes` → `disabled`（锁序见模块头不变量），
    /// 逐规则成功清零 / 超时累计 / 连续 [`RE_DOS_STRIKES`] 次停用并告警，已停用者跳过。
    /// D3：聚合超时**不**走本函数；调用方仅传 batch 内逐规则 `find_iter` Err 结果。
    pub(crate) fn account_rules_batch(&self, outcomes: &[(&str, bool)]) {
        let mut strikes = recover(self.strikes.lock());
        let mut disabled = recover(self.disabled.lock());
        for (name, timed_out) in outcomes {
            if disabled.contains(*name) {
                continue;
            }
            if !*timed_out {
                strikes.remove(*name);
                continue;
            }
            let c = strikes.entry((*name).to_string()).or_insert(0);
            *c += 1;
            if *c >= RE_DOS_STRIKES {
                disabled.insert((*name).to_string());
                tracing::warn!("自定义正则 {name} 连续 {} 次超时，临时停用", RE_DOS_STRIKES);
            } else {
                tracing::warn!("自定义正则 {name} 扫描超时（第 {c} 次），跳过该规则");
            }
        }
    }

    /// 单规则记账薄封装（`&[(name, timed_out)]` 单元素调用）；仅供既有测试面复用，
    /// 生产扫描一律经 [`Self::account_rules_batch`] 批量结算。
    #[cfg(test)]
    pub(crate) fn account_rule(&self, name: &str, timed_out: bool) {
        self.account_rules_batch(&[(name, timed_out)]);
    }
}

// ---------------------------------------------------------------------------
// `DCD-1`：启动装配从配置文件读取并抽取运行时注入内容
// ---------------------------------------------------------------------------

/// 自定义文件抽取结果：`(正则 [(name, pattern)], 字典 [(name, type)])`。
pub type CustomFileEntries = (Vec<(String, String)>, Vec<(String, String)>);

/// 从三个自定义配置文件路径读取并解析出 `(规则, 字典)`，供 `AppState` 启动装配
/// 注入检测器（`DCD-1`）。格式与 `config::custom_file::load_custom_file` 一致
/// （JSON / 极简 YAML / TXT 名单）；文件在配置加载期已 fail-closed 校验，此处仅
/// 运行时再读抽取，读取/解析失败仍返回 `Err`（调用方按 fail-closed 拒启动）。
pub fn load_custom_from_paths(
    rules_file: Option<&std::path::Path>,
    patterns_file: Option<&std::path::Path>,
    dict_file: Option<&std::path::Path>,
) -> std::result::Result<CustomFileEntries, String> {
    let mut patterns = Vec::new();
    for path in [rules_file, patterns_file].into_iter().flatten() {
        patterns.extend(extract_patterns(&read_custom_value(path, false)?));
    }
    let mut dict = Vec::new();
    if let Some(path) = dict_file {
        dict.extend(extract_dict(&read_custom_value(path, true)?));
    }
    Ok((patterns, dict))
}

/// 读取并解析自定义文件为 JSON 值：TXT 走名单，`.yaml`/`.yml` 走极简 YAML，
/// 其余 JSON 优先、失败回退 YAML（字典槽再回退 TXT 名单）。
fn read_custom_value(
    path: &std::path::Path,
    is_dict: bool,
) -> std::result::Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("自定义 PII 文件读取失败 {}: {e}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    if ext.as_deref() == Some("txt") {
        return Ok(txt_list(&text));
    }
    if matches!(ext.as_deref(), Some("yaml") | Some("yml")) {
        return serde_json::from_str(&text)
            .or_else(|_| yaml_subset(&text))
            .map_err(|e| format!("自定义 PII 文件解析失败 {}: {e}", path.display()));
    }
    match serde_json::from_str(&text) {
        Ok(v) => Ok(v),
        Err(json_err) => match yaml_subset(&text) {
            Ok(v) => Ok(v),
            Err(_) if is_dict => Ok(txt_list(&text)),
            Err(_) => Err(format!(
                "自定义 PII 文件解析失败 {}: {json_err}",
                path.display()
            )),
        },
    }
}

/// TXT 名单：每行一名，`#` 整行/行尾注释忽略。
fn txt_list(text: &str) -> serde_json::Value {
    let items = text
        .lines()
        .filter_map(|line| {
            let name = line.split('#').next().unwrap_or("").trim();
            (!name.is_empty()).then(|| serde_json::Value::String(name.to_string()))
        })
        .collect();
    serde_json::Value::Array(items)
}

/// 极简 YAML 子集（与 `config::custom_file` 同款解析语义的最小交集）：
/// 支持 `- name: foo` + `pattern: bar` 列表映射、`- somename` 字符串列表、
/// `key: value` 顶层映射；`#` 注释与空行忽略。
fn yaml_subset(text: &str) -> std::result::Result<serde_json::Value, String> {
    use serde_json::{Map, Value as V};
    let mut items: Vec<V> = Vec::new();
    let mut mapping = Map::new();
    let mut has_mapping_line = false;
    let mut has_list_line = false;
    let mut current: Option<Map<String, V>> = None;
    let flush = |current: &mut Option<Map<String, V>>, items: &mut Vec<V>| {
        if let Some(m) = current.take()
            && !m.is_empty()
        {
            items.push(V::Object(m));
        }
    };
    for (idx, raw_line) in text.lines().enumerate() {
        let no_comment = match raw_line.find('#') {
            Some(p) => &raw_line[..p],
            None => raw_line,
        };
        if no_comment.trim().is_empty() {
            continue;
        }
        let indent = no_comment.len() - no_comment.trim_start().len();
        let t = no_comment.trim();
        if let Some(dash_rest) = t.strip_prefix('-') {
            has_list_line = true;
            flush(&mut current, &mut items);
            let rest = dash_rest.trim();
            if rest.is_empty() {
                current = Some(Map::new());
                continue;
            }
            if let Some(colon) = rest.find(':') {
                let (k, v) = rest.split_at(colon);
                let v = v[1..].trim();
                if k.trim().is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                let mut m = Map::new();
                m.insert(k.trim().to_string(), V::String(strip_yaml_quotes(v)));
                current = Some(m);
            } else {
                items.push(V::String(strip_yaml_quotes(rest)));
                current = None;
            }
            continue;
        }
        if let Some(colon) = t.find(':') {
            let (k, v) = t.split_at(colon);
            let (k, v) = (k.trim(), v[1..].trim());
            if k.is_empty() || k.contains(' ') && indent == 0 && has_list_line {
                return Err(format!("第 {} 行形态非法: {t:?}", idx + 1));
            }
            if indent == 0 && current.is_none() && !has_list_line {
                has_mapping_line = true;
                mapping.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
            } else {
                if k.is_empty() {
                    return Err(format!("第 {} 行键为空", idx + 1));
                }
                match current.as_mut() {
                    Some(m) => {
                        m.insert(k.to_string(), V::String(strip_yaml_quotes(v)));
                    }
                    None => return Err(format!("第 {} 行缩进键无归属列表项: {t:?}", idx + 1)),
                }
            }
            continue;
        }
        return Err(format!("第 {} 行无法解析: {t:?}", idx + 1));
    }
    flush(&mut current, &mut items);
    if has_mapping_line && !has_list_line {
        return Ok(V::Object(mapping));
    }
    if !items.is_empty() {
        return Ok(V::Array(items));
    }
    if has_mapping_line {
        return Ok(V::Object(mapping));
    }
    Err("空 YAML 文档".to_string())
}

/// 抽取正则规则 `(name, pattern)`：数组对象形、`name: pattern` 映射形，
/// 以及顶层 `patterns:` 合并段。
fn extract_patterns(value: &serde_json::Value) -> Vec<(String, String)> {
    use serde_json::Value as V;
    match value {
        V::Array(items) => items
            .iter()
            .filter_map(|it| {
                let o = it.as_object()?;
                let name = o.get("name")?.as_str()?.trim();
                let pattern = o.get("pattern")?.as_str()?;
                (!name.is_empty() && !pattern.is_empty())
                    .then(|| (name.to_string(), pattern.to_string()))
            })
            .collect(),
        V::Object(map) => {
            if let Some(inner) = map.get("patterns") {
                return extract_patterns(inner);
            }
            map.iter()
                .filter_map(|(k, v)| {
                    let p = v.as_str().filter(|s| !s.is_empty())?;
                    (!k.trim().is_empty()).then(|| (k.clone(), p.to_string()))
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

/// 抽取字典 `(name, type)`：`{name,type}`/字符串数组形、`name: type` 映射形，
/// 以及顶层 `names:` 合并段；缺省 `type` 为 `name`。
fn extract_dict(value: &serde_json::Value) -> Vec<(String, String)> {
    use serde_json::Value as V;
    match value {
        V::Array(items) => items
            .iter()
            .filter_map(|it| match it {
                V::String(s) if !s.trim().is_empty() => Some((s.trim().to_string(), "name".into())),
                V::Object(o) => {
                    let name = o.get("name")?.as_str()?.trim();
                    if name.is_empty() {
                        return None;
                    }
                    let typ = o
                        .get("type")
                        .and_then(|t| t.as_str())
                        .filter(|t| !t.trim().is_empty())
                        .unwrap_or("name");
                    Some((name.to_string(), typ.to_string()))
                }
                _ => None,
            })
            .collect(),
        V::Object(map) => {
            if let Some(inner) = map.get("names") {
                return extract_dict(inner);
            }
            map.iter()
                .filter_map(|(k, v)| {
                    let typ = v.as_str().filter(|s| !s.trim().is_empty())?;
                    (!k.trim().is_empty()).then(|| (k.clone(), typ.to_string()))
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
