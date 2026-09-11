//! 自定义规则与字典：三槽加载 + ReDoS 守卫扫描 + 字典独立扫描。

use {
    super::{
        super::json_walk::SCAN_INPUT_LIMIT,
        chunk::{credential_spans, overlaps_any, protected_spans, split_chunks},
        detector::{BUILTIN_NAMES, PiiDetector, PiiHit, RE_DOS_BUDGET_MS, RE_DOS_STRIKES},
    },
    std::{
        collections::{HashMap, HashSet},
        time::Duration,
    },
};

/// T3/7.2 ReDoS 扫描墙钟绝对上界（毫秒）：对抗输入必须在
/// [`RE_DOS_BUDGET_MS`] 预算断言与连续三次禁用记账之外，以本明确绝对常量内返回
/// （独立兜底锁；公式：预算 100ms + 调度/阻塞池余量）。
pub const REDOS_WALL_CLOCK_CEILING_MS: u64 = 400;

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
        let m = self.dict.read().map(|g| g.len()).unwrap_or_default();
        (n, m)
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

    /// 字典命中边界：对标 Python `_dict_boundary_ok`（硬化门控差异化）。
    /// `name/person` 在强化开时走严格 CJK 边界，关闭时退化为 ASCII 字母数字边界
    /// （后接 CJK 仍阻断，保张三丰不误伤）；其余类型仅挡 ASCII 字母数字粘连。
    fn dict_boundary_ok(text: &str, start: usize, end: usize, typ: &str, strict_cjk: bool) -> bool {
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let is_cjk = |c: char| ('\u{4e00}'..='\u{9fff}').contains(&c) || c.is_alphanumeric();
        if typ == "name" || typ == "person" {
            if strict_cjk {
                if before.is_some_and(is_cjk) || after.is_some_and(is_cjk) {
                    return false;
                }
                return true;
            }
            let ascii_before = before.is_some_and(|c| c.is_ascii() && c.is_alphanumeric());
            if ascii_before || after.is_some_and(is_cjk) {
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
        let custom: Vec<(String, fancy_regex::Regex, String)> =
            self.custom.read().map(|g| g.clone()).unwrap_or_default();
        if custom.is_empty() || text.is_empty() {
            return Vec::new();
        }
        let disabled: HashSet<String> = self.disabled.lock().map(|g| g.clone()).unwrap_or_default();
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
}

#[cfg(test)]
mod tests {
    use {
        crate::service::pii::detector::{
            RE_DOS_BUDGET_MS,
            test_support::{detector, empty_cred},
        },
        std::time::Duration,
    };

    #[tokio::test]
    async fn b4_cjk_mixed_and_reserved_edges() {
        use super::super::detector::is_reserved_ip;
        assert!(is_reserved_ip("10.1.2.3", "ipv4"));
        assert!(!is_reserved_ip("8.8.8.8", "ipv4"));
        assert!(is_reserved_ip("fc00::1", "ipv6"));
        assert!(!is_reserved_ip("2001:4860:4860::8888", "ipv6"));
        let d = detector();
        d.load_custom_patterns(&[(
            "emp_no".to_string(),
            r"(?P<emp_no>(?<![\d])工号\d{6}(?![\d]))".to_string(),
        )]);
        let hits = d
            .scan_custom("Hi联系工号123456处理Done 上线", &empty_cred())
            .await;
        assert!(hits.iter().any(|h| h.1 == "工号123456"), "{hits:?}");
        d.load_dict(&[("张三".to_string(), "name".to_string())]);
        let hits = d.scan_dict_sync("Hi 张三，Done 来了", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
        // ASCII 字母数字紧贴粘连按边界口径阻断（防误伤，不断字即正确）。
        let hits = d.scan_dict_sync("Hi张三Done 来了", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
        let hits = d.scan_dict_sync("中文测试文本", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "中文测试文本"), "{hits:?}");
    }

    #[test]
    fn custom_regex_with_word_boundary_rejected() {
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
    async fn malicious_pattern_fast_reject_and_disable_after_three_timeouts() {
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

    #[tokio::test]
    async fn redos_wall_clock_absolute_ceiling_beyond_budget_assertion() {
        // T3/7.2：对抗输入在明确绝对上界常量内返回，不依赖 `RE_DOS_BUDGET_MS`
        // 预算断言，也不依赖连续三次禁用的记账路径（独立兜底锁）。
        let d = detector();
        d.load_custom_patterns(&[("evil-abs".to_string(), r"^(a+)+$".to_string())]);
        let input = format!("{}b", "a".repeat(2000));
        let start = std::time::Instant::now();
        let hits = d.scan_custom(&input, &empty_cred()).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(super::REDOS_WALL_CLOCK_CEILING_MS),
            "对抗扫描须在绝对上界 {}ms 内返回，实际 {elapsed:?}",
            super::REDOS_WALL_CLOCK_CEILING_MS
        );
        assert!(hits.iter().all(|h| h.0 != "evil-abs"), "{hits:?}");
        assert!(
            !d.disabled_snapshot().contains(&"evil-abs".to_string()),
            "单次超时不得触发三连禁用记账（上界与记账解耦）"
        );
    }

    #[test]
    fn dict_standalone_scan_with_cjk_boundary() {
        let d = detector();
        d.load_dict(&[
            ("张三".to_string(), "name".to_string()),
            ("db-prod-01".to_string(), "hostname".to_string()),
        ]);
        // 标点分界命中（严格 CJK 边界：两侧非 CJK 字母数字）。
        let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
        // 张三丰不误伤（后接 CJK 即阻断，双模式一致）。
        let hits = d.scan_dict_sync("张三丰来了", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
        // 非硬化：前接 CJK 按原仓口径放行（before 仅 ASCII 门）；
        // 硬化开：前接 CJK 阻断（严格 CJK 边界）。
        let hits = d.scan_dict_sync("我张三", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
        d.set_hardening(true);
        let hits = d.scan_dict_sync("我张三", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "张三"), "{hits:?}");
        let hits = d.scan_dict_sync("hi 张三，你好", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
        // 主机名 ASCII 粘连不命中。
        let hits = d.scan_dict_sync("abcdb-prod-01x", &empty_cred());
        assert!(hits.iter().all(|h| h.1 != "db-prod-01"));
        let hits = d.scan_dict_sync("主机 db-prod-01 在线", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "db-prod-01"));
    }

    #[test]
    fn named_group_inner_mismatch_uses_outer_name() {
        let d = detector();
        // 原仓口径：内命名组与外层失配允许加载（分类以外层 name 为准）。
        let n = d.load_custom_patterns(&[(
            "emp_no".to_string(),
            "(?P<other>(?<![\\d])AB\\d{6}(?![\\d]))".to_string(),
        )]);
        assert_eq!(n, 1, "内命名组失配按原仓口径放行");
        assert!(d.custom_names_snapshot().contains(&"emp_no".to_string()));
        let n = d.load_custom_patterns(&[("plain".to_string(), "ZZ-\\d{6}".to_string())]);
        assert_eq!(n, 1, "无命名组必须放行");
    }

    #[test]
    fn nested_group_and_duplicate_name_rejected() {
        let d = detector();
        let n = d.load_custom_patterns(&[(
            "nested".to_string(),
            "(?P<nested>a(?P<inner>b)c)".to_string(),
        )]);
        assert_eq!(n, 0, "嵌套命名组必须拒绝");
        let n = d.load_custom_patterns(&[("dup".to_string(), "DUP-\\d+".to_string())]);
        assert_eq!(n, 1);
        let n = d.load_custom_patterns(&[("dup".to_string(), "DUP-\\d+".to_string())]);
        assert_eq!(n, 0, "跨文件重名必须去重拒绝");
        assert_eq!(
            d.custom_names_snapshot()
                .iter()
                .filter(|n| *n == "dup")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn custom_overlap_placeholder_skipped_and_disabled_skipped() {
        let d = detector();
        d.load_custom_patterns(&[("tag".to_string(), "TAG-\\d+".to_string())]);
        let hits = d
            .scan_custom("已有 __PII_1_ab12cd34__ 与 TAG-99", &empty_cred())
            .await;
        assert!(hits.iter().any(|h| h.1 == "TAG-99"), "{hits:?}");
        let hits = d
            .scan_custom("data:image/png;base64,TAG-99", &empty_cred())
            .await;
        assert!(
            hits.is_empty(),
            "与 data URL 保护区间重叠必须跳过: {hits:?}"
        );
        d.account_rule("tag", true);
        d.account_rule("tag", true);
        d.account_rule("tag", true);
        assert!(d.disabled_snapshot().contains(&"tag".to_string()));
        let hits = d.scan_custom("TAG-77 独立出现", &empty_cred()).await;
        assert!(
            hits.iter().all(|h| h.0 != "tag"),
            "停用规则必须跳过: {hits:?}"
        );
    }

    #[tokio::test]
    async fn custom_pattern_cjk_adjacent_match() {
        let d = detector();
        d.load_custom_patterns(&[(
            "工号".to_string(),
            "(?P<工号>(?<![\\d])工号\\d{6}(?![\\d]))".to_string(),
        )]);
        let hits = d.scan_custom("联系工号123456处理", &empty_cred()).await;
        assert!(
            hits.iter().any(|h| h.1 == "工号123456"),
            "CJK 紧贴必须命中: {hits:?}"
        );
    }

    #[test]
    fn named_group_mismatch_relaxed_to_legacy() {
        let d = detector();
        // 内命名组与外层 name 不同名：原仓口径允许加载（分类以外层为准）。
        let n = d.load_custom_patterns(&[(
            "outer".to_string(),
            r"(?P<inner>(?<![\d])工号\d{6}(?![\d]))".to_string(),
        )]);
        assert_eq!(n, 1);
        assert!(d.custom_names_snapshot().contains(&"outer".to_string()));
    }

    #[test]
    fn three_slot_custom_dict_combined() {
        let d = detector();
        let (n, m) = d.load_custom_all(
            &[(
                "emp_no".to_string(),
                r"(?<![\d])工号\d{6}(?![\d])".to_string(),
            )],
            &[("张三".to_string(), "name".to_string())],
        );
        assert_eq!((n, m), (1, 1));
        let hits = d.scan_dict_sync("hi 张三，工号123456", &empty_cred());
        assert!(hits.iter().any(|h| h.1 == "张三"), "{hits:?}");
    }

    #[test]
    fn dict_scan_excluded_from_combined_regex() {
        let d = detector();
        d.load_dict(&[("张三".to_string(), "name".to_string())]);
        // 联合正则扫描不含字典命中（独立扫描语义）。
        let builtin = super::super::chunk::scan_builtin_sync("hi 张三，你好", &empty_cred());
        assert!(builtin.iter().all(|h| h.1 != "张三"), "{builtin:?}");
        let dict = d.scan_dict_sync("hi 张三，你好", &empty_cred());
        assert!(dict.iter().any(|h| h.1 == "张三"), "{dict:?}");
    }

    #[test]
    fn perf_5000_dict_scan_time_anchor() {
        let d = detector();
        let entries: Vec<(String, String)> = (0..5000)
            .map(|i| (format!("敏感词{i:05}号"), "name".to_string()))
            .collect();
        let start = std::time::Instant::now();
        d.load_dict(&entries);
        let text = "公告 敏感词01234号 与 敏感词04999号 上线";
        let hits = d.scan_dict_sync(text, &empty_cred());
        let elapsed = start.elapsed();
        assert!(
            hits.iter().any(|h| h.1 == "敏感词01234号"),
            "5000 字典首段须命中: {hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.1 == "敏感词04999号"),
            "5000 字典尾段须命中: {hits:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "5000 字典加载+扫描须 <10s，实测 {elapsed:?}"
        );
    }
}
