//! 跨帧占位符缝合 carry：token 被上游按 JSON 内容值切开时，把帧尾合法残缺前缀移入请求级
//! carry，下一帧与续段拼回完整 token 交既有还原路径。
//!
//! 帧各为独立 JSON 文档（如 `__CRE` + `D_000001__`），无法在原始字节层缝合；
//! `TokenCarry::prepare` 按**结构路径**（`Seg`）为每个字符串值定位实例：单趟三阶段
//! （stitch → absorb → 重建）合并同路径续段、回吐失配残段、为新候选建立独立持有。
//! 路径由保序 [`serde_json::Value`] 走查生成并与既有 `json_string_values` 逐位对齐；
//! 长度不等（重复键等异常帧）降级 key-only，绝不 panic。
//!
//! 候选判定沿用 **marker 前缀感知**：值尾部最长 `[A-Za-z0-9_]` run 的候选后缀（marker
//! 前缀或既有 `cred_prefix_re`/`pii_prefix_re`），覆盖 `_`│`_`、`__`│`PII_` 等任意切点。
//! 续段无法续写时执行 **fail-open 释放**：pending 原样前置**仅同路径**值，零字符丢失；
//! `TokenCarry::drain` 返回未配对残段供终端按形态释放/剥离，不再静默 `clear`。

use {
    regex::Regex,
    serde_json::Value,
    std::{borrow::Cow, sync::OnceLock},
};

/// 单实例残段上界（字符）：超过即不可能续写为完整 token，立即回吐。
const PENDING_MAX: usize = 64;

/// carry 条目上界：同帧多实例并行的持有总数上限，超限新候选不持有（原地保留并计数）。
pub(crate) const PENDING_MAX_ENTRIES: usize = 16;

/// 路径分段：对象成员键，或数组/身份槽位索引。
///
/// `Idx` 编码：`i=<index>` / `o=<output_index>` / `s=<summary_index>` /
/// `c=<content_index>` / `m=<item_id|call_id|tool_call_id|id>` / `t=<type>` /
/// `#<pos>`（位序回退）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Seg {
    /// 对象成员键名。
    Key(String),
    /// 实例身份编码（`<tag>=<value>`）。
    Idx(String),
}

/// 未配对残段：来源字符串值的完整结构路径与残段文本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Residual {
    /// 残段来源的结构路径（释放派生载体）。
    pub path: Vec<Seg>,
    /// 残段文本（仅 `[A-Za-z0-9_]`）。
    pub literal: String,
}

/// 单个持有的残缺前缀（路径 + 文本）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    path: Vec<Seg>,
    literal: String,
}

/// 单趟重建动作：替换 `[start, end)` 为 `replacement`。
struct Action {
    start: usize,
    end: usize,
    replacement: String,
}

/// 请求级跨帧 carry：至多持 `PENDING_MAX_ENTRIES` 个（各自独立的实例路径）token 残缺前缀。
#[derive(Debug, Default)]
pub(crate) struct TokenCarry {
    pendings: Vec<Pending>,
    over_limit_dropped: u64,
}

impl TokenCarry {
    pub(crate) fn new() -> Self { Self::default() }

    /// 是否持有未配对残段（单测断言）。
    #[cfg(test)]
    fn has_pending(&self) -> bool { !self.pendings.is_empty() }

    /// 取出并清零「条目上界外新候选未持有」累计次数（供 event_loop 排入网关指标）。
    pub(crate) fn take_over_limit_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.over_limit_dropped)
    }

    /// 帧入口：stitch 既有持有（同路径续段/完整 token/失配回吐），再从**未被 stitch 触碰**
    /// 的值吸收新残缺前缀（同帧允许多个，受条目上界约束）。
    pub(crate) fn prepare<'a>(&mut self, frame: &'a str, parsed: &Value) -> Cow<'a, str> {
        self.process(frame, parsed, true)
    }

    /// 终止帧入口（stitch-only）：只补全/消费既有持有，SHALL NOT 从终止帧吸收新候选。
    pub(crate) fn prepare_terminal<'a>(&mut self, frame: &'a str, parsed: &Value) -> Cow<'a, str> {
        self.process(frame, parsed, false)
    }

    /// 取出全部未配对残段（按持有顺序）：调用方按终端形态决定 fail-open 回吐或剥离。
    pub(crate) fn drain(&mut self) -> Vec<Residual> {
        self.pendings
            .drain(..)
            .map(|p| Residual {
                path: p.path,
                literal: p.literal,
            })
            .collect()
    }

    fn process<'a>(&mut self, frame: &'a str, parsed: &Value, absorb: bool) -> Cow<'a, str> {
        let values = json_string_values(frame);
        if values.is_empty() {
            return Cow::Borrowed(frame);
        }
        let paths = value_paths(parsed, &values);
        let mut actions: Vec<Action> = Vec::new();
        // 每值经 stitch 后的实际输出（`None` 表示未被 stitch 触碰）。absorb 据此
        // 对「已补全既有持有」的值继续摘除其**新**帧尾残缺，杜绝半截前缀泄漏。
        let mut effective: Vec<Option<String>> = vec![None; values.len()];
        self.stitch(frame, &values, &paths, &mut effective, &mut actions);
        if absorb {
            self.absorb(frame, &values, &paths, &effective, &mut actions);
        }
        if actions.is_empty() {
            return Cow::Borrowed(frame);
        }
        Cow::Owned(rebuild(frame, &mut actions))
    }

    /// 阶段 1（stitch）：对每个值，仅当存在**路径精确相等**的持有才参与——完整 token 命中
    /// 原位写回并消费持有；合法残缺续写并入该持有；否则 fail-open 原位前置回吐。
    /// 每值的实际输出写入 `effective`，供 absorb 继续摘除其新帧尾残缺。
    fn stitch(
        &mut self,
        frame: &str,
        values: &[(usize, usize, Option<&str>)],
        paths: &[Vec<Seg>],
        effective: &mut [Option<String>],
        actions: &mut Vec<Action>,
    ) {
        if self.pendings.is_empty() {
            return;
        }
        let mut matched = vec![false; self.pendings.len()];
        let mut remove = vec![false; self.pendings.len()];
        for i in 0..values.len() {
            let (start, end, _) = values[i];
            let path = &paths[i];
            let Some(pi) =
                (0..self.pendings.len()).find(|&p| !matched[p] && &self.pendings[p].path == path)
            else {
                continue;
            };
            matched[pi] = true;
            let value = &frame[start..end];
            let pending_lit = self.pendings[pi].literal.clone();
            let combined = format!("{pending_lit}{value}");
            if let Some(tok_len) = complete_token_len(&combined) {
                // 防御性下溢保护（`is_candidate_run` 已排除完整形态，正常不可达）。
                let consumed = tok_len.saturating_sub(pending_lit.len());
                if consumed <= value.len() {
                    let mut out = String::with_capacity(tok_len + value.len() - consumed);
                    out.push_str(&combined[..tok_len]);
                    out.push_str(&value[consumed..]);
                    effective[i] = Some(out.clone());
                    actions.push(Action {
                        start,
                        end,
                        replacement: out,
                    });
                    remove[pi] = true;
                    continue;
                }
            }
            if combined.len() > pending_lit.len()
                && combined.len() <= PENDING_MAX
                && is_candidate_run(&combined)
            {
                self.pendings[pi].literal = combined;
                effective[i] = Some(String::new());
                actions.push(Action {
                    start,
                    end,
                    replacement: String::new(),
                });
                continue;
            }
            let mut out = String::with_capacity(pending_lit.len() + value.len());
            out.push_str(&pending_lit);
            out.push_str(value);
            effective[i] = Some(out.clone());
            actions.push(Action {
                start,
                end,
                replacement: out,
            });
            remove[pi] = true;
        }
        if remove.iter().any(|&r| r) {
            let mut keep = Vec::with_capacity(self.pendings.len());
            for (p, r) in self.pendings.drain(..).zip(remove) {
                if !r {
                    keep.push(p);
                }
            }
            self.pendings = keep;
        }
    }

    /// 阶段 2（absorb）：对每个值从其（经 stitch 后的实际输出）尾部摘除合法候选后缀建立
    /// 独立持有——既能处理未被 stitch 触碰的值，也能处理「本帧刚补全既有持有、尾部又挂
    /// 新残缺前缀」的值；条目上界外的新候选不持有（原地保留）并计数。同路径已有持有则不重复建立。
    fn absorb(
        &mut self,
        frame: &str,
        values: &[(usize, usize, Option<&str>)],
        paths: &[Vec<Seg>],
        effective: &[Option<String>],
        actions: &mut Vec<Action>,
    ) {
        for i in 0..values.len() {
            let (start, end, _) = values[i];
            let value: &str = effective[i]
                .as_deref()
                .unwrap_or_else(|| &frame[start..end]);
            if value.is_empty() {
                continue;
            }
            let Some((cand_start, cand)) = candidate_suffix_in(value) else {
                continue;
            };
            let path = &paths[i];
            if self.pendings.iter().any(|p| &p.path == path) {
                continue;
            }
            if self.pendings.len() >= PENDING_MAX_ENTRIES {
                self.over_limit_dropped += 1;
                continue;
            }
            self.pendings.push(Pending {
                path: path.clone(),
                literal: cand.to_string(),
            });
            let stripped = value[..cand_start].to_string();
            match actions
                .iter_mut()
                .find(|a| a.start == start && a.end == end)
            {
                Some(action) => action.replacement = stripped,
                None => actions.push(Action {
                    start,
                    end,
                    replacement: stripped,
                }),
            }
        }
    }
}

impl TokenCarry {
    /// 单测访问器：持有条数。
    #[cfg(test)]
    fn pending_count(&self) -> usize { self.pendings.len() }

    /// 单测访问器：按路径查询持有的残段文本。
    #[cfg(test)]
    fn pending_literal_for(&self, path: &[Seg]) -> Option<&str> {
        self.pendings
            .iter()
            .find(|p| p.path == path)
            .map(|p| p.literal.as_str())
    }
}

/// 单趟沿原帧字节序重建输出（动作按起点升序，区间互不重叠）。
fn rebuild(frame: &str, actions: &mut [Action]) -> String {
    actions.sort_by_key(|a| a.start);
    let mut out = String::with_capacity(frame.len());
    let mut cursor = 0;
    for a in actions.iter() {
        if a.start < cursor {
            continue;
        }
        out.push_str(&frame[cursor..a.start]);
        out.push_str(&a.replacement);
        cursor = a.end;
    }
    out.push_str(&frame[cursor..]);
    out
}

/// 凭据完整 token（行首锚定）。
fn cred_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^__CRED_\d{4,}__").expect("凭据 token 正则恒合法"))
}

/// PII 完整 token（行首锚定）。
fn pii_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^__PII_\d+_[0-9a-fA-F]{8}__").expect("PII token 正则恒合法"))
}

/// 凭据合法残缺前缀（`__C`/`__CR`/`.../__CRED_000`），可续写为完整 token。
fn cred_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^__C(?:R(?:E(?:D(?:_?\d*_?)?)?)?)?$").expect("凭据残缺前缀正则恒合法")
    })
}

/// PII 合法残缺前缀（`__PII_`/`__PII_1_`/`.../__PII_1_ab12`），可续写为完整 token。
fn pii_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^__P(?:I(?:I(?:_(?:\d+(?:_[0-9a-fA-F]*_?)?)?)?)?)?$")
            .expect("PII 残缺前缀正则恒合法")
    })
}

/// 行首完整 token 长度（凭据/PII 形态；未命中返回 `None`）。
fn complete_token_len(s: &str) -> Option<usize> {
    [cred_full_re(), pii_full_re()]
        .into_iter()
        .find_map(|re| re.find(s).filter(|m| m.start() == 0).map(|m| m.end()))
}

/// 是否恰为合法残缺前缀（非完整 token）。
fn is_partial_only(s: &str) -> bool {
    (cred_prefix_re().is_match(s) || pii_prefix_re().is_match(s))
        && !cred_full_re().is_match(s)
        && !pii_full_re().is_match(s)
}

/// marker 前缀集（与 `seam.rs` 跨缝检测同源）——覆盖裸 `_`/`__` 等任意切点。
const MARKER_PREFIXES: [&str; 2] = ["__PII_", "__CRED_"];

/// 是否为 marker 前缀感知的继承候选（前缀形态或既有正则，且非完整 token）。
fn is_candidate_run(run: &str) -> bool {
    !run.is_empty() && (MARKER_PREFIXES.iter().any(|m| m.starts_with(run)) || is_partial_only(run))
}

/// 信封/控制字段键名——fail-open 释放 MUST NOT 改写（spec 不变量 4）。
/// 含结构 id/序号/停因字段：它们非自由文本流，MUST NOT 被当作 carry 续段吞并或释放落点。
fn is_envelope_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "object"
            | "created"
            | "created_at"
            | "model"
            | "index"
            | "role"
            | "usage"
            | "finish_reason"
            | "type"
            | "status"
            | "item_id"
            | "call_id"
            | "tool_call_id"
            | "tool_use_id"
            | "stop_reason"
            | "stop_sequence"
            | "sequence_number"
            | "output_index"
            | "content_index"
    )
}

/// 值尾最长合法候选后缀 `(后缀起始, 后缀)`；非候选或超上界返回 `None`。不要求其后帧尾
/// 仅结构字符——canonical 信封把 `finish_reason`/`sequence_number` 等字段置于内容值之后。
fn candidate_suffix_in(value: &str) -> Option<(usize, &str)> {
    let run_start = value
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_alphanumeric() || *c == '_')
        .last()
        .map(|(i, _)| i)?;
    let run = &value[run_start..];
    let cand_off = candidate_suffix_offset(run)?;
    let cand = &run[cand_off..];
    (cand.len() <= PENDING_MAX).then_some((run_start + cand_off, cand))
}

/// `run` 内最长候选后缀的字节偏移：自最早的 `_` 起扫描，取首个满足 marker 前缀或既有
/// 残缺正则者（迭代升序故首个命中即最长后缀）。命中完整 token 时**跳过其整个区间**后继续——
/// 兼容「同一 run 内先有完整 token、其后又挂新媒体前缀」的续段（如 `...__word__PII_`）；
/// 完整 token 自身不得被摘入 carry，故其区间内的 `_` 一概跳过。仅当整个 run 都无候选后缀时
/// 返回 `None`。
fn candidate_suffix_offset(run: &str) -> Option<usize> {
    let mut skip_until = 0usize;
    for (i, c) in run.char_indices() {
        if c != '_' || i < skip_until {
            continue;
        }
        let suffix = &run[i..];
        if let Some(tok_len) = complete_token_len(suffix) {
            skip_until = i + tok_len;
            continue;
        }
        if is_candidate_run(suffix) {
            return Some(i);
        }
    }
    None
}

/// JSON 字符串**值**区间（去引号）及其前导键名；键区间（其后紧跟 `:`）与信封键值被排除——
/// 缝合/释放 SHALL NOT 触碰信封字段（仍递归其容器）。
fn json_string_values(frame: &str) -> Vec<(usize, usize, Option<&str>)> {
    json_string_ranges(frame)
        .into_iter()
        .filter(|(_, end)| !is_key_range(frame, *end))
        .map(|(start, end)| (start, end, leading_key(frame, start)))
        .filter(|(_, _, key)| !key.as_deref().is_some_and(is_envelope_key))
        .collect()
}

/// 字符串区间是否为其后的键（`"k":` 中的 `"k"`）——`end` 为闭引号位，
/// 跳过闭引号后（忽略空白）紧跟 `:` 即为键。
fn is_key_range(frame: &str, end: usize) -> bool {
    frame
        .get(end.saturating_add(1)..)
        .is_some_and(|rest| rest.trim_start().starts_with(':'))
}

/// 字符串值 `value_start`（去引号首字节）的前导 JSON 键名（`"key":` 最近者）。
fn leading_key(frame: &str, value_start: usize) -> Option<&str> {
    let bytes = frame.as_bytes();
    if value_start == 0 || bytes[value_start - 1] != b'"' {
        return None;
    }
    let mut j = value_start - 1;
    while j > 0 && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    if j == 0 || bytes[j - 1] != b':' {
        return None;
    }
    j -= 1;
    while j > 0 && bytes[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    if j == 0 || bytes[j - 1] != b'"' {
        return None;
    }
    let key_end = j - 1;
    let mut k = key_end;
    while k > 0 {
        k -= 1;
        if bytes[k] == b'"' {
            return (k < key_end).then(|| &frame[k + 1..key_end]);
        }
    }
    None
}

/// 扫描 JSON 文本的字符串内容区间（去引号，含键与值；转义安全）。
fn json_string_ranges(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i += 1;
        while i < b.len() {
            match b[i] {
                b'\\' => i += 2,
                b'"' => break,
                _ => i += 1,
            }
        }
        out.push((start, i.min(b.len())));
        i += 1;
    }
    out
}

/// 为每帧内的每个非信封字符串值生成结构路径，逐位对齐既有 [`json_string_values`] 输出
/// （均按文档序）；长度不等（重复键被去重等异常帧）降级全帧 key-only，绝不 panic。
fn value_paths(parsed: &Value, values: &[(usize, usize, Option<&str>)]) -> Vec<Vec<Seg>> {
    let mut walked = Vec::new();
    walk_root(parsed, &mut walked);
    if walked.len() == values.len() {
        walked
    } else {
        values
            .iter()
            .map(|(_, _, k)| k.map(|k| vec![Seg::Key(k.to_string())]).unwrap_or_default())
            .collect()
    }
}

fn walk_root(value: &Value, out: &mut Vec<Vec<Seg>>) {
    match value {
        Value::Object(map) => {
            let mut prefix = object_identity_segs(map);
            walk_object_children(map, &mut prefix, out);
        }
        Value::Array(arr) => walk_array(arr, &[], None, out),
        Value::String(_) => out.push(Vec::new()),
        _ => {}
    }
}

/// 对象成员走查：`prefix` 已含该对象的身份分段（调用方保证）。
fn walk_object_children(
    map: &serde_json::Map<String, Value>,
    prefix: &mut Vec<Seg>,
    out: &mut Vec<Vec<Seg>>,
) {
    for (k, v) in map {
        prefix.push(Seg::Key(k.clone()));
        walk_child(k, v, prefix, out);
        prefix.pop();
    }
}

fn walk_child(key: &str, value: &Value, prefix: &[Seg], out: &mut Vec<Vec<Seg>>) {
    match value {
        Value::String(_) => {
            if !is_envelope_key(key) {
                out.push(prefix.to_vec());
            }
        }
        Value::Object(map) => {
            let mut child = prefix.to_vec();
            child.extend(object_identity_segs(map));
            walk_object_children(map, &mut child, out);
        }
        Value::Array(arr) => walk_array(arr, prefix, Some(key), out),
        _ => {}
    }
}

/// 数组走查：元素身份优先元素逻辑 `index`，次 `id` 系（`item_id`/`call_id`/`tool_call_id`/
/// 裸 `id`），再缺则位序 `#pos`。`direct_key` 为数组所在键（信封排除对齐字节扫描器）。
fn walk_array(items: &[Value], prefix: &[Seg], direct_key: Option<&str>, out: &mut Vec<Vec<Seg>>) {
    let envelope = direct_key.is_some_and(is_envelope_key);
    for (pos, elem) in items.iter().enumerate() {
        let mut child = prefix.to_vec();
        child.push(element_seg(elem, pos));
        match elem {
            Value::String(_) => {
                if !envelope {
                    out.push(child);
                }
            }
            Value::Object(map) => walk_object_children(map, &mut child, out),
            Value::Array(inner) => walk_array(inner, &child, direct_key, out),
            _ => {}
        }
    }
}

/// 对象自身身份分段（作为其后代路径前缀）：`type` 与结构索引/id 字段。
fn object_identity_segs(map: &serde_json::Map<String, Value>) -> Vec<Seg> {
    let mut segs = Vec::new();
    if let Some(t) = map.get("type").and_then(scalar_text) {
        segs.push(Seg::Idx(format!("t={t}")));
    }
    for (key, tag) in [
        ("index", "i"),
        ("output_index", "o"),
        ("summary_index", "s"),
        ("content_index", "c"),
    ] {
        if let Some(n) = map.get(key).and_then(scalar_text) {
            segs.push(Seg::Idx(format!("{tag}={n}")));
        }
    }
    for key in ["item_id", "call_id", "tool_call_id"] {
        if let Some(s) = map.get(key).and_then(Value::as_str) {
            segs.push(Seg::Idx(format!("m={s}")));
        }
    }
    segs
}

/// 数组元素身份分段：逻辑 `index` → `i=`，否则 `id` 系 → `m=`，再缺则位序 `#pos`。
fn element_seg(elem: &Value, pos: usize) -> Seg {
    if let Some(map) = elem.as_object() {
        if let Some(n) = map.get("index").and_then(scalar_text) {
            return Seg::Idx(format!("i={n}"));
        }
        for key in ["item_id", "call_id", "tool_call_id", "id"] {
            if let Some(s) = map.get(key).and_then(Value::as_str) {
                return Seg::Idx(format!("m={s}"));
            }
        }
    }
    Seg::Idx(format!("#{pos}"))
}

/// `Value` 的可作身份文本的标量：字符串原样，数字 `to_string`。
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
