//! 脱敏外观（§3.1–§3.4 编排）：请求级 `Scope` + 全出口残缺清理 +
//! 凭据优先 + json-aware 双侧脱敏。
//!
//! 管线（对标 design D3：凭据替换 → PII 替换 → json-walk 全量扫描 → roundtrip 校验）：
//! - 请求侧：凭据明文→`__VG_CRED_NNNNNN__`，PII→`__PII_<seq>_<rand8>__`（本 Scope 注册）；
//! - 响应侧：先还原本 Scope 请求 token 与凭据 token，再剥离幻觉完整凭据 token， 最后
//!   `_strip_partials` 残缺清理接全出口；响应期新检出 PII 注册进响应表， 原样保留不还原；
//! - 单向依赖：本模块只读 `state` 经调用方注入的 vault/detector，不触网络与路由。

use {
    super::{
        credential_vault::{CredentialVault, strip_cred_partials},
        json_walk,
        pii::{PiiDetector, PiiScope, apply_spans, arbitrate, credential_spans, protected_spans},
    },
    std::collections::HashMap,
};

/// 请求级作用域：PII 映射只活在本 Scope 内，请求结束即销毁，
/// 跨请求 MUST NOT 互见；PII 还原只查本 Scope。
#[derive(Debug)]
pub struct Scope {
    pii: PiiScope,
    response_side: bool,
    fuzzy_restore: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            pii: PiiScope::new(),
            response_side: true,
            fuzzy_restore: false,
        }
    }
}

impl Scope {
    /// 新建请求作用域（每请求一个）。
    pub fn new() -> Self { Self::default() }

    /// 按 `Config` 语义开关构造：`response_side` 关时响应新检出不再脱敏，
    /// `fuzzy_restore` 开时残缺/宽松形态 token 按序号回查还原。
    pub fn with_opts(response_side: bool, fuzzy_restore: bool) -> Self {
        Self {
            pii: PiiScope::new(),
            response_side,
            fuzzy_restore,
        }
    }

    /// 底层的请求级 PII 容器（高级用法/断言）。
    pub fn pii_scope(&self) -> &PiiScope { &self.pii }

    /// 请求侧脱敏：凭据优先 → PII（内置+字典同步，自定义预扫异步）→ json-walk。
    /// 输出末尾统一 `_strip_partials` 残缺清理。
    /// FIX-5 保字节：全叶零替换时返回原文（不走 dumps 重排）。
    pub async fn redact_request(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.snapshot_p2t();
        // 自定义正则先在原文上预扫并注册（值→token 快照供叶回调复用）。
        let custom_snapshot = prescan_custom(detector, &self.pii, text, &cred_map).await;
        let replaced = std::cell::Cell::new(false);
        let mut leaf = |s: String| {
            let r = redact_leaf(&self.pii, detector, &cred_map, &custom_snapshot, s.clone());
            if r != s {
                replaced.set(true);
            }
            r
        };
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        if replaced.get() || !custom_snapshot.is_empty() {
            strip_partials(&out)
        } else {
            strip_partials(text)
        }
    }

    /// 请求侧 plain 脱敏（非 JSON / 已超限输入的直通路径，同样全量扫描）。
    pub async fn redact_request_plain(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.snapshot_p2t();
        let custom_snapshot = prescan_custom(detector, &self.pii, text, &cred_map).await;
        let redacted = redact_leaf(
            &self.pii,
            detector,
            &cred_map,
            &custom_snapshot,
            text.to_string(),
        );
        strip_partials(&redacted)
    }

    /// 响应侧还原：凭据 token → PII 请求 token → 幻觉剥离 → 残缺清理。
    /// PII 完整形态一律保留（响应期新 token 原样保留语义）。
    /// `fuzzy_restore` 开启时追加宽松形态按序号回查。
    pub fn restore_response(&self, vault: &CredentialVault, text: &str) -> String {
        let step1 = vault.restore(text);
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        let step3 = vault.strip_hallucinated(&step2);
        strip_partials(&step3)
    }

    /// 响应还原（含 span 透传，§2.2）：
    /// 返回 `(还原文本, 还原明文区间)`；区间为还原文本中的字节下标。
    /// 调用方做响应侧新检出时须经 [`Scope::redact_response_new_pii_with_skip`]
    /// 跳过这些区间，否则刚还原的请求明文会被二次掩码为响应 token。
    /// 不触 handler 接线：纯库函数，零网络副作用。
    pub fn restore_response_with_spans(
        &self,
        vault: &CredentialVault,
        text: &str,
    ) -> (String, Vec<(usize, usize)>) {
        let restored = self.restore_response(vault, text);
        let mut spans = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (_, _, token) in scan_token_forms(text) {
            if !seen.insert(token.clone()) {
                continue;
            }
            // 经公开还原路径单 token 回查明文：未注册/幻觉形态回查不变或清空，直接跳过。
            let plain = self.restore_response(vault, &token);
            if plain.is_empty() || plain == token {
                continue;
            }
            for (s, e) in find_sub_spans(&restored, &plain) {
                spans.push((s, e));
            }
        }
        spans.sort_unstable();
        // 重叠区间保留最长者（短明文嵌在长明文内时只留长区间）。
        let mut dedup: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (s, e) in spans {
            if let Some((ls, le)) = dedup.last_mut() {
                if s < *le && e > *le {
                    *ls = (*ls).min(s);
                    *le = e;
                    continue;
                }
                if s < *le {
                    continue;
                }
            }
            dedup.push((s, e));
        }
        (restored, dedup)
    }

    /// 响应侧新检出：响应中出现的新 PII 注册进响应表（不进请求还原表），
    /// 以新占位符呈现，不还原为明文。
    /// `PII_RESPONSE_SIDE=0` 时直接返回原文（响应侧脱敏关闭）。
    pub async fn redact_response_new_pii(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        if !self.response_side {
            return text.to_string();
        }
        let cred_map = vault.snapshot_p2t();
        let custom_snapshot = prescan_custom_response(detector, &self.pii, text, &cred_map).await;
        let mut leaf =
            |s: String| redact_leaf_response(&self.pii, detector, &cred_map, &custom_snapshot, s);
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        strip_partials(&out)
    }

    /// 响应侧新检出（跳过还原区间，§2.2）：
    /// 与 [`Scope::redact_response_new_pii`] 同语义，但 `skip`
    /// （[`Scope::restore_response_with_spans`] 返回值）覆盖的原文区间原样保留，
    /// 刚还原的请求明文保持明文。按区间切段后仅对非跳过段做新检出，
    /// 再按原序拼接（跳过段字节级原样，坐标天然对齐）。
    pub async fn redact_response_new_pii_with_skip(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
        skip: &[(usize, usize)],
    ) -> String {
        if !self.response_side {
            return text.to_string();
        }
        let mut spans: Vec<(usize, usize)> = skip
            .iter()
            .filter(|(s, e)| *s < *e && *s <= text.len() && *e <= text.len())
            .copied()
            .collect();
        if spans.is_empty() {
            return self.redact_response_new_pii(vault, detector, text).await;
        }
        spans.sort_unstable();
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for (s, e) in spans {
            if s < cursor {
                continue;
            }
            if s > cursor {
                out.push_str(
                    &self
                        .redact_response_new_pii(vault, detector, &text[cursor..s])
                        .await,
                );
            }
            // 跳过段原样保留：还原出的请求明文不得二次掩码。
            out.push_str(&text[s..e]);
            cursor = e.max(cursor);
        }
        if cursor < text.len() {
            out.push_str(
                &self
                    .redact_response_new_pii(vault, detector, &text[cursor..])
                    .await,
            );
        }
        strip_partials(&out)
    }
}

/// 全出口残缺清理：凭据 + PII 两套半截形态统一入口。
/// 凭据完整形态同样被清理（还原须先行）；PII 完整形态由前瞻排除得以保留
/// （响应期新 token 原样保留语义）。
pub fn strip_partials(text: &str) -> String {
    super::pii::strip_pii_partials(&strip_cred_partials(text))
}

/// 响应出口统一清理：幻觉完整凭据 token 剥离 + 残缺清理接全出口。
/// 真实 token 应先经 `restore_response` 还原，未还原的完整形态必是幻觉。
pub fn strip_token_forms(vault: &CredentialVault, text: &str) -> String {
    strip_partials(&vault.strip_hallucinated(text))
}

/// 跨帧边界 hold（A 案，`PII_HOLD_MAX` 字符窗）：整帧延迟一级，缝合相邻两帧的
/// 尾/首窗口做跨缝 PII 检测，跨缝命中掩码两侧后再放行上一帧。
/// 与 [`strip_partials`] 分工：strip 清理本帧内残缺占位符（出口卫生，不跨帧）；
/// hold 防止 PII 被切在两帧而逐帧漏检（边界检测，需跨帧状态）。两者正交。
/// 解码文本窗口：JSON 信封字符（`"` `{` `}` `[` `]` `,` 与 `"key":` 键）会隔断缝合（如
/// `138"}}]}…{"content":"12345678`），窗口先过滤信封并保留对齐映射，使检测发生
/// 在近似解码文本空间；掩码映射回原帧坐标，结构字符守卫兜底保信封。
/// `window_chars == 0` 时直通（响应侧关闭）。
pub struct BoundaryHold {
    held_prefix: Option<String>,
    held_data: Option<String>,
    window_chars: usize,
}

impl BoundaryHold {
    pub fn new(window_chars: usize) -> Self {
        Self { held_prefix: None, held_data: None, window_chars }
    }

    pub fn has_held(&self) -> bool { self.held_data.is_some() }

    /// 推入下一帧已处理数据，返回本轮可放行帧。首帧返回空（延迟一级）；
    /// `spans_fn(window, seam)` 返回窗口内待掩码字节区间（窗口坐标，过滤后空间）。
    /// 仅跨缝区间被处理，非跨缝命中留给逐帧逻辑（已处理过）。
    pub fn push(
        &mut self,
        prefix: String,
        data: String,
        spans_fn: impl Fn(&str, usize) -> Vec<(usize, usize)>,
    ) -> (String, String) {
        if self.window_chars == 0 {
            return (prefix, data);
        }
        let (held_prefix, mut held_data) = match (self.held_prefix.take(), self.held_data.take()) {
            (Some(p), Some(d)) => (p, d),
            _ => {
                self.held_prefix = Some(prefix);
                self.held_data = Some(data);
                return (String::new(), String::new());
            }
        };
        let (tail_f, tail_map, tail_base) = {
            let (_, tail) = tail_window(&held_data, self.window_chars);
            let base = held_data.len().saturating_sub(tail.len());
            let (f, m) = filter_window(tail);
            (f, m, base)
        };
        let (head_f, head_map) = filter_window(head_window(&data, self.window_chars));
        let mut window = String::with_capacity(tail_f.len() + head_f.len());
        window.push_str(&tail_f);
        let seam = window.len();
        window.push_str(&head_f);
        let mut data = data;
        for (s, e) in spans_fn(&window, seam) {
            if s < seam && e > seam && e <= window.len() {
                if let Some((ps, pe)) = map_filtered_span(&tail_map, s, seam.min(e)) {
                    mask_span_bytes(&mut held_data, tail_base + ps, tail_base + pe);
                }
                if let Some((cs, ce)) = map_filtered_span(&head_map, 0, e - seam) {
                    let data_len = data.len();
                    mask_span_bytes(&mut data, cs.min(data_len), ce.min(data_len));
                }
            }
        }
        self.held_prefix = Some(prefix);
        self.held_data = Some(data);
        (held_prefix, held_data)
    }

    pub fn flush(&mut self) -> Option<(String, String)> {
        match (self.held_prefix.take(), self.held_data.take()) {
            (Some(p), Some(d)) => Some((p, d)),
            _ => None,
        }
    }

    /// 阻断时丢弃滞留帧（与 `agg.clear()` 同语义：阻断后不再透出常规内容）。
    pub fn clear(&mut self) {
        self.held_prefix = None;
        self.held_data = None;
    }
}

/// 窗口过滤：在原文上去除 JSON 信封（`"` `{` `}` `[` `]` `,` 与 `"key":` 键），
/// 返回过滤文本及逐字符原字节映射。`"key":` 要求引号后首字符为字母/下划线，
/// 故纯数字值（IPv6 组、电话片段）不受影响；`:` 本身保留（IPv6 跨缝需要）。
/// 全字母组 IPv6 紧邻缝合缝仍可能受 `"key":` 误删影响，为可接受残留
/// （逐帧检测仍覆盖完整形态）。
fn filter_window(s: &str) -> (String, Vec<(usize, usize)>) {
    let mut out = String::with_capacity(s.len());
    let mut map: Vec<(usize, usize)> = Vec::new();
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (off, c) = chars[i];
        let next_off = |k: usize| chars.get(k).map(|(o, _)| *o).unwrap_or(s.len());
        if c == '"' {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].1.is_ascii_alphanumeric() || chars[j].1 == '_') {
                j += 1;
            }
            if j > i + 1
                && j + 1 < chars.len()
                && chars[i + 1].1.is_ascii_alphabetic()
                && chars[i + 1].1 != '_'
                && chars[j].1 == '"'
                && chars[j + 1].1 == ':'
            {
                i = j + 2;
                continue;
            }
            i += 1;
            continue;
        }
        if matches!(c, '{' | '}' | '[' | ']' | ',') {
            i += 1;
            continue;
        }
        out.push(c);
        map.push((off, next_off(i + 1)));
        i += 1;
    }
    (out, map)
}

/// 过滤坐标映射回原坐标：`[fs, fe)`（过滤字节区间）→ 原字节 `(start, end)`。
/// 非字符边界返回 `None`（调用方跳过）。
fn map_filtered_span(
    map: &[(usize, usize)],
    fs: usize,
    fe: usize,
) -> Option<(usize, usize)> {
    if fs >= fe {
        return None;
    }
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let mut byte = 0;
    // 过滤仅整字符删除，保留字符字节原样，过滤字节偏移按原字符长度递增。
    for (os, oe) in map {
        let clen = oe - os;
        if byte == fs && start.is_none() {
            start = Some(*os);
        }
        if byte + clen == fe {
            end = Some(*oe);
            break;
        }
        byte += clen;
    }
    match (start, end) {
        (Some(s), Some(e)) if s < e => Some((s, e)),
        _ => None,
    }
}

/// 占位符残片跨缝区间：`__PII_`/`__VG_CRED_` 前缀残片横跨缝合缝时返回可见部分
/// 区间（窗口坐标），供 [`BoundaryHold`] 掩码。完整 token 不在此处理（逐帧逻辑归属）。
pub fn marker_cross_spans(window: &str, seam: usize) -> Vec<(usize, usize)> {
    const MARKERS: [&str; 2] = ["__PII_", "__VG_CRED_"];
    let mut out = Vec::new();
    for m in MARKERS {
        let mlen = m.len();
        let from = seam.saturating_sub(mlen);
        for start in from..seam.min(window.len()) {
            if !window.is_char_boundary(start) {
                continue;
            }
            let end_cap = (start + mlen).min(window.len());
            if !window.is_char_boundary(end_cap) || end_cap <= seam {
                continue;
            }
            if m.starts_with(&window[start..end_cap]) && start + mlen > seam {
                out.push((start, end_cap));
            }
        }
    }
    out
}

fn tail_window(s: &str, n_chars: usize) -> (usize, &str) {
    let total: usize = s.chars().count();
    if total <= n_chars {
        return (0, s);
    }
    let skip = total - n_chars;
    let off = s
        .char_indices()
        .nth(skip)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    (off, &s[off..])
}

fn head_window(s: &str, n_chars: usize) -> &str {
    match s.char_indices().nth(n_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// 字节区间掩码（等字符数 `*` 替换）：越界/非字符边界/含 JSON 结构字符时拒绝，
/// 保证信封结构不被破坏。
fn mask_span_bytes(text: &mut String, start: usize, end: usize) {
    if start >= end || end > text.len() {
        return;
    }
    if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
        return;
    }
    let span = &text[start..end];
    if span.contains(['{', '}', '"', '[', ']']) {
        return;
    }
    let masked: String = span.chars().map(|_| '*').collect();
    text.replace_range(start..end, &masked);
}

pub const NORMALIZED_HEADER_NAME: &str = "x-veil-normalized";
pub const NORMALIZED_HEADER_VALUE: &str = "json-whitespace";

/// 占位符说明注入开关（与 `Config::is_falsy` 同口径）：`0/false/no/off` 关闭，
/// 其余（含空）启用。网关实际以 `Config::parse_placeholder_prompt` 为准，
/// 本函数仅供单测对账，两者语义一致。
pub fn placeholder_prompt_enabled(raw: &str) -> bool {
    !matches!(raw.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off")
}

/// span 加法 API：去重后位置化替换（原 `apply_spans` 语义不变，本函数仅叠加去重层）。
pub fn apply_spans_dedup(text: &str, spans: &[(usize, usize, String)]) -> String {
    let mut seen = std::collections::HashSet::new();
    let uniq: Vec<(usize, usize, String)> = spans
        .iter()
        .filter(|(s, e, r)| seen.insert((*s, *e, r.clone())))
        .cloned()
        .collect();
    super::pii::apply_spans(text, &uniq)
}

pub fn normalize_flag_enabled(raw: Option<&str>) -> bool { matches!(raw.map(str::trim), Some("1")) }

pub fn select_request_bytes<'a>(
    original: &'a [u8],
    normalized: &'a [u8],
    normalize_enabled: bool,
) -> (&'a [u8], Option<(&'static str, &'static str)>) {
    if normalize_enabled {
        (
            normalized,
            Some((NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE)),
        )
    } else {
        (original, None)
    }
}

/// 自定义预扫（请求侧）：原文级异步扫描 → 请求表注册 → 值→token 快照。
async fn prescan_custom(
    detector: &PiiDetector,
    scope: &PiiScope,
    text: &str,
    cred_map: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut snapshot = HashMap::new();
    for (kind, value, ..) in detector.scan_custom(text, cred_map).await {
        let _ = kind;
        if snapshot.contains_key(&value) {
            continue;
        }
        if let Ok(tok) = scope.register(&value, false) {
            snapshot.insert(value, tok);
        }
    }
    snapshot
}

/// 自定义预扫（响应侧）：注册进响应表。
async fn prescan_custom_response(
    detector: &PiiDetector,
    scope: &PiiScope,
    text: &str,
    cred_map: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut snapshot = HashMap::new();
    for (kind, value, ..) in detector.scan_custom(text, cred_map).await {
        let _ = kind;
        if snapshot.contains_key(&value) {
            continue;
        }
        if let Ok(tok) = scope.register(&value, true) {
            snapshot.insert(value, tok);
        }
    }
    snapshot
}

/// 叶回调（请求侧）：凭据替换 → 内置+字典扫描注册 → 自定义快照值替换。
/// 全程位置化仲裁，凭据区间与占位符区间重叠排除。
fn redact_leaf(
    scope: &PiiScope,
    detector: &PiiDetector,
    cred_map: &HashMap<String, String>,
    custom_snapshot: &HashMap<String, String>,
    text: String,
) -> String {
    // 1) 凭据替换（长度降序单次）。
    let after_cred = super::credential_vault::redact_with_map(&text, cred_map);
    // 2) 内置 + 字典同步扫描（凭据优先已在扫描内跳过）。
    let mut hits = detector.scan_spans_sync(&after_cred, cred_map);
    // 3) 自定义快照值在叶内定位（逐值全出现点，边界由加载期 lookaround 保证，
    //    此处做区间保护：与凭据/占位符/已命中重叠则跳过）。
    let protected = protected_spans(&after_cred);
    let cred_spans = credential_spans(&after_cred, cred_map);
    let mut extra = Vec::new();
    let mut keys: Vec<&String> = custom_snapshot.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for value in keys {
        if value.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(idx) = after_cred[from..].find(value.as_str()) {
            let (s, e) = (from + idx, from + idx + value.len());
            extra.push(("custom".to_string(), value.clone(), s, e));
            from = e.max(from + 1);
            if from >= after_cred.len() {
                break;
            }
        }
    }
    hits.extend(extra.into_iter().filter(|(_, v, s, e)| {
        !protected
            .iter()
            .chain(cred_spans.iter())
            .any(|(a, b)| *a <= *s && *s < *b || *a < *e && *e <= *b || *s <= *a && *b <= *e)
            && !cred_map.contains_key(v)
    }));
    // 4) 仲裁 + 注册 + 位置化替换。
    let mut spans = Vec::new();
    for (kind, value, s, e) in arbitrate(hits) {
        let _ = kind;
        let tok = if let Some(t) = custom_snapshot.get(&value) {
            t.clone()
        } else {
            match scope.register(&value, false) {
                Ok(t) => t,
                Err(_) => continue,
            }
        };
        spans.push((s, e, tok));
    }
    apply_spans(&after_cred, &spans)
}

/// 叶回调（响应侧）：注册进响应表（不进请求还原表）。
fn redact_leaf_response(
    scope: &PiiScope,
    detector: &PiiDetector,
    cred_map: &HashMap<String, String>,
    custom_snapshot: &HashMap<String, String>,
    text: String,
) -> String {
    let after_cred = super::credential_vault::redact_with_map(&text, cred_map);
    let mut hits = detector.scan_spans_sync(&after_cred, cred_map);
    let protected = protected_spans(&after_cred);
    let cred_spans = credential_spans(&after_cred, cred_map);
    let mut keys: Vec<&String> = custom_snapshot.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for value in keys {
        if value.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(idx) = after_cred[from..].find(value.as_str()) {
            let (s, e) = (from + idx, from + idx + value.len());
            hits.push(("custom".to_string(), value.clone(), s, e));
            from = e.max(from + 1);
            if from >= after_cred.len() {
                break;
            }
        }
    }
    let hits: Vec<_> =
        hits.into_iter()
            .filter(|(_, v, s, e)| {
                !protected.iter().chain(cred_spans.iter()).any(|(a, b)| {
                    *a <= *s && *s < *b || *a < *e && *e <= *b || *s <= *a && *b <= *e
                }) && !cred_map.contains_key(v)
            })
            .collect();
    let mut spans = Vec::new();
    for (kind, value, s, e) in arbitrate(hits) {
        let _ = kind;
        let tok = if let Some(t) = custom_snapshot.get(&value) {
            t.clone()
        } else {
            match scope.register(&value, true) {
                Ok(t) => t,
                Err(_) => continue,
            }
        };
        spans.push((s, e, tok));
    }
    apply_spans(&after_cred, &spans)
}

/// 扫描文本中的占位符形态（凭据/PII 完整形），返回 `(起始, 结束, token)` 字节区间。
/// 只做形态初筛，真伪由公开还原路径回查确认，误报无害。
fn scan_token_forms(text: &str) -> Vec<(usize, usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // 字符边界步进：中文等多字节字符按整字跳过，不从字中切分。
        let rest = &text[i..];
        let prefix_len = if rest.starts_with("__VG_CRED_") {
            "__VG_CRED_".len()
        } else if rest.starts_with("__PII_") {
            "__PII_".len()
        } else {
            i += rest.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            continue;
        };
        if let Some(end) = rest[prefix_len..].find("__") {
            let token = &rest[..prefix_len + end + 2];
            let inner = &token[prefix_len..token.len() - 2];
            if !inner.is_empty()
                && inner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                out.push((i, i + token.len(), token.to_string()));
                i += token.len();
                continue;
            }
        }
        i += 1;
    }
    out
}

/// 在 `haystack` 中定位 `needle` 的全部非重叠出现点（字节区间）。
fn find_sub_spans(haystack: &str, needle: &str) -> Vec<(usize, usize)> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(idx) = haystack[from..].find(needle) {
        let (s, e) = (from + idx, from + idx + needle.len());
        out.push((s, e));
        from = e.max(from + 1);
        if from >= haystack.len() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with_secret(secret: &str) -> CredentialVault {
        let v = CredentialVault::new();
        v.register(secret).unwrap();
        v
    }

    #[tokio::test]
    async fn 请求侧替换响应侧还原() {
        let vault = vault_with_secret("my-secret-001");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"pwd":"my-secret-001","phone":"13812345678"}"#;
        let redacted = scope.redact_request(&vault, &detector, req).await;
        assert!(!redacted.contains("my-secret-001"), "{redacted}");
        assert!(!redacted.contains("13812345678"), "{redacted}");
        assert!(redacted.contains("__VG_CRED_"), "{redacted}");
        assert!(redacted.contains("__PII_"), "{redacted}");
        // JSON 语义等价：仍可解析，键名层级不变。
        let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert!(v.get("pwd").is_some() && v.get("phone").is_some());
        let restored = scope.restore_response(&vault, &redacted);
        assert!(restored.contains("my-secret-001"), "{restored}");
        assert!(restored.contains("13812345678"), "{restored}");
    }
    #[tokio::test]
    async fn 响应新检出不还原() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        // 请求期未注册的新 PII：响应侧以新占位符呈现。
        let resp = scope
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(!resp.contains("8.8.8.8"), "{resp}");
        assert!(resp.contains("__PII_"), "{resp}");
        // 请求还原表不含该 token：restore 原样保留。
        let again = scope.restore_response(&vault, &resp);
        assert!(again.contains("__PII_"), "{again}");
    }

    #[tokio::test]
    async fn 同秘密复用不重复注册且重建一致() {
        let vault = vault_with_secret("cache-secret-xyz");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"a":"cache-secret-xyz","b":"cache-secret-xyz"}"#;
        let once = scope.redact_request(&vault, &detector, req).await;
        let twice = scope.redact_request(&vault, &detector, req).await;
        assert_eq!(once, twice, "同秘密重复脱敏须复用一致");
        assert_eq!(vault.len(), 1, "同一秘密只注册一次");
        // 重建一致：还原后结构与原文一致。
        let rebuilt = scope.restore_response(&vault, &once);
        let v_orig: serde_json::Value = serde_json::from_str(req).unwrap();
        let v_back: serde_json::Value = serde_json::from_str(&rebuilt).unwrap();
        assert_eq!(v_orig, v_back);
    }

    #[tokio::test]
    async fn 跨请求不可还原他方pii() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let a = Scope::new();
        let b = Scope::new();
        let redacted = a
            .redact_request(&vault, &detector, "电话 13812345678")
            .await;
        assert!(redacted.contains("__PII_"));
        // B 持有 A 的占位符：还原失败并原样保留。
        let restored_by_b = b.restore_response(&vault, &redacted);
        assert!(restored_by_b.contains("__PII_"), "{restored_by_b}");
        assert!(!restored_by_b.contains("13812345678"));
    }

    #[tokio::test]
    async fn 嵌套tool_calls回归() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = r#"{"tool_calls":[{"name":"login","arguments":"{\"user\":\"admin\",\"key\":\"p@ss\\\"quote\",\"code\":\"\\u0031\"}"}]}"#;
        let redacted = scope.redact_request(&vault, &detector, req).await;
        // 无 PII/凭据命中时结构原样（roundtrip 保证可解析）。
        let v: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        let args: serde_json::Value =
            serde_json::from_str(v["tool_calls"][0]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["key"], "p@ss\"quote");
        assert_eq!(args["code"], "1");
    }

    #[tokio::test]
    async fn 非流式与流末残余出口一致清理() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        // 残缺前缀在出口被清理，不泄漏半截占位符。
        let dirty = "正文 __VG_CRED_000 与 __PII_2_ab 结尾";
        let cleaned = scope.redact_request_plain(&vault, &detector, dirty).await;
        assert!(!cleaned.contains("__VG_CRED_000"), "{cleaned}");
        assert!(!cleaned.contains("__PII_2_ab"), "{cleaned}");
        let restored = scope.restore_response(&vault, "ok __VG_CRED_12");
        assert!(!restored.contains("__VG_CRED_12"), "{restored}");
    }

    #[tokio::test]
    async fn 响应侧关闭透出原文() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::with_opts(false, false);
        let resp = scope
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(resp.contains("8.8.8.8"), "{resp}");
        assert!(!resp.contains("__PII_"), "{resp}");
        let open = Scope::with_opts(true, false);
        let masked = open
            .redact_response_new_pii(&vault, &detector, r#"{"ip":"8.8.8.8"}"#)
            .await;
        assert!(!masked.contains("8.8.8.8"), "{masked}");
    }

    #[test]
    fn 宽松还原按序号回查() {
        let vault = CredentialVault::new();
        let plain = "13812345678";
        let exact = Scope::with_opts(true, false);
        let token = exact.pii_scope().register(plain, false).unwrap();
        let seq: usize = token
            .strip_prefix("__PII_")
            .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
            .flatten()
            .expect("token 恒带序号");
        let fuzzy_tok = format!("__PII_{seq}_zzzz__");
        // 精确模式保留宽松形态。
        assert!(
            exact
                .restore_response(&vault, &format!("回拨 {fuzzy_tok}"))
                .contains(&fuzzy_tok)
        );
        // 宽松模式按序号还原明文。
        let scope2 = Scope::with_opts(true, true);
        let token2 = scope2.pii_scope().register(plain, false).unwrap();
        let seq2: usize = token2
            .strip_prefix("__PII_")
            .and_then(|r| r.split_once('_').map(|(s, _)| s.parse().ok()))
            .flatten()
            .unwrap();
        let restored = scope2.restore_response(&vault, &format!("回拨 __PII_{seq2}_zzzz__"));
        assert!(restored.contains(plain), "{restored}");
        assert!(!restored.contains("__PII_"), "{restored}");
    }

    #[test]
    fn strip出口函数语义() {
        let vault = CredentialVault::new();
        assert_eq!(strip_partials("a __VG_CRED_00 b"), "a  b");
        assert_eq!(strip_partials("a __PII_3_ab b"), "a  b");
        assert_eq!(strip_token_forms(&vault, "x __VG_CRED_123456__ y"), "x  y");
        // PII 完整形态保留（响应期新 token 语义）。
        assert!(strip_token_forms(&vault, "x __PII_1_ab12cd34__ y").contains("__PII_1_ab12cd34__"));
    }

    #[test]
    fn fix5默认子串不重排仅开启才声明头() {        let original = br#"{"b": 1,  "a": 2}"#;
        let normalized = br#"{"a":2,"b":1}"#;
        let (bytes, header) = select_request_bytes(original, normalized, false);
        assert_eq!(bytes, original);
        assert!(header.is_none());
        let (bytes2, header2) = select_request_bytes(original, normalized, true);
        assert_eq!(bytes2, normalized);
        assert_eq!(header2, Some(("x-veil-normalized", "json-whitespace")));
        assert!(!normalize_flag_enabled(None));
        assert!(!normalize_flag_enabled(Some("0")));
        assert!(normalize_flag_enabled(Some("1")));
    }

    #[tokio::test]
    async fn 多行保真往返字节一致() {
        let vault = vault_with_secret("my-secret-001");
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let req = "第一行 电话 13812345678 📞\n第二行 密钥 my-secret-001 ✅\n第三行 纯文本无敏感";
        let redacted = scope.redact_request_plain(&vault, &detector, req).await;
        assert!(!redacted.contains("13812345678"), "{redacted}");
        assert!(!redacted.contains("my-secret-001"), "{redacted}");
        assert!(redacted.contains("第三行 纯文本无敏感"), "{redacted}");
        let restored = scope.restore_response(&vault, &redacted);
        assert_eq!(restored, req, "往返须字节一致");
    }

    #[tokio::test]
    async fn 还原span跳过防二次掩码() {
        let vault = CredentialVault::new();
        let detector = PiiDetector::new();
        let scope = Scope::new();
        let redacted = scope
            .redact_request(&vault, &detector, r#"{"phone":"13812345678"}"#)
            .await;
        assert!(redacted.contains("__PII_"), "{redacted}");
        let (restored, spans) = scope.restore_response_with_spans(&vault, &redacted);
        assert!(restored.contains("13812345678"), "{restored}");
        assert!(!spans.is_empty());
        assert!(
            spans.iter().any(|(s, e)| &restored[*s..*e] == "13812345678"),
            "{spans:?}"
        );
        // 带 skip：还原明文保持明文。
        let kept = scope
            .redact_response_new_pii_with_skip(&vault, &detector, &restored, &spans)
            .await;
        assert!(kept.contains("13812345678"), "{kept}");
        // 对照（不带 skip）：同一明文被套上响应 token，证明 skip 生效。
        let masked = scope
            .redact_response_new_pii(&vault, &detector, &restored)
            .await;
        assert!(!masked.contains("13812345678"), "{masked}");
        assert!(masked.contains("__PII_"), "{masked}");
    }

    #[test]
    fn 凭据还原span覆盖明文() {
        let vault = CredentialVault::new();
        vault.register("my-secret-001").expect("注册恒成功");
        let scope = Scope::new();
        let masked = vault.redact("密码 my-secret-001 结束");
        assert!(!masked.contains("my-secret-001"), "{masked}");
        let (restored, spans) = scope.restore_response_with_spans(&vault, &masked);
        assert_eq!(restored, "密码 my-secret-001 结束");
        assert_eq!(spans.len(), 1);
        assert_eq!(&restored[spans[0].0..spans[0].1], "my-secret-001");
        // 未知 token 不产生 span。
        let (unchanged, empty) = scope.restore_response_with_spans(&vault, "纯文本无 token");
        assert_eq!(unchanged, "纯文本无 token");
        assert!(empty.is_empty());
    }

    #[test]
    fn 占位符关闭条件与原仓对齐() {
        assert!(!placeholder_prompt_enabled("0"));
        assert!(!placeholder_prompt_enabled("false"));
        assert!(!placeholder_prompt_enabled("no"));
        assert!(!placeholder_prompt_enabled(" NO "));
        // 与 Config::is_falsy 同口径：`off` 视为关闭。
        assert!(!placeholder_prompt_enabled("off"));
        assert!(!placeholder_prompt_enabled(" OFF "));
        assert!(placeholder_prompt_enabled(""));
        assert!(placeholder_prompt_enabled("1"));
    }

    #[test]
    fn span加法去重语义() {
        let out = apply_spans_dedup("hello world", &[(6, 11, "W".to_string()), (6, 11, "W".to_string())]);
        assert_eq!(out, "hello W");
    }

    #[test]
    fn 还原幂等不双还原且未知透传() {
        let vault = vault_with_secret("my-secret-001");
        let scope = Scope::new();
        let tok = scope.pii_scope().register("13812345678", false).unwrap();
        let mixed = format!("回拨 {tok} 与 __PII_9_ab12cd34__ 及 my-secret-001");
        let once = scope.restore_response(&vault, &mixed);
        assert!(once.contains("13812345678"), "{once}");
        assert!(once.contains("__PII_9_ab12cd34__"), "{once}");
        assert!(once.contains("my-secret-001"), "明文直通不改写: {once}");
        let twice = scope.restore_response(&vault, &once);
        assert_eq!(twice, once, "二次还原须与一次一致");
    }

    #[test]
    fn 边界hold跨缝手机号双侧掩码() {
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push("event: message\n".to_string(), "call 138".to_string(), |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let span_fn = |_: &str, sm: usize| {
            vec![(5, 16)]
                .into_iter()
                .filter(|(s, e)| *s < sm && *e > sm)
                .collect()
        };
        let (p1, d1) = h.push("event: message\n".to_string(), "12345678 ok".to_string(), span_fn);
        assert_eq!(p1, "event: message\n");
        assert_eq!(d1, "call ***", "上一帧尾部残片须掩码: {d1}");
        let (pf, df) = h.flush().expect("次帧须滞留");
        assert_eq!(pf, "event: message\n");
        assert_eq!(df, "******** ok", "次帧头部延续须掩码: {df}");
    }

    #[test]
    fn 边界hold无跨缝原样透传() {
        let mut h = BoundaryHold::new(64);
        let (p0, d0) = h.push("e\n".to_string(), "hello".to_string(), |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let (p1, d1) = h.push("e\n".to_string(), "world".to_string(), |_, _| vec![]);
        assert_eq!((p1.as_str(), d1.as_str()), ("e\n", "hello"));
        let (pf, df) = h.flush().expect("须有滞留");
        assert_eq!((pf.as_str(), df.as_str()), ("e\n", "world"));
        assert!(!h.has_held());
    }

    #[test]
    fn 边界hold零窗直通且json结构守卫() {
        let mut h = BoundaryHold::new(0);
        let (p, d) = h.push("e\n".to_string(), "{\"a\":1}".to_string(), |_, _| vec![(0, 7)]);
        assert_eq!((p.as_str(), d.as_str()), ("e\n", "{\"a\":1}"));
        let mut t = "{\"a\":1}".to_string();
        mask_span_bytes(&mut t, 0, 7);
        assert_eq!(t, "{\"a\":1}", "含结构字符不得掩码");
        let mut t2 = "13812345678".to_string();
        mask_span_bytes(&mut t2, 0, 11);
        assert_eq!(t2, "***********");
    }

    #[test]
    fn 占位符残片跨缝可检出() {
        // marker 前缀本身横跨缝合缝："ab __VG_CRE" + "D_12..."。
        let window = "ab __VG_CRED".to_string();
        let seam = "ab __VG_CRE".len();
        let spans = marker_cross_spans(&window, seam);
        assert!(!spans.is_empty(), "残片横跨缝合缝须检出: {spans:?}");
        let window2 = "abc def".to_string();
        assert!(marker_cross_spans(&window2, 4).is_empty());
        let window3 = "__PII_1_ab12cd34__ tail".to_string();
        assert!(marker_cross_spans(&window3, 19).is_empty(), "完整 token 左侧不算跨缝");
    }

    #[test]
    fn 信封过滤缝合跨帧数字() {
        let prev = "{\"delta\":{\"content\":\"call 138\"}}";
        let cur = "{\"delta\":{\"content\":\"12345678 ok\"}}";
        let (tail_f, _) = filter_window(prev);
        let (head_f, _) = filter_window(cur);
        assert!(tail_f.ends_with("call 138"), "尾部解码文本保留: {tail_f}");
        assert!(head_f.starts_with(":delta:content:") == false, "{head_f}");
        let mut window = String::new();
        window.push_str(&tail_f);
        let seam = window.len();
        window.push_str(&head_f);
        let digits = format!("{}{}", "138", "12345678");
        assert!(
            window.contains(&digits),
            "信封过滤后跨帧数字须相邻: {window}"
        );
        let _ = seam;
    }

    #[test]
    fn 边界hold信封分隔同样掩码() {
        let mut h = BoundaryHold::new(128);
        let prev = "{\"delta\":{\"content\":\"call 138\"}}".to_string();
        let cur = "{\"delta\":{\"content\":\"12345678 ok\"}}".to_string();
        let (p0, d0) = h.push("event: message\n".to_string(), prev, |_, _| vec![]);
        assert!(p0.is_empty() && d0.is_empty(), "首帧延迟无放行");
        let span_fn = |w: &str, sm: usize| {
            let rel = w.find("13812345678").expect("过滤窗口须缝合数字");
            vec![(rel, rel + 11)]
                .into_iter()
                .filter(|(s, e)| *s < sm && *e > sm)
                .collect()
        };
        let (p1, d1) = h.push("event: message\n".to_string(), cur, span_fn);
        assert_eq!(p1, "event: message\n");
        assert!(!d1.contains("138"), "上一帧尾部残片须掩码: {d1}");
        assert!(d1.contains("call "), "{d1}");
        assert!(d1.contains("\"content\""), "信封键须完整保留: {d1}");
        let (_, df) = h.flush().expect("次帧须滞留");
        assert!(!df.contains("12345678"), "次帧头部延续须掩码: {df}");
    }
}
