//! 请求级 `Scope` 脱敏外观（D2 自 `redaction.rs` 拆出）：请求/响应双侧编排。

use super::{
    super::{
        credential_vault::{CredentialVault, strip_cred_partials},
        json_walk,
        pii::{PiiDetector, PiiScope},
    },
    leaf::{
        find_sub_spans,
        prescan_custom,
        prescan_custom_response,
        redact_leaf,
        redact_leaf_response,
        scan_token_forms,
    },
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
        self.redact_request_with_report(vault, detector, text)
            .await
            .0
    }

    /// 请求侧脱敏（H1/D3 报告变体）：返回 `(脱敏文本, 是否经 loads→walk→dumps 重序列化)`。
    /// 重序列化判定 = 有替换命中（含自定义预扫）且输入为可 walk 的 JSON 容器；
    /// 非 JSON 字节级替换与原文透传返回 `false`（对齐 README §7.7 置位口径）。
    pub async fn redact_request_with_report(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool) {
        let cred_map = vault.p2t_snapshot();
        // 自定义正则先在原文上预扫并注册（值→token 快照供叶回调复用）。
        let custom_snapshot = prescan_custom(detector, &self.pii, text, cred_map.map()).await;
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
            (strip_partials(&out), is_json_container(text))
        } else {
            (strip_partials(text), false)
        }
    }

    /// 请求侧 plain 脱敏（非 JSON / 已超限输入的直通路径，同样全量扫描）。
    pub async fn redact_request_plain(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> String {
        let cred_map = vault.p2t_snapshot();
        let custom_snapshot = prescan_custom(detector, &self.pii, text, cred_map.map()).await;
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
    /// R7：本函数为内部步骤，唯一公开还原入口为
    /// [`Scope::restore_response_with_spans`]（生产调用方均经该入口）；
    /// 可见性收敛为模块内，单测同文件可达。
    fn restore_response(&self, vault: &CredentialVault, text: &str) -> String {
        let step1 = restore_cred_tokens(vault, text);
        let step2 = self.pii.restore_with_fuzzy(&step1, self.fuzzy_restore);
        let step3 = vault.strip_hallucinated(&step2);
        strip_partials(&step3)
    }

    /// 单 token 回查（X3/D4）：凭据 token 经 `CredentialVault::restore_one`
    /// 直查（不克隆全表、不重建 alternation 正则）；非凭据 token 原样进入
    /// PII 回查。其余步骤与 [`Scope::restore_response`] 同序（PII 还原 →
    /// 幻觉剥离 → 残缺清理），保证 span 明文与全量还原结果一致。
    fn restore_response_one(&self, vault: &CredentialVault, token: &str) -> String {
        let step1 = vault
            .restore_one(token)
            .unwrap_or_else(|| token.to_string());
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
            // 逐 token 直查（不触全量快照）：未注册/幻觉形态回查不变或清空，直接跳过。
            let plain = self.restore_response_one(vault, &token);
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

    /// 响应还原（JSON 字符串上下文变体，H2/D1）：与
    /// [`Scope::restore_response_with_spans`] 同还原语义（PII/凭据/幻觉/残缺），
    /// 写回明文按 RFC 8259 转义（`"`→`\"`、`\`→`\\`、控制字符转义），
    /// 保证「还原前可解析」的 JSON 帧「还原后仍可解析」；返回的 span 为
    /// 转义后文本中的还原明文区间（供
    /// [`Scope::redact_response_new_pii_with_skip`] 跳过二次掩码）。
    /// 非 JSON 帧（plain 分支）MUST NOT 走本入口（保持字节级原样还原）。
    pub fn restore_response_with_spans_json(
        &self,
        vault: &CredentialVault,
        text: &str,
    ) -> (String, Vec<(usize, usize)>) {
        let (restored, spans) = self.restore_response_with_spans(vault, text);
        if spans.is_empty() {
            return (restored, spans);
        }
        let mut out = String::with_capacity(restored.len());
        let mut escaped_spans: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        let mut cursor = 0usize;
        for (s, e) in spans {
            out.push_str(&restored[cursor..s]);
            let start = out.len();
            out.push_str(&json_escape_plain(&restored[s..e]));
            escaped_spans.push((start, out.len()));
            cursor = e;
        }
        out.push_str(&restored[cursor..]);
        (out, escaped_spans)
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
        self.redact_response_new_pii_tracked(vault, detector, text)
            .await
            .0
    }

    /// 响应侧新检出追踪内核（H1/D2，对齐请求侧 FIX-5 `replaced` Cell）：
    /// 返回 `(输出, 是否发生替换)`；全程零替换且无自定义预扫命中时返回原文
    /// （跳过 `json_walk::process_text` 的 `jdumps` 重排，逐字节透传）。
    async fn redact_response_new_pii_tracked(
        &self,
        vault: &CredentialVault,
        detector: &PiiDetector,
        text: &str,
    ) -> (String, bool) {
        if !self.response_side {
            return (text.to_string(), false);
        }
        let cred_map = vault.p2t_snapshot();
        let custom_snapshot =
            prescan_custom_response(detector, &self.pii, text, cred_map.map()).await;
        let replaced = std::cell::Cell::new(false);
        let mut leaf = |s: String| {
            let r =
                redact_leaf_response(&self.pii, detector, &cred_map, &custom_snapshot, s.clone());
            if r != s {
                replaced.set(true);
            }
            r
        };
        let out = json_walk::process_text(text, &mut leaf, json_walk::DEPTH_LIMIT);
        if replaced.get() || !custom_snapshot.is_empty() {
            (strip_partials(&out), true)
        } else {
            (strip_partials(text), false)
        }
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
        let replaced = std::cell::Cell::new(false);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for (s, e) in spans {
            if s < cursor {
                continue;
            }
            if s > cursor {
                let (seg, seg_replaced) = self
                    .redact_response_new_pii_tracked(vault, detector, &text[cursor..s])
                    .await;
                if seg_replaced {
                    replaced.set(true);
                }
                out.push_str(&seg);
            }
            // 跳过段原样保留：还原出的请求明文不得二次掩码。
            out.push_str(&text[s..e]);
            cursor = e.max(cursor);
        }
        if cursor < text.len() {
            let (seg, seg_replaced) = self
                .redact_response_new_pii_tracked(vault, detector, &text[cursor..])
                .await;
            if seg_replaced {
                replaced.set(true);
            }
            out.push_str(&seg);
        }
        if replaced.get() {
            strip_partials(&out)
        } else {
            strip_partials(text)
        }
    }
}

/// 凭据 token 逐 token 直查重建（B2/D2）：仅对 `scan_token_forms` 命中的完整形态
/// 调 `CredentialVault::restore_one`，未注册形态原样保留；与全量 alternation
/// 替换逐字节等价（还原只做 token→明文，不重序列化）。
fn restore_cred_tokens(vault: &CredentialVault, text: &str) -> String {
    let forms = scan_token_forms(text);
    if forms.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for (start, end, token) in forms {
        out.push_str(&text[cursor..start]);
        match vault.restore_one(&token) {
            Some(plain) => out.push_str(&plain),
            None => out.push_str(&token),
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// `json_walk::process_text` 是否会对该输入走 `loads→walk→dumps`
/// （长度未超限、BOM 剥离 trim 后以 `{`/`[` 开头且可解析为 object/array）。
fn is_json_container(text: &str) -> bool {
    if text.len() > json_walk::SCAN_INPUT_LIMIT {
        return false;
    }
    let stripped = json_walk::strip_bom(text).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return false;
    }
    matches!(
        json_walk::jloads(json_walk::strip_bom(text)),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    )
}

/// RFC 8259 字符串上下文转义（JSON 帧还原写回用）：`"`/`\`/控制字符转义。
/// 复用 `serde_json` 的字符串序列化实现，保证与 JSON 解析器严格互逆。
fn json_escape_plain(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""));
    quoted
        .strip_prefix('"')
        .and_then(|q| q.strip_suffix('"'))
        .map_or_else(|| s.to_string(), str::to_string)
}

/// 全出口残缺清理：凭据 + PII 两套半截形态统一入口。
/// 凭据完整形态同样被清理（还原须先行）；PII 完整形态由前瞻排除得以保留
/// （响应期新 token 原样保留语义）。
pub fn strip_partials(text: &str) -> String {
    super::super::pii::strip_pii_partials(&strip_cred_partials(text))
}

/// 响应出口统一清理：幻觉完整凭据 token 剥离 + 残缺清理接全出口。
/// 真实 token 应先经 `restore_response` 还原，未还原的完整形态必是幻觉。
pub fn strip_token_forms(vault: &CredentialVault, text: &str) -> String {
    strip_partials(&vault.strip_hallucinated(text))
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod scope_tests;
