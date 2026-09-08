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

pub const NORMALIZED_HEADER_NAME: &str = "x-veil-normalized";
pub const NORMALIZED_HEADER_VALUE: &str = "json-whitespace";

/// 占位符说明注入开关（对标原仓口径）：仅 `0/false/no` 关闭，其余（含空/`off`）启用。
/// 接线注记：`Config::is_falsy` 另把 `off` 视为关（更严收敛）；此处保留原仓口径供网关侧
/// 对账，`off` 语义差异由配置归属方在发布说明中声明。
pub fn placeholder_prompt_enabled(raw: &str) -> bool {
    !matches!(raw.trim().to_lowercase().as_str(), "0" | "false" | "no")
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
        // 原仓口径：`off`/空均视为启用（`off` 差异见函数注记）。
        assert!(placeholder_prompt_enabled("off"));
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
}
