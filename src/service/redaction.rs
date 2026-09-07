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
    fn fix5默认子串不重排仅开启才声明头() {
        let original = br#"{"b": 1,  "a": 2}"#;
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
}
