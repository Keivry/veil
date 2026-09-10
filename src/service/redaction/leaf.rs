//! 叶回调与请求字节选择（D2 自 `redaction.rs` 拆出）：凭据优先的位置化仲裁。

use {
    super::super::{
        credential_vault::redact_with_map,
        pii::{PiiDetector, PiiScope, apply_spans, arbitrate, credential_spans, protected_spans},
    },
    std::collections::HashMap,
};

/// 归一化声明头（protocol-parity Cvem）：注入改写请求体空白归一时声明，
/// 名/值均为线协议常量，硬编码理由：下游按精确头名识别，改名即 BREAKING。
pub const NORMALIZED_HEADER_NAME: &str = "x-veil-normalized";
/// 归一化声明头值（同上）。
pub const NORMALIZED_HEADER_VALUE: &str = "json-whitespace";

// D1.8：以下三辅助生产零引用（生产走 `Config` 同名成员），`#[cfg(test)]` 收编。
/// 占位符说明注入开关（与 `Config::is_falsy` 同口径）：`0/false/no/off` 关闭，
/// 其余（含空）启用。网关实际以 `Config::parse_placeholder_prompt` 为准，
/// 本函数仅供单测对账，两者语义一致。
#[cfg(test)]
pub fn placeholder_prompt_enabled(raw: &str) -> bool {
    !matches!(
        raw.trim().to_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

#[cfg(test)]
pub fn normalize_flag_enabled(raw: Option<&str>) -> bool { matches!(raw.map(str::trim), Some("1")) }

#[cfg(test)]
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
pub(crate) async fn prescan_custom(
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
pub(crate) async fn prescan_custom_response(
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
pub(crate) fn redact_leaf(
    scope: &PiiScope,
    detector: &PiiDetector,
    cred_map: &HashMap<String, String>,
    custom_snapshot: &HashMap<String, String>,
    text: String,
) -> String {
    // 1) 凭据替换（长度降序单次）。
    let after_cred = redact_with_map(&text, cred_map);
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
    apply_spans(&after_cred, &spans, false)
}

/// 叶回调（响应侧）：注册进响应表（不进请求还原表）。
pub(crate) fn redact_leaf_response(
    scope: &PiiScope,
    detector: &PiiDetector,
    cred_map: &HashMap<String, String>,
    custom_snapshot: &HashMap<String, String>,
    text: String,
) -> String {
    let after_cred = redact_with_map(&text, cred_map);
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
    apply_spans(&after_cred, &spans, false)
}

/// 扫描文本中的占位符形态（凭据/PII 完整形），返回 `(起始, 结束, token)` 字节区间。
/// 只做形态初筛，真伪由公开还原路径回查确认，误报无害。
pub(crate) fn scan_token_forms(text: &str) -> Vec<(usize, usize, String)> {
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
                && inner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
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
pub(crate) fn find_sub_spans(haystack: &str, needle: &str) -> Vec<(usize, usize)> {
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
mod leaf_tests {
    use super::*;

    #[test]
    fn fix5_default_no_reorder_header_only_when_enabled() {
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

    #[test]
    fn placeholder_disable_conditions_match_legacy() {
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
}
