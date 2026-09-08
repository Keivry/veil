//! 协议识别与流判定：尾缀匹配（严格/宽容）+ `stream` 意图判定 + `stream_options` 注入。

use {super::GatewayMetrics, serde_json::Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Chat,
    Anthropic,
    Responses,
    NonDialog,
}

impl Protocol {
    pub fn as_tail(&self) -> &'static str {
        match self {
            Self::Chat => "chat/completions",
            Self::Anthropic => "v1/messages",
            Self::Responses => "v1/responses",
            Self::NonDialog => "non-dialog",
        }
    }
}

const STRICT_TAILS: [(&str, Protocol); 3] = [
    ("chat/completions", Protocol::Chat),
    ("v1/messages", Protocol::Anthropic),
    ("v1/responses", Protocol::Responses),
];

fn strip_query(path: &str) -> &str { path.split(['?', '#']).next().unwrap_or(path) }

fn strict_match(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    for (suffix, proto) in STRICT_TAILS {
        if p == format!("/{suffix}") || p == suffix {
            return Some(proto);
        }
        if p.len() > suffix.len() + 1
            && p.as_bytes()[p.len() - suffix.len() - 1] == b'/'
            && p[p.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return Some(proto);
        }
    }
    None
}

fn lenient_match(path: &str) -> Option<(Protocol, String)> {
    let p = strip_query(path);
    let trimmed = p.strip_suffix('/').unwrap_or(p);
    if trimmed != p
        && let Some(proto) = strict_match(trimmed)
    {
        return Some((proto, proto.as_tail().to_string()));
    }
    if let Some(slash) = p.rfind('/')
        && slash > 0
    {
        let parent = &p[..slash];
        if parent.contains('/') || parent.is_empty() {
            if let Some(proto) = strict_match(parent) {
                let rest = &p[slash + 1..];
                if !rest.is_empty() && !rest.contains('/') {
                    return Some((proto, proto.as_tail().to_string()));
                }
            }
        } else {
            return None;
        }
    }
    None
}

pub fn is_chat_tail(path: &str, metrics: Option<&GatewayMetrics>) -> (bool, Protocol) {
    if let Some(proto) = strict_match(path) {
        return (true, proto);
    }
    if let Some((proto, tail)) = lenient_match(path) {
        if let Some(m) = metrics {
            m.record_lenient(&tail);
        }
        tracing::debug!(path = %path, tail = %tail, "chat tail 宽容命中");
        return (true, proto);
    }
    (false, Protocol::NonDialog)
}

pub fn resolve_protocol(
    tail: &str,
    content_type: Option<&str>,
    metrics: Option<&GatewayMetrics>,
) -> Protocol {
    let (hit, proto) = is_chat_tail(tail, metrics);
    if let Some(ct) = content_type {
        tracing::debug!(tail = %tail, content_type = %ct, is_chat = %hit, "tail 优先分发，Content-Type 仅日志参考");
    }
    if hit { proto } else { Protocol::NonDialog }
}

pub fn is_stream_body(body: &Value) -> bool {
    body.as_object().is_some_and(|m| {
        m.get("stream")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    })
}

pub fn should_inject_stream_options(protocol: Protocol, body: &Value) -> bool {
    match protocol {
        Protocol::Chat | Protocol::Responses => {
            if !is_stream_body(body) {
                return false;
            }
            match body.as_object().and_then(|m| m.get("stream_options")) {
                // 键内合并语义（对齐 Python setdefault）：整键缺失或
                // `include_usage` 缺失即需注入，保留用户自带其他键。
                None => true,
                Some(Value::Object(opts)) => opts.get("include_usage").is_none(),
                // 非对象形态视为缺失，由 inject 整体替换 + warn。
                Some(_) => true,
            }
        }
        Protocol::Anthropic | Protocol::NonDialog => false,
    }
}

pub fn inject_stream_options(body: &mut Value) {
    if let Some(map) = body.as_object_mut() {
        match map.get_mut("stream_options") {
            Some(Value::Object(opts)) => {
                opts.entry("include_usage".to_string())
                    .or_insert(serde_json::json!(true));
            }
            Some(slot) => {
                tracing::warn!("stream_options 非对象形态，已整体替换为 include_usage");
                *slot = serde_json::json!({"include_usage": true});
            }
            None => {
                map.insert(
                    "stream_options".to_string(),
                    serde_json::json!({"include_usage": true}),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_tail_strictly_matches_three_protocols() {
        let m = GatewayMetrics::default();
        for (path, want) in [
            ("/v1/chat/completions", Protocol::Chat),
            ("https://x/v1/messages", Protocol::Anthropic),
            ("/v1/responses", Protocol::Responses),
        ] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(hit && proto == want, "{path}");
        }
    }

    #[test]
    fn non_dialog_miss_without_counting() {
        let m = GatewayMetrics::default();
        let (hit, proto) = is_chat_tail("/v1/models", Some(&m));
        assert!(!hit && proto == Protocol::NonDialog);
        assert_eq!(m.lenient_count("chat/completions"), 0);
        let (hit2, _) = is_chat_tail("/v1/fake-chat/completions-extra", Some(&m));
        assert!(!hit2);
    }

    #[test]
    fn single_suffix_lenient_match_with_count() {
        let m = GatewayMetrics::default();
        let (hit, proto) = is_chat_tail("/v1/chat/completions/", Some(&m));
        assert!(hit && proto == Protocol::Chat);
        assert_eq!(m.lenient_count("chat/completions"), 1);
        let (hit2, _) = is_chat_tail("/v1/chat/completions/extra", Some(&m));
        assert!(hit2);
        assert_eq!(m.lenient_count("chat/completions"), 2);
        let (hit3, _) = is_chat_tail("/v1/chat/completions/a/b", Some(&m));
        assert!(!hit3);
    }

    #[test]
    fn tail_takes_precedence_over_content_type() {
        let m = GatewayMetrics::default();
        assert_eq!(
            resolve_protocol("/v1/models", Some("text/event-stream"), Some(&m)),
            Protocol::NonDialog
        );
        assert_eq!(
            resolve_protocol("/v1/chat/completions", Some("application/json"), Some(&m)),
            Protocol::Chat
        );
    }

    #[test]
    fn stream_options_injected_only_for_chat_and_responses() {
        let chat_stream = serde_json::json!({"model":"m","stream":true});
        let resp_stream = serde_json::json!({"model":"m","stream":true});
        let anth_stream = serde_json::json!({"model":"m","stream":true});
        let chat_nostream = serde_json::json!({"model":"m"});
        assert!(should_inject_stream_options(Protocol::Chat, &chat_stream));
        assert!(should_inject_stream_options(
            Protocol::Responses,
            &resp_stream
        ));
        assert!(!should_inject_stream_options(
            Protocol::Anthropic,
            &anth_stream
        ));
        assert!(!should_inject_stream_options(
            Protocol::Chat,
            &chat_nostream
        ));
        let with_opt = serde_json::json!({"stream":true,"stream_options":{"include_usage":true}});
        assert!(!should_inject_stream_options(Protocol::Chat, &with_opt));
        let partial_opt = serde_json::json!({"stream":true,"stream_options":{"other":1}});
        assert!(
            should_inject_stream_options(Protocol::Chat, &partial_opt),
            "用户自带其他键但缺 include_usage 时须合并注入"
        );
        let mut merged = partial_opt.clone();
        inject_stream_options(&mut merged);
        assert_eq!(merged["stream_options"]["include_usage"], true);
        assert_eq!(merged["stream_options"]["other"], 1);
        let bad_opt = serde_json::json!({"stream":true,"stream_options":"yes"});
        assert!(should_inject_stream_options(Protocol::Chat, &bad_opt));
        let mut fixed = bad_opt.clone();
        inject_stream_options(&mut fixed);
        assert_eq!(fixed["stream_options"]["include_usage"], true);
        let anth_partial = serde_json::json!({"stream":true,"stream_options":{"other":1}});
        assert!(
            !should_inject_stream_options(Protocol::Anthropic, &anth_partial),
            "Anthropic 永不注入"
        );
        let non_dict = serde_json::json!([1, 2]);
        assert!(!should_inject_stream_options(Protocol::Chat, &non_dict));
        let mut body = chat_stream.clone();
        inject_stream_options(&mut body);
        assert_eq!(body["stream_options"]["include_usage"], true);
    }

    #[test]
    fn stream_options_conflict_merged_by_key_not_replaced() {
        // D5 回归：已存在 object 内键冲突时按 key 合并，既有值（含 false）不得被覆盖。
        let mut conflict =
            serde_json::json!({"stream":true,"stream_options":{"include_usage":false,"other":1}});
        inject_stream_options(&mut conflict);
        assert_eq!(
            conflict["stream_options"]["include_usage"], false,
            "既有 include_usage=false 须保留，不得替换为 true"
        );
        assert_eq!(conflict["stream_options"]["other"], 1);
        let mut present =
            serde_json::json!({"stream":true,"stream_options":{"include_usage":true,"other":2}});
        inject_stream_options(&mut present);
        assert_eq!(present["stream_options"]["include_usage"], true);
        assert_eq!(present["stream_options"]["other"], 2);
    }
}
