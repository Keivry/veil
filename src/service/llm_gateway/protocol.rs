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

    /// 协议线级标签的单一来源：下游 `x-veil-protocol` 头值（`NonDialog` 对外为
    /// `passthrough`）。收敛 `handler/llm/mod.rs::protocol_header_value` 的重复 match。
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Anthropic => "anthropic",
            Self::Responses => "responses",
            Self::NonDialog => "passthrough",
        }
    }

    /// 类型化分派谓词：全仓 `protocol == Protocol::X` 比较统一经此收敛，
    /// 新增变体只改本组方法（穷举 `match` 臂仍由编译器强制）。
    pub fn is_chat(self) -> bool { matches!(self, Self::Chat) }

    pub fn is_anthropic(self) -> bool { matches!(self, Self::Anthropic) }

    pub fn is_responses(self) -> bool { matches!(self, Self::Responses) }

    pub fn is_nondialog(self) -> bool { matches!(self, Self::NonDialog) }

    /// 对话协议（`Chat`/`Anthropic`/`Responses`）——`NonDialog` 为唯一字节透传协议。
    pub fn is_dialog(self) -> bool { !self.is_nondialog() }
}

// 新增协议检查清单（D6/hygiene-round5）：新增第 4 协议时，除本表外还须同步：
// `usage.rs`（用量提取/缓存列）、`tool.rs`（工具调用判定）、`sse/meta.rs`（截断模式）、
// `block_inject/frames.rs`（终止帧合成）、`placeholder.rs`（说明注入/schema 判定）、
// `handler/llm/mod.rs::protocol_header_value`（下游协议头）、`rewrite.rs`（请求改写）、
// `block_inject.rs`（阻断体）。本清单为最低覆盖，新增协议 change 仍须全量
// grep `Protocol::` 复查（见 design D6）。
const STRICT_TAILS: [(&str, Protocol); 3] = [
    ("chat/completions", Protocol::Chat),
    ("v1/messages", Protocol::Anthropic),
    ("v1/responses", Protocol::Responses),
];

fn strip_query(path: &str) -> &str { path.split(['?', '#']).next().unwrap_or(path) }

fn strict_match(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    for (suffix, proto) in STRICT_TAILS {
        // NLP-7/D-gateway-protocol-fix：宽容匹配大小写不敏感为**有意声明**
        // （见 change `veil-audit-r2-remediation` `gateway-protocol-fix` spec）——
        // 仅大小写不同的同一对话尾 SHALL 归类一致，不得回落 `NonDialog`。
        if p.eq_ignore_ascii_case(&format!("/{suffix}")) || p.eq_ignore_ascii_case(suffix) {
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

/// `T5`/D5：官方子资源排除。尾后缀的一层额外路径段若命中官方子资源，MUST NOT
/// 判为对话协议（`lenient_match` 返回 `None` ⇒ `NonDialog` 字节透传），避免请求被
/// 改写、响应被注入占位符或触发审计后处理：
/// - Anthropic `v1/messages/{batches}`：异步批处理元数据端点，body 与响应形态均不同；
/// - Responses `v1/responses/{任意单段}`：均为响应对象检索（`.cancel`/`.input_items`
///   为两段后缀，`strict_match` 已不命中，天然 `NonDialog`，无需另列）。
///
/// `count_tokens` 已由 [`redact_only_protocol`] 收窄为 redact-only 对话变体，不再经
/// 此排除（`C`/`veil-audit-r4-remediation`）：它在 `is_chat_tail` 中先于宽容匹配被
/// **精确识别**为 `Protocol::Anthropic`，故不计 `chat_tail_lenient_total`。
///
/// Chat 无同类官方子资源，保留一层宽容（`/v1/chat/completions/extra` 仍命中）。
fn is_official_subresource(proto: Protocol, seg: &str) -> bool {
    if proto.is_anthropic() {
        return seg.eq_ignore_ascii_case("batches");
    }
    proto.is_responses()
}

/// `C`/3.1：Anthropic `count_tokens` 官方子资源判定——**redact-only 对话变体**。
///
/// 仅 `/v1/messages/{count_tokens}`（大小写不敏感、剥离 query 与尾斜杠）命中，返回
/// `Protocol::Anthropic`。**SHALL NOT 新增 `Protocol` 变体**——redact-only 切分由
/// `RequestCtx::redact_only` 布尔标记承载（见 `handler/llm/dispatch.rs` 装配点）；
/// `is_passthrough`（[`is_passthrough`]）/`is_dialog`（[`Protocol::is_dialog`]）语义不变。
///
/// 与 [`is_official_subresource`] 同源的一层子资源识别：本函数在 `is_chat_tail` 中先于
/// `lenient_match` 拦截，故 `count_tokens` 归类为 `Anthropic` 而非 `NonDialog`，且不计
/// 宽容计数；`batches` 仍由 `is_official_subresource` 排除为 `NonDialog` 字节透传。
pub fn redact_only_protocol(path: &str) -> Option<Protocol> {
    let p = strip_query(path);
    let p = p.strip_suffix('/').unwrap_or(p);
    let (parent, seg) = p.rsplit_once('/')?;
    if seg.eq_ignore_ascii_case("count_tokens") && strict_match(parent) == Some(Protocol::Anthropic)
    {
        return Some(Protocol::Anthropic);
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
                    if is_official_subresource(proto, rest) {
                        return None;
                    }
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
    // C/3.1：`count_tokens` 为**精确识别**的 redact-only 对话变体（官方子资源，非宽容
    // 命中），先于宽容匹配拦截，故不计 `chat_tail_lenient_total`。
    if let Some(proto) = redact_only_protocol(path) {
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

/// D4 透传谓词：`NonDialog` 为唯一字节透传协议（无用量/审计/还原）。
/// 全仓布尔判定统一经此函数，新增协议变体只改一处；穷举 `match` 臂保留模式。
pub fn is_passthrough(protocol: Protocol) -> bool { protocol.is_nondialog() }

pub fn is_stream_body(body: &Value) -> bool {
    body.as_object().is_some_and(|m| {
        m.get("stream")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    })
}

pub fn should_inject_stream_options(protocol: Protocol, body: &Value) -> bool {
    // P1-1（决策 b）：官方 Responses `stream_options` 仅接受 `include_obfuscation`，
    // 无 `include_usage`，故注入收窄为仅 `Protocol::Chat`。Responses 流式用量经
    // `response.completed.response.usage` 携带，由 `extract_usage_stream` 三级回退
    // 闭环（见 `usage.rs`），不依赖请求注入；用户自带 `stream_options` 原样保留。
    if !protocol.is_chat() {
        return false;
    }
    if !is_stream_body(body) {
        return false;
    }
    match body.as_object().and_then(|m| m.get("stream_options")) {
        // 键内合并语义（对齐 Python setdefault）：整键缺失或
        // `include_usage` 缺失即需注入，保留用户自带其他键。
        None => true,
        // TRN-5：`null` 是用户显式第三态，原样保留、不注入不替换。
        Some(Value::Null) => false,
        Some(Value::Object(opts)) => opts.get("include_usage").is_none(),
        // 非对象非 null（畸形）视为缺失，由 inject 整体替换 + warn。
        Some(_) => true,
    }
}

pub fn inject_stream_options(body: &mut Value) {
    if let Some(map) = body.as_object_mut() {
        match map.get_mut("stream_options") {
            Some(Value::Object(opts)) => {
                opts.entry("include_usage".to_string())
                    .or_insert(serde_json::json!(true));
            }
            // TRN-5：显式 `null` 不动（不注入、不替换、不告警）。
            Some(Value::Null) => {}
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
    fn official_subresources_are_nondialog() {
        // T5 + C/3.1：`batches` 与 Responses 单段检索为 NonDialog，且不得记宽容计数；
        // `count_tokens` 已收窄为 redact-only 对话变体（Anthropic，不计宽容）。
        let m = GatewayMetrics::default();
        for path in [
            "/v1/messages/batches",
            "/v1/responses/abc123",
            "/v1/responses/abc123/cancel",
            "/v1/responses/abc123/input_items",
        ] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(!hit && proto == Protocol::NonDialog, "{path} 须 NonDialog");
        }
        for path in ["/v1/messages/count_tokens", "/V1/MESSAGES/COUNT_TOKENS"] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(
                hit && proto == Protocol::Anthropic,
                "{path} 须 redact-only Anthropic，实得 {proto:?}"
            );
            assert_eq!(
                redact_only_protocol(path),
                Some(Protocol::Anthropic),
                "{path} redact-only sibling 判定须命中"
            );
        }
        assert_eq!(m.lenient_count("v1/messages"), 0, "官方子资源不得记宽容");
        assert_eq!(m.lenient_count("v1/responses"), 0, "官方子资源不得记宽容");
    }

    #[test]
    fn protocol_lenient_regression() {
        // T5：排除官方子资源后，既有严格/尾斜杠/一层宽容语义不回退。
        let m = GatewayMetrics::default();
        for (path, want) in [
            ("/v1/chat/completions/", Protocol::Chat),
            ("/v1/chat/completions/extra", Protocol::Chat),
            ("/v1/messages/", Protocol::Anthropic),
            ("/v1/messages/legacy-one-seg", Protocol::Anthropic),
            ("/v1/responses/", Protocol::Responses),
        ] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(hit && proto == want, "{path} 须 {want:?}");
        }
        assert!(!is_chat_tail("/v1/models", Some(&m)).0);
    }

    #[test]
    fn protocol_path_case_sensitivity() {
        // NLP-7（3.8）：协议尾判定宽容匹配大小写不敏感为有意裁决（见
        // `gateway-protocol-fix` spec）——仅大小写不同的同一路径归类一致，
        // 不回落 `NonDialog`；且不因此放宽官方子资源排除。
        let m = GatewayMetrics::default();
        for (path, want) in [
            ("/V1/Chat/Completions", Protocol::Chat),
            ("/v1/MESSAGES", Protocol::Anthropic),
            ("/V1/messages", Protocol::Anthropic),
            ("/v1/RESPONSES", Protocol::Responses),
            ("/V1/Chat/Completions/extra", Protocol::Chat),
        ] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(hit && proto == want, "{path} 须为 {want:?}，实得 {proto:?}");
        }
        // 大小写变体归类不变（同尾不同 case）。
        for pair in [
            ("/v1/chat/completions", "/V1/CHAT/COMPLETIONS"),
            ("/v1/messages", "/V1/MESSAGES"),
            ("/v1/responses", "/V1/RESPONSES"),
        ] {
            assert_eq!(
                is_chat_tail(pair.0, Some(&m)).1,
                is_chat_tail(pair.1, Some(&m)).1,
                "{} 与 {} 归类须一致",
                pair.0,
                pair.1
            );
        }
        // 大小写宽容不放宽官方子资源排除；`count_tokens` 归 redact-only Anthropic（C）。
        for path in ["/v1/MESSAGES/batches", "/V1/RESPONSES/abc123"] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(!hit && proto == Protocol::NonDialog, "{path} 须 NonDialog");
        }
        for path in ["/v1/MESSAGES/count_tokens", "/V1/Messages/Count_Tokens"] {
            let (hit, proto) = is_chat_tail(path, Some(&m));
            assert!(
                hit && proto == Protocol::Anthropic,
                "{path} 须 redact-only Anthropic，实得 {proto:?}"
            );
        }
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
    fn passthrough_predicate_matches_nondialog_only() {
        assert!(is_passthrough(Protocol::NonDialog));
        for p in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
            assert!(!is_passthrough(p), "{p:?}");
        }
    }

    #[test]
    fn stream_options_injected_only_for_chat() {
        let chat_stream = serde_json::json!({"model":"m","stream":true});
        let resp_stream = serde_json::json!({"model":"m","stream":true});
        let anth_stream = serde_json::json!({"model":"m","stream":true});
        let chat_nostream = serde_json::json!({"model":"m"});
        assert!(should_inject_stream_options(Protocol::Chat, &chat_stream));
        assert!(
            !should_inject_stream_options(Protocol::Responses, &resp_stream),
            "Responses 不得注入规范外 include_usage（P1-1 决策 b）"
        );
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

    #[test]
    fn stream_options_three_state_matrix() {
        // TRN-5：三态——缺失注入 / null 保留 / 对象按 key 合并 / 含 include_usage 保留（含 false）。
        let missing = serde_json::json!({"stream":true});
        assert!(should_inject_stream_options(Protocol::Chat, &missing));
        let null = serde_json::json!({"stream":true,"stream_options":null});
        assert!(
            !should_inject_stream_options(Protocol::Chat, &null),
            "null 不得视为缺失"
        );
        let partial = serde_json::json!({"stream":true,"stream_options":{"other":1}});
        assert!(should_inject_stream_options(Protocol::Chat, &partial));
        let has_false = serde_json::json!({"stream":true,"stream_options":{"include_usage":false}});
        assert!(!should_inject_stream_options(Protocol::Chat, &has_false));
        let has_true = serde_json::json!({"stream":true,"stream_options":{"include_usage":true}});
        assert!(!should_inject_stream_options(Protocol::Chat, &has_true));
    }

    #[test]
    fn stream_options_null_preserved() {
        // TRN-5：显式 null 在注入调用后仍为 null，不注入 include_usage。
        let mut null = serde_json::json!({"stream":true,"stream_options":null});
        inject_stream_options(&mut null);
        assert!(null["stream_options"].is_null(), "null 须原样保留: {null}");
    }

    #[test]
    fn stream_options_malformed_replaced() {
        // TRN-5：字符串/数组畸形形态维持 warn + 整体替换，不静默丢键。
        for bad in [
            serde_json::json!({"stream":true,"stream_options":"yes"}),
            serde_json::json!({"stream":true,"stream_options":[1,2]}),
        ] {
            assert!(should_inject_stream_options(Protocol::Chat, &bad));
            let mut fixed = bad.clone();
            inject_stream_options(&mut fixed);
            assert_eq!(fixed["stream_options"]["include_usage"], true, "{fixed}");
        }
    }
}
