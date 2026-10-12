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
    // `batches` 与 Responses 单段检索为 NonDialog，且不得记宽容计数；
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
    // 排除官方子资源后，既有严格/尾斜杠/一层宽容语义不回退。
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
    // 协议尾判定宽容匹配大小写不敏感为有意裁决——仅大小写不同的同一路径归类一致，
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
        "Responses 不得注入规范外 include_usage"
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
    // 回归：已存在 object 内键冲突时按 key 合并，既有值（含 false）不得被覆盖。
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
    // 三态——缺失注入 / null 保留 / 对象按 key 合并 / 含 include_usage 保留（含 false）。
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
    // 显式 null 在注入调用后仍为 null，不注入 include_usage。
    let mut null = serde_json::json!({"stream":true,"stream_options":null});
    inject_stream_options(&mut null);
    assert!(null["stream_options"].is_null(), "null 须原样保留: {null}");
}

#[test]
fn stream_options_malformed_replaced() {
    // 字符串/数组畸形形态维持 warn + 整体替换，不静默丢键。
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

#[test]
fn protocol_spec_minimal_fields() {
    // 仅 Chat 有终止标记；三协议真终端集合按协议声明。
    assert_eq!(Protocol::Chat.spec().done_terminator, Some("[DONE]"));
    for p in [
        Protocol::Anthropic,
        Protocol::Responses,
        Protocol::NonDialog,
    ] {
        assert_eq!(p.spec().done_terminator, None, "{p:?} 不得有 DONE 终止标记");
    }
    assert_eq!(
        Protocol::Anthropic.spec().terminal_event_types,
        &["message_stop", "error"]
    );
    assert_eq!(
        Protocol::Responses.spec().terminal_event_types,
        &[
            "response.completed",
            "response.failed",
            "response.incomplete"
        ]
    );
    assert!(Protocol::Chat.spec().terminal_event_types.is_empty());
    assert!(Protocol::NonDialog.spec().terminal_event_types.is_empty());
}
