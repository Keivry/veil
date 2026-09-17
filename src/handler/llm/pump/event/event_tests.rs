use {super::*, crate::service::block_inject};

/// 6.1/ARH-2：测试面字符串签名包装（既有用例零改）——内部经单点
/// [`parse_event_data`] 产出解析产物后委托生产签名。
fn sticky_terminal_event(protocol: Protocol, data: &str, metrics: &GatewayMetrics) -> bool {
    super::sticky_terminal_event(protocol, parse_event_data(data).as_ref(), data, metrics)
}

/// 6.1/ARH-2：测试面字符串签名包装（单点解析后委托生产签名）。
fn responses_failed_incomplete(data: &str, metrics: &GatewayMetrics) -> (bool, bool, bool) {
    super::responses_failed_incomplete(parse_event_data(data).as_ref(), data, metrics)
}

/// 6.1/ARH-2：测试面字符串签名包装（单点解析后委托生产签名）。
fn responses_error_object(data: &str) -> Option<(Value, Option<u64>)> {
    super::responses_error_object(parse_event_data(data).as_ref())
}

#[test]
fn terminal_error_spaced_variant_triggers_truncation() {
    use crate::service::llm_gateway::{GatewayMetrics, Protocol as P};
    let m = GatewayMetrics::default();
    for raw in [
        r#"{"type":"error"}"#,
        r#"{"type": "error"}"#,
        "  {\"type\": \"error\"}  ",
    ] {
        assert!(
            sticky_terminal_event(P::Responses, raw, &m),
            "变体须终结: {raw}"
        );
        let (failed, incomplete, is_error) = responses_failed_incomplete(raw, &m);
        assert!(!failed && !incomplete && is_error, "须归为 error 类: {raw}");
    }
    assert_eq!(m.terminal_fallback_count(), 0, "合法 JSON 不得走兜底");
    let texty = r#"{"type":"response.output_text.delta","delta":"response.completed 不是终结"}"#;
    assert!(
        !sticky_terminal_event(P::Responses, texty, &m),
        "正文关键词不得误判终结"
    );
    let (f, i, e) = responses_failed_incomplete(texty, &m);
    assert!(!f && !i && !e);
    let failed_raw = r#"{"type":"response.failed"}"#;
    assert!(sticky_terminal_event(P::Responses, failed_raw, &m));
    assert!(responses_failed_incomplete(failed_raw, &m).0);
    let incomplete_raw = r#"{"type":"response.incomplete"}"#;
    assert!(responses_failed_incomplete(incomplete_raw, &m).1);
    assert!(!sticky_terminal_event(
        P::Chat,
        r#"{"type":"response.completed"}"#,
        &m
    ));
    assert!(sticky_terminal_event(
        P::Anthropic,
        r#"{"type":"message_stop"}"#,
        &m
    ));
    assert!(
        !sticky_terminal_event(
            P::Anthropic,
            r#"{"type":"content_block_delta","delta":{"text":"message_stop"}}"#,
            &m
        ),
        "Anthropic 正文关键词不得误判"
    );
}

#[test]
fn terminal_fallback_counts_invalid_json() {
    use crate::service::llm_gateway::{GatewayMetrics, Protocol as P};
    let m = GatewayMetrics::default();
    let raw = r#"{"type": response.completed"#;
    assert!(
        sticky_terminal_event(P::Responses, raw, &m),
        "非法帧关键词兜底须终结"
    );
    assert_eq!(m.terminal_fallback_count(), 1);
    let (failed, ..) = responses_failed_incomplete(r#"not json response.failed tail"#, &m);
    assert!(failed);
    assert_eq!(m.terminal_fallback_count(), 2);
    assert!(!sticky_terminal_event(P::Responses, "[[[", &m));
    assert_eq!(m.terminal_fallback_count(), 3, "无关键词非法帧仍须计数");
}

#[test]
fn incomplete_conv_stream_first_id_wins() {
    use crate::service::{
        block_inject,
        llm_gateway::{self, GatewayMetrics},
    };
    let m = GatewayMetrics::default();
    let created = serde_json::json!({"type":"response.created","response":{"id":"resp_123"}});
    let first = llm_gateway::extract_conv_id(&created);
    assert_eq!(first.as_deref(), Some("resp_123"));
    let fid = responses_synth_conv_id(first.as_deref(), None, &m);
    assert_eq!(fid, "resp_123");
    let frames = block_inject::ensure_event_lines(block_inject::responses_truncated_frames(&fid));
    assert!(
        frames.iter().any(|f| f.contains("resp_123")),
        "合成帧须带流内 id"
    );
    assert_eq!(
        m.conv_missing_count("failed"),
        0,
        "命中流内 id 不得计数缺失"
    );
}

#[test]
fn dedupe_terminal_single_truncated_frame() {
    use crate::service::{block_inject, llm_gateway::GatewayMetrics};
    let m = GatewayMetrics::default();
    let fid = responses_synth_conv_id(None, None, &m);
    assert!(fid.starts_with("unknown_"), "缺失须回退归档: {fid}");
    assert_eq!(m.conv_missing_count("failed"), 1);
    let frames = block_inject::ensure_event_lines(block_inject::responses_truncated_frames(&fid));
    let deduped = block_inject::dedupe_terminal_frames(frames, "responses");
    assert_eq!(
        block_inject::terminal_count(&deduped, "responses"),
        1,
        "下游须收到唯一终结帧"
    );
}

#[test]
fn minor_events_passthrough_without_audit() {
    use crate::service::llm_gateway::Protocol as P;
    assert!(is_minor_event(
        P::Anthropic,
        &serde_json::json!({"type":"thinking_delta","thinking":"hmm"})
    ));
    assert!(is_minor_event(
        P::Anthropic,
        &serde_json::json!({"delta":{"type":"signature_delta","signature":"s"}})
    ));
    assert!(is_minor_event(
        P::Responses,
        &serde_json::json!({"type":"response.reasoning.delta","delta":"x"})
    ));
    // RED-4：`mcp`/`code_interpreter` 工具事件现计入审计，不再次要。
    assert!(!is_minor_event(
        P::Responses,
        &serde_json::json!({"type":"response.mcp_call.in_progress"})
    ));
    assert!(is_minor_event(
        P::Chat,
        &serde_json::json!({"choices":[{"delta":{"refusal":"no"}}]})
    ));
    assert!(!is_minor_event(
        P::Chat,
        &serde_json::json!({"choices":[{"delta":{"content":"hi"}}]})
    ));
    assert!(!is_minor_event(
        P::Responses,
        &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"x"})
    ));
}

#[test]
fn chat_refusal_null_not_minor() {
    use crate::service::llm_gateway::Protocol as P;
    // CHC-4/2.23：`refusal:null`（缺省占位）不判次要；空串同不判次要。
    for v in [
        serde_json::json!({"choices":[{"delta":{"content":"hi","refusal":null}}]}),
        serde_json::json!({"choices":[{"delta":{"refusal":null}}]}),
        serde_json::json!({"choices":[{"message":{"refusal":null}}]}),
    ] {
        assert!(!is_minor_event(P::Chat, &v), "refusal:null 不得判次要: {v}");
    }
    // 非 null 且非空仍次要；空串非次要。
    assert!(is_minor_event(
        P::Chat,
        &serde_json::json!({"choices":[{"delta":{"refusal":"no"}}]})
    ));
    assert!(!is_minor_event(
        P::Chat,
        &serde_json::json!({"choices":[{"delta":{"refusal":""}}]})
    ));
}

#[test]
fn refusal_message_shape_passthrough_as_minor() {
    use crate::service::llm_gateway::Protocol as P;
    assert!(is_minor_event(
        P::Chat,
        &serde_json::json!({"choices":[{"message":{"refusal":"no"}}]})
    ));
    assert!(is_minor_event(
        P::Anthropic,
        &serde_json::json!({"type":"redacted_thinking","redacted_data":"x"})
    ));
    assert!(!is_minor_event(
        P::NonDialog,
        &serde_json::json!({"refusal":"no"})
    ));
}

#[test]
fn responses_error_no_message_fallback() {
    use crate::service::block_inject;
    // D5：error 对象无 message 或 error 非对象 ⇒ 提取 None，合成帧回退
    // 既有 `{"id","status"}` 形态（无 panic、无空体、无 error 字段）。
    for raw in [
        r#"{"type":"error","error":{"code":"x"}}"#,
        r#"{"type":"error","error":"oops"}"#,
        r#"{"type":"error"}"#,
    ] {
        assert!(responses_error_object(raw).is_none(), "须回退: {raw}");
    }
    let frame = block_inject::responses_failed_frame("r1", None, None);
    assert!(frame.contains("\"status\":\"failed\""));
    assert!(!frame.contains("\"error\""), "回退形态不得带 error 字段");
    // 顶层 message 回退 + 仅 message 无空字段噪声。
    let (obj, seq) =
        responses_error_object(r#"{"type":"error","message":"boom"}"#).expect("顶层回退");
    assert_eq!(obj["message"], "boom");
    assert_eq!(seq, None);
    let (obj, _) =
        responses_error_object(r#"{"type":"error","error":{"message":"only"}}"#).unwrap();
    assert!(obj.get("code").is_none() && obj.get("param").is_none() && obj.get("type").is_none());
    // 完整诊断字段全保留（嵌套形态）。
    let (obj, _) = responses_error_object(
        r#"{"type":"error","error":{"type":"err","code":"c","param":"p","message":"m"}}"#,
    )
    .unwrap();
    for (k, v) in [
        ("type", "err"),
        ("code", "c"),
        ("param", "p"),
        ("message", "m"),
    ] {
        assert_eq!(obj[k], v);
    }
}

#[test]
fn responses_error_official_shape_keeps_code_param() {
    // TRN-2：官方 `ResponseErrorEvent` 顶层形态——`code`/`param`/`message` 与
    // `sequence_number` 均保留，并写入合成 `response.failed` 载荷顶层。
    let raw = r#"{"type":"error","code":"server_error","message":"boom","param":"p","sequence_number":7}"#;
    let (obj, seq) = responses_error_object(raw).expect("官方形态须提取");
    assert_eq!(obj["code"], "server_error");
    assert_eq!(obj["param"], "p");
    assert_eq!(obj["message"], "boom");
    assert_eq!(seq, Some(7));
    let frame = block_inject::responses_failed_frame("r1", Some(&obj), seq);
    assert!(frame.contains("\"code\":\"server_error\""), "{frame}");
    assert!(frame.contains("\"param\":\"p\""), "{frame}");
    assert!(frame.contains("\"sequence_number\":7"), "{frame}");
}

#[test]
fn responses_error_nested_shape_still_supported() {
    // TRN-2：既有嵌套形态保留 `code`/`message`，无 sequence_number 不写。
    let raw = r#"{"type":"error","error":{"code":"rate_limit_exceeded","message":"slow"}}"#;
    let (obj, seq) = responses_error_object(raw).expect("嵌套形态须提取");
    assert_eq!(obj["code"], "rate_limit_exceeded");
    assert_eq!(obj["message"], "slow");
    assert_eq!(seq, None);
    let frame = block_inject::responses_failed_frame("r1", Some(&obj), seq);
    assert!(
        frame.contains("\"code\":\"rate_limit_exceeded\""),
        "{frame}"
    );
    assert!(
        !frame.contains("sequence_number"),
        "缺失不得空噪声: {frame}"
    );
}

#[test]
fn responses_error_fallback_shape() {
    // TRN-2/D5：无 `message` 或 error 非对象时维持 `{"id","status"}` 回退，不断链。
    for raw in [
        r#"{"type":"error","error":{"code":"x"}}"#,
        r#"{"type":"error","error":"oops"}"#,
        r#"{"type":"error"}"#,
    ] {
        assert!(responses_error_object(raw).is_none(), "须回退: {raw}");
    }
    let frame = block_inject::responses_failed_frame("r1", None, None);
    assert!(frame.contains("\"status\":\"failed\""));
    assert!(!frame.contains("\"error\""), "回退形态不得带 error 字段");
}

#[test]
fn empty_stream_synthesis_gate_truth_table() {
    assert!(should_synthesize_empty_stream(false, false, false));
    assert!(!should_synthesize_empty_stream(false, true, false));
    assert!(!should_synthesize_empty_stream(true, false, false));
    assert!(!should_synthesize_empty_stream(false, false, true));
    assert!(!should_synthesize_empty_stream(true, true, true));
}

#[test]
fn anthropic_message_start_model_bucket() {
    use crate::service::metrics::normalize_model;
    let start =
        serde_json::json!({"type":"message_start","message":{"id":"msg_abc","model":"claude-x"}});
    assert_eq!(stream_model_of(&start), Some("claude-x"));
    assert_eq!(
        normalize_model(stream_model_of(&start).unwrap_or("")),
        "claude-x"
    );
    let top = serde_json::json!({"model":"gpt-4o"});
    assert_eq!(stream_model_of(&top), Some("gpt-4o"), "顶层优先不回退");
    let resp = serde_json::json!({
        "type":"response.completed","response":{"id":"resp_1","model":"gpt-5.1"}
    });
    assert_eq!(
        stream_model_of(&resp),
        Some("gpt-5.1"),
        "R5-02：Responses 嵌套 response.model 须回退提取"
    );
    assert_eq!(
        normalize_model(stream_model_of(&resp).unwrap_or("")),
        "gpt-5.1",
        "流式嵌套 model 分桶须与非流上游回显口径一致"
    );
    let none = serde_json::json!({"type":"message_start","message":{"id":"m"}});
    assert_eq!(stream_model_of(&none), None);
    assert_eq!(
        normalize_model(stream_model_of(&none).unwrap_or("")),
        "unknown_model"
    );
}

#[test]
fn minor_event_excludes_tool_deltas() {
    use crate::service::llm_gateway::Protocol as P;
    for t in [
        "response.code_interpreter_call_code.delta",
        "response.shell_call_command.delta",
        "response.mcp_call_arguments.delta",
        "response.custom_tool_call_input.delta",
    ] {
        assert!(
            !is_minor_event(P::Responses, &serde_json::json!({"type": t})),
            "{t} 不得为次要事件（审计须可达）"
        );
    }
    for t in [
        "response.reasoning_text.delta",
        "response.image_gen_call.delta",
    ] {
        assert!(
            is_minor_event(P::Responses, &serde_json::json!({"type": t})),
            "{t} 须维持次要"
        );
    }
}

#[test]
fn responses_seq_cursor_missing_and_regression_ignored() {
    // A-2/F-02：游标取上界——缺 `sequence_number` 不更新、回退值不降游标。
    let mut cursor = None;
    advance_responses_seq_cursor(&mut cursor, &serde_json::json!({"sequence_number": 4}));
    assert_eq!(cursor, Some(4), "首见序号须置位");
    advance_responses_seq_cursor(&mut cursor, &serde_json::json!({"type": "response.x"}));
    assert_eq!(cursor, Some(4), "缺序号帧不得复位游标");
    advance_responses_seq_cursor(&mut cursor, &serde_json::json!({"sequence_number": 2}));
    assert_eq!(cursor, Some(4), "回退值不降游标（只取 max）");
    advance_responses_seq_cursor(&mut cursor, &serde_json::json!({"sequence_number": -1}));
    assert_eq!(cursor, Some(4), "非 u64 回退值忽略");
    advance_responses_seq_cursor(&mut cursor, &serde_json::json!({"sequence_number": 9}));
    assert_eq!(cursor, Some(9), "更大序号须推进");
}

#[test]
fn chat_error_terminal_predicate_boundaries() {
    // A-6/F-08：判据边界——顶层 `error` 且无 `choices` 才判终端；`choices`
    // 内 `error` 或二者共存不误伤；`is_terminal_event` 对 Chat 恒 false 保持。
    use crate::service::llm_gateway::Protocol as P;
    assert!(is_chat_error_terminal(
        P::Chat,
        &serde_json::json!({"error": {"message": "boom"}})
    ));
    assert!(!is_chat_error_terminal(
        P::Chat,
        &serde_json::json!({"choices": [{"delta": {"error": "x"}}]})
    ));
    assert!(!is_chat_error_terminal(
        P::Chat,
        &serde_json::json!({"error": {"message": "x"}, "choices": []})
    ));
    assert!(!is_chat_error_terminal(
        P::Responses,
        &serde_json::json!({"error": {"message": "boom"}})
    ));
    assert!(
        !is_terminal_event(P::Chat, &serde_json::json!({"error": {"message": "boom"}})),
        "is_terminal_event 对 Chat 恒 false（错误帧由独立判据承载）"
    );
}

#[tokio::test]
async fn build_sse_response_passes_upstream_2xx_status() {
    // R5-05/D4：上游 2xx 非 200（如 206）经状态码入参透传，不再硬编码 200。
    for code in [
        axum::http::StatusCode::OK,
        axum::http::StatusCode::PARTIAL_CONTENT,
        axum::http::StatusCode::CREATED,
    ] {
        let (_tx, rx) = tokio::sync::mpsc::channel::<String>(1);
        let pump = tokio::spawn(async {
            std::future::pending::<crate::handler::llm::pump::PumpOutcome>().await
        });
        let resp = build_sse_response(rx, false, pump, code);
        assert_eq!(resp.status(), code, "下游须携带上游 2xx 原状态码");
    }
}

#[test]
fn anthropic_error_is_upstream_error_terminal() {
    // R5-04：Anthropic `type:"error"` 即上游错误终端；Responses 走独立合成路径。
    use crate::service::llm_gateway::Protocol as P;
    let err = serde_json::json!({"type":"error","error":{"message":"boom"}});
    assert!(is_upstream_error_terminal(P::Anthropic, &err));
    assert!(!is_upstream_error_terminal(P::Responses, &err));
    assert!(!is_upstream_error_terminal(
        P::Anthropic,
        &serde_json::json!({"type":"message_stop"})
    ));
    assert!(is_upstream_error_terminal(
        P::Chat,
        &serde_json::json!({"error":{"message":"boom"}})
    ));
}
