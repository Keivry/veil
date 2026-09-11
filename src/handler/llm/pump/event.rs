//! 流泵事件判定 + SSE 响应装配（D2 自 `pump.rs` 拆出）：终止/次要事件与空流守门。

use {
    crate::service::{
        json_walk::strip_bom,
        llm_gateway::{self, GatewayMetrics, Protocol},
    },
    axum::{
        body::Body,
        http::{StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::Value,
};

/// 2.3 `build_sse_response`：把泵出的帧通道装成下游 SSE 响应，保留
/// `x-veil-normalized` 声明与 `X-Accel-Buffering: no`。
pub fn build_sse_response(
    rx: tokio::sync::mpsc::Receiver<String>,
    normalized_out: bool,
) -> Response {
    use bytes::Bytes;
    let stream = async_stream::stream! {
        let mut rx = rx;
        while let Some(msg) = rx.recv().await {
            yield Ok::<_, anyhow::Error>(Bytes::from(msg));
        }
    };
    let mut stream_builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache");
    if normalized_out {
        stream_builder = stream_builder.header("x-veil-normalized", "json-whitespace");
    }
    stream_builder
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "stream").into_response())
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 空流合成守门（D4）：以是否已发终端/任意帧为准，不依赖 `forwarded` 计数器。
pub fn should_synthesize_empty_stream(
    terminal_sent: bool,
    any_frame_sent: bool,
    block_injected: bool,
) -> bool {
    !terminal_sent && !any_frame_sent && !block_injected
}

/// E8 终止精确判定：解析成功按顶层 `type` 精确匹配，解析失败回退
/// contains 兜底并由调用方计数。Anthropic 集合为
/// `content_block_stop/message_delta/message_stop`，Responses 集合为
/// `response.completed/response.failed/response.incomplete/error`。
pub(super) fn sticky_terminal_precise(protocol: Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
    match protocol {
        P::Anthropic => t == "content_block_stop" || t == "message_delta" || t == "message_stop",
        P::Responses => {
            t == "response.completed"
                || t == "response.failed"
                || t == "response.incomplete"
                || t == "error"
        }
        _ => false,
    }
}

pub(super) fn sticky_terminal_fallback(protocol: Protocol, data: &str) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => {
            data.contains("content_block_stop")
                || data.contains("message_delta")
                || data.contains("message_stop")
        }
        P::Responses => {
            data.contains("response.completed")
                || data.contains("response.failed")
                || data.contains("response.incomplete")
                || data.contains("\"type\":\"error\"")
                || data.contains("\"type\": \"error\"")
        }
        _ => false,
    }
}

/// E8 对拒止粘滞分支的终止判定：JSON 可解析走精确判定，否则走
/// contains 兜底并记 `terminal_fallback` 计数。
pub(super) fn sticky_terminal_event(
    protocol: Protocol,
    data: &str,
    metrics: &GatewayMetrics,
) -> bool {
    if let Ok(v) = serde_json::from_str::<Value>(strip_bom(data)) {
        sticky_terminal_precise(protocol, &v)
    } else {
        metrics.record_terminal_fallback();
        sticky_terminal_fallback(protocol, data)
    }
}

/// E8 Responses 合成前的失败/未完成分类：解析成功按 `type` 精确分类，
/// 失败回退 contains 并计数。返回 `(is_failed, is_incomplete, is_error)`。
pub(super) fn responses_failed_incomplete(
    data: &str,
    metrics: &GatewayMetrics,
) -> (bool, bool, bool) {
    if let Ok(v) = serde_json::from_str::<Value>(strip_bom(data)) {
        let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        (
            t == "response.failed",
            t == "response.incomplete",
            t == "error",
        )
    } else {
        metrics.record_terminal_fallback();
        (
            data.contains("response.failed"),
            data.contains("response.incomplete"),
            data.contains("\"type\":\"error\"") || data.contains("\"type\": \"error\""),
        )
    }
}

/// D5：`type:"error"` 事件的上游 error 诊断提取：`error` 对象内存在的
/// `code`/`type`/`param`/`message` 字段原样保留（缺失 `message` 时回退顶层
/// `message`）；无 `message` 或 `error` 非对象返回 `None`
/// （合成帧回退既有 `{"id","status"}` 形态，不带 error 字段、无空字段噪声）。
pub(super) fn responses_error_object(data: &str) -> Option<Value> {
    let v = serde_json::from_str::<Value>(strip_bom(data)).ok()?;
    let mut obj = serde_json::Map::new();
    if let Some(err) = v.get("error").filter(|e| e.is_object()) {
        for key in ["type", "code", "param", "message"] {
            if let Some(val) = err.get(key).filter(|x| !x.is_null()) {
                obj.insert(key.to_string(), val.clone());
            }
        }
    }
    if !obj.contains_key("message")
        && let Some(msg) = v
            .get("message")
            .and_then(|m| m.as_str())
            .filter(|s| !s.is_empty())
    {
        obj.insert("message".to_string(), Value::String(msg.to_string()));
    }
    let has_message = obj
        .get("message")
        .and_then(|m| m.as_str())
        .is_some_and(|s| !s.is_empty());
    has_message.then_some(Value::Object(obj))
}

/// E9 合成截断帧 conv 取值：优先流内首见 `id`，其次泵内最新 `conv_id`，
/// 缺失才回退 `resolve_conv_id` 归档（记 `conv_missing`，不断链）。
pub(super) fn responses_synth_conv_id(
    stream_first_id: Option<&str>,
    conv_id: Option<&str>,
    metrics: &GatewayMetrics,
) -> String {
    let clean = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(str::to_string);
    if let Some(id) = clean(stream_first_id) {
        return id;
    }
    if let Some(id) = clean(conv_id) {
        return id;
    }
    llm_gateway::resolve_conv_id(None, &serde_json::Value::Null, Some(metrics), "failed").0
}

/// 流式终端事件判定（§2.6 去重用）：chat 以 `[DONE]` 为准（非 JSON 分支处理，
/// 此处恒 false）；anthropic 为 `message_stop` 或 `error`（P2/D3：`error` 本身
/// 即终端，其后不得注入 `message_stop`）；responses 为
/// `completed/failed/incomplete`（`incomplete` P4 原样透传并作为唯一终端）。
pub(super) fn is_terminal_event(protocol: Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => v
            .get("type")
            .and_then(|t| t.as_str())
            .is_some_and(|t| t == "message_stop" || t == "error"),
        P::Responses => v.get("type").and_then(|t| t.as_str()).is_some_and(|t| {
            t == "response.completed" || t == "response.failed" || t == "response.incomplete"
        }),
        _ => false,
    }
}

/// 外层事件序号（§2.5/§2.4）：anthropic 取事件级 `index`
/// （`content_block_start/delta.index`），responses 取 `output_index`；
/// 缺失返回 None（调用方跳过按槽清理，不误清）。
pub(super) fn outer_event_index(protocol: Protocol, v: &Value) -> Option<u32> {
    use crate::service::llm_gateway::Protocol as P;
    let n = match protocol {
        P::Anthropic => v.get("index")?.as_u64()?,
        P::Responses => v.get("output_index").or_else(|| v.get("index"))?.as_u64()?,
        _ => return None,
    };
    Some(n as u32)
}

pub(super) fn extract_responses_seq(v: &Value) -> Option<u64> {
    v.get("sequence_number").and_then(|x| {
        x.as_u64()
            .or_else(|| x.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

/// B3/P2-2：Chat 是否出现非 null `finish_reason`（soft-terminal 信号）。
/// 上游以 `finish_reason` 收尾却不发 `[DONE]` 时据此置 open-ended 可观测。
pub(super) fn chat_finish_reason_seen(v: &Value) -> bool {
    v.get("choices")
        .and_then(|c| c.as_array())
        .is_some_and(|choices| {
            choices
                .iter()
                .any(|ch| ch.get("finish_reason").is_some_and(|r| !r.is_null()))
        })
}

/// M3/D6：Anthropic opaque 帧（`thinking`/`signature`/`redacted` 载体）——
/// 签名/密文完整性优先，响应侧须跳过新 PII 扫描（`redact_response_new_pii*`）
/// 与 `json_aware_line` 重序列化，仅做字节级还原后透传。
/// 载体三处：顶层 `type`、`delta.type`、真实 wire 的 `content_block.type`
/// （`content_block_start` 的 `redacted_thinking`/`thinking`）。
pub(super) fn is_anthropic_opaque_event(v: &Value) -> bool {
    let opaque =
        |t: &str| t.contains("thinking") || t.contains("signature") || t.contains("redacted");
    let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    if opaque(t) {
        return true;
    }
    v.get("delta")
        .and_then(|d| d.get("type"))
        .and_then(|x| x.as_str())
        .is_some_and(opaque)
        || v.get("content_block")
            .and_then(|b| b.get("type"))
            .and_then(|x| x.as_str())
            .is_some_and(opaque)
}

pub(super) fn is_minor_event(protocol: Protocol, v: &Value) -> bool {
    use crate::service::llm_gateway::Protocol as P;
    match protocol {
        P::Anthropic => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            t.contains("thinking")
                || t.contains("signature")
                || t.contains("redacted")
                || t.contains("citation")
                || v.get("delta")
                    .and_then(|d| d.get("type"))
                    .and_then(|x| x.as_str())
                    .is_some_and(|dt| {
                        dt.contains("thinking")
                            || dt.contains("signature")
                            || dt.contains("citation")
                    })
        }
        P::Responses => {
            let t = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            // C10：`file_search/web_search` 计 tool（与非流一致），不再列为
            // 次要事件；其余检索外围（reasoning/mcp/code_interpreter/image_gen）
            // 仍透传不审计。
            ["reasoning", "mcp", "code_interpreter", "image_gen"]
                .iter()
                .any(|k| t.contains(k))
        }
        P::Chat => v
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|choices| {
                choices.iter().any(|ch| {
                    ["delta", "message"]
                        .iter()
                        .any(|k| ch.get(k).and_then(|c| c.get("refusal")).is_some())
                })
            }),
        P::NonDialog => false,
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

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
        let texty =
            r#"{"type":"response.output_text.delta","delta":"response.completed 不是终结"}"#;
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
        let frames =
            block_inject::ensure_event_lines(block_inject::responses_truncated_frames(&fid));
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
        let frames =
            block_inject::ensure_event_lines(block_inject::responses_truncated_frames(&fid));
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
        assert!(is_minor_event(
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
        let frame = block_inject::responses_failed_frame("r1", None);
        assert!(frame.contains("\"status\":\"failed\""));
        assert!(!frame.contains("\"error\""), "回退形态不得带 error 字段");
        // 顶层 message 回退 + 仅 message 无空字段噪声。
        let obj = responses_error_object(r#"{"type":"error","message":"boom"}"#).expect("顶层回退");
        assert_eq!(obj["message"], "boom");
        let obj = responses_error_object(r#"{"type":"error","error":{"message":"only"}}"#).unwrap();
        assert!(
            obj.get("code").is_none() && obj.get("param").is_none() && obj.get("type").is_none()
        );
        // 完整诊断字段全保留。
        let obj = responses_error_object(
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
    fn empty_stream_synthesis_gate_truth_table() {
        assert!(should_synthesize_empty_stream(false, false, false));
        assert!(!should_synthesize_empty_stream(false, true, false));
        assert!(!should_synthesize_empty_stream(true, false, false));
        assert!(!should_synthesize_empty_stream(false, false, true));
        assert!(!should_synthesize_empty_stream(true, true, true));
    }
}
