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

/// D3/ARH-1：泵任务回收守卫——响应体（及其帧流）被 drop 时中止泵任务，避免
/// `let _pump=` detach 后泵任务/上游连接泄漏；流正常消费完毕时 `abort` 为 no-op。
struct PumpTaskGuard(tokio::task::JoinHandle<super::PumpOutcome>);

impl Drop for PumpTaskGuard {
    fn drop(&mut self) { self.0.abort(); }
}

/// 2.3 `build_sse_response`：把泵出的帧通道装成下游 SSE 响应，保留
/// `x-veil-normalized` 声明与 `X-Accel-Buffering: no`。泵 `JoinHandle` 由响应体
/// 持有（不 detach）：客户端断开致响应体 drop 时经 [`PumpTaskGuard`] 中止并回收。
pub fn build_sse_response(
    rx: tokio::sync::mpsc::Receiver<String>,
    normalized_out: bool,
    pump: tokio::task::JoinHandle<super::PumpOutcome>,
) -> Response {
    use bytes::Bytes;
    let guard = PumpTaskGuard(pump);
    let stream = async_stream::stream! {
        let _guard = guard;
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

/// ARC-2/2.18：Fast 攒批下一帧可含多个逻辑 SSE 事件——以 `data:` 行数计
/// （Slow/未攒批单帧恒为 1），保持 `sse_events` 与下游逻辑帧数一致。
pub(super) fn data_event_count(frame: &str) -> usize {
    frame
        .lines()
        .filter(|l| l.trim_start().starts_with("data:"))
        .count()
}

pub(super) fn record_emitted_events(metrics: &GatewayMetrics, frame: &str) {
    for _ in 0..data_event_count(frame) {
        metrics.add_sse_event();
    }
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

/// D5 + TRN-2：`type:"error"` 事件的双形态诊断提取——兼容官方顶层形态
/// （`code`/`message`/`param` 在顶层）与既有嵌套 `error` 对象形态：嵌套字段优先，
/// 顶层 `code`/`param`/`message` 仅补缺；同时携带顶层 `sequence_number`（可得时）。
/// 无 `message`（合并后为空）或两形态均无有效字段时返回 `None`
/// （合成帧回退既有 `{"id","status"}` 形态，不带 error 字段、无空字段噪声）。
pub(super) fn responses_error_object(data: &str) -> Option<(Value, Option<u64>)> {
    let v = serde_json::from_str::<Value>(strip_bom(data)).ok()?;
    let mut obj = serde_json::Map::new();
    if let Some(err) = v.get("error").filter(|e| e.is_object()) {
        for key in ["type", "code", "param", "message"] {
            if let Some(val) = err.get(key).filter(|x| !x.is_null()) {
                obj.insert(key.to_string(), val.clone());
            }
        }
    }
    for key in ["code", "param", "message"] {
        if !obj.contains_key(key)
            && let Some(val) = v.get(key).filter(|x| !x.is_null())
        {
            obj.insert(key.to_string(), val.clone());
        }
    }
    let has_message = obj
        .get("message")
        .and_then(|m| m.as_str())
        .is_some_and(|s| !s.is_empty());
    has_message.then(|| (Value::Object(obj), extract_responses_seq(&v)))
}

/// TRN-7：流式模型提取——顶层 `model` 优先，回退 Anthropic `message_start.message.model`
/// （Anthropic 唯一模型名位于嵌套 `message`，顶层恒无）。
pub(super) fn stream_model_of(v: &Value) -> Option<&str> {
    v.get("model")
        .or_else(|| v.get("message").and_then(|m| m.get("model")))
        .and_then(|m| m.as_str())
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

/// MSP-4/2.28：Anthropic 思考**明文**载体（`thinking_delta`，或顶层
/// `thinking_delta` 且不携签名/密文）——可安全参与跨帧 token 缝合；
/// `signature`/`redacted`（签名/密文）与 `content_block_start` 的
/// `thinking`+`signature` 组合不在此列，维持 opaque fail-closed。
pub(super) fn is_anthropic_thinking_event(v: &Value) -> bool {
    let is_thinking = |t: &str| t.contains("thinking") && !t.contains("redacted");
    if v.get("type")
        .and_then(|x| x.as_str())
        .is_some_and(is_thinking)
        && v.get("signature").is_none()
        && v.get("redacted_data").is_none()
    {
        return true;
    }
    v.get("delta")
        .and_then(|d| d.get("type"))
        .and_then(|x| x.as_str())
        .is_some_and(is_thinking)
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
            // 次要事件；RED-4：`mcp`/`code_interpreter` 工具 delta 现计入审计，
            // 从次要集移除使审计判定可达；`reasoning`/`image_gen` 维持次要。
            ["reasoning", "image_gen"].iter().any(|k| t.contains(k))
        }
        P::Chat => v
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|choices| {
                choices.iter().any(|ch| {
                    ["delta", "message"].iter().any(|k| {
                        ch.get(k)
                            .and_then(|c| c.get("refusal"))
                            // CHC-4/2.23：仅 `refusal` 非 null 且非空才判次要；
                            // `refusal:null`（OpenAI 常态默认字段）不构成次要语义，
                            // 含工具/参数信息的帧不得据此跳过审计。
                            .is_some_and(|r| {
                                !r.is_null() && r.as_str().is_none_or(|s| !s.is_empty())
                            })
                    })
                })
            }),
        P::NonDialog => false,
    }
}

#[cfg(test)]
mod event_tests {
    use {super::*, crate::service::block_inject};

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
        assert!(
            obj.get("code").is_none() && obj.get("param").is_none() && obj.get("type").is_none()
        );
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
        let start = serde_json::json!({"type":"message_start","message":{"id":"msg_abc","model":"claude-x"}});
        assert_eq!(stream_model_of(&start), Some("claude-x"));
        assert_eq!(
            normalize_model(stream_model_of(&start).unwrap_or("")),
            "claude-x"
        );
        let top = serde_json::json!({"model":"gpt-4o"});
        assert_eq!(stream_model_of(&top), Some("gpt-4o"), "顶层优先不回退");
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
}
