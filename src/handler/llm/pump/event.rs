//! 流泵事件判定 + SSE 响应装配（D2 自 `pump.rs` 拆出）：终止/次要事件与空流守门。

use {
    crate::service::{
        json_walk::{jloads, strip_bom},
        llm_gateway::{self, GatewayMetrics, Protocol},
        redaction::leaf::{NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE},
        sse::is_done_payload,
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
/// D4/R5-05：状态码入参由调用方传上游 2xx 原状态，不再硬编码 `200`。
pub fn build_sse_response(
    rx: tokio::sync::mpsc::Receiver<String>,
    normalized_out: bool,
    pump: tokio::task::JoinHandle<super::PumpOutcome>,
    status: StatusCode,
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
        .status(status)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache");
    if normalized_out {
        stream_builder = stream_builder.header(NORMALIZED_HEADER_NAME, NORMALIZED_HEADER_VALUE);
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

/// 6.1/ARH-2：每帧 `ev.data` 的唯一全量解析点——剥 BOM 后单次 `jloads`，
/// 产物供本函数各判定复用；空帧/`[DONE]`/非法 JSON 返回 `None`（调用方按需走
/// contains 兜底）。生产段 SHALL NOT 再出现第二处帧解析（源码守护见
/// `model_bucket_tests.rs` 的 `single_parse_per_frame` 与
/// `event_rs_production_prefix_no_from_str`）。
pub(super) fn parse_event_data(data: &str) -> Option<Value> {
    if data.is_empty() || is_done_payload(data) {
        return None;
    }
    count_parse();
    jloads(strip_bom(data)).ok()
}

/// E8 对拒止粘滞分支的终止判定：已解析帧走精确判定，未解析帧走 contains
/// 兜底并记 `terminal_fallback` 计数（调用点已排除空帧/`[DONE]`，`None`
/// 即解析失败）。
/// 6.1/ARH-2：解析产物经 [`parse_event_data`] 单点产出，此处零重解析。
pub(super) fn sticky_terminal_event(
    protocol: Protocol,
    parsed: Option<&Value>,
    data: &str,
    metrics: &GatewayMetrics,
) -> bool {
    match parsed {
        Some(v) => sticky_terminal_precise(protocol, v),
        None => {
            metrics.record_terminal_fallback();
            sticky_terminal_fallback(protocol, data)
        }
    }
}

/// E8 Responses 合成前的失败/未完成分类：已解析帧按 `type` 精确分类，
/// 未解析帧回退 contains 并计数。返回 `(is_failed, is_incomplete, is_error)`。
/// 6.1/ARH-2：解析产物经 [`parse_event_data`] 单点产出，此处零重解析。
pub(super) fn responses_failed_incomplete(
    parsed: Option<&Value>,
    data: &str,
    metrics: &GatewayMetrics,
) -> (bool, bool, bool) {
    match parsed {
        Some(v) => {
            let t = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            (
                t == "response.failed",
                t == "response.incomplete",
                t == "error",
            )
        }
        None => {
            metrics.record_terminal_fallback();
            (
                data.contains("response.failed"),
                data.contains("response.incomplete"),
                data.contains("\"type\":\"error\"") || data.contains("\"type\": \"error\""),
            )
        }
    }
}

/// D5 + TRN-2：`type:"error"` 事件的双形态诊断提取——兼容官方顶层形态
/// （`code`/`message`/`param` 在顶层）与既有嵌套 `error` 对象形态：嵌套字段优先，
/// 顶层 `code`/`param`/`message` 仅补缺；同时携带顶层 `sequence_number`（可得时）。
/// 无 `message`（合并后为空）或两形态均无有效字段时返回 `None`
/// （合成帧回退既有 `{"id","status"}` 形态，不带 error 字段、无空字段噪声）。
/// 6.1/ARH-2：解析产物经 [`parse_event_data`] 单点产出，此处零重解析。
pub(super) fn responses_error_object(parsed: Option<&Value>) -> Option<(Value, Option<u64>)> {
    let v = parsed?;
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
    has_message.then(|| (Value::Object(obj), extract_responses_seq(v)))
}

/// TRN-7 + R5-02：流式模型提取三级回退——顶层 `model` → Anthropic
/// `message_start.message.model` → Responses `response.completed.response.model`
/// （与 `extract_conv_id` 的 `response.id` 回退对称、无条件）。
pub(super) fn stream_model_of(v: &Value) -> Option<&str> {
    v.get("model")
        .or_else(|| v.get("message").and_then(|m| m.get("model")))
        .or_else(|| v.get("response").and_then(|m| m.get("model")))
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

/// 流式终端事件判定（§2.6 去重用）：唯一来源为 `Protocol::spec().terminal_event_types`
/// （R5-24/D8）——chat 集合为空（以 `[DONE]` 收尾，非 JSON 分支处理，此处恒 false）；
/// anthropic 为 `message_stop` 或 `error`（P2/D3：`error` 本身即终端，其后不得注入
/// `message_stop`）；responses 为 `completed/failed/incomplete`（`incomplete` P4
/// 原样透传并作为唯一终端）。
pub(super) fn is_terminal_event(protocol: Protocol, v: &Value) -> bool {
    v.get("type")
        .and_then(|t| t.as_str())
        .is_some_and(|t| protocol.spec().terminal_event_types.contains(&t))
}

/// A-6/F-08：Chat 错误载荷帧即终端——判据严格限定为「顶层 `error` 存在」与
/// 「`choices` 缺席」同时成立；`choices[].error` 或顶层 `error` 与 `choices`
/// 共存的正常形态不满足判据（不误伤，既有透传与收尾语义不变）。
pub(super) fn is_chat_error_terminal(protocol: Protocol, v: &Value) -> bool {
    protocol.is_chat() && v.get("error").is_some() && v.get("choices").is_none()
}

/// R5-04：上游错误即终端的统一判据——Chat 走 [`is_chat_error_terminal`]
/// （顶层 `error` 且无 `choices`），Anthropic 为 `type:"error"`（该事件本身即终端）。
/// Responses `type:"error"` 由独立合成路径承载（记 `synthesized_failed`），不在此列。
pub(super) fn is_upstream_error_terminal(protocol: Protocol, v: &Value) -> bool {
    is_chat_error_terminal(protocol, v)
        || (protocol.is_anthropic() && v.get("type").and_then(|t| t.as_str()) == Some("error"))
}

/// A-2/F-02：Responses 序号游标推进——取既有上界与上游 `sequence_number` 的
/// 较大值（`cursor = max(cursor.unwrap_or(0), seq)`）；缺 `sequence_number` 的
/// 帧不更新、回退值被忽略（只取 max），断序不升级为错误。
pub(super) fn advance_responses_seq_cursor(cursor: &mut Option<u64>, v: &Value) {
    if let Some(seq) = extract_responses_seq(v) {
        *cursor = Some(cursor.unwrap_or(0).max(seq));
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

/// 6.2/ARH-2：帧解析计数钩子——生产编译为空实现（零开销），测试经线程本地
/// `PARSE_COUNT` 计数，供泵 e2e 断言每帧恰一次解析。
#[cfg(not(test))]
fn count_parse() {}

#[cfg(test)]
fn count_parse() { PARSE_COUNT.with(|c| c.set(c.get() + 1)); }

#[cfg(test)]
thread_local! {
    /// 6.2/ARH-2：线程本地解析计数（并行用例互不串扰，勿改全局原子）。
    static PARSE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// 6.2/ARH-2：取出并清零本线程帧解析计数（仅测试可见）。
#[cfg(test)]
pub(super) fn take_parse_count() -> usize { PARSE_COUNT.with(std::cell::Cell::take) }

#[cfg(test)]
mod event_tests;
