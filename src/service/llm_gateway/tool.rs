//! 工具调用提取与会话归档：三协议 `tool_calls` 归一 + `conv_id` 提取/归档。

use {
    super::{GatewayMetrics, Protocol},
    serde_json::Value,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub index: u32,
    pub id: String,
    pub name: Option<String>,
    pub args: String,
    pub id_synth: bool,
}

pub fn normalize_tool_args(raw: Option<&Value>) -> String {
    match raw {
        None => {
            tracing::warn!("tool args 缺失，已记告警不断链（置空串审计暂缓）");
            String::new()
        }
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) => {
            tracing::warn!("tool args 为 null，已记告警不断链");
            String::new()
        }
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn synth_id(index: u32, present: Option<&str>) -> (String, bool) {
    match present.filter(|s| !s.is_empty()) {
        Some(s) => (s.to_string(), false),
        None => {
            tracing::warn!("tool id 缺失，已合成 call_stable_<index> 不断链");
            (format!("call_stable_{index}"), true)
        }
    }
}

/// 检索调用名派生（C10）：`file_search_call`→`file_search`、
/// `web_search_call`→`web_search`（对齐 Python `allow` 名单口径）；
/// 非检索类型返回 `None`。事件类型串（含 `response.` 前缀）与条目类型同解。
pub fn retrieval_tool_name(type_str: &str) -> Option<&'static str> {
    if type_str.contains("file_search") {
        Some("file_search")
    } else if type_str.contains("web_search") {
        Some("web_search")
    } else {
        None
    }
}

/// 检索参数归一（C10）：`arguments/input/args` 优先，`queries/query`
/// 回退序列化；全缺失返回空串（建槽不断链）。有意排除 `results`
/// （检索结果体量大，进 hold 有炸槽风险，审计只看查询）。
pub fn retrieval_args(obj: &serde_json::Map<String, Value>) -> String {
    for key in ["arguments", "input", "args"] {
        if let Some(v) = obj.get(key) {
            match v {
                Value::String(s) => return s.clone(),
                Value::Null => continue,
                other => return serde_json::to_string(other).unwrap_or_default(),
            }
        }
    }
    for key in ["queries", "query"] {
        if let Some(v) = obj.get(key)
            && !v.is_null()
        {
            match v {
                Value::String(s) => return s.clone(),
                other => return serde_json::to_string(other).unwrap_or_default(),
            }
        }
    }
    String::new()
}

fn custom_obj_to_call(index: u32, obj: &serde_json::Map<String, Value>) -> Option<ToolCall> {
    let id_raw = obj
        .get("id")
        .or_else(|| obj.get("call_id"))
        .or_else(|| obj.get("tool_call_id"))
        .and_then(|v| v.as_str());
    let name = obj
        .get("name")
        .or_else(|| obj.get("tool_name"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            obj.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.to_string());
    let args_raw = obj
        .get("arguments")
        .or_else(|| obj.get("input"))
        .or_else(|| obj.get("args"));
    let (id, id_synth) = synth_id(index, id_raw);
    let args = normalize_tool_args(args_raw);
    // L16：空增量（id 缺失合成 + 无名 + 无参，创槽心跳）只 warn 不建条目，
    // 与 anthropic 空跳过同条件；有真实 id 的待名槽仍保留锚定。
    if name.is_none() && args.is_empty() && id_synth {
        tracing::warn!("tool 三元组缺失（id/name/args 全空），跳过建条目不断链");
        return None;
    }
    Some(ToolCall {
        index,
        id,
        name,
        args,
        id_synth,
    })
}

/// Anthropic 分桶唯一实现（P0-2.2）：外层事件 `index` > 内层块 `index` >
/// 枚举下标；流式（`handler::llm::pump`）与非流共用，单优先级单实现。
pub fn anthropic_bucket_index(outer: Option<u32>, block: &Value, fallback: u32) -> u32 {
    outer
        .or_else(|| {
            block
                .get("index")
                .and_then(|v| v.as_u64())
                .map(|n| n as u32)
        })
        .unwrap_or(fallback)
}

/// 非流/流 tool 调用提取：外层 `index` 语义经 [`anthropic_bucket_index`]
/// 与流式分桶单实现对齐（chat 取 call.index/枚举下标、legacy 取 choice 序号；
/// anthropic 外层→内层→枚举回退；responses 取 output_index/index）。
pub fn extract_tool_calls(protocol: Protocol, payload: &Value) -> Vec<ToolCall> {
    let mut out = Vec::new();
    match protocol {
        Protocol::Chat => {
            if let Some(choices) = payload.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
                    for key in ["delta", "message"] {
                        if let Some(container) = ch.get(key) {
                            if let Some(calls) =
                                container.get("tool_calls").and_then(|c| c.as_array())
                            {
                                for (i, call) in calls.iter().enumerate() {
                                    let idx = call
                                        .get("index")
                                        .and_then(|x| x.as_u64())
                                        .unwrap_or(i as u64)
                                        as u32;
                                    let (id, id_synth) =
                                        synth_id(idx, call.get("id").and_then(|x| x.as_str()));
                                    let name = call
                                        .get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = normalize_tool_args(
                                        call.get("function").and_then(|f| f.get("arguments")),
                                    );
                                    if name.is_none() && args.is_empty() {
                                        tracing::warn!("chat tool 三元组缺失，暂缓审计放行");
                                    }
                                    out.push(ToolCall {
                                        index: idx,
                                        id,
                                        name,
                                        args,
                                        id_synth,
                                    });
                                }
                            }
                            for legacy_key in ["function_call", "custom_tool_call"] {
                                if let Some(legacy) = container.get(legacy_key) {
                                    let items: Vec<&Value> = match legacy {
                                        Value::Array(a) => a.iter().collect(),
                                        Value::Object(_) => vec![legacy],
                                        _ => vec![],
                                    };
                                    for (i, item) in items.iter().enumerate() {
                                        if let Some(obj) = item.as_object() {
                                            if legacy_key == "function_call" {
                                                let idx = ci as u32;
                                                let (id, id_synth) = synth_id(idx, None);
                                                let name = obj
                                                    .get("name")
                                                    .and_then(|v| v.as_str())
                                                    .map(|s| s.to_string());
                                                let args =
                                                    normalize_tool_args(obj.get("arguments"));
                                                out.push(ToolCall {
                                                    index: idx,
                                                    id,
                                                    name,
                                                    args,
                                                    id_synth,
                                                });
                                            } else if let Some(c) =
                                                custom_obj_to_call(i as u32, obj)
                                            {
                                                out.push(c);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Protocol::Anthropic => {
            let mut blocks: Vec<&Value> = Vec::new();
            for key in ["content_block", "delta"] {
                if let Some(b) = payload.get(key) {
                    blocks.push(b);
                }
            }
            if let Some(arr) = payload.get("content").and_then(|c| c.as_array()) {
                for b in arr {
                    blocks.push(b);
                }
            }
            if let Some(msg) = payload.get("message").and_then(|m| m.get("content")) {
                if let Some(arr) = msg.as_array() {
                    for b in arr {
                        blocks.push(b);
                    }
                } else if msg.is_object() {
                    blocks.push(msg);
                }
            }
            // §2.4：分桶经共享 [`anthropic_bucket_index`]（外层优先，见上）。
            let outer_index: Option<u32> = payload
                .get("index")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32);
            for (i, b) in blocks.iter().enumerate() {
                let bucket = anthropic_bucket_index(outer_index, b, i as u32);
                let is_tool = b.get("type").and_then(|v| v.as_str()).is_some_and(|t| {
                    t.contains("tool_use") || t.contains("function") || t.contains("custom")
                }) || b.get("name").is_some()
                    || b.get("partial_json").is_some()
                    || b.get("input").is_some()
                    || b.get("function_call").is_some()
                    || b.get("custom_tool_call").is_some();
                if !is_tool {
                    continue;
                }
                if let Some(fc) = b.get("function_call").and_then(|v| v.as_object()) {
                    let (id, id_synth) = synth_id(bucket, None);
                    let name = fc
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let args = normalize_tool_args(fc.get("arguments"));
                    out.push(ToolCall {
                        index: bucket,
                        id,
                        name,
                        args,
                        id_synth,
                    });
                    continue;
                }
                if let Some(cc) = b.get("custom_tool_call") {
                    match cc {
                        Value::Object(obj) => {
                            if let Some(c) = custom_obj_to_call(bucket, obj) {
                                out.push(c);
                            }
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object()
                                    && let Some(c) = custom_obj_to_call(j as u32, obj)
                                {
                                    out.push(c);
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let id_raw = b.get("id").and_then(|v| v.as_str());
                let name = b
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let args_raw = b
                    .get("partial_json")
                    .or_else(|| b.get("input"))
                    .or_else(|| b.get("arguments"));
                let args = normalize_tool_args(args_raw);
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                let (id, id_synth) = synth_id(bucket, id_raw);
                out.push(ToolCall {
                    index: bucket,
                    id,
                    name,
                    args,
                    id_synth,
                });
            }
        }
        Protocol::Responses => {
            // 5.1：单事件形态优先（delta 只累积不解析、done 全量才审计）。
            // 三级键：`output_index` 为桶号、`item_id/id` 为槽键、
            // `sequence_number` 由 AuditHold 保序；此处只做提取不排序不解析。
            let ev_type = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                let id_raw = payload
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .or_else(|| payload.get("id").and_then(|v| v.as_str()));
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = payload
                        .get("delta")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if !delta.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_id(idx, id_raw);
                        out.push(ToolCall {
                            index: idx,
                            id,
                            name,
                            args: delta.to_string(),
                            id_synth,
                        });
                    }
                    return out;
                }
                if ev_type.ends_with(".done") {
                    let args = match payload.get("arguments") {
                        Some(Value::String(s)) => s.clone(),
                        Some(other) => serde_json::to_string(other).unwrap_or_default(),
                        None => String::new(),
                    };
                    if !args.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_id(idx, id_raw);
                        out.push(ToolCall {
                            index: idx,
                            id,
                            name,
                            args,
                            id_synth,
                        });
                    }
                    return out;
                }
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = payload.get("item")
                && let Some(type_str) = item.get("type").and_then(|v| v.as_str())
                && (type_str == "function_call" || retrieval_tool_name(type_str).is_some())
            {
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                let mut args = match item.get("arguments") {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                    None => String::new(),
                };
                // C10：检索完成项参按 queries 回退（与流式分片同结论）。
                if args.is_empty()
                    && let Some(obj) = item.as_object()
                {
                    args = retrieval_args(obj);
                }
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| retrieval_tool_name(type_str).map(|s| s.to_string()));
                let id_raw = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
                if !args.is_empty() || name.is_some() {
                    let (id, id_synth) = synth_id(idx, id_raw);
                    out.push(ToolCall {
                        index: idx,
                        id,
                        name,
                        args,
                        id_synth,
                    });
                }
                return out;
            }
            if ev_type == "response.output_item.added"
                && let Some(item) = payload.get("item")
            {
                // C9 起始事件建槽：`added` 携带 function_call 名/id（尚无
                // arguments），建槽保留名/id 供后续 delta 累积与截断前审计；
                // C10 检索起始同样建槽（名按类型派生）；非 tool 形态仍直返。
                let type_str = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let is_tool = type_str.contains("function_call")
                    || type_str.contains("custom_tool_call")
                    || type_str.contains("tool")
                    || retrieval_tool_name(type_str).is_some()
                    || item.get("name").is_some();
                if !is_tool {
                    return out;
                }
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| retrieval_tool_name(type_str).map(|s| s.to_string()));
                let id_raw = item
                    .get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
                let (id, id_synth) = synth_id(idx, id_raw);
                out.push(ToolCall {
                    index: idx,
                    id,
                    name,
                    args: String::new(),
                    id_synth,
                });
                return out;
            }
            if payload.get("item").is_some() {
                return out;
            }
            if let Some(output) = payload.get("output").and_then(|o| o.as_array()) {
                for (i, item) in output.iter().enumerate() {
                    let bucket = item
                        .get("output_index")
                        .and_then(|x| x.as_u64())
                        .map(|n| n as u32)
                        .unwrap_or(i as u32);
                    let is_tool = item.get("type").and_then(|v| v.as_str()).is_some_and(|t| {
                        t.contains("function_call")
                            || t.contains("custom_tool_call")
                            || t.contains("tool")
                            || retrieval_tool_name(t).is_some()
                    }) || item.get("name").is_some()
                        || item.get("arguments").is_some()
                        || item.get("input").is_some();
                    if !is_tool {
                        continue;
                    }
                    // C10 检索调用直建条目：名缺失时按类型派生，参按
                    // queries 回退；与流式分片同结论（误报优于漏审）。
                    if let Some(obj) = item.as_object()
                        && let Some(rname) = obj
                            .get("type")
                            .and_then(|v| v.as_str())
                            .and_then(retrieval_tool_name)
                    {
                        let id_raw = obj
                            .get("id")
                            .and_then(|v| v.as_str())
                            .or_else(|| obj.get("call_id").and_then(|v| v.as_str()));
                        let name = obj
                            .get("name")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| Some(rname.to_string()));
                        let (id, id_synth) = synth_id(bucket, id_raw);
                        out.push(ToolCall {
                            index: bucket,
                            id,
                            name,
                            args: retrieval_args(obj),
                            id_synth,
                        });
                        continue;
                    }
                    if let Some(obj) = item.as_object()
                        && let Some(Value::Object(inner)) = obj.get("custom_tool_call")
                        && let Some(c) = custom_obj_to_call(bucket, inner)
                    {
                        out.push(c);
                        continue;
                    }
                    if let Some(obj) = item.as_object()
                        && let Some(c) = custom_obj_to_call(bucket, obj)
                    {
                        let meaningful = c.name.is_some() || !c.args.is_empty() || !c.id_synth;
                        if meaningful {
                            out.push(c);
                        }
                    }
                }
            }
        }
        Protocol::NonDialog => {}
    }
    out
}

pub fn extract_conv_id(data: &Value) -> Option<String> {
    let non_empty = |v: Option<&Value>| -> Option<String> {
        v.and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    if let Some(id) = non_empty(data.get("id")) {
        return Some(id);
    }
    if let Some(resp) = data.get("response")
        && let Some(id) = non_empty(resp.get("id"))
    {
        return Some(id);
    }
    if let Some(inner) = data.get("data") {
        if let Some(id) = non_empty(inner.get("id")) {
            return Some(id);
        }
        if let Some(resp) = inner.get("response")
            && let Some(id) = non_empty(resp.get("id"))
        {
            return Some(id);
        }
    }
    if let Some(err) = data.get("error") {
        match err {
            Value::String(s) if !s.is_empty() => return Some(s.clone()),
            Value::Object(obj) => {
                if let Some(id) = obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    return Some(id.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

pub fn archive_unknown_id(payload: &Value) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    format!("unknown_{}", hex::encode(&digest[..4]))
}

pub fn resolve_conv_id(
    header_id: Option<&str>,
    body: &Value,
    metrics: Option<&GatewayMetrics>,
    reason: &str,
) -> (String, bool) {
    let clean = |s: Option<&str>| s.filter(|v| !v.is_empty()).map(|s| s.to_string());
    if let Some(h) = clean(header_id) {
        return (h, true);
    }
    if let Some(id) = extract_conv_id(body) {
        return (id, false);
    }
    let archived = archive_unknown_id(body);
    if let Some(m) = metrics {
        m.record_conv_missing(reason);
    }
    tracing::debug!(reason = %reason, archived = %archived, "conv_id 缺失已归档不断链");
    (archived, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t5_null_tool_fragment_skipped_without_entry() {
        let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[null]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 1);
        assert!(calls[0].name.is_none(), "空增量无名");
        assert!(calls[0].args.is_empty(), "空增量无参");
        let empty_custom = serde_json::json!({"choices":[{"message":{"custom_tool_call":{}}}]});
        assert!(extract_tool_calls(Protocol::Chat, &empty_custom).is_empty());
        let null_items =
            serde_json::json!({"choices":[{"message":{"custom_tool_call":[null, 42]}}]});
        assert!(extract_tool_calls(Protocol::Chat, &null_items).is_empty());
    }

    #[test]
    fn t5_missing_index_falls_back_without_panic() {
        let v = serde_json::json!({"content_block":{"type":"tool_use","id":"a1","name":"bash","input":{}}});
        assert_eq!(anthropic_bucket_index(None, &v["content_block"], 7), 7);
        assert_eq!(
            anthropic_bucket_index(None, &serde_json::json!({"index": 4}), 7),
            4
        );
        assert_eq!(
            anthropic_bucket_index(Some(3), &serde_json::json!({"index": 9}), 7),
            3,
            "外层 index 优先"
        );
        let chat =
            serde_json::json!({"choices":[{"delta":{"tool_calls":[{"function":{"name":"run"}}]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &chat);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 0);
    }

    #[test]
    fn t5_multi_index_grouping_keeps_slots_separate() {
        let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"c0","function":{"name":"a","arguments":"{}"}},
            {"index":2,"id":"c2","function":{"name":"b","arguments":"{}"}}
        ]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].index, 0);
        assert_eq!(calls[1].index, 2);
        assert_eq!(calls[0].name.as_deref(), Some("a"));
        assert_eq!(calls[1].name.as_deref(), Some("b"));
    }

    #[test]
    fn fix3_missing_id_synthesizes_call_stable_id() {
        let v = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"name":"run","arguments":"{}"}}]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_stable_2");
        assert!(calls[0].id_synth);
        assert_eq!(calls[0].name.as_deref(), Some("run"));
    }

    #[test]
    fn fix3_preserved_id_normalizes_non_string_args() {
        let v = serde_json::json!({"choices":[{"message":{"tool_calls":[{"id":"c1","function":{"name":"q","arguments":{"a":1}}}]}}]});
        let calls = extract_tool_calls(Protocol::Chat, &v);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "c1");
        assert!(!calls[0].id_synth);
        assert_eq!(calls[0].args, r#"{"a":1}"#);
        let v2 = serde_json::json!({"choices":[{"delta":{"tool_calls":[{"id":"c2","function":{"name":"q"}}]}}]});
        let calls2 = extract_tool_calls(Protocol::Chat, &v2);
        assert_eq!(calls2[0].args, "");
    }

    #[test]
    fn fix3_supports_legacy_and_custom_dialects() {
        let legacy = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let calls = extract_tool_calls(Protocol::Chat, &legacy);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), Some("old"));
        assert!(calls[0].id_synth);
        let custom = serde_json::json!({"choices":[{"message":{"custom_tool_call":{"id":"k1","name":"t","input":{"p":2}}}}]});
        let calls2 = extract_tool_calls(Protocol::Chat, &custom);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].id, "k1");
        assert_eq!(calls2[0].args, r#"{"p":2}"#);
        let anth = serde_json::json!({"content_block":{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}});
        let calls3 = extract_tool_calls(Protocol::Anthropic, &anth);
        assert_eq!(calls3.len(), 1);
        assert_eq!(calls3[0].args, r#"{"cmd":"ls"}"#);
        let resp = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
        let calls4 = extract_tool_calls(Protocol::Responses, &resp);
        assert_eq!(calls4.len(), 1);
        assert!(calls4[0].id_synth);
    }

    #[test]
    fn responses_delta_extracted_by_three_level_key_ignoring_text() {
        let d1 = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":1,"item_id":"item-7","sequence_number":0,"delta":"{\"x\":"});
        let calls = extract_tool_calls(Protocol::Responses, &d1);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 1);
        assert_eq!(calls[0].id, "item-7");
        assert!(!calls[0].id_synth);
        assert_eq!(calls[0].args, "{\"x\":");
        let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":1,"item_id":"item-7","sequence_number":2,"name":"run","arguments":"{\"x\":1}"});
        let calls2 = extract_tool_calls(Protocol::Responses, &done);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].name.as_deref(), Some("run"));
        assert_eq!(calls2[0].args, "{\"x\":1}");
        let text =
            serde_json::json!({"type":"response.output_text.delta","output_index":0,"delta":"hi"});
        assert!(extract_tool_calls(Protocol::Responses, &text).is_empty());
        let item_done = serde_json::json!({"type":"response.output_item.done","output_index":2,"item":{"type":"function_call","id":"c9","name":"q","arguments":"{}"}});
        let calls3 = extract_tool_calls(Protocol::Responses, &item_done);
        assert_eq!(calls3.len(), 1);
        assert_eq!((calls3[0].index, calls3[0].id.as_str()), (2, "c9"));
    }

    #[test]
    fn anthropic_interleaved_indices_bucketed_by_event_index() {
        let b0 = serde_json::json!({"content_block":{"type":"tool_use","index":3,"id":"a3","name":"t3","input":{}}});
        let calls = extract_tool_calls(Protocol::Anthropic, &b0);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 3);
        let d1 = serde_json::json!({"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"a\":"}});
        let calls2 = extract_tool_calls(Protocol::Anthropic, &d1);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].index, 5);
        assert_eq!(calls2[0].args, "{\"a\":");
        assert!(calls2[0].id_synth);
    }

    #[test]
    fn anthropic_outer_index_interleaving_keeps_buckets_separate() {
        let start0 = serde_json::json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a0","name":"run"}});
        let start1 = serde_json::json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"a1","name":"run"}});
        let d0 = serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":"}});
        let d1 = serde_json::json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"y\":"}});
        let c0 = extract_tool_calls(Protocol::Anthropic, &start0);
        assert_eq!((c0.len(), c0[0].index), (1, 0));
        assert_eq!(c0[0].id, "a0");
        let c1 = extract_tool_calls(Protocol::Anthropic, &start1);
        assert_eq!((c1.len(), c1[0].index), (1, 1));
        let p0 = extract_tool_calls(Protocol::Anthropic, &d0);
        assert_eq!((p0.len(), p0[0].index), (1, 0));
        assert_eq!(p0[0].args, "{\"x\":");
        let p1 = extract_tool_calls(Protocol::Anthropic, &d1);
        assert_eq!((p1.len(), p1[0].index), (1, 1));
        assert_eq!(p1[0].args, "{\"y\":");
        let inner = serde_json::json!({"content":[{"type":"tool_use","index":7,"id":"z","name":"q","input":{}}]});
        let ci = extract_tool_calls(Protocol::Anthropic, &inner);
        assert_eq!(ci[0].index, 7);
    }

    #[test]
    fn anthropic_outer_index_wins_over_conflicting_inner() {
        // P0-2.3 回归：外层 0/1 + 内层 3/5 交错时以外层分桶（与流式同槽）。
        let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
        let c0 = extract_tool_calls(Protocol::Anthropic, &start0);
        assert_eq!(c0.len(), 1);
        assert_eq!(c0[0].index, 0, "外层 0 须胜过内层 3");
        let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
        let c1 = extract_tool_calls(Protocol::Anthropic, &d1);
        assert_eq!(c1.len(), 1);
        assert_eq!(c1[0].index, 1, "外层 1 须胜过内层 5");
        assert_eq!(c1[0].args, "{\"y\":");
        // 共享分桶函数直断言：三级回退（外层 > 内层 > 下标）。
        let blk = serde_json::json!({"index":3});
        assert_eq!(anthropic_bucket_index(Some(0), &blk, 9), 0);
        assert_eq!(anthropic_bucket_index(None, &blk, 9), 3);
        assert_eq!(anthropic_bucket_index(None, &serde_json::json!({}), 9), 9);
    }

    #[test]
    fn responses_added_creates_slot_preserving_name_id() {
        // C9 起始事件建槽：`added` 无 arguments 仍须产出空参调用保留名/id。
        let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
        let calls = extract_tool_calls(Protocol::Responses, &added);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, 2);
        assert_eq!(calls[0].id, "call-9");
        assert!(!calls[0].id_synth);
        assert_eq!(calls[0].name.as_deref(), Some("run"));
        assert!(calls[0].args.is_empty());
        // 非 tool 形态 `added`（纯消息项）仍直返，不建槽。
        let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
        assert!(extract_tool_calls(Protocol::Responses, &msg).is_empty());
        // 无名无 id 的裸 `added` 合成稳定 id，不断链。
        let bare = serde_json::json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call"}});
        let bare_calls = extract_tool_calls(Protocol::Responses, &bare);
        assert_eq!(bare_calls.len(), 1);
        assert!(bare_calls[0].id_synth);
    }

    #[test]
    fn empty_custom_heartbeat_builds_no_entry() {
        // L16：空心跳（无 id/name/args）只 warn 不建条目；对照组非空仍建槽。
        let empty = serde_json::json!({"choices": [{"delta": {"custom_tool_call": {}}}]});
        assert!(
            extract_tool_calls(Protocol::Chat, &empty).is_empty(),
            "空 custom_tool_call 不得建条目"
        );
        let named =
            serde_json::json!({"choices": [{"delta": {"custom_tool_call": {"name": "run"}}}]});
        let calls = extract_tool_calls(Protocol::Chat, &named);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), Some("run"));
    }

    #[test]
    fn fix6_single_double_layer_fallback_with_missing_archive() {
        let m = GatewayMetrics::default();
        let single = serde_json::json!({"type":"response.failed","id":"r1"});
        assert_eq!(extract_conv_id(&single).as_deref(), Some("r1"));
        let dbl = serde_json::json!({"type":"response.incomplete","response":{"id":"r2"}});
        assert_eq!(extract_conv_id(&dbl).as_deref(), Some("r2"));
        let nested = serde_json::json!({"type":"error","data":{"response":{"id":"r3"}}});
        assert_eq!(extract_conv_id(&nested).as_deref(), Some("r3"));
        let err_obj = serde_json::json!({"type":"error","error":{"id":"e1"}});
        assert_eq!(extract_conv_id(&err_obj).as_deref(), Some("e1"));
        let empty = serde_json::json!({"type":"response.failed"});
        assert!(extract_conv_id(&empty).is_none());
        let (archived, exempt) = resolve_conv_id(None, &empty, Some(&m), "failed");
        assert!(archived.starts_with("unknown_") && archived.len() == 8 + 8);
        assert!(!exempt);
        assert_eq!(m.conv_missing_count("failed"), 1);
        let (hid, hexempt) = resolve_conv_id(
            Some("h1"),
            &serde_json::json!({"id":"b1"}),
            Some(&m),
            "failed",
        );
        assert_eq!(hid, "h1");
        assert!(hexempt);
        assert_eq!(m.conv_missing_count("failed"), 1);
    }
}
