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

/// Chat 桶键混入 choice 序号（F-P1b）：`ci*64+index`，`n>1` 时跨 choice
/// 同 `index` 分桶隔离；`ci=0` 时与旧键等值，单 choice 快照不变。
pub fn chat_bucket(ci: usize, idx: u32) -> u32 {
    (ci as u32).saturating_mul(64).saturating_add(idx)
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
/// 与流式分桶单实现对齐（chat 取 `chat_bucket(ci, call.index)`、legacy 取
/// `chat_bucket(ci, 0)`；anthropic 外层→内层→枚举回退；responses 取 output_index/index）。
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
                                    let bucket = chat_bucket(ci, idx);
                                    let (id, id_synth) =
                                        synth_id(bucket, call.get("id").and_then(|x| x.as_str()));
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
                                        index: bucket,
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
                                                let bucket = chat_bucket(ci, 0);
                                                let (id, id_synth) = synth_id(bucket, None);
                                                let name = obj
                                                    .get("name")
                                                    .and_then(|v| v.as_str())
                                                    .map(|s| s.to_string());
                                                let args =
                                                    normalize_tool_args(obj.get("arguments"));
                                                out.push(ToolCall {
                                                    index: bucket,
                                                    id,
                                                    name,
                                                    args,
                                                    id_synth,
                                                });
                                            } else if let Some(c) =
                                                custom_obj_to_call(chat_bucket(ci, i as u32), obj)
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
mod tests;
