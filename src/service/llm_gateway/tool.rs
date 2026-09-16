//! 工具调用提取与会话归档：三协议 `tool_calls` 归一 + `conv_id` 提取/归档。

use {
    super::{GatewayMetrics, Protocol},
    serde_json::Value,
};

pub(crate) use super::tool_responses::{
    derived_item_tool_call,
    responses_derived_tool_kind,
    responses_item_tool_name,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub index: u32,
    pub id: String,
    pub name: Option<String>,
    pub args: String,
    pub id_synth: bool,
}

pub fn normalize_tool_args(raw: Option<&Value>) -> String { normalize_tool_args_with(true, raw) }

/// X2/D8：tool 参数归一共享实现：`emit_warn=true` 保留非流告警现值，
/// `false` 静默（流式现值）；两入口共用防漂移。
pub(crate) fn normalize_tool_args_with(emit_warn: bool, raw: Option<&Value>) -> String {
    match raw {
        None => {
            if emit_warn {
                tracing::warn!("tool args 缺失，已记告警不断链（置空串审计暂缓）");
            }
            String::new()
        }
        Some(Value::Null) => {
            if emit_warn {
                tracing::warn!("tool args 为 null，已记告警不断链");
            }
            String::new()
        }
        Some(Value::String(s)) => s.clone(),
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// X2/D8：合成 id 共享实现（缺失/空 → `call_stable_<index>`），`emit_warn`
/// 控制告警（非流 warn、流式静默），两入口共用防漂移。
pub(crate) fn synth_tool_id_with(
    emit_warn: bool,
    index: u32,
    present: Option<&str>,
) -> (String, bool) {
    match present.filter(|s| !s.is_empty()) {
        Some(s) => (s.to_string(), false),
        None => {
            if emit_warn {
                tracing::warn!("tool id 缺失，已合成 call_stable_<index> 不断链");
            }
            (format!("call_stable_{index}"), true)
        }
    }
}

/// X2/D8：custom 形态字段归一（`id/call_id/tool_call_id`、`name/tool_name/function.name`、
/// `arguments/input/args`），流/非流共享；args 经 [`normalize_tool_args_with`] 归一。
pub(crate) fn custom_tool_parts(
    emit_warn: bool,
    obj: &serde_json::Map<String, Value>,
) -> (Option<String>, Option<String>, String) {
    let id = obj
        .get("id")
        .or_else(|| obj.get("call_id"))
        .or_else(|| obj.get("tool_call_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
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
    let args = normalize_tool_args_with(
        emit_warn,
        obj.get("arguments")
            .or_else(|| obj.get("input"))
            .or_else(|| obj.get("args")),
    );
    (id, name, args)
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
    // T11/D10：官方 Responses 检索条目查询在 `action` 对象内
    // （`{"type":"search","query":...}`）；`query` 字符串直取、`queries`
    // 数组/其他非 null 值序列化。`results` 仍排除（体量风险）。
    if let Some(action) = obj.get("action").and_then(|v| v.as_object()) {
        for key in ["query", "queries"] {
            if let Some(v) = action.get(key)
                && !v.is_null()
            {
                match v {
                    Value::String(s) => return s.clone(),
                    other => return serde_json::to_string(other).unwrap_or_default(),
                }
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

/// Chat 桶键（F-P1b + CHC-6/2.25）：`choice` 序号与 tool `index` 位域拼接，
/// 声明域内 `ci < 2^16 && idx < 2^16` 单射无碰撞。旧实现 `ci*64+idx` 在
/// `idx >= 64` 时与下一 choice 的桶 0 碰撞（64 步长饱和）；`ci = 0` 时本键
/// 与旧实现等值，单 choice 快照不变。
pub fn chat_bucket(ci: usize, idx: u32) -> u32 {
    let ci = ci as u32;
    debug_assert!(ci < (1 << 16), "choice index 超出位域: {ci}");
    debug_assert!(idx < (1 << 16), "tool index 超出位域: {idx}");
    (ci << 16) | (idx & 0xFFFF)
}

/// P9/X2：Responses `output[]` 桶号唯一实现（流/非流同键）：`item.output_index`
/// 优先，缺失回退枚举下标；两路径共用防漂移。
pub(crate) fn responses_output_bucket(item: &Value, fallback: usize) -> u32 {
    item.get("output_index")
        .and_then(|x| x.as_u64())
        .map(|n| n as u32)
        .unwrap_or(fallback as u32)
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

fn custom_obj_to_call(
    emit_warn: bool,
    index: u32,
    obj: &serde_json::Map<String, Value>,
) -> Option<ToolCall> {
    let (id_raw, name, args) = custom_tool_parts(emit_warn, obj);
    let (id, id_synth) = synth_tool_id_with(emit_warn, index, id_raw.as_deref());
    // L16：空增量（id 缺失合成 + 无名 + 无参，创槽心跳）只 warn 不建条目，
    // 与 anthropic 空跳过同条件；有真实 id 的待名槽仍保留锚定。
    if name.is_none() && args.is_empty() && id_synth {
        if emit_warn {
            tracing::warn!("tool 三元组缺失（id/name/args 全空），跳过建条目不断链");
        }
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

/// ARC-3/D3：三协议 tool 调用提取单一核心，流式分片与非流两路径共用同一三臂
/// walk；`emit_warn` 区分非流（warn）与流式（静默）。分桶、合成 id、字段优先级、
/// 检索事件派生、`.delta`/`.done` 语义逐项等价。
pub(crate) fn extract_tool_calls_with(
    emit_warn: bool,
    protocol: Protocol,
    payload: &Value,
) -> Vec<ToolCall> {
    let mut out = Vec::new();
    match protocol {
        Protocol::Chat => {
            if let Some(choices) = payload.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
                    // RED-7：分桶用协议声明 `choices[].index`（缺省回退枚举位置）。
                    let choice_idx = ch
                        .get("index")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(ci as u64) as usize;
                    for key in ["delta", "message"] {
                        let Some(container) = ch.get(key) else {
                            continue;
                        };
                        if let Some(calls) = container.get("tool_calls").and_then(|c| c.as_array())
                        {
                            for (i, call) in calls.iter().enumerate() {
                                let idx = call
                                    .get("index")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(i as u64)
                                    as u32;
                                let bucket = chat_bucket(choice_idx, idx);
                                let (id, id_synth) = synth_tool_id_with(
                                    emit_warn,
                                    bucket,
                                    call.get("id").and_then(|x| x.as_str()),
                                );
                                let name = call
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let args = normalize_tool_args_with(
                                    emit_warn,
                                    call.get("function").and_then(|f| f.get("arguments")),
                                );
                                if emit_warn && name.is_none() && args.is_empty() {
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
                            let Some(legacy) = container.get(legacy_key) else {
                                continue;
                            };
                            let items: Vec<&Value> = match legacy {
                                Value::Array(a) => a.iter().collect(),
                                Value::Object(_) => vec![legacy],
                                _ => vec![],
                            };
                            for (i, item) in items.iter().enumerate() {
                                let Some(obj) = item.as_object() else {
                                    continue;
                                };
                                if legacy_key == "function_call" {
                                    let bucket = chat_bucket(choice_idx, 0);
                                    let (id, id_synth) =
                                        synth_tool_id_with(emit_warn, bucket, None);
                                    let name = obj
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let args =
                                        normalize_tool_args_with(emit_warn, obj.get("arguments"));
                                    out.push(ToolCall {
                                        index: bucket,
                                        id,
                                        name,
                                        args,
                                        id_synth,
                                    });
                                } else if let Some(c) = custom_obj_to_call(
                                    emit_warn,
                                    chat_bucket(choice_idx, i as u32),
                                    obj,
                                ) {
                                    out.push(c);
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
            let outer_index: Option<u32> = payload
                .get("index")
                .and_then(|x| x.as_u64())
                .map(|n| n as u32);
            for (i, b) in blocks.iter().enumerate() {
                let bucket = anthropic_bucket_index(outer_index, b, i as u32);
                if let Some(fc) = b.get("function_call").and_then(|v| v.as_object()) {
                    let (id, id_synth) = synth_tool_id_with(emit_warn, bucket, None);
                    let name = fc
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let args = normalize_tool_args_with(emit_warn, fc.get("arguments"));
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
                            if let Some(c) = custom_obj_to_call(emit_warn, bucket, obj) {
                                out.push(c);
                            }
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object()
                                    && let Some(c) = custom_obj_to_call(emit_warn, j as u32, obj)
                                {
                                    out.push(c);
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
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
                let id_raw = b.get("id").and_then(|v| v.as_str());
                let name = b
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                // TRN-6：`content_block_start` 的空占位 `input`（`{}`/空串/null）
                // 不作为 args 累积，避免与后续 `partial_json` 拼接成 `"{}{...}"`。
                let empty_placeholder = |v: &Value| match v {
                    Value::Null => true,
                    Value::String(s) => s.is_empty(),
                    Value::Object(m) => m.is_empty(),
                    Value::Array(a) => a.is_empty(),
                    _ => false,
                };
                let args_raw = if let Some(pj) = b.get("partial_json") {
                    Some(pj)
                } else if let Some(inp) = b.get("input").filter(|x| !empty_placeholder(x)) {
                    Some(inp)
                } else {
                    b.get("arguments")
                };
                let args = normalize_tool_args_with(emit_warn, args_raw);
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                let (id, id_synth) = synth_tool_id_with(emit_warn, bucket, id_raw);
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
            let derived = responses_derived_tool_kind(ev_type);
            if ev_type.contains("function_call_arguments") || derived.is_some() {
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
                    .map(|s| s.to_string())
                    .or_else(|| derived.map(str::to_string));
                if ev_type.ends_with(".delta") {
                    let delta = payload
                        .get("delta")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if !delta.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_tool_id_with(emit_warn, idx, id_raw);
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
                    let args = ["arguments", "code", "command", "input"]
                        .iter()
                        .find_map(|k| payload.get(*k))
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !args.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_tool_id_with(emit_warn, idx, id_raw);
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
            // C10 检索事件计 tool（与非流一致）：名按类型派生，参按
            // queries 回退；中间态同样建槽审计，误报优于漏审。
            if let Some(rname) = retrieval_tool_name(ev_type) {
                let idx = payload
                    .get("output_index")
                    .or_else(|| payload.get("index"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u32;
                let id_raw = payload
                    .get("item_id")
                    .and_then(|v| v.as_str())
                    .or_else(|| payload.get("id").and_then(|v| v.as_str()));
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some(rname.to_string()));
                let mut args = payload.as_object().map(retrieval_args).unwrap_or_default();
                if args.is_empty()
                    && let Some(d) = payload.get("delta").and_then(|v| v.as_str())
                {
                    args = d.to_string();
                }
                let (id, id_synth) = synth_tool_id_with(emit_warn, idx, id_raw);
                out.push(ToolCall {
                    index: idx,
                    id,
                    name,
                    args,
                    id_synth,
                });
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = payload.get("item")
            {
                let type_str = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let idx = payload
                    .get("output_index")
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0);
                // A/M-1：内置工具（code_interpreter/shell/mcp/computer/custom_tool/
                // 检索）经共享派生路径 `derived_item_tool_call`，与非流 `output[]`
                // 同结论（parity 由 `responses_output_stream_nonstream_parity` 锁定）。
                if let Some(c) = derived_item_tool_call(emit_warn, idx, item, type_str) {
                    out.push(c);
                    return out;
                }
                // function_call 等其余形态维持既有内联提取。
                let is_tool = type_str.contains("function_call")
                    || item.get("name").is_some()
                    || item.get("arguments").is_some()
                    || item.get("input").is_some();
                if is_tool {
                    let mut args = ["arguments", "code", "command", "input"]
                        .iter()
                        .find_map(|k| item.get(*k))
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if args.is_empty()
                        && let Some(obj) = item.as_object()
                    {
                        args = retrieval_args(obj);
                    }
                    if args.is_empty()
                        && let Some(action) = item.get("action")
                    {
                        args = serde_json::to_string(action).unwrap_or_default();
                    }
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let id_raw = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
                    if !args.is_empty() || name.is_some() {
                        let (id, id_synth) = synth_tool_id_with(emit_warn, idx, id_raw);
                        out.push(ToolCall {
                            index: idx,
                            id,
                            name,
                            args,
                            id_synth,
                        });
                    }
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
                let (id, id_synth) = synth_tool_id_with(emit_warn, idx, id_raw);
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
                    let item_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let is_tool = item_type.contains("function_call")
                        || item_type.contains("custom_tool_call")
                        || item_type.contains("tool")
                        || responses_item_tool_name(item_type).is_some()
                        || retrieval_tool_name(item_type).is_some()
                        || item.get("name").is_some()
                        || item.get("arguments").is_some()
                        || item.get("input").is_some();
                    if !is_tool {
                        continue;
                    }
                    let bucket = responses_output_bucket(item, i);
                    // 嵌套 custom 方言（非官方 Responses 形态）保持既有 custom_obj_to_call。
                    if let Some(obj) = item.as_object()
                        && let Some(Value::Object(inner)) = obj.get("custom_tool_call")
                        && let Some(c) = custom_obj_to_call(emit_warn, bucket, inner)
                    {
                        out.push(c);
                        continue;
                    }
                    // A/M-1：内置（非 function_call）工具条目经共享派生路径建条目
                    // （名派生 + 参数三级回退），与 item-done 路径同结论。
                    if let Some(c) = derived_item_tool_call(emit_warn, bucket, item, item_type) {
                        out.push(c);
                        continue;
                    }
                    // function/custom 等其余形态保持既有 custom_obj_to_call 路径。
                    if let Some(obj) = item.as_object()
                        && let Some(c) = custom_obj_to_call(emit_warn, bucket, obj)
                    {
                        out.push(c);
                    }
                }
            }
        }
        Protocol::NonDialog => {}
    }
    out
}

/// 非流 tool 调用提取（ARC-3 薄包装）：`emit_warn=true` 调用单一核心。
pub fn extract_tool_calls(protocol: Protocol, payload: &Value) -> Vec<ToolCall> {
    extract_tool_calls_with(true, protocol, payload)
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
    // TRN-7：Anthropic `message_start`——唯一 id 位于嵌套 `message.id`，顶层恒无。
    if let Some(msg) = data.get("message")
        && let Some(id) = non_empty(msg.get("id"))
    {
        return Some(id);
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
