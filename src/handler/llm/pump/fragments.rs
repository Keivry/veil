//! tool 分片提取（D2 自 `pump.rs` 拆出）：三协议 tool 调用分桶与序号归一。

use {
    crate::service::llm_gateway::{
        Protocol,
        anthropic_bucket_index,
        chat_bucket,
        retrieval_args,
        retrieval_tool_name,
        tool::{
            custom_tool_parts,
            normalize_tool_args_with,
            responses_output_bucket,
            synth_tool_id_with,
        },
    },
    serde_json::Value,
};

pub(super) fn extract_tool_fragments(
    protocol: Protocol,
    v: &Value,
) -> Vec<(u32, Option<String>, Option<String>, String)> {
    use crate::service::llm_gateway::Protocol as P;
    let mut out = Vec::new();
    match protocol {
        P::Chat => {
            // X2/D8：字段归一/合成 id 复用共享 helper（流式静默，与非流 warn 现值对齐）。
            let norm_args = |raw: Option<&Value>| normalize_tool_args_with(false, raw);
            let synth = |idx: u32, present: Option<&str>| synth_tool_id_with(false, idx, present).0;
            if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
                for (ci, ch) in choices.iter().enumerate() {
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
                                let bucket = chat_bucket(ci, idx);
                                let id = synth(bucket, call.get("id").and_then(|x| x.as_str()));
                                let name = call
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let args = norm_args(
                                    call.get("function").and_then(|f| f.get("arguments")),
                                );
                                out.push((bucket, Some(id), name, args));
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
                                    let bucket = chat_bucket(ci, 0);
                                    let name = obj
                                        .get("name")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = norm_args(obj.get("arguments"));
                                    out.push((bucket, Some(synth(bucket, None)), name, args));
                                } else {
                                    let bucket = chat_bucket(ci, i as u32);
                                    let (id_raw, name, args) = custom_tool_parts(false, obj);
                                    let (id, id_synth) =
                                        synth_tool_id_with(false, bucket, id_raw.as_deref());
                                    if name.is_some() || !args.is_empty() || !id_synth {
                                        out.push((bucket, Some(id), name, args));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        P::Anthropic => {
            // X2/D8：同 Chat，字段归一/合成 id 复用共享 helper（流式静默）。
            let norm_args = |raw: Option<&Value>| normalize_tool_args_with(false, raw);
            let synth = |idx: u32, present: Option<&str>| synth_tool_id_with(false, idx, present).0;
            let mut blocks: Vec<&Value> = Vec::new();
            for key in ["content_block", "delta"] {
                if let Some(b) = v.get(key) {
                    blocks.push(b);
                }
            }
            // §2.4/P0-2.2：分桶复用共享 `anthropic_bucket_index`
            // （外层事件序号优先，内层回退，与非流单实现）。
            let outer_index = v.get("index").and_then(|x| x.as_u64()).map(|n| n as u32);
            if let Some(arr) = v.get("content").and_then(|c| c.as_array()) {
                blocks.extend(arr.iter());
            }
            if let Some(msg) = v.get("message").and_then(|m| m.get("content")) {
                if let Some(arr) = msg.as_array() {
                    blocks.extend(arr.iter());
                } else if msg.is_object() {
                    blocks.push(msg);
                }
            }
            for (i, b) in blocks.iter().enumerate() {
                let idx = anthropic_bucket_index(outer_index, b, i as u32);
                if let Some(fc) = b.get("function_call").and_then(|x| x.as_object()) {
                    let name = fc
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let args = norm_args(fc.get("arguments"));
                    out.push((idx, Some(synth(idx, None)), name, args));
                    continue;
                }
                if let Some(cc) = b.get("custom_tool_call") {
                    match cc {
                        Value::Object(obj) => {
                            let (id_raw, name, args) = custom_tool_parts(false, obj);
                            let (id, id_synth) = synth_tool_id_with(false, idx, id_raw.as_deref());
                            if name.is_some() || !args.is_empty() || !id_synth {
                                out.push((idx, Some(id), name, args));
                            }
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    let jdx = j as u32;
                                    let (id_raw, name, args) = custom_tool_parts(false, obj);
                                    let (id, id_synth) =
                                        synth_tool_id_with(false, jdx, id_raw.as_deref());
                                    if name.is_some() || !args.is_empty() || !id_synth {
                                        out.push((jdx, Some(id), name, args));
                                    }
                                }
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let is_tool = b.get("type").and_then(|x| x.as_str()).is_some_and(|t| {
                    t.contains("tool_use") || t.contains("function") || t.contains("custom")
                }) || b.get("name").is_some()
                    || b.get("partial_json").is_some()
                    || b.get("input").is_some()
                    || b.get("function_call").is_some()
                    || b.get("custom_tool_call").is_some();
                if !is_tool {
                    continue;
                }
                let id_raw = b.get("id").and_then(|x| x.as_str());
                let name = b
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                let args = norm_args(
                    b.get("partial_json")
                        .or_else(|| b.get("input"))
                        .or_else(|| b.get("arguments")),
                );
                if name.is_none() && args.is_empty() && id_raw.is_none() {
                    continue;
                }
                out.push((idx, Some(synth(idx, id_raw)), name, args));
            }
        }
        P::Responses => {
            let ev_type = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
            if ev_type.contains("function_call_arguments") {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id_raw = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()));
                let id = Some(synth_tool_id_with(false, idx, id_raw).0);
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                if ev_type.ends_with(".delta") {
                    let delta = v
                        .get("delta")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !delta.is_empty() || name.is_some() {
                        out.push((idx, id, name, delta));
                    }
                } else if ev_type.ends_with(".done") {
                    let args = v
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    if !args.is_empty() || name.is_some() {
                        out.push((idx, id, name, args));
                    }
                }
                return out;
            }
            // C10 检索事件计 tool（与非流一致）：名按类型派生，参按
            // queries 回退；中间态同样建槽审计，误报优于漏审。
            if let Some(rname) = retrieval_tool_name(ev_type) {
                let idx = v
                    .get("output_index")
                    .or_else(|| v.get("index"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u32;
                let id_raw = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()));
                let id = Some(synth_tool_id_with(false, idx, id_raw).0);
                let name = v
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| Some(rname.to_string()));
                let mut args = v.as_object().map(retrieval_args).unwrap_or_default();
                if args.is_empty()
                    && let Some(d) = v.get("delta").and_then(|x| x.as_str())
                {
                    args = d.to_string();
                }
                out.push((idx, id, name, args));
                return out;
            }
            if ev_type.contains("output_text") {
                return out;
            }
            if ev_type == "response.output_item.done"
                && let Some(item) = v.get("item")
                && let Some(type_str) = item.get("type").and_then(|x| x.as_str())
                && (type_str == "function_call" || retrieval_tool_name(type_str).is_some())
            {
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let mut args = item
                    .get("arguments")
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
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| retrieval_tool_name(type_str).map(|s| s.to_string()));
                let id_raw = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()));
                let id = Some(synth_tool_id_with(false, idx, id_raw).0);
                if !args.is_empty() || name.is_some() {
                    out.push((idx, id, name, args));
                }
                return out;
            }
            if ev_type == "response.output_item.added"
                && let Some(item) = v.get("item")
            {
                // C9 起始事件建槽（与非流同形）：`added` 携带 function_call
                // 名/id（尚无 arguments），产出空参数分片经既有
                // `push_responses_fragment` 建槽，复用按槽缓冲；
                // C10 检索起始同样建槽（名按类型派生）；非 tool 形态直返。
                let type_str = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                let is_tool = type_str.contains("function_call")
                    || type_str.contains("custom_tool_call")
                    || type_str.contains("tool")
                    || retrieval_tool_name(type_str).is_some()
                    || item.get("name").is_some();
                if !is_tool {
                    return out;
                }
                let idx = v.get("output_index").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let id_raw = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()));
                let id = Some(synth_tool_id_with(false, idx, id_raw).0);
                let name = item
                    .get("name")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| retrieval_tool_name(type_str).map(|s| s.to_string()));
                out.push((idx, id, name, String::new()));
                return out;
            }
            if v.get("item").is_some() {
                return out;
            }
            if let Some(output) = v.get("output").and_then(|o| o.as_array()) {
                // X2/C9：复用共享 `custom_tool_parts` 字段优先级
                //（`id/call_id/tool_call_id`、`name/tool_name/function.name`、
                // `arguments/input/args`），流/非流同调用同结论。
                for (i, item) in output.iter().enumerate() {
                    // 非流同形 `is_tool` 前置门：非 tool 项直接跳过，不得建槽。
                    let item_type = item.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    let is_tool = item_type.contains("function_call")
                        || item_type.contains("custom_tool_call")
                        || item_type.contains("tool")
                        || retrieval_tool_name(item_type).is_some()
                        || item.get("name").is_some()
                        || item.get("arguments").is_some()
                        || item.get("input").is_some();
                    if !is_tool {
                        continue;
                    }
                    let bucket = responses_output_bucket(item, i);
                    // C10 检索调用直建分片（与非流同形：名派生+queries 回退）。
                    if let Some(obj) = item.as_object()
                        && let Some(rname) = retrieval_tool_name(item_type)
                    {
                        let cid_raw = obj
                            .get("id")
                            .and_then(|x| x.as_str())
                            .or_else(|| obj.get("call_id").and_then(|x| x.as_str()));
                        let cid = Some(synth_tool_id_with(false, bucket, cid_raw).0);
                        let cname = obj
                            .get("name")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| Some(rname.to_string()));
                        out.push((bucket, cid, cname, retrieval_args(obj)));
                        continue;
                    }
                    if let Some(obj) = item.as_object() {
                        if let Some(Value::Object(inner)) = obj.get("custom_tool_call") {
                            let (id_raw, cname, cargs) = custom_tool_parts(false, inner);
                            let (cid, id_synth) =
                                synth_tool_id_with(false, bucket, id_raw.as_deref());
                            if cname.is_some() || !cargs.is_empty() || !id_synth {
                                out.push((bucket, Some(cid), cname, cargs));
                            }
                            continue;
                        }
                        let (id_raw, name, args) = custom_tool_parts(false, obj);
                        let (id, id_synth) = synth_tool_id_with(false, bucket, id_raw.as_deref());
                        if !args.is_empty() || name.is_some() || !id_synth {
                            out.push((bucket, Some(id), name, args));
                        }
                    }
                }
            }
        }
        P::NonDialog => {}
    }
    out
}

#[cfg(test)]
mod tests;
