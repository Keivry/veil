//! tool 分片提取（D2 自 `pump.rs` 拆出）：三协议 tool 调用分桶与序号归一。

use {
    crate::service::llm_gateway::{
        Protocol,
        anthropic_bucket_index,
        retrieval_args,
        retrieval_tool_name,
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
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
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
                                let id = synth(idx, call.get("id").and_then(|x| x.as_str()));
                                let name = call
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                                    .map(|s| s.to_string());
                                let args = norm_args(
                                    call.get("function").and_then(|f| f.get("arguments")),
                                );
                                out.push((idx, Some(id), name, args));
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
                                    let idx = ci as u32;
                                    let name = obj
                                        .get("name")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let args = norm_args(obj.get("arguments"));
                                    out.push((idx, Some(synth(idx, None)), name, args));
                                } else {
                                    let idx = i as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    if name.is_some() || !args.is_empty() || id_raw.is_some() {
                                        out.push((idx, Some(synth(idx, id_raw)), name, args));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        P::Anthropic => {
            let norm_args = |raw: Option<&Value>| -> String {
                match raw {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                }
            };
            let synth = |idx: u32, present: Option<&str>| -> String {
                match present.filter(|s| !s.is_empty()) {
                    Some(s) => s.to_string(),
                    None => format!("call_stable_{idx}"),
                }
            };
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
                            let id_raw = obj
                                .get("id")
                                .or_else(|| obj.get("call_id"))
                                .or_else(|| obj.get("tool_call_id"))
                                .and_then(|x| x.as_str());
                            let name = obj
                                .get("name")
                                .or_else(|| obj.get("tool_name"))
                                .and_then(|x| x.as_str())
                                .or_else(|| {
                                    obj.get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(|x| x.as_str())
                                })
                                .map(|s| s.to_string());
                            let args = norm_args(
                                obj.get("arguments")
                                    .or_else(|| obj.get("input"))
                                    .or_else(|| obj.get("args")),
                            );
                            out.push((idx, Some(synth(idx, id_raw)), name, args));
                            continue;
                        }
                        Value::Array(a) => {
                            for (j, item) in a.iter().enumerate() {
                                if let Some(obj) = item.as_object() {
                                    let jdx = j as u32;
                                    let id_raw = obj
                                        .get("id")
                                        .or_else(|| obj.get("call_id"))
                                        .or_else(|| obj.get("tool_call_id"))
                                        .and_then(|x| x.as_str());
                                    let name = obj
                                        .get("name")
                                        .or_else(|| obj.get("tool_name"))
                                        .and_then(|x| x.as_str())
                                        .or_else(|| {
                                            obj.get("function")
                                                .and_then(|f| f.get("name"))
                                                .and_then(|x| x.as_str())
                                        })
                                        .map(|s| s.to_string());
                                    let args = norm_args(
                                        obj.get("arguments")
                                            .or_else(|| obj.get("input"))
                                            .or_else(|| obj.get("args")),
                                    );
                                    out.push((jdx, Some(synth(jdx, id_raw)), name, args));
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
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
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
                let id = v
                    .get("item_id")
                    .and_then(|x| x.as_str())
                    .or_else(|| v.get("id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
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
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
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
                let id = item
                    .get("id")
                    .and_then(|x| x.as_str())
                    .or_else(|| item.get("call_id").and_then(|x| x.as_str()))
                    .map(|s| s.to_string());
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
                // C9：复用非流 `custom_obj_to_call` 取字段优先级
                //（`id/call_id/tool_call_id`、`name/tool_name/function.name`、
                // `arguments/input/args`），流/非流同调用同结论。
                let custom_parts =
                    |obj: &serde_json::Map<String, Value>| -> (Option<String>, Option<String>, String) {
                        let cid = obj
                            .get("id")
                            .or_else(|| obj.get("call_id"))
                            .or_else(|| obj.get("tool_call_id"))
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string());
                        let cname = obj
                            .get("name")
                            .or_else(|| obj.get("tool_name"))
                            .and_then(|x| x.as_str())
                            .or_else(|| {
                                obj.get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(|x| x.as_str())
                            })
                            .map(|s| s.to_string());
                        let cargs = obj
                            .get("arguments")
                            .or_else(|| obj.get("input"))
                            .or_else(|| obj.get("args"))
                            .map(|a| {
                                if let Some(s) = a.as_str() {
                                    s.to_string()
                                } else if a.is_null() {
                                    String::new()
                                } else {
                                    a.to_string()
                                }
                            })
                            .unwrap_or_default();
                        (cid, cname, cargs)
                    };
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
                    // C10 检索调用直建分片（与非流同形：名派生+queries 回退）。
                    if let Some(obj) = item.as_object()
                        && let Some(rname) = retrieval_tool_name(item_type)
                    {
                        let cid = obj
                            .get("id")
                            .and_then(|x| x.as_str())
                            .or_else(|| obj.get("call_id").and_then(|x| x.as_str()))
                            .map(|s| s.to_string());
                        let cname = obj
                            .get("name")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| Some(rname.to_string()));
                        out.push((i as u32, cid, cname, retrieval_args(obj)));
                        continue;
                    }
                    if let Some(obj) = item.as_object() {
                        if let Some(Value::Object(inner)) = obj.get("custom_tool_call") {
                            let (cid, cname, cargs) = custom_parts(inner);
                            out.push((i as u32, cid, cname, cargs));
                            continue;
                        }
                        let (cid, cname, cargs) = custom_parts(obj);
                        if cname.is_some() || !cargs.is_empty() || cid.is_some() {
                            out.push((i as u32, cid, cname, cargs));
                            continue;
                        }
                    }
                    let args = item
                        .get("arguments")
                        .map(|a| {
                            if let Some(s) = a.as_str() {
                                s.to_string()
                            } else {
                                a.to_string()
                            }
                        })
                        .unwrap_or_default();
                    let name = item
                        .get("name")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    let id = item
                        .get("id")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string());
                    if !args.is_empty() || name.is_some() {
                        out.push((i as u32, id, name, args));
                    }
                }
            }
        }
        P::NonDialog => {}
    }
    out
}

#[cfg(test)]
mod fragments_tests {
    use {
        super::{super::event::is_minor_event, *},
        crate::service::audit_hold::AuditHold,
    };

    #[test]
    fn streaming_legacy_function_call_matches_nonstream() {
        use crate::service::llm_gateway::Protocol as P;
        let stream_delta = serde_json::json!({"choices":[{"delta":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags = extract_tool_fragments(P::Chat, &stream_delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 0);
        assert_eq!(frags[0].1.as_deref(), Some("call_stable_0"));
        assert_eq!(frags[0].2.as_deref(), Some("old"));
        assert_eq!(frags[0].3, "{\"x\":1}");
        let non_stream = serde_json::json!({"choices":[{"message":{"function_call":{"name":"old","arguments":"{\"x\":1}"}}}]});
        let frags2 = extract_tool_fragments(P::Chat, &non_stream);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("old"));
        assert_eq!(frags2[0].1.as_deref(), Some("call_stable_0"));
        let legacy_arr = serde_json::json!({"choices":[{"delta":{"function_call":[{"name":"a","arguments":"{}"}]}}]});
        let frags3 = extract_tool_fragments(P::Chat, &legacy_arr);
        assert!(frags3.is_empty() || frags3.len() == 1);
    }

    #[test]
    fn dual_tool_calls_accumulate_independently_by_index() {
        use crate::service::llm_gateway::Protocol as P;
        let two = serde_json::json!({"choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"call_a","type":"function","function":{"name":"exec_a","arguments":"{\"x\":1}"}},
            {"index":1,"id":"call_b","type":"function","function":{"name":"exec_b","arguments":"{\"y\":2}"}}
        ]}}]});
        let frags = extract_tool_fragments(P::Chat, &two);
        assert_eq!(frags.len(), 2, "双路须各一条: {frags:?}");
        assert_eq!(frags[0].0, 0);
        assert_eq!(frags[1].0, 1);
        assert_eq!(frags[0].2.as_deref(), Some("exec_a"));
        assert_eq!(frags[1].2.as_deref(), Some("exec_b"));
        assert!(frags[0].3.contains("\"x\":1") && !frags[0].3.contains("\"y\""));
        assert!(frags[1].3.contains("\"y\":2") && !frags[1].3.contains("\"x\""));
    }

    #[test]
    fn anthropic_array_content_aligns_with_gateway() {
        use crate::service::llm_gateway::Protocol as P;
        let content_arr = serde_json::json!({"content":[{"type":"tool_use","id":"a1","name":"bash","input":{"cmd":"ls"}}]});
        let frags = extract_tool_fragments(P::Anthropic, &content_arr);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].1.as_deref(), Some("a1"));
        assert_eq!(frags[0].2.as_deref(), Some("bash"));
        assert_eq!(frags[0].3, r#"{"cmd":"ls"}"#);
        let msg_content = serde_json::json!({"message":{"content":[{"type":"tool_use","id":"m1","name":"run","input":{"p":2}}]}});
        let frags2 = extract_tool_fragments(P::Anthropic, &msg_content);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].1.as_deref(), Some("m1"));
        let delta =
            serde_json::json!({"delta":{"type":"tool_use","name":"t","partial_json":"{\"a\":"}});
        let frags3 = extract_tool_fragments(P::Anthropic, &delta);
        assert_eq!(frags3.len(), 1);
        assert_eq!(frags3[0].1.as_deref(), Some("call_stable_0"));
        let text_only = serde_json::json!({"delta":{"type":"text","text":"hi"}});
        assert!(extract_tool_fragments(P::Anthropic, &text_only).is_empty());
    }

    #[test]
    fn anthropic_buckets_by_event_index_not_position() {
        use crate::service::llm_gateway::Protocol as P;
        let first = serde_json::json!({"content_block":{"type":"tool_use","index":4,"id":"a4","name":"t","input":{}}});
        let frags = extract_tool_fragments(P::Anthropic, &first);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 4);
        let second =
            serde_json::json!({"delta":{"type":"input_json_delta","index":4,"partial_json":"{}"}});
        let frags2 = extract_tool_fragments(P::Anthropic, &second);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].0, 4);
        assert_eq!(frags2[0].3, "{}");
    }

    #[test]
    fn responses_delta_carries_sequence_and_done_is_full() {
        use crate::service::llm_gateway::Protocol as P;
        let delta = serde_json::json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"it1","sequence_number":3,"delta":"{\"a\":"});
        let frags = extract_tool_fragments(P::Responses, &delta);
        assert_eq!(frags.len(), 1);
        assert_eq!(super::super::event::extract_responses_seq(&delta), Some(3));
        assert!(!AuditHold::is_complete_event(&delta));
        let done = serde_json::json!({"type":"response.function_call_arguments.done","output_index":0,"item_id":"it1","sequence_number":4,"name":"run","arguments":"{\"a\":1}"});
        let frags2 = extract_tool_fragments(P::Responses, &done);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("run"));
        assert!(AuditHold::is_complete_event(&done));
    }

    #[test]
    fn mixed_thinking_tool_fragments_win_hold() {
        // E7-P0 混帧回归：`content_block_delta` 同含 `thinking_delta` 与
        // `partial_json` 时工具片段优先，非空走 tool 通道进 hold 审计，
        // 剩余 thinking 部分才走 minor 透传；纯 thinking 帧仍为 minor。
        use crate::service::llm_gateway::Protocol as P;
        let mixed = serde_json::json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "thinking_delta", "thinking": "让我想想", "partial_json": "{\"x\":"}
        });
        let frags = extract_tool_fragments(P::Anthropic, &mixed);
        assert!(!frags.is_empty(), "混帧工具增量不得漏提: {mixed}");
        let is_tool_event = !frags.is_empty();
        let minor = !is_tool_event && is_minor_event(P::Anthropic, &mixed);
        assert!(!minor, "混帧不得整帧标 minor");
        // 主循环同形：tool 通道进 hold，审计三元组可见。
        let mut hold = AuditHold::new(1_048_576);
        for (idx, id, name, args) in &frags {
            hold.push_fragment(*idx, id.as_deref(), name.as_deref(), args);
        }
        assert!(
            !hold.tool_triples().is_empty(),
            "混帧工具增量须进 hold 审计"
        );
        assert!(hold.tool_triples()[0].2.contains("\"x\":"));
        // 纯 thinking 帧：仍为 minor，工具片段为空即 hold 无新增。
        let pure = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": "纯思考"}
        });
        assert!(extract_tool_fragments(P::Anthropic, &pure).is_empty());
        assert!(is_minor_event(P::Anthropic, &pure));
        let hold2 = AuditHold::new(1_048_576);
        assert!(hold2.tool_triples().is_empty(), "纯 thinking 不得进 hold");
    }

    #[test]
    fn responses_added_builds_slot_so_truncation_stays_auditable() {
        // C9 起始截断漏审回归：仅 `added` 到达（`.done` 前截断）时槽须已建，
        // 名/id 保留至审计三元组；非 tool 起始不建槽。
        use crate::service::llm_gateway::Protocol as P;
        let added = serde_json::json!({"type":"response.output_item.added","output_index":2,"item":{"type":"function_call","id":"call-9","name":"run"}});
        let frags = extract_tool_fragments(P::Responses, &added);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 2);
        assert_eq!(frags[0].1.as_deref(), Some("call-9"));
        assert_eq!(frags[0].2.as_deref(), Some("run"));
        assert!(frags[0].3.is_empty());
        // 复用既有按槽缓冲建槽：空参分片入槽后，即使零参数到达完成点，
        // 审计仍可见起始名（截断前可审计，不断链漏审）。
        let mut hold = AuditHold::new(1_048_576);
        for (idx, id, name, args) in &frags {
            let key = AuditHold::responses_key(id.as_deref(), *idx);
            hold.push_responses_fragment(&key, *idx, None, id.as_deref(), name.as_deref(), args);
            hold.mark_responses_done(&key, None);
        }
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0, 2);
        assert_eq!(triples[0].1, "run");
        let msg = serde_json::json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","content":[]}});
        assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
    }

    #[test]
    fn responses_custom_tool_call_stream_matches_nonstream() {
        // C9 流式 custom 覆盖：同调用在流/非流须同结论（名/参/id 一致）。
        use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
        let nested = serde_json::json!({"output":[{"type":"custom_tool_call","custom_tool_call":{"name":"ct","arguments":"{}"}}]});
        let frags = extract_tool_fragments(P::Responses, &nested);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].2.as_deref(), Some("ct"));
        assert_eq!(frags[0].3, "{}");
        let calls = extract_tool_calls(P::Responses, &nested);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), frags[0].2.as_deref());
        assert_eq!(calls[0].args, frags[0].3);
        // 裸回退形态（`tool_name`+`input` 别名）双向同解。
        let bare =
            serde_json::json!({"output":[{"type":"tool","tool_name":"grep","input":{"p":1}}]});
        let frags2 = extract_tool_fragments(P::Responses, &bare);
        assert_eq!(frags2.len(), 1);
        assert_eq!(frags2[0].2.as_deref(), Some("grep"));
        assert_eq!(frags2[0].3, r#"{"p":1}"#);
        let calls2 = extract_tool_calls(P::Responses, &bare);
        assert_eq!(calls2.len(), 1);
        assert_eq!(calls2[0].name.as_deref(), Some("grep"));
        assert_eq!(calls2[0].args, r#"{"p":1}"#);
        // 纯消息项双向皆不建槽。
        let msg = serde_json::json!({"output":[{"type":"message","id":"m1","content":[]}]});
        assert!(extract_tool_fragments(P::Responses, &msg).is_empty());
        assert!(extract_tool_calls(P::Responses, &msg).is_empty());
    }

    #[test]
    fn retrieval_calls_reach_identical_verdicts_across_modes() {
        // C10 同调用同结论：同一检索调用经流/非流须得同一审计结论。
        use crate::{
            config::AuditMode,
            service::{
                audit::{AuditPolicy, evaluate},
                llm_gateway::{Protocol as P, extract_tool_calls},
            },
        };
        let policy = AuditPolicy::default_policy();
        let nonstream = serde_json::json!({"output":[{"type":"file_search_call","id":"fs1","queries":["rm -rf /"]}]});
        let calls = extract_tool_calls(P::Responses, &nonstream);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name.as_deref(), Some("file_search"));
        assert!(calls[0].args.contains("rm -rf /"));
        let stream = serde_json::json!({"type":"response.file_search_call.completed","output_index":0,"item_id":"fs1","queries":["rm -rf /"]});
        let frags = extract_tool_fragments(P::Responses, &stream);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].2.as_deref(), Some("file_search"));
        assert!(frags[0].3.contains("rm -rf /"));
        assert!(
            !is_minor_event(P::Responses, &stream),
            "检索事件不再列为次要"
        );
        let v_stream = evaluate(
            AuditMode::Block,
            frags[0].2.as_deref().unwrap_or(""),
            &frags[0].3,
            &policy,
        );
        let v_nonstream = evaluate(
            AuditMode::Block,
            calls[0].name.as_deref().unwrap_or(""),
            &calls[0].args,
            &policy,
        );
        assert!(
            matches!(v_stream, crate::service::audit::AuditVerdict::Block { .. }),
            "流式危险检索须阻断"
        );
        assert!(
            matches!(
                v_nonstream,
                crate::service::audit::AuditVerdict::Block { .. }
            ),
            "非流危险检索须阻断"
        );
        // 良性检索双向同放行；检索外围仍透传不审计。
        let benign_ns = serde_json::json!({"output":[{"type":"web_search_call","id":"w1","queries":["hello"]}]});
        let benign_calls = extract_tool_calls(P::Responses, &benign_ns);
        assert_eq!(benign_calls[0].name.as_deref(), Some("web_search"));
        let benign_s = serde_json::json!({"type":"response.web_search_call.completed","output_index":0,"item_id":"w1","queries":["hello"]});
        let benign_frags = extract_tool_fragments(P::Responses, &benign_s);
        assert_eq!(benign_frags[0].2.as_deref(), Some("web_search"));
        assert!(matches!(
            evaluate(AuditMode::Block, "web_search", &benign_frags[0].3, &policy),
            crate::service::audit::AuditVerdict::Allow
        ));
        assert!(is_minor_event(
            P::Responses,
            &serde_json::json!({"type":"response.reasoning.delta"})
        ));
    }

    #[test]
    fn stream_interleaved_outer_index_matches_nonstream_slot() {
        // P0-2.3 回归：流式分桶与非流同槽（外层 0/1 胜过内层 3/5）。
        use crate::service::llm_gateway::{Protocol as P, extract_tool_calls};
        let start0 = serde_json::json!({"index":0,"content_block":{"type":"tool_use","index":3,"id":"a0","name":"run","input":{}}});
        let frags = extract_tool_fragments(P::Anthropic, &start0);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0, 0, "流式外层 0 须胜过内层 3");
        let calls = extract_tool_calls(P::Anthropic, &start0);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].index, frags[0].0, "流/非流同槽");
        let d1 = serde_json::json!({"index":1,"delta":{"type":"input_json_delta","index":5,"partial_json":"{\"y\":"}});
        let frags1 = extract_tool_fragments(P::Anthropic, &d1);
        assert_eq!(frags1.len(), 1);
        assert_eq!(frags1[0].0, 1, "流式外层 1 须胜过内层 5");
        let calls1 = extract_tool_calls(P::Anthropic, &d1);
        assert_eq!(calls1.len(), 1);
        assert_eq!(calls1[0].index, frags1[0].0, "流/非流同槽");
    }
}
