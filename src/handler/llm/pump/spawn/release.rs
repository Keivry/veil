//! 正常结束前的 fail-open 释放帧合成：把 [`TokenCarry`](super::super::carry::TokenCarry)
//! 未配对残段按**原实例路径**在终止帧之前回吐（并入 `agg` 保序），保证零字符丢失。
//!
//! 仅合成协议正确的最小 `delta` 载体：Chat `choices[<choice>].delta`（工具形参走
//! `tool_calls[<tc>].function`）、Anthropic `content_block_delta`（`index:<block>`）、
//! Responses `response.output_text.delta` / `response.function_call_arguments.delta` /
//! `response.reasoning_text.delta` / `response.reasoning_summary_text.delta`。
//! 信封字段按流内已有 `conv_id`/`model` 回显，缺失走内建回退；残段仅 `[A-Za-z0-9_]`，
//! 不触发转义/结构风险。

use {
    super::super::carry::Seg,
    crate::service::{llm_gateway::Protocol, metrics::normalize_model},
};

/// 释放帧合成上下文（回显信封字段；缺失走内建回退）。
pub(super) struct ReleaseCtx<'a> {
    pub protocol: Protocol,
    pub id: Option<&'a str>,
    pub model: Option<&'a str>,
}

/// 合成协议最小增量释放帧 `(prefix, data)`（`prefix` 为 `event:` 行）；
/// `NonDialog` 或空残段返回 `None`。
pub(super) fn release_frame(
    ctx: &ReleaseCtx<'_>,
    path: &[Seg],
    literal: &str,
) -> Option<(String, String)> {
    if literal.is_empty() {
        return None;
    }
    match ctx.protocol {
        Protocol::Chat => Some((String::new(), chat_delta(ctx, path, literal))),
        Protocol::Anthropic => Some((
            "event: content_block_delta\n".to_string(),
            anthropic_delta(path, literal),
        )),
        Protocol::Responses => responses_delta(ctx, path, literal),
        Protocol::NonDialog => None,
    }
}

/// 路径末位键名（`Seg::Key`；无则 `None`）。
fn last_key(path: &[Seg]) -> Option<&str> {
    path.iter().rev().find_map(|s| match s {
        Seg::Key(k) => Some(k.as_str()),
        Seg::Idx(_) => None,
    })
}

/// 路径是否含指定键名。
fn has_key(path: &[Seg], key: &str) -> bool {
    path.iter().any(|s| matches!(s, Seg::Key(k) if k == key))
}

/// 首个以 `<tag>=` 开头的身份分段的值（如 `i=0` 的 `0`）。
fn tag_value<'a>(path: &'a [Seg], tag: &str) -> Option<&'a str> {
    path.iter().find_map(|s| match s {
        Seg::Idx(v) => {
            let (t, val) = v.split_once('=')?;
            (t == tag).then_some(val)
        }
        Seg::Key(_) => None,
    })
}

/// 紧跟指定键名之后的身份分段的值（如 `choices` 后的 choice index）。
fn value_after_key<'a>(path: &'a [Seg], key: &str) -> Option<&'a str> {
    let mut iter = path.iter();
    while let Some(seg) = iter.next() {
        if matches!(seg, Seg::Key(k) if k == key)
            && let Some(Seg::Idx(v)) = iter.next()
        {
            return v.split_once('=').map(|(_, val)| val);
        }
    }
    None
}

/// `u64` 解析失败回退 `default`。
fn parse_or(val: Option<&str>, default: u64) -> u64 {
    val.and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Unix 秒时间戳（合成 `created` 的合规默认值）。
fn now_created() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Chat 最小增量帧——按末位键/工具路径选载体：工具形参/名走 `tool_calls[<tc>]`，
/// reasoning 走 `reasoning_content`，`refusal` 走 `refusal`，其余 `content`。
fn chat_delta(ctx: &ReleaseCtx<'_>, path: &[Seg], literal: &str) -> String {
    let id = ctx
        .id
        .filter(|s| !s.is_empty())
        .unwrap_or("chatcmpl-residual");
    let model = normalize_model(ctx.model.unwrap_or(""));
    let choice = parse_or(value_after_key(path, "choices"), 0);
    let tool = has_key(path, "tool_calls");
    let last = last_key(path);
    let delta = if tool && last == Some("arguments") {
        let tc = parse_or(value_after_key(path, "tool_calls"), 0);
        serde_json::json!({"tool_calls": [{"index": tc, "function": {"arguments": literal}}]})
    } else if tool && last == Some("name") {
        let tc = parse_or(value_after_key(path, "tool_calls"), 0);
        serde_json::json!({"tool_calls": [{"index": tc, "function": {"name": literal}}]})
    } else if last.is_some_and(|k| k.starts_with("reasoning"))
        || (last == Some("text") && has_key(path, "reasoning_details"))
    {
        serde_json::json!({"reasoning_content": literal})
    } else if last == Some("refusal") {
        serde_json::json!({"refusal": literal})
    } else {
        serde_json::json!({"content": literal})
    };
    serde_json::json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": now_created(),
        "model": model,
        "choices": [{"index": choice, "delta": delta}]
    })
    .to_string()
}

/// Anthropic 最小增量帧——`partial_json` 走 `input_json_delta`，`thinking` 走
/// `thinking_delta`，其余 `text_delta`；`index` 取原内容块号。
fn anthropic_delta(path: &[Seg], literal: &str) -> String {
    let block = parse_or(tag_value(path, "i"), 0);
    let delta = match last_key(path) {
        Some("partial_json") => {
            serde_json::json!({"type": "input_json_delta", "partial_json": literal})
        }
        Some("thinking") => serde_json::json!({"type": "thinking_delta", "thinking": literal}),
        _ => serde_json::json!({"type": "text_delta", "text": literal}),
    };
    serde_json::json!({"type": "content_block_delta", "index": block, "delta": delta}).to_string()
}

/// Responses 最小增量帧——按原事件类型/末位键选载体并携带原
/// `output_index`/`content_index`/`item_id`（缺省回退 ReleaseCtx conv id）；
/// `sequence_number` 有意省略：释放帧插在终止帧之前，续编会与终止帧冲突或倒序。
fn responses_delta(ctx: &ReleaseCtx<'_>, path: &[Seg], literal: &str) -> Option<(String, String)> {
    let fallback_id = ctx.id.filter(|s| !s.is_empty()).unwrap_or("resp-residual");
    let event_type = tag_value(path, "t");
    let output_index = parse_or(tag_value(path, "o"), 0);
    let content_index = parse_or(tag_value(path, "c"), 0);
    let summary_index = tag_value(path, "s").and_then(|v| v.parse::<u64>().ok());
    let item_id = tag_value(path, "m").unwrap_or(fallback_id);
    let last = last_key(path);
    let summary = event_type.is_some_and(|t| t.contains("reasoning_summary"))
        || last.is_some_and(|k| k.starts_with("reasoning_summary"))
        || has_key(path, "reasoning_summary");
    let fn_args = event_type.is_some_and(|t| t.contains("function_call_arguments"))
        || last == Some("arguments")
        || last == Some("function_call");
    let reasoning = !summary
        && (event_type.is_some_and(|t| t.contains("reasoning"))
            || last.is_some_and(|k| k.starts_with("reasoning") || k == "thinking"));
    let event = if fn_args {
        "response.function_call_arguments.delta"
    } else if summary {
        "response.reasoning_summary_text.delta"
    } else if reasoning {
        "response.reasoning_text.delta"
    } else {
        "response.output_text.delta"
    };
    let mut payload = serde_json::json!({
        "type": event,
        "item_id": item_id,
        "output_index": output_index,
        "content_index": content_index,
        "delta": literal
    });
    if summary && let Some(si) = summary_index {
        payload["summary_index"] = serde_json::json!(si);
    }
    Some((format!("event: {event}\n"), payload.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> Seg { Seg::Key(k.to_string()) }
    fn idx(v: &str) -> Seg { Seg::Idx(v.to_string()) }

    fn ctx(protocol: Protocol) -> ReleaseCtx<'static> {
        ReleaseCtx {
            protocol,
            id: Some("id-1"),
            model: Some("m-1"),
        }
    }

    #[test]
    fn chat_release_maps_path_to_delta_field() {
        // 末位键/工具路径决定 Chat 释放帧载体。
        for (path, field) in [
            (
                vec![key("choices"), idx("i=0"), key("delta"), key("content")],
                "content",
            ),
            (
                vec![key("choices"), idx("i=2"), key("delta"), key("reasoning")],
                "reasoning_content",
            ),
            (
                vec![
                    key("choices"),
                    idx("i=0"),
                    key("delta"),
                    key("reasoning_details"),
                    idx("i=0"),
                    key("text"),
                ],
                "reasoning_content",
            ),
            (
                vec![key("choices"), idx("i=0"), key("delta"), key("refusal")],
                "refusal",
            ),
        ] {
            let (prefix, data) =
                release_frame(&ctx(Protocol::Chat), &path, "lit").expect("Chat 恒可合成");
            assert!(prefix.is_empty(), "Chat 无 event: 前缀");
            let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
            let choice = value_after_key(&path, "choices").unwrap_or("0");
            assert_eq!(v["choices"][0]["index"].to_string(), choice);
            assert_eq!(v["choices"][0]["delta"][field], "lit", "path={path:?}");
        }
    }

    #[test]
    fn chat_release_tool_calls_carriers() {
        // 工具形参残段落 `tool_calls[<tc>].function.arguments`（非 `content`）；
        // `function.name` 残余落同索引 `function.name`。
        let args_path = vec![
            key("choices"),
            idx("i=0"),
            key("delta"),
            key("tool_calls"),
            idx("i=1"),
            key("function"),
            key("arguments"),
        ];
        let (_, data) = release_frame(&ctx(Protocol::Chat), &args_path, "__C").expect("可合成");
        let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
        assert_eq!(v["choices"][0]["index"], 0);
        assert_eq!(v["choices"][0]["delta"]["tool_calls"][0]["index"], 1);
        assert_eq!(
            v["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"],
            "__C"
        );
        assert!(v["choices"][0]["delta"].get("content").is_none());

        let name_path = vec![
            key("choices"),
            idx("i=0"),
            key("delta"),
            key("tool_calls"),
            idx("i=3"),
            key("function"),
            key("name"),
        ];
        let (_, data2) = release_frame(&ctx(Protocol::Chat), &name_path, "exec").expect("可合成");
        let v2: serde_json::Value = serde_json::from_str(&data2).expect("合法 JSON");
        assert_eq!(v2["choices"][0]["delta"]["tool_calls"][0]["index"], 3);
        assert_eq!(
            v2["choices"][0]["delta"]["tool_calls"][0]["function"]["name"],
            "exec"
        );
    }

    #[test]
    fn anthropic_release_partial_json_and_block_index() {
        // `partial_json` 走 `input_json_delta`；`index` 取原内容块号（非硬编码 0）。
        let path = vec![
            idx("t=content_block_delta"),
            idx("i=2"),
            key("delta"),
            key("partial_json"),
        ];
        let (prefix, data) =
            release_frame(&ctx(Protocol::Anthropic), &path, "{\"a\"").expect("可合成");
        assert_eq!(prefix, "event: content_block_delta\n");
        let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
        assert_eq!(v["type"], "content_block_delta");
        assert_eq!(v["index"], 2);
        assert_eq!(v["delta"]["type"], "input_json_delta");
        assert_eq!(v["delta"]["partial_json"], "{\"a\"");

        let thinking = vec![
            idx("t=content_block_delta"),
            idx("i=1"),
            key("delta"),
            key("thinking"),
        ];
        let (_, data2) =
            release_frame(&ctx(Protocol::Anthropic), &thinking, "tan").expect("可合成");
        let v2: serde_json::Value = serde_json::from_str(&data2).expect("合法 JSON");
        assert_eq!(v2["index"], 1);
        assert_eq!(v2["delta"]["type"], "thinking_delta");
        assert_eq!(v2["delta"]["thinking"], "tan");

        let text = vec![
            idx("t=content_block_delta"),
            idx("i=0"),
            key("delta"),
            key("text"),
        ];
        let (_, data3) = release_frame(&ctx(Protocol::Anthropic), &text, "hi").expect("可合成");
        let v3: serde_json::Value = serde_json::from_str(&data3).expect("合法 JSON");
        assert_eq!(v3["index"], 0);
        assert_eq!(v3["delta"]["type"], "text_delta");
        assert_eq!(v3["delta"]["text"], "hi");
    }

    #[test]
    fn responses_release_carriers_and_indices() {
        // output_text：携带原 output_index/content_index/item_id，省略 sequence_number。
        let out = vec![
            idx("t=response.output_text.delta"),
            idx("o=3"),
            idx("c=1"),
            idx("m=msg_9"),
            key("delta"),
        ];
        let (prefix, data) = release_frame(&ctx(Protocol::Responses), &out, "lit").expect("可合成");
        assert_eq!(prefix, "event: response.output_text.delta\n");
        let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
        assert_eq!(v["type"], "response.output_text.delta");
        assert_eq!(v["output_index"], 3);
        assert_eq!(v["content_index"], 1);
        assert_eq!(v["item_id"], "msg_9");
        assert_eq!(v["delta"], "lit");
        assert!(v.get("sequence_number").is_none());

        // function_call_arguments：走专用事件，`index>0` 不落错槽。
        let args = vec![
            idx("t=response.function_call_arguments.delta"),
            idx("o=5"),
            idx("m=fc_1"),
            key("delta"),
        ];
        let (prefix2, data2) =
            release_frame(&ctx(Protocol::Responses), &args, "x").expect("可合成");
        assert_eq!(prefix2, "event: response.function_call_arguments.delta\n");
        let v2: serde_json::Value = serde_json::from_str(&data2).expect("合法 JSON");
        assert_eq!(v2["output_index"], 5);
        assert_eq!(v2["item_id"], "fc_1");

        // reasoning_text：reasoning/thinking → `response.reasoning_text.delta`。
        let reason = vec![
            idx("t=response.reasoning_text.delta"),
            idx("o=1"),
            idx("m=rs_1"),
            key("delta"),
        ];
        let (prefix3, data3) =
            release_frame(&ctx(Protocol::Responses), &reason, "th").expect("可合成");
        assert_eq!(prefix3, "event: response.reasoning_text.delta\n");
        let v3: serde_json::Value = serde_json::from_str(&data3).expect("合法 JSON");
        assert_eq!(v3["type"], "response.reasoning_text.delta");
    }

    #[test]
    fn responses_release_reasoning_summary_carrier() {
        // reasoning_summary 残段走 `response.reasoning_summary_text.delta`，
        // 携带 output_index/summary_index/item_id。
        let path = vec![
            idx("t=response.reasoning_summary_text.delta"),
            idx("o=2"),
            idx("s=1"),
            idx("m=rs_1"),
            key("delta"),
        ];
        let (prefix, data) =
            release_frame(&ctx(Protocol::Responses), &path, "sum").expect("可合成");
        assert_eq!(prefix, "event: response.reasoning_summary_text.delta\n");
        let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
        assert_eq!(v["type"], "response.reasoning_summary_text.delta");
        assert_eq!(v["output_index"], 2);
        assert_eq!(v["summary_index"], 1);
        assert_eq!(v["item_id"], "rs_1");
        assert_eq!(v["delta"], "sum");
    }

    #[test]
    fn key_only_and_fallback_degrade() {
        // key-only 路径（异常帧降级）无索引身份：索引回退 0，item_id 回退 conv id。
        let path = vec![key("content")];
        let (_, data) = release_frame(&ctx(Protocol::Chat), &path, "lit").expect("可合成");
        let v: serde_json::Value = serde_json::from_str(&data).expect("合法 JSON");
        assert_eq!(v["choices"][0]["index"], 0);

        let empty: Vec<Seg> = Vec::new();
        let (_, data2) = release_frame(&ctx(Protocol::Responses), &empty, "lit").expect("可合成");
        let v2: serde_json::Value = serde_json::from_str(&data2).expect("合法 JSON");
        assert_eq!(v2["item_id"], "id-1");
        assert_eq!(v2["output_index"], 0);
    }

    #[test]
    fn non_dialog_and_empty_literal_return_none() {
        let path = vec![key("content")];
        assert!(
            release_frame(&ctx(Protocol::NonDialog), &path, "lit").is_none(),
            "NonDialog 恒 None"
        );
        assert!(
            release_frame(&ctx(Protocol::Chat), &path, "").is_none(),
            "空残段恒 None"
        );
    }
}
