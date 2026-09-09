//! 用量口径：非流/流式提取 + `max` 合并（不双计）+ 累计。

use {super::Protocol, serde_json::Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// 缓存命中读（对标 `_metrics.py:155` `cached_read` 列）。
    pub cached_read: u64,
    /// 缓存写入（仅 Anthropic 有值，其余归零）。
    pub cached_write: u64,
}

fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

/// 三协议缓存列提取（对标 `_metrics.py:155`）：Anthropic 取顶层
/// `cache_read/cache_creation_input_tokens`；Responses 取
/// `input_tokens_details.cached_tokens`；Chat 取
/// `prompt_tokens_details.cached_tokens`（`null` 细节对象按缺失归零）。
fn cached_columns(protocol: Protocol, obj: &serde_json::Map<String, Value>) -> (u64, u64) {
    let details_cached = |key: &str| {
        obj.get(key)
            .and_then(|v| v.as_object())
            .and_then(|d| d.get("cached_tokens"))
            .and_then(as_u64)
            .unwrap_or(0)
    };
    match protocol {
        Protocol::Anthropic => (
            obj.get("cache_read_input_tokens")
                .and_then(as_u64)
                .unwrap_or(0),
            obj.get("cache_creation_input_tokens")
                .and_then(as_u64)
                .unwrap_or(0),
        ),
        Protocol::Responses => (details_cached("input_tokens_details"), 0),
        Protocol::Chat | Protocol::NonDialog => (details_cached("prompt_tokens_details"), 0),
    }
}

fn usage_from_obj(obj: &serde_json::Map<String, Value>, protocol: Protocol) -> Option<Usage> {
    let has_known = [
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "input_tokens",
        "output_tokens",
        "total",
    ]
    .iter()
    .any(|k| obj.contains_key(*k));
    if !has_known {
        return None;
    }
    let prompt = obj
        .get("prompt_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("input_tokens").and_then(as_u64))
        .unwrap_or(0);
    let completion = obj
        .get("completion_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("output_tokens").and_then(as_u64))
        .unwrap_or(0);
    let total = obj
        .get("total_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("total").and_then(as_u64))
        .unwrap_or_else(|| prompt.saturating_add(completion));
    let (cached_read, cached_write) = cached_columns(protocol, obj);
    Some(Usage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: total,
        cached_read,
        cached_write,
    })
}

fn usage_in(obj: &serde_json::Map<String, Value>, protocol: Protocol) -> Option<Usage> {
    obj.get("usage")?
        .as_object()
        .and_then(|o| usage_from_obj(o, protocol))
}

fn merge_usage(acc: &mut Option<Usage>, next: Usage) {
    match acc {
        Some(a) => {
            a.prompt_tokens = a.prompt_tokens.max(next.prompt_tokens);
            a.completion_tokens = a.completion_tokens.max(next.completion_tokens);
            a.total_tokens = a.total_tokens.max(next.total_tokens);
            a.cached_read = a.cached_read.max(next.cached_read);
            a.cached_write = a.cached_write.max(next.cached_write);
        }
        None => *acc = Some(next),
    }
}

pub fn extract_usage_nonstream(protocol: Protocol, body: &Value) -> Option<Usage> {
    match protocol {
        Protocol::Chat => body
            .get("usage")?
            .as_object()
            .and_then(|o| usage_from_obj(o, protocol)),
        Protocol::Responses => {
            let outer = body.get("response")?.as_object()?;
            if let Some(u) = outer
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(|o| usage_from_obj(o, protocol))
            {
                return Some(u);
            }
            outer
                .get("response")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(|o| usage_from_obj(o, protocol))
        }
        Protocol::Anthropic => {
            if let Some(u) = body
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(|o| usage_from_obj(o, protocol))
            {
                return Some(u);
            }
            body.get("message")?
                .get("usage")?
                .as_object()
                .and_then(|o| usage_from_obj(o, protocol))
        }
        Protocol::NonDialog => None,
    }
}

/// 流式 SSE 事件载荷捕获 usage（对标 Python `_capture_usage_ctx`）。
///
/// 口径：顶层 `usage` 优先；Responses 单层 `response.usage` 优先、双层
/// `response.response.usage` 回退；Anthropic `delta.usage` / `message.usage`
/// 回退；缺失返回 `None` 不估算。数值归一与 [`extract_usage_nonstream`] 同口径
/// （`input_tokens`/`output_tokens`/`total` 回退，`total` 缺失时 `prompt+completion`）。
pub fn extract_usage_stream(protocol: Protocol, payload: &Value) -> Option<Usage> {
    let obj = payload.as_object()?;
    // 快路径：无 usage/cached_tokens/裸 token 键的心跳分片直接跳过，避免全量归一。
    let raw = payload.to_string();
    if !raw.contains("\"usage\"")
        && !raw.contains("\"cached_tokens\"")
        && !raw.contains("input_tokens")
        && !raw.contains("output_tokens")
    {
        return None;
    }
    if let Some(u) = usage_in(obj, protocol) {
        return Some(u);
    }
    match protocol {
        Protocol::Chat => None,
        Protocol::Responses => {
            let resp = obj.get("response")?.as_object()?;
            if let Some(u) = resp
                .get("usage")
                .and_then(|v| v.as_object())
                .and_then(|o| usage_from_obj(o, protocol))
            {
                return Some(u);
            }
            resp.get("response")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(|o| usage_from_obj(o, protocol))
        }
        Protocol::Anthropic => {
            if let Some(u) = obj
                .get("delta")
                .and_then(|v| v.as_object())
                .and_then(|o| usage_in(o, protocol))
            {
                return Some(u);
            }
            obj.get("message")?
                .as_object()?
                .get("usage")?
                .as_object()
                .and_then(|o| usage_from_obj(o, protocol))
        }
        Protocol::NonDialog => None,
    }
}

/// 流式 usage 累加（§2.7 口径：统一 `max`，禁用 `sum`）。
/// 上游分片语义为累计值（`message_start` 给全量、`message_delta` 给累计），
/// 按字段单调取大；`sum` 会把同一 token 算两次（双计），此处禁止。
pub fn accumulate_usage(acc: &mut Option<Usage>, next: Option<Usage>) {
    if let Some(u) = next {
        merge_usage(acc, u);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstream_usage_matches_stream_convention() {
        let chat =
            serde_json::json!({"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Chat, &chat)
                .unwrap()
                .total_tokens,
            3
        );
        let resp = serde_json::json!({"response":{"usage":{"prompt_tokens":4,"completion_tokens":5,"total_tokens":9}}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Responses, &resp)
                .unwrap()
                .total_tokens,
            9
        );
        let bad_resp = serde_json::json!({"usage":{"total_tokens":9}});
        assert!(extract_usage_nonstream(Protocol::Responses, &bad_resp).is_none());
        let anth =
            serde_json::json!({"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Anthropic, &anth)
                .unwrap()
                .total_tokens,
            5
        );
        let anth_nested = serde_json::json!({"message":{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}});
        assert_eq!(
            extract_usage_nonstream(Protocol::Anthropic, &anth_nested)
                .unwrap()
                .total_tokens,
            2
        );
        assert!(extract_usage_nonstream(Protocol::NonDialog, &chat).is_none());
    }

    #[test]
    fn responses_double_layer_fallback_with_alias_normalization() {
        let double = serde_json::json!({"response":{"response":{"usage":{"prompt_tokens":7,"completion_tokens":8,"total_tokens":15}}}});
        let u = extract_usage_nonstream(Protocol::Responses, &double).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (7, 8, 15)
        );
        let single = serde_json::json!({"response":{"usage":{"input_tokens":4,"output_tokens":6}}});
        let u = extract_usage_nonstream(Protocol::Responses, &single).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (4, 6, 10)
        );
        let stream_double = serde_json::json!({"type":"response.completed","response":{"response":{"usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}}});
        let u = extract_usage_stream(Protocol::Responses, &stream_double).unwrap();
        assert_eq!(u.total_tokens, 5);
        let stream_single = serde_json::json!({"type":"response.completed","response":{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}});
        let u = extract_usage_stream(Protocol::Responses, &stream_single).unwrap();
        assert_eq!(u.total_tokens, 3);
        let chat_ev =
            serde_json::json!({"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}});
        assert!(extract_usage_stream(Protocol::Chat, &chat_ev).is_some());
        assert!(extract_usage_stream(Protocol::Chat, &serde_json::json!({"delta":"hi"})).is_none());
        let anth_delta = serde_json::json!({"delta":{"usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30}}});
        assert_eq!(
            extract_usage_stream(Protocol::Anthropic, &anth_delta)
                .unwrap()
                .total_tokens,
            30
        );
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"message":{"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}}),
            ),
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(Protocol::Anthropic, &anth_delta),
        );
        let a = acc.unwrap();
        assert_eq!(
            (a.prompt_tokens, a.completion_tokens, a.total_tokens),
            (10, 20, 30),
            "双段按字段单调 max，不求和双计"
        );
    }

    #[test]
    fn streaming_usage_two_segments_take_max_without_double_count() {
        let start =
            serde_json::json!({"type":"message_start","message":{"usage":{"input_tokens":5}}});
        let delta = serde_json::json!({"type":"message_delta","usage":{"output_tokens":20}});
        let mut acc: Option<Usage> = None;
        accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &start));
        accumulate_usage(&mut acc, extract_usage_stream(Protocol::Anthropic, &delta));
        let a = acc.unwrap();
        assert_eq!((a.prompt_tokens, a.completion_tokens), (5, 20));
        let bare = serde_json::json!({"delta":{"input_tokens":5}});
        assert!(
            extract_usage_stream(Protocol::Anthropic, &bare).is_none(),
            "裸键分片过快路径门后仍按归一口径返回 None，不估算"
        );
        let heartbeat = serde_json::json!({"delta":"hi"});
        assert!(extract_usage_stream(Protocol::Anthropic, &heartbeat).is_none());
    }

    #[test]
    fn responses_streaming_single_layer_preferred_over_double() {
        let both = serde_json::json!({"response":{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2},"response":{"usage":{"prompt_tokens":9,"completion_tokens":9,"total_tokens":18}}}});
        let u = extract_usage_stream(Protocol::Responses, &both).unwrap();
        assert_eq!(
            (u.prompt_tokens, u.completion_tokens, u.total_tokens),
            (1, 1, 2)
        );
    }

    #[test]
    fn usage_accumulation_takes_max_without_double_count() {
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"message":{"usage":{"input_tokens":5,"output_tokens":0,"total_tokens":5}}}),
            ),
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"delta":{"usage":{"input_tokens":30,"output_tokens":0,"total_tokens":30}}}),
            ),
        );
        let a = acc.as_ref().expect("须有累计值");
        assert_eq!((a.prompt_tokens, a.total_tokens), (30, 30));
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"delta":{"usage":{"input_tokens":9,"output_tokens":1,"total_tokens":10}}}),
            ),
        );
        let a2 = acc.as_ref().expect("须保持累计值");
        assert_eq!(
            (a2.prompt_tokens, a2.completion_tokens, a2.total_tokens),
            (30, 1, 30)
        );
    }

    #[test]
    fn cached_columns_follow_python_normalize_usage() {
        // Given：三协议各自口径的缓存键
        // When：归一提取
        // Then：cached_read/write 落位，缺失归零（对标 `_metrics.py:155`）
        let chat = serde_json::json!({"usage": {
            "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
            "prompt_tokens_details": {"cached_tokens": 4},
        }});
        let u = extract_usage_nonstream(Protocol::Chat, &chat).unwrap();
        assert_eq!((u.cached_read, u.cached_write), (4, 0));

        let chat_null = serde_json::json!({"usage": {
            "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
            "prompt_tokens_details": null,
        }});
        let u = extract_usage_nonstream(Protocol::Chat, &chat_null).unwrap();
        assert_eq!((u.cached_read, u.cached_write), (0, 0));

        let resp = serde_json::json!({"response": {"usage": {
            "input_tokens": 8, "output_tokens": 3,
            "input_tokens_details": {"cached_tokens": 6},
        }}});
        let u = extract_usage_nonstream(Protocol::Responses, &resp).unwrap();
        assert_eq!((u.cached_read, u.cached_write), (6, 0));

        let anth = serde_json::json!({"usage": {
            "input_tokens": 8, "output_tokens": 3,
            "cache_read_input_tokens": 5, "cache_creation_input_tokens": 2,
        }});
        let u = extract_usage_nonstream(Protocol::Anthropic, &anth).unwrap();
        assert_eq!((u.cached_read, u.cached_write), (5, 2));

        // 流式累计按列取 max，不双计。
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_nonstream(Protocol::Anthropic, &anth),
        );
        let anth_small = serde_json::json!({"usage": {
            "input_tokens": 1, "output_tokens": 1,
            "cache_read_input_tokens": 1, "cache_creation_input_tokens": 9,
        }});
        accumulate_usage(
            &mut acc,
            extract_usage_nonstream(Protocol::Anthropic, &anth_small),
        );
        let a = acc.unwrap();
        assert_eq!((a.cached_read, a.cached_write), (5, 9));
    }

    #[test]
    fn usage_regression_keeps_historical_max_with_delta_coverage() {
        let mut acc: Option<Usage> = None;
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"type":"message_delta","usage":{"input_tokens":100,"output_tokens":50,"total_tokens":150}}),
            ),
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"type":"message_delta","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}),
            ),
        );
        let a = acc.as_ref().expect("须有累计值");
        assert_eq!(
            (a.prompt_tokens, a.completion_tokens, a.total_tokens),
            (100, 50, 150),
            "递减输入不得回退"
        );
        accumulate_usage(
            &mut acc,
            extract_usage_stream(
                Protocol::Anthropic,
                &serde_json::json!({"type":"message_delta","usage":{"input_tokens":20,"output_tokens":200,"total_tokens":220}}),
            ),
        );
        let b = acc.as_ref().expect("须保持累计值");
        assert_eq!(
            (b.prompt_tokens, b.completion_tokens, b.total_tokens),
            (100, 200, 220),
            "乱序输入按列取历史最大"
        );
        assert_ne!(b.total_tokens, 150 + 15 + 220, "禁止 sum 双计");
    }
}
