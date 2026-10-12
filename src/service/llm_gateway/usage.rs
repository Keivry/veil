//! 用量口径：非流/流式提取 + `max` 合并（不双计）+ 累计。

use {super::Protocol, serde_json::Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    /// 该事件是否显式携带 total（`total_tokens`/`total`）。
    /// 跨事件合并口径：任一事件显式 total 取显式 `max`；全部事件均无显式
    /// total 时最终 `total = max(prompt)+max(completion)`。
    pub total_explicit: bool,
    /// 缓存命中读（`cached_read` 列）。
    pub cached_read: u64,
    /// 缓存写入（仅 Anthropic 有值，其余归零）。
    pub cached_write: u64,
}

fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

/// 三协议缓存列提取：Anthropic 取顶层
/// `cache_read_input_tokens`/`cache_creation_input_tokens`；Responses 取
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
    let explicit_total = obj
        .get("total_tokens")
        .and_then(as_u64)
        .or_else(|| obj.get("total").and_then(as_u64));
    let total = explicit_total.unwrap_or_else(|| prompt.saturating_add(completion));
    let (cached_read, cached_write) = cached_columns(protocol, obj);
    Some(Usage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: total,
        total_explicit: explicit_total.is_some(),
        cached_read,
        cached_write,
    })
}

fn usage_in(obj: &serde_json::Map<String, Value>, protocol: Protocol) -> Option<Usage> {
    obj.get("usage")?
        .as_object()
        .and_then(|o| usage_from_obj(o, protocol))
}

/// 跨事件合并口径（勿改）：`prompt/completion/cached_*` 逐列 `max`；
/// `total_tokens` 若任一事件显式携带则取显式 `max`（保留上游声明），
/// 若全部事件均无显式 total 则最终按合并后 `prompt_max+completion_max` 归一
/// （Anthropic `message_start` 输入 + `message_delta` 输出必须求和而非取 max）。
fn merge_usage(acc: &mut Option<Usage>, next: Usage) {
    match acc {
        Some(a) => {
            a.prompt_tokens = a.prompt_tokens.max(next.prompt_tokens);
            a.completion_tokens = a.completion_tokens.max(next.completion_tokens);
            a.cached_read = a.cached_read.max(next.cached_read);
            a.cached_write = a.cached_write.max(next.cached_write);
            if next.total_explicit {
                a.total_tokens = if a.total_explicit {
                    a.total_tokens.max(next.total_tokens)
                } else {
                    next.total_tokens
                };
            }
            a.total_explicit |= next.total_explicit;
            if !a.total_explicit {
                a.total_tokens = a.prompt_tokens.saturating_add(a.completion_tokens);
            }
        }
        None => *acc = Some(next),
    }
}

/// 嵌套 `usage` 回退公共骨架（单一来源）：按路径序列逐级定位 usage 对象
/// 并归一，首个命中者胜。非流与流式的差异仅由调用方传入的路径序列与顶层
/// `usage_in` 组合承载；流式快路径门与 Anthropic `delta.usage` 层调用时机
/// 保留在调用方。
fn usage_from_paths(root: &Value, protocol: Protocol, paths: &[&[&str]]) -> Option<Usage> {
    paths.iter().find_map(|path| {
        let mut cur = root;
        for key in path.iter() {
            cur = cur.get(*key)?;
        }
        cur.as_object().and_then(|o| usage_from_obj(o, protocol))
    })
}

pub fn extract_usage_nonstream(protocol: Protocol, body: &Value) -> Option<Usage> {
    match protocol {
        Protocol::Chat => usage_in(body.as_object()?, protocol),
        Protocol::Responses => {
            // F-P1a：官方非流顶层 `usage` 优先，其次 `response.usage`，
            // 最后 `response.response.usage` 回退；缓存列同口径。
            usage_in(body.as_object()?, protocol).or_else(|| {
                usage_from_paths(
                    body,
                    protocol,
                    &[&["response", "usage"], &["response", "response", "usage"]],
                )
            })
        }
        Protocol::Anthropic => usage_in(body.as_object()?, protocol)
            .or_else(|| usage_from_paths(body, protocol, &[&["message", "usage"]])),
        Protocol::NonDialog => None,
    }
}

/// 流式 SSE 事件载荷捕获 usage。
///
/// 口径：顶层 `usage` 优先；Responses `response.usage`、双层
/// `response.response.usage` 回退；Anthropic `delta.usage` / `message.usage`
/// 回退；缺失返回 `None` 不估算。数值归一与 [`extract_usage_nonstream`] 同口径
/// （`input_tokens`/`output_tokens`/`total` 回退，`total` 缺失时 `prompt+completion`）。
pub fn extract_usage_stream(protocol: Protocol, payload: &Value) -> Option<Usage> {
    let obj = payload.as_object()?;
    // F-P2b 快路径：借用判断有无用量承载键，心跳分片零分配跳过。
    // 完备性：能产出 `Some` 的路径必含四键之一（顶层 `usage`；
    // Responses 嵌套 `response`；Anthropic 嵌套 `delta`/`message`），
    // 门外一律归一亦为 `None`，结论等价。
    if !obj.contains_key("usage")
        && !obj.contains_key("response")
        && !obj.contains_key("delta")
        && !obj.contains_key("message")
    {
        return None;
    }
    if let Some(u) = usage_in(obj, protocol) {
        return Some(u);
    }
    match protocol {
        Protocol::Chat => None,
        Protocol::Responses => usage_from_paths(
            payload,
            protocol,
            &[&["response", "usage"], &["response", "response", "usage"]],
        ),
        Protocol::Anthropic => usage_from_paths(
            payload,
            protocol,
            &[&["delta", "usage"], &["message", "usage"]],
        ),
        Protocol::NonDialog => None,
    }
}

/// 流式 usage 累加（口径：统一 `max`，禁用 `sum`）。
/// 上游分片语义为累计值（`message_start` 给全量、`message_delta` 给累计），
/// 按字段单调取大；`sum` 会把同一 token 算两次（双计），此处禁止。
pub fn accumulate_usage(acc: &mut Option<Usage>, next: Option<Usage>) {
    if let Some(u) = next {
        merge_usage(acc, u);
    }
}

#[cfg(test)]
mod tests;
