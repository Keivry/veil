//! 占位符说明注入：三条件判定 + 三协议形态注入 + schema 护栏。

use {super::Protocol, serde_json::Value};

pub fn should_inject_placeholders(
    is_chat: bool,
    redaction_enabled: bool,
    body_has_values: bool,
) -> bool {
    is_chat && redaction_enabled && body_has_values
}

fn match_pii_token(tail: &[u8]) -> bool {
    let mut j = 0;
    while j < tail.len() && tail[j].is_ascii_digit() {
        j += 1;
    }
    if j == 0 || j + 1 + 8 + 2 > tail.len() || tail[j] != b'_' {
        return false;
    }
    tail[j + 1..j + 1 + 8].iter().all(|b| b.is_ascii_hexdigit())
        && tail[j + 1 + 8..].starts_with(b"__")
}

fn match_cred_token(tail: &[u8]) -> bool {
    // 严格子集说明：生产 token 恒为 `%06d` 6 位（见 credential_vault.rs 的 `make_cred_token`），
    // 此处要求 `\d{6,}` 是 vault 还原侧 `\d{4,}`（credential_vault.rs 的 `token_re`，兼容
    // 历史 4-5 位幻觉形；检测侧形态保护另见 pii/detector.rs）的严格
    // 子集；4-5 位形不触发注入门属有意保守（注入宜漏不宜误），还原侧仍按宽松口径处理。
    let mut j = 0;
    while j < tail.len() && tail[j].is_ascii_digit() {
        j += 1;
    }
    j >= 6 && j + 2 <= tail.len() && tail[j..].starts_with(b"__")
}

pub fn has_placeholder_tokens(body: &[u8]) -> bool {
    let mut i = 0;
    while i < body.len() {
        let rest = &body[i..];
        if (rest.starts_with(b"__PII_") && match_pii_token(&rest[6..]))
            || (rest.starts_with(b"__CRED_") && match_cred_token(&rest[7..]))
        {
            return true;
        }
        i += 1;
    }
    false
}

fn append_prompt_text(field: &mut Value, prompt: &str) {
    match field {
        Value::String(s) => {
            if s.is_empty() {
                *s = prompt.to_string();
            } else {
                s.push_str("\n\n");
                s.push_str(prompt);
            }
        }
        Value::Array(arr) => {
            if let Some(Value::Object(last)) = arr.last_mut()
                && last.get("type").and_then(|v| v.as_str()) == Some("text")
                && let Some(text) = last.get_mut("text")
                && let Some(t) = text.as_str()
            {
                let merged = if t.is_empty() {
                    prompt.to_string()
                } else {
                    format!("{t}\n\n{prompt}")
                };
                last.insert("text".to_string(), Value::String(merged));
                return;
            }
            arr.push(serde_json::json!({"type": "text", "text": prompt}));
        }
        _ => {}
    }
}

/// Responses 数组前插 system 说明（与 Chat `messages` 同语义）：
/// 空数组追加首条；首条为 system 则合并 `content`；否则头部插入。
fn front_insert_system(msgs: &mut Vec<Value>, prompt: &str) {
    if msgs.is_empty() {
        msgs.push(serde_json::json!({"role": "system", "content": prompt}));
        return;
    }
    if let Some(Value::Object(first)) = msgs.first_mut()
        && first.get("role").and_then(|v| v.as_str()) == Some("system")
    {
        match first.get_mut("content") {
            Some(content @ (Value::String(_) | Value::Array(_))) => {
                append_prompt_text(content, prompt);
            }
            Some(other) => {
                let base = other.as_str().unwrap_or_default().to_string();
                let merged = if base.is_empty() {
                    prompt.to_string()
                } else {
                    format!("{base}\n\n{prompt}")
                };
                first.insert("content".to_string(), Value::String(merged));
            }
            None => {
                first.insert("content".to_string(), Value::String(prompt.to_string()));
            }
        }
        return;
    }
    msgs.insert(0, serde_json::json!({"role": "system", "content": prompt}));
}

/// Responses 文本字段注入（`input` 与 `instructions` 同等语义；独立回退）：
/// - `String`：末尾追加说明（与 Anthropic `system` 字符串形态一致）；
/// - `Array`：首条 system 前插；
/// - 非法形态（数字/对象等）：warn 后不注入，该字段保持原值（不连坐合法字段）。
fn inject_responses_text_field(field: &mut Value, key: &str, prompt: &str) -> bool {
    match field {
        Value::String(_) | Value::Array(_) => {}
        _ => {
            tracing::warn!("Responses {key} 非法形态不注入，原体透传");
            return false;
        }
    }
    match field {
        Value::String(_) => {
            append_prompt_text(field, prompt);
            true
        }
        Value::Array(arr) => {
            front_insert_system(arr, prompt);
            true
        }
        _ => false,
    }
}

/// 占位符说明注入：chat 前插 `messages` 首条 system；
/// anthropic 合并 `system`；responses 对 `input` 与 `instructions`
/// 同等注入（string 追加 / array 前插），非法形态 warn 后不注入。
pub fn placeholder_inject_obj(body: &mut Value, prompt: &str, protocol: Protocol) -> bool {
    if protocol.is_anthropic() {
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        if let Some(sys) = map.get_mut("system") {
            if matches!(sys, Value::String(_) | Value::Array(_)) {
                append_prompt_text(sys, prompt);
                return true;
            }
            tracing::warn!("Anthropic system 非法形态不注入，原体透传");
            return false;
        }
        map.insert("system".to_string(), Value::String(prompt.to_string()));
        return true;
    }
    // Responses `input` 与 `instructions` 同等注入；string 按串追加、
    // array 按首条前插；独立回退：非法字段 warn 后保持原值，仅双字段
    // 均无注入时整体不注入。
    if protocol.is_responses() {
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        let mut injected = false;
        for key in ["input", "instructions"] {
            let Some(field) = map.get_mut(key) else {
                continue;
            };
            injected |= inject_responses_text_field(field, key, prompt);
        }
        if !injected {
            tracing::warn!("Responses input/instructions 缺失或非法，不注入");
        }
        return injected;
    }
    let key = "messages";
    let Some(map) = body.as_object_mut() else {
        return false;
    };
    let Some(field) = map.get_mut(key) else {
        return false;
    };
    let Some(msgs) = field.as_array_mut() else {
        return false;
    };
    front_insert_system(msgs, prompt);
    true
}

pub fn placeholder_schema_ok(body: &Value, protocol: Protocol) -> bool {
    let Some(map) = body.as_object() else {
        return false;
    };
    match protocol {
        Protocol::Anthropic => match map.get("system") {
            None => true,
            Some(Value::String(_)) | Some(Value::Array(_)) => true,
            Some(_) => false,
        },
        // Responses 允许 `input`/`instructions` 各为 string|array；
        // 存在者须形态合法，且至少存在其一；非法回退不注入。
        Protocol::Responses => {
            let field_ok = |v: Option<&Value>| match v {
                None => true,
                Some(Value::String(_) | Value::Array(_)) => true,
                Some(_) => false,
            };
            (map.get("input").is_some() || map.get("instructions").is_some())
                && field_ok(map.get("input"))
                && field_ok(map.get("instructions"))
        }
        Protocol::Chat => map.get("messages").is_some_and(|v| v.is_array()),
        Protocol::NonDialog => false,
    }
}

fn text_has_prompt(v: &Value, prompt: &str) -> bool {
    match v {
        Value::String(s) => s.contains(prompt),
        Value::Array(arr) => arr.iter().any(|e| {
            e.get("content").is_some_and(|c| text_has_prompt(c, prompt))
                || e.get("text")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t.contains(prompt))
        }),
        _ => false,
    }
}

fn first_system_has_prompt(obj: &serde_json::Map<String, Value>, key: &str, prompt: &str) -> bool {
    obj.get(key)
        .and_then(|v| v.as_array())
        .and_then(|msgs| {
            msgs.first()
                .filter(|first| first.get("role").and_then(|r| r.as_str()) == Some("system"))
        })
        .is_some_and(|first| {
            first
                .get("content")
                .is_some_and(|c| text_has_prompt(c, prompt))
        })
}

pub fn inject_placeholder_prompt(
    body_text: &str,
    prompt: &str,
    protocol: Protocol,
) -> Option<String> {
    if body_text.is_empty() || prompt.is_empty() {
        return None;
    }
    let stripped = body_text.trim_start_matches('\u{feff}').trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return None;
    }
    // 生产请求体 JSON 解析统一经中央 `json_walk::{strip_bom, jloads}`
    // （BOM 处理单一来源），非 BOM 输入与非中央路径逐字节等价。
    let mut obj: Value =
        crate::service::json_walk::jloads(crate::service::json_walk::strip_bom(body_text)).ok()?;
    if !obj.is_object() {
        return None;
    }
    // Responses 双字段独立注入独立回退：合法字段注入保留，非法字段
    // 保持原值（`inject_responses_text_field` 内已不触碰非法形态）；
    // 仅当双字段均缺失/非法（无任何注入）时整体返回 `None`。
    // `placeholder_schema_ok` 保留作他协议与单测的最终兜底。
    // F-P2a 幂等守卫：目标位置已含说明不再重复前插，返回 `None`
    // 使调用方保留原字节（字节等价透传，不置位 normalized）。
    if protocol.is_responses() {
        let already = ["input", "instructions"].iter().all(|key| {
            obj.as_object()
                .and_then(|m| m.get(*key))
                .is_none_or(|f| text_has_prompt(f, prompt))
        }) && obj
            .as_object()
            .is_some_and(|m| m.get("input").is_some() || m.get("instructions").is_some());
        if already {
            return None;
        }
        let mut injected = false;
        let map = obj.as_object_mut()?;
        for key in ["input", "instructions"] {
            let Some(field) = map.get_mut(key) else {
                continue;
            };
            if text_has_prompt(field, prompt) {
                continue;
            }
            injected |= inject_responses_text_field(field, key, prompt);
        }
        if !injected {
            tracing::warn!("Responses input/instructions 缺失或非法，不注入");
            return None;
        }
        return serde_json::to_string(&obj).ok();
    }
    if protocol.is_anthropic()
        && obj
            .as_object()
            .and_then(|m| m.get("system"))
            .is_some_and(|s| text_has_prompt(s, prompt))
    {
        return None;
    }
    if protocol.is_chat()
        && obj
            .as_object()
            .is_some_and(|m| first_system_has_prompt(m, "messages", prompt))
    {
        return None;
    }
    if !placeholder_inject_obj(&mut obj, prompt, protocol) {
        return None;
    }
    if !placeholder_schema_ok(&obj, protocol) {
        tracing::warn!("占位符说明注入 schema 校验失败，回退不注入");
        return None;
    }
    serde_json::to_string(&obj).ok()
}

#[cfg(test)]
mod tests;
