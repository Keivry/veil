//! 占位符说明注入：三条件判定 + 三协议形态注入 + schema 护栏。

use {super::Protocol, serde_json::Value};

pub fn should_inject_placeholders(
    is_chat: bool,
    redaction_enabled: bool,
    body_has_values: bool,
) -> bool {
    is_chat && redaction_enabled && body_has_values
}

pub fn has_placeholder_tokens(body: &[u8]) -> bool {
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(b"__PII_") || body[i..].starts_with(b"__VG_CRED_") {
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

/// Responses 文本字段注入（`input` 与 `instructions` 同等语义，§2.1）：
/// - `String`：末尾追加说明（与 Anthropic `system` 字符串形态一致）；
/// - `Array`：首条 system 前插；
/// - 非法形态（数字/对象等）：warn 后不注入，调用方回退原体。
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

/// 占位符说明注入（§2.1）：chat 前插 `messages` 首条 system；
/// anthropic 合并 `system`；responses 对 `input` 与 `instructions`
/// 同等注入（string 追加 / array 前插），非法形态 warn 后不注入。
pub fn placeholder_inject_obj(body: &mut Value, prompt: &str, protocol: Protocol) -> bool {
    if protocol == Protocol::Anthropic {
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
    // §2.1：Responses `input` 与 `instructions` 同等注入；string 按串追加、
    // array 按首条前插；非法形态 warn 后不注入（回退原体）。
    if protocol == Protocol::Responses {
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
        // §2.1：Responses 允许 `input`/`instructions` 各为 string|array；
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
    let mut obj: Value = serde_json::from_str(body_text.trim_start_matches('\u{feff}')).ok()?;
    if !obj.is_object() {
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
mod tests {
    use super::*;

    #[test]
    fn placeholder_injection_requires_three_conditions() {
        assert!(should_inject_placeholders(true, true, true));
        assert!(!should_inject_placeholders(false, true, true));
        assert!(!should_inject_placeholders(true, false, true));
        assert!(!should_inject_placeholders(true, true, false));
    }

    #[test]
    fn placeholder_injection_covers_three_protocol_shapes() {
        let prompt = "PROMPT";
        let openai = serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&openai).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["role"], "system");
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains(prompt)
        );

        let sys_first = serde_json::json!({"messages":[{"role":"system","content":"你是助手"},{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&sys_first).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("你是助手")
        );
        assert!(
            v["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains(prompt)
        );

        let empty_msgs = serde_json::json!({"messages":[]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&empty_msgs).unwrap(),
            prompt,
            Protocol::Chat,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["content"].as_str().unwrap(), prompt);

        let anth = serde_json::json!({"model":"m","system":"你是助手"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&anth).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["system"].as_str().unwrap().contains(prompt));

        let anth_none = serde_json::json!({"model":"m"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&anth_none).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["system"].as_str().unwrap(), prompt);

        let resp = serde_json::json!({"input":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["input"][0]["role"], "system");

        assert!(inject_placeholder_prompt("plain text", prompt, Protocol::Chat).is_none());
        assert!(inject_placeholder_prompt("[1,2]", prompt, Protocol::Chat).is_none());
        assert!(inject_placeholder_prompt("", prompt, Protocol::Chat).is_none());
        assert!(!has_placeholder_tokens(b"no tokens here"));
        assert!(has_placeholder_tokens(b"a __PII_1_ab12cd34__ b"));
        assert!(has_placeholder_tokens(b"a __VG_CRED_000001__ b"));
    }

    #[test]
    fn placeholder_four_shape_injection_with_fallback() {
        let prompt = "PROMPT";
        // §2.1：Responses 字符串 input 按串追加注入（与 input 数组同等）。
        let resp_str = serde_json::json!({"model":"m","input":"hello"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp_str).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("字符串 input 须可注入");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["input"].as_str().unwrap().contains(prompt));
        assert!(parsed["input"].as_str().unwrap().contains("hello"));
        let mut v = resp_str.clone();
        assert!(placeholder_inject_obj(&mut v, prompt, Protocol::Responses));
        assert!(placeholder_schema_ok(&v, Protocol::Responses));
        // 非法形态（数字 input）仍回退不注入。
        let resp_bad = serde_json::json!({"model":"m","input":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&resp_bad).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
        let mut vb = resp_bad.clone();
        assert!(!placeholder_inject_obj(
            &mut vb,
            prompt,
            Protocol::Responses
        ));
        assert!(!placeholder_schema_ok(&vb, Protocol::Responses));
        let anth_bad = serde_json::json!({"model":"m","system":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&anth_bad).unwrap(),
                prompt,
                Protocol::Anthropic,
            )
            .is_none()
        );
        let mut v2 = anth_bad.clone();
        assert!(!placeholder_inject_obj(
            &mut v2,
            prompt,
            Protocol::Anthropic
        ));
        assert!(!placeholder_schema_ok(&v2, Protocol::Anthropic));
        let resp_arr = serde_json::json!({"input":[{"role":"user","content":"hi"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&resp_arr).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["input"][0]["role"], "system");
        let anth_ok = serde_json::json!({"model":"m","system":"base"});
        let out2 = inject_placeholder_prompt(
            &serde_json::to_string(&anth_ok).unwrap(),
            prompt,
            Protocol::Anthropic,
        )
        .unwrap();
        let parsed2: Value = serde_json::from_str(&out2).unwrap();
        assert!(parsed2["system"].as_str().unwrap().contains(prompt));
    }

    #[test]
    fn responses_instructions_injected_like_input() {
        let prompt = "PROMPT";
        // instructions 字符串与 input 字符串同时注入。
        let both = serde_json::json!({"input":"hi","instructions":"be nice"});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&both).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("双字段须可注入");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v["input"].as_str().unwrap().contains(prompt));
        assert!(v["instructions"].as_str().unwrap().contains("be nice"));
        assert!(v["instructions"].as_str().unwrap().contains(prompt));
        // 仅 instructions（无 input）同样可注入。
        let only = serde_json::json!({"instructions":["a"]});
        let out2 = inject_placeholder_prompt(
            &serde_json::to_string(&only).unwrap(),
            prompt,
            Protocol::Responses,
        )
        .expect("仅 instructions 须可注入");
        let v2: Value = serde_json::from_str(&out2).unwrap();
        assert_eq!(v2["instructions"][0]["role"], "system");
        // instructions 非法形态不注入整体回退。
        let bad = serde_json::json!({"input":[{"role":"user","content":"hi"}],"instructions":42});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&bad).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
        // 两字段皆缺失不注入。
        let none = serde_json::json!({"model":"m"});
        assert!(
            inject_placeholder_prompt(
                &serde_json::to_string(&none).unwrap(),
                prompt,
                Protocol::Responses,
            )
            .is_none()
        );
    }
}
