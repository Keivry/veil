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
    // 严格子集说明：生产 token 恒为 `%06d` 6 位（见 credential_vault.rs），此处要求
    // `\d{6,}` 是 vault 侧 `\d{4,}`（detector.rs 宽松识别，兼容历史 4-5 位幻觉形）的严格
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
            || (rest.starts_with(b"__VG_CRED_") && match_cred_token(&rest[10..]))
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

/// Responses 文本字段注入（`input` 与 `instructions` 同等语义，§2.1；E2 独立回退）：
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
    // array 按首条前插；E2 独立回退：非法字段 warn 后保持原值，仅双字段
    // 均无注入时整体不注入。
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
    let mut obj: Value = serde_json::from_str(body_text.trim_start_matches('\u{feff}')).ok()?;
    if !obj.is_object() {
        return None;
    }
    // E2：Responses 双字段独立注入独立回退：合法字段注入保留，非法字段
    // 保持原值（`inject_responses_text_field` 内已不触碰非法形态）；
    // 仅当双字段均缺失/非法（无任何注入）时整体返回 `None`。
    // `placeholder_schema_ok` 保留作他协议与单测的最终兜底。
    // F-P2a 幂等守卫：目标位置已含说明不再重复前插，返回 `None`
    // 使调用方保留原字节（字节等价透传，不置位 normalized）。
    if protocol == Protocol::Responses {
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
    if protocol == Protocol::Anthropic
        && obj
            .as_object()
            .and_then(|m| m.get("system"))
            .is_some_and(|s| text_has_prompt(s, prompt))
    {
        return None;
    }
    if protocol == Protocol::Chat
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

/// T3 占位符回补：原 `pii_placeholder_prompt_test.py` 断言语义移植（仅语言改写）。
#[cfg(test)]
mod placeholder_parity_tests {
    use {
        super::{
            has_placeholder_tokens,
            inject_placeholder_prompt,
            placeholder_inject_obj,
            placeholder_schema_ok,
            should_inject_placeholders,
        },
        crate::{
            config::{PLACEHOLDER_PROMPT_DEFAULT, effective_placeholder_prompt},
            service::{credential_vault::CredentialVault, llm_gateway::Protocol},
        },
        serde_json::Value,
    };

    const PROMPT: &str = "PROMPT";
    const REAL_PII: &str = "__PII_1_ab12cd34__";
    const REAL_CRED: &str = "__VG_CRED_000005__";

    fn inject(body: &Value, protocol: Protocol) -> Option<Value> {
        inject_placeholder_prompt(&serde_json::to_string(body).unwrap(), PROMPT, protocol)
            .and_then(|s| serde_json::from_str(&s).ok())
    }

    #[test]
    fn t3_openai_existing_system_str_exact_merge() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"你是助手"},
            {"role":"user","content":format!("查 {REAL_PII}")}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(
            v["messages"][0]["content"].as_str().unwrap(),
            format!("你是助手\n\n{PROMPT}")
        );
        assert_eq!(
            v["messages"][1]["content"].as_str().unwrap(),
            format!("查 {REAL_PII}")
        );
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn t3_openai_existing_system_array_merged_in_place() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"system","content":[{"type":"text","text":"你是助手"}]},
            {"role":"user","content":"查 13800138000"}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        let content = &v["messages"][0]["content"];
        assert!(content.is_array());
        assert_eq!(content.as_array().unwrap().len(), 1);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(
            content[0]["text"].as_str().unwrap(),
            format!("你是助手\n\n{PROMPT}")
        );
    }

    #[test]
    fn t3_openai_no_system_insert_head_exact_prompt() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"user","content":format!("查 {REAL_PII}")}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][0]["content"].as_str().unwrap(), PROMPT);
        assert_eq!(v["messages"][1]["role"], "user");
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn t3_openai_empty_messages_single_system() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        assert_eq!(
            v["messages"],
            serde_json::json!([{"role":"system","content":PROMPT}])
        );
    }

    #[test]
    fn t3_openai_multiple_system_only_first_merged() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"system","content":"A"},
            {"role":"user","content":"hi"},
            {"role":"system","content":"B"}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        assert_eq!(
            v["messages"][0]["content"].as_str().unwrap(),
            format!("A\n\n{PROMPT}")
        );
        assert_eq!(v["messages"][2]["content"].as_str().unwrap(), "B");
    }

    #[test]
    fn t3_openai_system_empty_string_replaced_exactly() {
        let body = serde_json::json!({"messages":[{"role":"system","content":""}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        assert_eq!(v["messages"][0]["content"].as_str().unwrap(), PROMPT);
    }

    #[test]
    fn t3_anthropic_system_str_exact_merge() {
        let body = serde_json::json!({"model":"claude","system":"你是助手",
            "messages":[{"role":"user","content":"查 13800138000"}]});
        let v = inject(&body, Protocol::Anthropic).expect("须可注入");
        assert_eq!(
            v["system"].as_str().unwrap(),
            format!("你是助手\n\n{PROMPT}")
        );
    }

    #[test]
    fn t3_anthropic_system_array_merged_in_place() {
        let body = serde_json::json!({"model":"claude",
            "system":[{"type":"text","text":"你是助手"}],
            "messages":[{"role":"user","content":"hi"}]});
        let v = inject(&body, Protocol::Anthropic).expect("须可注入");
        assert!(v["system"].is_array());
        assert_eq!(v["system"].as_array().unwrap().len(), 1);
        assert_eq!(v["system"][0]["type"], "text");
        assert_eq!(
            v["system"][0]["text"].as_str().unwrap(),
            format!("你是助手\n\n{PROMPT}")
        );
    }

    #[test]
    fn t3_anthropic_no_system_created() {
        let body = serde_json::json!({"model":"claude",
            "messages":[{"role":"user","content":"hi"}]});
        let v = inject(&body, Protocol::Anthropic).expect("须可注入");
        assert_eq!(v["system"].as_str().unwrap(), PROMPT);
    }

    #[test]
    fn t3_anthropic_system_array_image_last_appended() {
        let body = serde_json::json!({"model":"claude",
            "system":[{"type":"image","source":{}}]});
        let v = inject(&body, Protocol::Anthropic).expect("须可注入");
        let arr = v["system"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1], serde_json::json!({"type":"text","text":PROMPT}));
    }

    #[test]
    fn t3_responses_input_array_existing_system_merged() {
        let body = serde_json::json!({"model":"gpt-4o","input":[
            {"role":"system","content":"你是助手"},
            {"role":"user","content":format!("查 {REAL_PII}")}]});
        let v = inject(&body, Protocol::Responses).expect("须可注入");
        assert_eq!(v["input"][0]["role"], "system");
        assert_eq!(
            v["input"][0]["content"].as_str().unwrap(),
            format!("你是助手\n\n{PROMPT}")
        );
        assert_eq!(v["input"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn t3_responses_empty_input_single_system() {
        let body = serde_json::json!({"model":"gpt-4o","input":[]});
        let v = inject(&body, Protocol::Responses).expect("须可注入");
        assert_eq!(
            v["input"],
            serde_json::json!([{"role":"system","content":PROMPT}])
        );
    }

    #[test]
    fn t3_chat_content_array_with_image_block_appended() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"system","content":[
                {"type":"text","text":"你是助手"},
                {"type":"image_url","image_url":{"url":"data:..."}}]},
            {"role":"user","content":"查 13800138000"}]});
        let v = inject(&body, Protocol::Chat).expect("须可注入");
        let content = v["messages"][0]["content"].as_array().unwrap().clone();
        assert_eq!(
            content.last().unwrap(),
            &serde_json::json!({"type":"text","text":PROMPT})
        );
        assert_eq!(content[content.len() - 2]["type"], "image_url");
        assert_eq!(content[0]["text"].as_str().unwrap(), "你是助手");
    }

    #[test]
    fn t3_custom_prompt_used_verbatim() {
        let body = serde_json::json!({"model":"gpt-4o","messages":[
            {"role":"user","content":"查 13800138000"}]});
        let out = inject_placeholder_prompt(
            &serde_json::to_string(&body).unwrap(),
            "Keep tokens verbatim",
            Protocol::Chat,
        )
        .expect("自定义文案须可注入");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["messages"][0]["content"].as_str().unwrap(),
            "Keep tokens verbatim"
        );
    }

    #[test]
    fn t3_non_json_passthrough() {
        assert!(inject_placeholder_prompt("not json at all", PROMPT, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_truncated_json_passthrough() {
        let body = r#"{"model": "gpt-4o", "messages": [{"role": "user", "content": ""#;
        assert!(inject_placeholder_prompt(body, PROMPT, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_truncated_json_with_tokens_passthrough_without_panic() {
        let body = format!("{{\"messages\":[{{\"content\":\"{REAL_PII}");
        assert!(inject_placeholder_prompt(&body, PROMPT, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_non_object_json_passthrough() {
        assert!(inject_placeholder_prompt("[1, 2, 3]", PROMPT, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_unknown_structure_passthrough() {
        let body = serde_json::json!({"model":"gpt-4o","foo":"bar"});
        assert!(inject(&body, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_empty_prompt_and_body_rejected() {
        let body = serde_json::json!({"messages":[{"role":"user","content":"hi"}]});
        let text = serde_json::to_string(&body).unwrap();
        assert!(inject_placeholder_prompt(&text, "", Protocol::Chat).is_none());
        assert!(inject_placeholder_prompt("", PROMPT, Protocol::Chat).is_none());
    }

    #[test]
    fn t3_whitespace_and_bom_prefixed_json_injected() {
        let body = "  \n {\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}".to_string();
        let out =
            inject_placeholder_prompt(&body, PROMPT, Protocol::Chat).expect("前导空白须可注入");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["role"], "system");
        let bom = "\u{feff}{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}".to_string();
        let out2 = inject_placeholder_prompt(&bom, PROMPT, Protocol::Chat).expect("BOM 须可注入");
        let v2: Value = serde_json::from_str(&out2).unwrap();
        assert_eq!(v2["messages"][0]["role"], "system");
    }

    #[test]
    fn t3_trigger_gate_or_semantics() {
        assert!(should_inject_placeholders(true, true, true));
        assert!(!should_inject_placeholders(false, true, true));
        assert!(!should_inject_placeholders(true, false, true));
        assert!(!should_inject_placeholders(true, true, false));
        assert!(has_placeholder_tokens(
            format!("{{\"x\":\"{REAL_PII}\"}}").as_bytes()
        ));
        assert!(has_placeholder_tokens(
            format!("{{\"x\":\"{REAL_CRED}\"}}").as_bytes()
        ));
        assert!(!has_placeholder_tokens(b"{\"x\": \"no placeholder\"}"));
    }

    #[test]
    fn t3_default_prompt_static_no_real_data() {
        assert!(!PLACEHOLDER_PROMPT_DEFAULT.contains("13800138000"));
        assert!(!PLACEHOLDER_PROMPT_DEFAULT.contains("192.168"));
        let has_full_shape = PLACEHOLDER_PROMPT_DEFAULT
            .split("__")
            .any(|seg| seg.starts_with("PII_") && seg.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!has_full_shape, "内置文案不得含合法形态占位符");
        assert!(PLACEHOLDER_PROMPT_DEFAULT.contains("__PII_*__"));
        assert!(PLACEHOLDER_PROMPT_DEFAULT.contains("__VG_CRED_*__"));
        assert_eq!(effective_placeholder_prompt(""), PLACEHOLDER_PROMPT_DEFAULT);
        assert_eq!(
            effective_placeholder_prompt("   "),
            PLACEHOLDER_PROMPT_DEFAULT
        );
    }

    #[test]
    fn t3_r5_injected_star_literal_not_a_token() {
        // F-P2a：说明文案自身的 `__PII_*__` 字面不再触发注入门控；
        // 还原侧仍原样保留字面（vault 行为不变）。
        assert!(!has_placeholder_tokens(b"__PII_*__"));
        assert!(!has_placeholder_tokens(
            PLACEHOLDER_PROMPT_DEFAULT.as_bytes()
        ));
        let vault = CredentialVault::new();
        let out = vault.restore("说明：__PII_*__ 是占位符");
        assert!(out.contains("__PII_*__"), "字面描述不被还原");
        let tok = vault.register("1380013800abc").expect("注册须成功");
        let mixed = format!("说明：__PII_*__ 是占位符；真实的是 {tok}");
        assert!(vault.restore(&mixed).contains("1380013800abc"));
        assert!(vault.restore(&mixed).contains("__PII_*__"));
    }

    #[test]
    fn f2a_exact_token_shape_gate_with_idempotent_inject() {
        // F-P2a 精确形态：全形态判 true，字面/残缺判 false。
        assert!(has_placeholder_tokens(b"a __PII_1_ab12cd34__ b"));
        assert!(has_placeholder_tokens(b"a __VG_CRED_000001__ b"));
        assert!(!has_placeholder_tokens(b"__PII_*__"));
        assert!(!has_placeholder_tokens(b"__VG_CRED_*__"));
        assert!(!has_placeholder_tokens(b"__PII_1_ab12cd3__"));
        assert!(!has_placeholder_tokens(b"__PII__ab12cd34__"));
        assert!(!has_placeholder_tokens(b"__PI_1_ab12cd34__"));
        assert!(!has_placeholder_tokens(b"no tokens here"));
        // F-P2a 幂等：已含说明不再前插，三协议均字节等价回退 `None`。
        let chat = serde_json::json!({"messages":[
            {"role":"user","content":"hi __PII_1_ab12cd34__"}]});
        let once = inject(&chat, Protocol::Chat).expect("首次须可注入");
        assert_eq!(once["messages"][0]["role"], "system");
        let text = serde_json::to_string(&once).unwrap();
        assert!(
            inject_placeholder_prompt(&text, PROMPT, Protocol::Chat).is_none(),
            "二次注入须幂等跳过"
        );
        let anth = serde_json::json!({"messages":[{"role":"user","content":"hi"}]});
        let once = inject(&anth, Protocol::Anthropic).expect("首次须可注入");
        let text = serde_json::to_string(&once).unwrap();
        assert!(
            inject_placeholder_prompt(&text, PROMPT, Protocol::Anthropic).is_none(),
            "二次注入须幂等跳过"
        );
        let resp = serde_json::json!({"input":"hi __VG_CRED_000001__"});
        let once = inject(&resp, Protocol::Responses).expect("首次须可注入");
        let text = serde_json::to_string(&once).unwrap();
        assert!(
            inject_placeholder_prompt(&text, PROMPT, Protocol::Responses).is_none(),
            "二次注入须幂等跳过"
        );
        // Responses 部分已含：仅未含字段注入，已含字段原样保留。
        let partial = serde_json::json!({"input":PROMPT,"instructions":"be nice"});
        let out = inject(&partial, Protocol::Responses).expect("未含字段仍须注入");
        assert_eq!(out["input"], PROMPT);
        assert!(out["instructions"].as_str().unwrap().contains(PROMPT));
    }

    #[test]
    fn b7_cred_gate_conservative_four_five_digit_not_detected() {
        // B7：`\d{6,}` 门控有意保守——4/5 位形态（vault 宽松侧兼容）不触发说明注入。
        assert!(!has_placeholder_tokens(b"__VG_CRED_0001__"));
        assert!(!has_placeholder_tokens(b"__VG_CRED_00001__"));
        assert!(has_placeholder_tokens(b"__VG_CRED_000001__"));
    }

    #[test]
    fn t3_r5_unregistered_cred_token_not_restored() {
        let vault = CredentialVault::new();
        let out = vault.restore("未注册 __VG_CRED_999999__ 保持原样");
        assert!(out.contains("__VG_CRED_999999__"));
    }

    #[test]
    fn t3_large_body_injection_linear() {
        let big: String = format!("查 13800138000 {}", "x".repeat(10 * 1024 * 1024));
        let body = serde_json::json!({"model":"gpt-4o",
            "messages":[{"role":"user","content":big.clone()}]});
        let text = serde_json::to_string(&body).unwrap();
        let start = std::time::Instant::now();
        let out =
            inject_placeholder_prompt(&text, PROMPT, Protocol::Chat).expect("大 body 须可注入");
        assert!(start.elapsed().as_secs_f64() < 5.0);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["messages"][0]["role"], "system");
        assert_eq!(v["messages"][1]["content"].as_str().unwrap(), big);
    }

    #[test]
    fn t3_responses_both_input_and_instructions_injected() {
        let body = serde_json::json!({"input":"hi","instructions":"be nice"});
        let v = inject(&body, Protocol::Responses).expect("双字段须可注入");
        assert!(v["input"].as_str().unwrap().contains(PROMPT));
        assert!(v["instructions"].as_str().unwrap().contains("be nice"));
        assert!(placeholder_schema_ok(&v, Protocol::Responses));
        let mut raw = body.clone();
        assert!(placeholder_inject_obj(
            &mut raw,
            PROMPT,
            Protocol::Responses
        ));
    }

    #[test]
    fn t3_non_chat_messages_non_array_rejected() {
        let body = serde_json::json!({"messages":"oops"});
        assert!(inject(&body, Protocol::Chat).is_none());
        assert!(!placeholder_schema_ok(&body, Protocol::Chat));
    }

    #[test]
    fn t3_nondialog_never_injects() {
        let body = serde_json::json!({"messages":[{"role":"user","content":"hi"}]});
        assert!(inject(&body, Protocol::NonDialog).is_none());
        assert!(!placeholder_schema_ok(&body, Protocol::NonDialog));
    }

    #[test]
    fn t3_cred_token_shape_detected_for_gate() {
        for sample in [
            "__VG_CRED_000001__",
            "__VG_CRED_123456789012__",
            "__PII_3_abcdef12__",
        ] {
            assert!(has_placeholder_tokens(sample.as_bytes()), "{sample}");
        }
        assert!(!has_placeholder_tokens(b"__PI_1_ab12cd34__"));
        assert!(!has_placeholder_tokens(b"plain text"));
    }
}
