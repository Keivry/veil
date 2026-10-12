//! 占位符回补：原 `pii_placeholder_prompt_test.py` 断言语义移植（仅语言改写）。

use {
    super::super::{
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
const REAL_CRED: &str = "__CRED_000005__";

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
    let out = inject_placeholder_prompt(&body, PROMPT, Protocol::Chat).expect("前导空白须可注入");
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
    assert!(PLACEHOLDER_PROMPT_DEFAULT.contains("__CRED_*__"));
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
    assert!(has_placeholder_tokens(b"a __CRED_000001__ b"));
    assert!(!has_placeholder_tokens(b"__PII_*__"));
    assert!(!has_placeholder_tokens(b"__CRED_*__"));
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
    let resp = serde_json::json!({"input":"hi __CRED_000001__"});
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
    // `\d{6,}` 门控有意保守——4/5 位形态（vault 宽松侧兼容）不触发说明注入。
    assert!(!has_placeholder_tokens(b"__CRED_0001__"));
    assert!(!has_placeholder_tokens(b"__CRED_00001__"));
    assert!(has_placeholder_tokens(b"__CRED_000001__"));
}

#[test]
fn b7_cred_gate_multibyte_adjacency_no_panic() {
    // 新前缀 `__CRED_` 长 7：多字节字符紧邻 token 前后，字节切片须恒落字符边界、不 panic。
    assert!(has_placeholder_tokens("中文__CRED_000001__结尾".as_bytes()));
    assert!(!has_placeholder_tokens("中文__CRED_0001__结尾".as_bytes()));
}

#[test]
fn t3_r5_unregistered_cred_token_not_restored() {
    let vault = CredentialVault::new();
    let out = vault.restore("未注册 __CRED_999999__ 保持原样");
    assert!(out.contains("__CRED_999999__"));
}

#[test]
fn t3_large_body_injection_linear() {
    let big: String = format!("查 13800138000 {}", "x".repeat(10 * 1024 * 1024));
    let body = serde_json::json!({"model":"gpt-4o",
        "messages":[{"role":"user","content":big.clone()}]});
    let text = serde_json::to_string(&body).unwrap();
    let start = std::time::Instant::now();
    let out = inject_placeholder_prompt(&text, PROMPT, Protocol::Chat).expect("大 body 须可注入");
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
        "__CRED_000001__",
        "__CRED_123456789012__",
        "__PII_3_abcdef12__",
    ] {
        assert!(has_placeholder_tokens(sample.as_bytes()), "{sample}");
    }
    assert!(!has_placeholder_tokens(b"__PI_1_ab12cd34__"));
    assert!(!has_placeholder_tokens(b"plain text"));
}
