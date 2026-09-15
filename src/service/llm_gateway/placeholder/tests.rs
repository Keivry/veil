#[test]
fn file_len_redline() {
    crate::test_support::file_len_under_800_or_split(
        "placeholder.rs",
        include_str!("../placeholder.rs"),
    );
    crate::test_support::file_len_under_800_or_split(
        "placeholder/tests.rs",
        include_str!("tests.rs"),
    );
}

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
    // E2 部分非法独立回退：`input` 合法注入保留，`instructions` 非法保持原值。
    let partial = serde_json::json!({"input":"hi","instructions":42});
    let out = inject_placeholder_prompt(
        &serde_json::to_string(&partial).unwrap(),
        prompt,
        Protocol::Responses,
    )
    .expect("合法字段注入须保留");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["input"].as_str().unwrap().contains(prompt));
    assert_eq!(v["instructions"], 42);
    // 双字段均非法整体回退。
    let both_bad = serde_json::json!({"input":42,"instructions":42});
    assert!(
        inject_placeholder_prompt(
            &serde_json::to_string(&both_bad).unwrap(),
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

#[test]
fn placeholder_responses_partial_illegal_keeps_valid() {
    let prompt = "PROMPT";
    // R5.1：`input` 合法 string 加 `instructions` 非法 number 时，
    // `input` 注入保留、`instructions` 原值不变。
    let body = serde_json::json!({"model":"m","input":"hello","instructions":42});
    let out = inject_placeholder_prompt(
        &serde_json::to_string(&body).unwrap(),
        prompt,
        Protocol::Responses,
    )
    .expect("部分合法须保留注入");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["input"].as_str().unwrap().contains("hello"));
    assert!(v["input"].as_str().unwrap().contains(prompt));
    assert_eq!(v["instructions"], 42);
    // 反向：`instructions` 合法、`input` 非法时同样独立。
    let rev = serde_json::json!({"input":42,"instructions":"be nice"});
    let out2 = inject_placeholder_prompt(
        &serde_json::to_string(&rev).unwrap(),
        prompt,
        Protocol::Responses,
    )
    .expect("反向部分合法须保留注入");
    let v2: Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(v2["input"], 42);
    assert!(v2["instructions"].as_str().unwrap().contains(prompt));
    // 双合法场景双字段均注入。
    let both = serde_json::json!({"input":"hi","instructions":"be nice"});
    let out3 = inject_placeholder_prompt(
        &serde_json::to_string(&both).unwrap(),
        prompt,
        Protocol::Responses,
    )
    .expect("双合法须注入");
    let v3: Value = serde_json::from_str(&out3).unwrap();
    assert!(v3["input"].as_str().unwrap().contains(prompt));
    assert!(v3["instructions"].as_str().unwrap().contains(prompt));
}

#[test]
fn placeholder_case_sensitive() {
    use crate::service::pii::detector::{cred_token_shape_re, pii_token_re};
    // 注入门：精确大小写前缀（无折叠）。
    assert!(has_placeholder_tokens(b"a __PII_1_ab12cd34__ b"));
    assert!(has_placeholder_tokens(b"a __VG_CRED_000123__ b"));
    for drift in [
        b"__pii_1_ab12cd34__".as_slice(),
        b"__Pii_1_ab12cd34__".as_slice(),
        b"__vg_cred_000123__".as_slice(),
        b"__Vg_Cred_000123__".as_slice(),
        b"__VG_cred_000123__".as_slice(),
    ] {
        assert!(
            !has_placeholder_tokens(drift),
            "漂移形不得触发注入门: {drift:?}"
        );
    }
    // 还原形态（pii_token_re/cred_token_shape_re）同为大小写敏感精确前缀。
    assert!(pii_token_re().is_match("__PII_1_ab12cd34__"));
    assert!(!pii_token_re().is_match("__pii_1_ab12cd34__"));
    assert!(!pii_token_re().is_match("__Pii_1_ab12cd34__"));
    assert!(cred_token_shape_re().is_match("__VG_CRED_000123__"));
    assert!(!cred_token_shape_re().is_match("__vg_cred_000123__"));
    assert!(!cred_token_shape_re().is_match("__VG_cred_000123__"));
}

#[test]
fn placeholder_case_drift() {
    use crate::service::{
        credential_vault::CredentialVault,
        pii::{PiiScope, detector::pii_token_re},
    };
    // 注入侧：大小写漂移 prefix 既不触发门，也不进入三条件注入链。
    let drift_pii = b"body __pii_1_ab12cd34__ tail";
    let drift_cred = b"body __vg_cred_000123__ tail";
    assert!(!has_placeholder_tokens(drift_pii));
    assert!(!has_placeholder_tokens(drift_cred));
    assert!(!should_inject_placeholders(
        true,
        true,
        has_placeholder_tokens(drift_pii)
    ));
    assert!(should_inject_placeholders(
        true,
        true,
        has_placeholder_tokens(b"__PII_1_ab12cd34__")
    ));
    // 还原侧：漂移形原样保留（大小写敏感，不做替换）。
    let vault = CredentialVault::new();
    assert_eq!(vault.restore("__vg_cred_000123__"), "__vg_cred_000123__");
    let scope = PiiScope::new();
    let tok = scope.register("13800138000", false).expect("注册须成功");
    assert!(pii_token_re().is_match(&tok));
    assert_eq!(scope.restore("__pii_1_ab12cd34__"), "__pii_1_ab12cd34__");
}

#[test]
fn x5_protocol_matrix_injection_stable_after_unreachable_block_removal() {
    const PROMPT: &str = "PROMPT";
    // Anthropic：system 存在（string/array）合并；缺失插入；非法形态拒绝且原体不变。
    let mut anthropic_str = serde_json::json!({"system":"你是助手"});
    assert!(placeholder_inject_obj(
        &mut anthropic_str,
        PROMPT,
        Protocol::Anthropic
    ));
    assert_eq!(
        anthropic_str["system"].as_str().unwrap(),
        format!("你是助手\n\n{PROMPT}")
    );
    let mut anthropic_arr = serde_json::json!({"system":[{"type":"text","text":"你是助手"}]});
    assert!(placeholder_inject_obj(
        &mut anthropic_arr,
        PROMPT,
        Protocol::Anthropic
    ));
    assert_eq!(
        anthropic_arr["system"][0]["text"].as_str().unwrap(),
        format!("你是助手\n\n{PROMPT}")
    );
    let mut anthropic_missing = serde_json::json!({"model":"claude"});
    assert!(placeholder_inject_obj(
        &mut anthropic_missing,
        PROMPT,
        Protocol::Anthropic
    ));
    assert_eq!(anthropic_missing["system"].as_str().unwrap(), PROMPT);
    let mut anthropic_invalid = serde_json::json!({"system":{"bad":true}});
    assert!(!placeholder_inject_obj(
        &mut anthropic_invalid,
        PROMPT,
        Protocol::Anthropic
    ));
    assert_eq!(
        anthropic_invalid,
        serde_json::json!({"system":{"bad":true}})
    );

    // Responses：input/instructions 独立注入、非法字段不连坐、双缺失拒绝。
    let mut resp_both = serde_json::json!({"input":"hi","instructions":"be nice"});
    assert!(placeholder_inject_obj(
        &mut resp_both,
        PROMPT,
        Protocol::Responses
    ));
    assert!(resp_both["input"].as_str().unwrap().contains(PROMPT));
    assert!(resp_both["instructions"].as_str().unwrap().contains(PROMPT));
    let mut resp_one_invalid = serde_json::json!({"input":42,"instructions":"be nice"});
    assert!(placeholder_inject_obj(
        &mut resp_one_invalid,
        PROMPT,
        Protocol::Responses
    ));
    assert_eq!(resp_one_invalid["input"], 42, "非法字段不得被改写");
    assert!(
        resp_one_invalid["instructions"]
            .as_str()
            .unwrap()
            .contains(PROMPT)
    );
    let mut resp_both_invalid = serde_json::json!({"input":42,"instructions":true});
    assert!(!placeholder_inject_obj(
        &mut resp_both_invalid,
        PROMPT,
        Protocol::Responses
    ));
    assert_eq!(
        resp_both_invalid,
        serde_json::json!({"input":42,"instructions":true})
    );

    // Chat：前插 system；NonDialog：schema 门禁拒绝（对象注入本体不识别该协议）。
    let mut chat = serde_json::json!({"messages":[{"role":"user","content":"hi"}]});
    assert!(placeholder_inject_obj(&mut chat, PROMPT, Protocol::Chat));
    assert_eq!(chat["messages"][0]["role"], "system");
    assert_eq!(chat["messages"][0]["content"].as_str().unwrap(), PROMPT);
    let nondialog = serde_json::json!({"messages":[{"role":"user","content":"hi"}]});
    assert!(!placeholder_schema_ok(&nondialog, Protocol::NonDialog));
    assert!(
        inject_placeholder_prompt(
            &serde_json::to_string(&nondialog).unwrap(),
            PROMPT,
            Protocol::NonDialog
        )
        .is_none()
    );
}
