#[test]
fn file_len_under_800_or_split() {
    // 红线看护（口径=文件总行，含测试与注释，见 veil-arch-file-size-closeout / hygiene-round4）：
    // 超 800 即失败，须按测试外迁模板拆分，不得只改数字放行。
    const MAIN_SRC: &str = include_str!("../placeholder.rs");
    let main_lines = MAIN_SRC.lines().count();
    assert!(
        main_lines <= 800,
        "placeholder.rs {main_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
    );
    const TESTS_SRC: &str = include_str!("tests.rs");
    let tests_lines = TESTS_SRC.lines().count();
    assert!(
        tests_lines <= 800,
        "placeholder/tests.rs {tests_lines} 行超 800 红线：须拆分（见 veil-arch-file-size-closeout / hygiene-round4）"
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
