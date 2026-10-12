//! `json_walk` 单测（自 `json_walk.rs` 外迁；测试名与断言不变）。

use super::*;

#[test]
fn b6_bom_depth_wrappers_nested() {
    // BOM 剥离、depth 超限截断不崩、三包装器逐项解析 + 嵌套包装器。
    assert_eq!(strip_bom("\u{feff}abc"), "abc");
    assert_eq!(strip_bom("\u{feff}\u{feff}abc"), "abc");
    assert_eq!(strip_bom("abc"), "abc");
    // 三包装器逐项：对象 / 数组 / 字符串叶。
    let out = process_text(r#"{"w":{"x":"v"}}"#, &mut |s| s.to_string(), DEPTH_LIMIT);
    let v: serde_json::Value =
        serde_json::from_str(strip_bom(&out)).expect("对象包装器输出须合法 JSON");
    assert_eq!(v["w"]["x"], "v");
    let out = process_text(r#"[{"x":"v"}]"#, &mut |s| s.to_string(), DEPTH_LIMIT);
    let v: serde_json::Value =
        serde_json::from_str(strip_bom(&out)).expect("数组包装器输出须合法 JSON");
    assert_eq!(v[0]["x"], "v");
    // 嵌套包装器：串中串中串逐层还原且转义安全。
    let inner = serde_json::to_string(&serde_json::json!({"k": "p@ss\"q"})).unwrap();
    let mid = serde_json::to_string(&serde_json::json!({"args": inner})).unwrap();
    let outer = serde_json::to_string(&serde_json::json!({"tool": "x", "nested": mid})).unwrap();
    let out = process_text(&outer, &mut |s| s.replace("p@ss\"q", "MASKED"), DEPTH_LIMIT);
    let v: serde_json::Value = serde_json::from_str(strip_bom(&out)).unwrap();
    let mid_v: serde_json::Value = serde_json::from_str(v["nested"].as_str().unwrap()).unwrap();
    let inner_v: serde_json::Value = serde_json::from_str(mid_v["args"].as_str().unwrap()).unwrap();
    assert_eq!(inner_v["k"], "MASKED");
    // 超深截断不崩：输出仍为合法 JSON。
    let mut s = "leaf".to_string();
    for _ in 0..(DEPTH_LIMIT + 3) {
        s = serde_json::to_string(&serde_json::json!({"w": s})).unwrap();
    }
    let out = process_text(&s, &mut |x| x.to_string(), DEPTH_LIMIT);
    let _v: serde_json::Value = serde_json::from_str(strip_bom(&out)).expect("超深输出须合法 JSON");
    assert_eq!(out, s, "恒等叶超深截断须保持原值");
}

#[test]
fn nested_stringified_json_recurses_with_special_chars_safe() {
    // tool_calls.arguments 场景：内层含 p@ss"quote 与 \u 转义。
    let text = r#"{"tool":"x","arguments":"{\"key\":\"p@ss\\\"quote\",\"u\":\"\\u0031\"}"}"#;
    let out = process_text(text, &mut |s| s.replace("p@ss\"quote", "MASKED"), 5);
    let v: serde_json::Value = serde_json::from_str(&out).expect("输出必须仍是合法 JSON");
    let inner: serde_json::Value = serde_json::from_str(v["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(inner["key"], "MASKED");
    // \u0031 解码为 "1"，替换后结构完好。
    assert_eq!(inner["u"], "1");
}

#[test]
fn top_level_walk_leaves_strings_only() {
    let text = r#"{"a":"hello","n":42,"b":true,"z":null}"#;
    let out = process_text(
        text,
        &mut |s| {
            if s == "hello" { "world".to_string() } else { s }
        },
        5,
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["a"], "world");
    assert_eq!(v["n"], 42);
    assert_eq!(v["b"], true);
    assert!(v["z"].is_null());
}

#[test]
fn bom_stripped_parses_normally() {
    let text = "\u{feff}{\"a\":\"hi\"}";
    let out = process_text(
        text,
        &mut |s| {
            if s == "hi" { "yo".to_string() } else { s }
        },
        5,
    );
    let v: serde_json::Value = serde_json::from_str(strip_bom(&out)).unwrap();
    assert_eq!(v["a"], "yo");
}

#[test]
fn oversize_input_falls_back_to_plain() {
    let big = format!("{{\"a\":\"{}\"}}", "x".repeat(SCAN_INPUT_LIMIT));
    let out = process_text(&big, &mut |s| s.replace('x', "y"), 5);
    // plain 路径：整体替换生效且不抛错。
    assert!(out.contains('y'));
}

#[test]
fn overdeep_nesting_falls_back_to_plain() {
    // 7 层 stringified 嵌套：depth=5 处的叶走 plain。
    let mut s = "deep_value".to_string();
    for _ in 0..7 {
        let v = serde_json::json!({"w": s});
        s = serde_json::to_string(&v).unwrap();
    }
    let out = process_text(&s, &mut |x| x.replace("deep_value", "MASKED"), 5);
    let v: serde_json::Value =
        serde_json::from_str(strip_bom(&out)).expect("超深回退输出须合法 JSON");
    assert!(v.is_object(), "顶层结构须保持对象: {out}");
    assert!(out.contains("MASKED"), "超深叶须走 plain 替换: {out}");
    assert!(!out.contains("deep_value"), "替换后源值不得残留: {out}");
}

#[test]
fn deep_container_guard_no_crash_falls_back_verbatim() {
    // 500 层裸数组：serde 解析限层失败走 plain 回退，不崩。
    let mut v = serde_json::json!("leaf");
    for _ in 0..500 {
        v = serde_json::json!([v]);
    }
    let text = serde_json::to_string(&v).unwrap();
    let out = process_text(&text, &mut |s| s.replace("leaf", "MASKED"), 5);
    assert!(!out.is_empty());
    // 程序化深 Value 直走 walk：超限子树原样保留，不栈溢出。
    let walked = json_walk(v, &mut |s| s, 5, 0);
    assert!(walked.is_array());
    // 守卫边界内正常遍历不受影响。
    let shallow = serde_json::json!({"a": [{"b": "leaf"}]});
    let out2 = json_walk(shallow, &mut |s| s.replace("leaf", "MASKED"), 5, 0);
    assert_eq!(out2["a"][0]["b"], "MASKED");
}

#[test]
fn non_json_goes_plain() {
    let out = process_text("plain p@ss text", &mut |s| s.replace("p@ss", "X"), 5);
    assert_eq!(out, "plain X text");
}

#[test]
fn three_wrappers_nasty_values_stay_valid_json() {
    // 含引号密码、
    // Unicode 转义、嵌套 stringified JSON、数组成员经 JSON-aware 路径后
    // 输出恒可解析且还原值一致（token 脱敏/还原 + LLM 响应还原三条）。
    let nasty = r#"{"pwd":"p@ss\"quote","uni":"\u0061\u0031\u0062","nested":"{\"k\":\"v1\"}","list":["x","y"]}"#;
    // ① token 脱敏：密码值替换为凭据 token。
    let redacted = process_text(
        nasty,
        &mut |s| s.replace("p@ss\"quote", "__CRED_000001__"),
        DEPTH_LIMIT,
    );
    let rv: serde_json::Value = serde_json::from_str(&redacted).expect("脱敏输出须合法 JSON");
    assert_eq!(rv["pwd"], "__CRED_000001__");
    assert_eq!(rv["uni"], "a1b", "Unicode 转义须解码正确");
    assert_eq!(rv["list"][0], "x");
    let nested: serde_json::Value =
        serde_json::from_str(rv["nested"].as_str().expect("nested 为字符串"))
            .expect("嵌套 JSON 须完好");
    assert_eq!(nested["k"], "v1");

    // ①b token 还原：token → 明文，字段值一致。
    let restored = process_text(
        &redacted,
        &mut |s| s.replace("__CRED_000001__", "p@ss\"quote"),
        DEPTH_LIMIT,
    );
    let sv: serde_json::Value = serde_json::from_str(&restored).expect("还原输出须合法 JSON");
    assert_eq!(sv["pwd"], "p@ss\"quote");

    // ③ LLM 响应还原：token 出现在 JSON 字符串内被还原。
    let frame = r#"{"msg":"hi __CRED_000001__"}"#;
    let out = process_text(
        frame,
        &mut |s| s.replace("__CRED_000001__", "p@ss\"quote"),
        DEPTH_LIMIT,
    );
    let ov: serde_json::Value = serde_json::from_str(&out).expect("响应输出须合法 JSON");
    assert_eq!(ov["msg"], "hi p@ss\"quote");
}

#[test]
fn json_walk_key_pii_masked_and_parseable() {
    // 键位 PII 同 leaf 口径替换，值不变、输出仍可 jloads。
    let text = r#"{"13800138000":"x"}"#;
    let out = process_text(
        text,
        &mut |s| s.replace("13800138000", "__PII_1_abcdef__"),
        DEPTH_LIMIT,
    );
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("键位替换后须为合法 JSON");
    assert_eq!(v["__PII_1_abcdef__"], "x");
    assert!(!out.contains("13800138000"), "键位明文不得残留: {out}");
}

#[test]
fn json_walk_key_collision_with_original_falls_back() {
    // 替换后键与原始键同名时保留原键（两成员均在，不合并、不丢键）。
    let text = r#"{"a":"1","b":"2"}"#;
    let out = process_text(
        text,
        &mut |s| if s == "a" { "b".to_string() } else { s },
        DEPTH_LIMIT,
    );
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("输出须合法 JSON");
    assert_eq!(v["a"], "1", "碰撞回退须保留原键: {out}");
    assert_eq!(v["b"], "2");
    assert_eq!(v.as_object().expect("对象").len(), 2, "不得合并成员: {out}");
}

#[test]
fn json_walk_key_collision_with_chosen_falls_back() {
    // 替换后键与此前已选定的替换键同名时保留原键（先到者胜、后到回退）。
    let text = r#"{"x":"1","y":"2"}"#;
    let out = process_text(
        text,
        &mut |s| {
            if s == "x" || s == "y" {
                "z".to_string()
            } else {
                s
            }
        },
        DEPTH_LIMIT,
    );
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("输出须合法 JSON");
    assert_eq!(v["z"], "1", "先到替换键胜出: {out}");
    assert_eq!(v["y"], "2", "后到碰撞回退原键: {out}");
    assert_eq!(v.as_object().expect("对象").len(), 2, "不得丢键: {out}");
}

#[test]
fn json_walk_key_substring_scan_and_plain_leaf() {
    // 键串内嵌敏感子串被子串扫描替换；键串按纯字符串 leaf 处理，
    // MUST NOT 做 stringified-JSON 递归展开（整串精确匹配叶可见键原文）。
    let text = r#"{"prefix-13812345678-suffix":"v"}"#;
    let out = process_text(text, &mut |s| s.replace("13812345678", "MASK"), DEPTH_LIMIT);
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("输出须合法 JSON");
    assert_eq!(v["prefix-MASK-suffix"], "v");

    let key_text = r#"{"phone":"13812345678"}"#;
    let nested_key = serde_json::json!({ key_text: "v" }).to_string();
    let out = process_text(
        &nested_key,
        &mut |s| {
            if s == "13812345678" {
                "MASK".to_string()
            } else {
                s
            }
        },
        DEPTH_LIMIT,
    );
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("输出须合法 JSON");
    assert_eq!(
        v[key_text], "v",
        "键串 MUST NOT 被 stringified-JSON 递归展开: {out}"
    );
}

#[test]
fn json_walk_key_token_shape_preserved() {
    // 本身即内部 token 形态的键由 leaf 守卫跳过、原样保留。
    let text = r#"{"__CRED_000001__":"x","k":"13812345678"}"#;
    let out = process_text(
        text,
        &mut |s| {
            if s.starts_with("__CRED_") || s.starts_with("__PII_") {
                s
            } else {
                s.replace("13812345678", "MASK")
            }
        },
        DEPTH_LIMIT,
    );
    let v: serde_json::Value = jloads(strip_bom(&out)).expect("输出须合法 JSON");
    assert_eq!(v["__CRED_000001__"], "x", "token 形态键须原样保留");
    assert_eq!(v["k"], "MASK");
}

#[test]
fn json_walk_key_roundtrip_restores_content_and_keys() {
    // 键位替换往返（redact→restore）后 JSON 内容与键集合一致。
    let original = r#"{"13800138000":{"contact":"13800138000"},"ok":1}"#;
    let redacted = process_text(
        original,
        &mut |s| s.replace("13800138000", "__PII_9_deadbeef__"),
        DEPTH_LIMIT,
    );
    assert!(!redacted.contains("13800138000"), "脱敏后不得残留明文");
    let restored = process_text(
        &redacted,
        &mut |s| s.replace("__PII_9_deadbeef__", "13800138000"),
        DEPTH_LIMIT,
    );
    let a: serde_json::Value = jloads(original).expect("原文合法");
    let b: serde_json::Value = jloads(&restored).expect("还原输出须合法 JSON");
    assert_eq!(a, b, "往返后内容与键集合须一致: {restored}");
}

#[test]
fn validate_roundtrip_contract() {
    // 三校验器共用契约（Rust 单实现 `validate_json_roundtrip`）：
    // 合法原文 + 非法输出 → 回退原文；非 JSON 原文 + 任意输出 → 输出。
    let legal = r#"{"a":1}"#;
    let bad = r#"{"a":}"#;
    assert_eq!(validate_json_roundtrip(legal, bad, "t"), legal);
    assert_eq!(
        validate_json_roundtrip(legal, r#"{"a":2}"#, "t"),
        r#"{"a":2}"#
    );
    assert_eq!(validate_json_roundtrip("plain", bad, "t"), bad);
    assert_eq!(validate_json_roundtrip("plain text", "xxx", "t"), "xxx");
}

#[test]
fn roundtrip_broken_falls_back_to_original() {
    // 字符串叶替换恒产生合法 JSON；roundtrip 校验针对非法输出直测。
    let original = r#"{"a":1}"#;
    assert_eq!(
        validate_json_roundtrip(original, r#"{"a":}"#, "t"),
        original
    );
    assert_eq!(
        validate_json_roundtrip(original, r#"{"a":2}"#, "t"),
        r#"{"a":2}"#
    );
    // 非 JSON 原文不触发校验。
    assert_eq!(validate_json_roundtrip("plain", "xxx", "t"), "xxx");
}
