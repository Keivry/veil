//! json-walk（§3.4）：嵌套 stringified JSON 递归、顶层叶 loads→walk→dumps、
//! BOM 剥离、`p@ss"quote` / `\u` 转义安全、len>1M / depth>5 守卫回退 plain、
//! roundtrip 失败回退原串。
//!
//! 口径对标原仓 `utils/json_walk.py`：
//! - `depth` 仅统计 `str→inner` 嵌套 JSON 递归层数，dict/list 裸递归不计数；
//! - `dumps` 用 `serde_json::to_string`（紧凑分隔符，不转义 CJK， 等价 `ensure_ascii=False,
//!   separators=(',',':')`）；
//! - 转义安全靠 `loads` 解码成串后处理，MUST NOT 字符串级切分 `\u`；
//! - 超限（len>1M）/ 超深（depth>5）回退 plain，roundtrip 破坏回退原串。

/// 单次扫描输入上限（字节），超限走 plain 回退。
pub const SCAN_INPUT_LIMIT: usize = 1_048_576;
/// `str→inner` 嵌套 JSON 递归深度上限。
pub const DEPTH_LIMIT: u32 = 5;
/// 裸容器（dict/list）递归深度上限（§2.7 深炸弹守卫）：
/// `depth` 仅计 `str→inner` 嵌套层数，裸容器层数另计；
/// 超限子树回退原样（fallback-to-original），不栈溢出。
/// 输入过长（`len > SCAN_INPUT_LIMIT`）同样回退 plain 处理；
/// 结构破坏时 [`validate_json_roundtrip`] 回退原串。
pub const CONTAINER_NEST_LIMIT: u32 = 128;

/// 剥离前导 BOM（`\ufeff`，等价 `lstrip('\ufeff')`）。
pub fn strip_bom(s: &str) -> &str { s.trim_start_matches('\u{feff}') }

/// 解析 JSON 文本（BOM 已剥离由调用方保证）。
pub fn jloads(s: &str) -> serde_json::Result<serde_json::Value> { serde_json::from_str(s) }

/// 回写 JSON（紧凑分隔符，不转义 CJK）。
pub fn jdumps(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// json-aware 后置校验：原文本是合法 JSON（object/array）而输出不是时，
/// 回退到原始文本，保证下游不收到 `JSONDecodeError`。
pub fn validate_json_roundtrip(original: &str, output: &str, _label: &str) -> String {
    let stripped = strip_bom(original).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return output.to_string();
    }
    if jloads(strip_bom(original)).is_err() {
        return output.to_string();
    }
    if jloads(strip_bom(output)).is_ok() {
        output.to_string()
    } else {
        tracing::warn!("json-walk roundtrip 破坏，已回退原串");
        original.to_string()
    }
}

/// 同步 walk：dict/list 递归（不增加 `depth`），str 叶调 `leaf`。
///
/// str 叶若本身为 JSON 文本（剥 BOM 后 trim 再判 `{` / `[`，
/// 且可解析为 object/array），则对内层同走 walk→dumps，失败回退 plain；
/// `depth > DEPTH_LIMIT` 时直接 plain 处理该叶。
pub fn json_walk(
    value: serde_json::Value,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
) -> serde_json::Value {
    json_walk_nested(value, leaf, depth_limit, depth, 0)
}

/// 裸容器递归本体：dict/list 层数超 `CONTAINER_NEST_LIMIT` 时该子树
/// 原样返回（fallback-to-original），防恶意深嵌套栈溢出。
fn json_walk_nested(
    value: serde_json::Value,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
    nest: u32,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(walk_string_leaf(s, leaf, depth_limit, depth))
        }
        serde_json::Value::Array(items) => {
            if nest >= CONTAINER_NEST_LIMIT {
                return serde_json::Value::Array(items);
            }
            serde_json::Value::Array(
                items
                    .into_iter()
                    .map(|v| json_walk_nested(v, leaf, depth_limit, depth, nest + 1))
                    .collect(),
            )
        }
        serde_json::Value::Object(map) => {
            if nest >= CONTAINER_NEST_LIMIT {
                return serde_json::Value::Object(map);
            }
            serde_json::Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, json_walk_nested(v, leaf, depth_limit, depth, nest + 1)))
                    .collect(),
            )
        }
        other => other,
    }
}

fn walk_string_leaf(
    s: String,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
    depth: u32,
) -> String {
    if depth > depth_limit {
        return leaf(s);
    }
    let inner_stripped = strip_bom(&s).trim();
    if (inner_stripped.starts_with('{') || inner_stripped.starts_with('['))
        && let Ok(inner) = jloads(inner_stripped)
        && matches!(
            inner,
            serde_json::Value::Object(_) | serde_json::Value::Array(_)
        )
    {
        let walked = json_walk(inner, leaf, depth_limit, depth + 1);
        let out = jdumps(&walked);
        // 内层合法而回写非法时回退该叶原串。
        let checked = validate_json_roundtrip(inner_stripped, &out, "json_walk");
        if checked == out {
            return out;
        }
        return s;
    }
    leaf(s)
}

/// 顶层入口：JSON 文本走 loads→walk→dumps，非 JSON / 解析失败 / 超限回退 plain。
///
/// - `text.len() > SCAN_INPUT_LIMIT` 直接 plain（不解析）；»MUST NOT 字符串级切分 `\u`«：
///   本函数永不手切转义，一律经 `loads` 解码成串后处理。
pub fn process_text(
    text: &str,
    leaf: &mut dyn FnMut(String) -> String,
    depth_limit: u32,
) -> String {
    if text.len() > SCAN_INPUT_LIMIT {
        return leaf(text.to_string());
    }
    let stripped = strip_bom(text).trim_start();
    if !(stripped.starts_with('{') || stripped.starts_with('[')) {
        return leaf(text.to_string());
    }
    let obj = match jloads(strip_bom(text)) {
        Ok(v) => v,
        Err(_) => return leaf(text.to_string()),
    };
    // 仅 object/array 走 walk，其余标量原样 plain。
    if !matches!(
        obj,
        serde_json::Value::Object(_) | serde_json::Value::Array(_)
    ) {
        return leaf(text.to_string());
    }
    let walked = json_walk(obj, leaf, depth_limit, 0);
    let out = jdumps(&walked);
    validate_json_roundtrip(text, &out, "json_walk")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b6_bom_depth_wrappers_nested() {
        // B6.2：BOM 剥离、depth 超限截断不崩、三包装器逐项解析 + 嵌套包装器。
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
        let outer =
            serde_json::to_string(&serde_json::json!({"tool": "x", "nested": mid})).unwrap();
        let out = process_text(&outer, &mut |s| s.replace("p@ss\"q", "MASKED"), DEPTH_LIMIT);
        let v: serde_json::Value = serde_json::from_str(strip_bom(&out)).unwrap();
        let mid_v: serde_json::Value = serde_json::from_str(v["nested"].as_str().unwrap()).unwrap();
        let inner_v: serde_json::Value =
            serde_json::from_str(mid_v["args"].as_str().unwrap()).unwrap();
        assert_eq!(inner_v["k"], "MASKED");
        // 超深截断不崩：输出仍为合法 JSON。
        let mut s = "leaf".to_string();
        for _ in 0..(DEPTH_LIMIT + 3) {
            s = serde_json::to_string(&serde_json::json!({"w": s})).unwrap();
        }
        let out = process_text(&s, &mut |x| x.to_string(), DEPTH_LIMIT);
        let _v: serde_json::Value =
            serde_json::from_str(strip_bom(&out)).expect("超深输出须合法 JSON");
        assert_eq!(out, s, "恒等叶超深截断须保持原值");
    }

    #[test]
    fn nested_stringified_json_recurses_with_special_chars_safe() {
        // tool_calls.arguments 场景：内层含 p@ss"quote 与 \u 转义。
        let text = r#"{"tool":"x","arguments":"{\"key\":\"p@ss\\\"quote\",\"u\":\"\\u0031\"}"}"#;
        let out = process_text(text, &mut |s| s.replace("p@ss\"quote", "MASKED"), 5);
        let v: serde_json::Value = serde_json::from_str(&out).expect("输出必须仍是合法 JSON");
        let inner: serde_json::Value =
            serde_json::from_str(v["arguments"].as_str().unwrap()).unwrap();
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
        // G1.2 对照 Python `tests/vault_stable_test.py:298-342`：含引号密码、
        // Unicode 转义、嵌套 stringified JSON、数组成员经 JSON-aware 路径后
        // 输出恒可解析且还原值一致（token 脱敏/还原 + LLM 响应还原三条）。
        let nasty = r#"{"pwd":"p@ss\"quote","uni":"\u0061\u0031\u0062","nested":"{\"k\":\"v1\"}","list":["x","y"]}"#;
        // ① token 脱敏：密码值替换为凭据 token。
        let redacted = process_text(
            nasty,
            &mut |s| s.replace("p@ss\"quote", "__VG_CRED_000001__"),
            DEPTH_LIMIT,
        );
        let rv: serde_json::Value = serde_json::from_str(&redacted).expect("脱敏输出须合法 JSON");
        assert_eq!(rv["pwd"], "__VG_CRED_000001__");
        assert_eq!(rv["uni"], "a1b", "Unicode 转义须解码正确");
        assert_eq!(rv["list"][0], "x");
        let nested: serde_json::Value =
            serde_json::from_str(rv["nested"].as_str().expect("nested 为字符串"))
                .expect("嵌套 JSON 须完好");
        assert_eq!(nested["k"], "v1");

        // ①b token 还原：token → 明文，字段值一致。
        let restored = process_text(
            &redacted,
            &mut |s| s.replace("__VG_CRED_000001__", "p@ss\"quote"),
            DEPTH_LIMIT,
        );
        let sv: serde_json::Value = serde_json::from_str(&restored).expect("还原输出须合法 JSON");
        assert_eq!(sv["pwd"], "p@ss\"quote");

        // ③ LLM 响应还原：token 出现在 JSON 字符串内被还原。
        let frame = r#"{"msg":"hi __VG_CRED_000001__"}"#;
        let out = process_text(
            frame,
            &mut |s| s.replace("__VG_CRED_000001__", "p@ss\"quote"),
            DEPTH_LIMIT,
        );
        let ov: serde_json::Value = serde_json::from_str(&out).expect("响应输出须合法 JSON");
        assert_eq!(ov["msg"], "hi p@ss\"quote");
    }

    #[test]
    fn validate_roundtrip_contract() {
        // G1.3 三校验器共用契约（Rust 单实现 `validate_json_roundtrip`）：
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
}
