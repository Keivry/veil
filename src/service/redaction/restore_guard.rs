//! 还原守卫共享纯逻辑（F-2/D-2）：流式帧路径（`frame_feed.rs`）与非流路径
//! （`nonstream.rs`）共用的「还原后 JSON 完整性」谓词，原两份逐字拷贝收敛至此。
//! 零 axum 依赖（仅 `serde_json` 与 `json_walk`），判定与 handler 职责解耦。

use {
    super::super::{
        credential_vault::{TOKEN_PREFIX, TOKEN_SUFFIX},
        json_walk::{jloads, strip_bom},
        pii::detector::PII_TOKEN_PREFIX,
    },
    serde_json::Value,
};

/// 还原守卫谓词（NLP-3/D12 + H2/D1）：`restored` 须可解析为 JSON，且当占位符帧的
/// 字符串值内嵌 stringified JSON 时，还原后内层仍须同构可解析（内层破损
/// fail-closed 不得被外层合法掩盖）。`placeholder_parsed` 为调用方已持有的占位符
/// 帧解析产物（ARH-2：避免同帧二次解析）；`None` 时内部解析，占位符不可解析则
/// 无内层参照、维持外层口径（返回 true）。
pub(crate) fn restore_guard_ok(
    restored: &str,
    placeholder: &str,
    placeholder_parsed: Option<&Value>,
) -> bool {
    let Ok(rv) = jloads(strip_bom(restored)) else {
        return false;
    };
    match placeholder_parsed {
        Some(pv) => inner_json_intact(pv, &rv),
        None => match jloads(strip_bom(placeholder)) {
            Ok(pv) => inner_json_intact(&pv, &rv),
            Err(_) => true,
        },
    }
}

/// R8-18/D6：键是否为**完整**占位符 token 形态——`__VG_CRED_` + ≥6 位数字
/// （mint 侧 `{n:06}` 随序号增长，故位数只增不减）+ `__`，
/// 或 `__PII_` + 数字序号 + `_` + 恰 8 位小写十六进制 + `__`。前缀相同但形态不完整
/// （如 `__VG_CRED_0001__`、`__PII_12_zzzzzzzz__`）不得作为配对依据。
fn is_token_shaped_key(k: &str) -> bool {
    if let Some(rest) = k.strip_prefix(TOKEN_PREFIX) {
        let Some(digits) = rest.strip_suffix(TOKEN_SUFFIX) else {
            return false;
        };
        return digits.len() >= 6 && digits.bytes().all(|b| b.is_ascii_digit());
    }
    if let Some(rest) = k.strip_prefix(PII_TOKEN_PREFIX) {
        let Some(body) = rest.strip_suffix(TOKEN_SUFFIX) else {
            return false;
        };
        let Some((seq, rand)) = body.split_once('_') else {
            return false;
        };
        return !seq.is_empty()
            && seq.bytes().all(|b| b.is_ascii_digit())
            && rand.len() == 8
            && rand.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    }
    false
}

/// RED-1：递归比对占位符帧与还原帧的字符串值。占位符字符串值若为
/// stringified JSON，则还原后仍须可解析为同构容器（内层破损 fail-closed）。
pub(crate) fn inner_json_intact(placeholder: &Value, restored: &Value) -> bool {
    match (placeholder, restored) {
        (Value::String(p), Value::String(r)) => {
            let pt = strip_bom(p).trim();
            if (pt.starts_with('{') || pt.starts_with('['))
                && let Ok(pv) = jloads(pt)
                && matches!(pv, Value::Object(_) | Value::Array(_))
            {
                return jloads(strip_bom(r).trim())
                    .ok()
                    .filter(|rv| matches!(rv, Value::Object(_) | Value::Array(_)))
                    .is_some_and(|rv| inner_json_intact(&pv, &rv));
            }
            true
        }
        (Value::Array(pa), Value::Array(ra)) => {
            pa.len() == ra.len() && pa.iter().zip(ra).all(|(p, r)| inner_json_intact(p, r))
        }
        (Value::Object(pm), Value::Object(rm)) => {
            // R8-18/D6：条目数恒等；同名键逐键递归；非同名键仅允许
            // 「占位符侧完整 token 形态 ↔ 还原侧新增键」一一配对（双射且与
            // 同名键集互补，故等价于计数相等 + 占位符侧全部 token 形态）。
            if pm.len() != rm.len() {
                return false;
            }
            let mut restored_only = 0usize;
            for (k, rv) in rm {
                match pm.get(k) {
                    Some(pv) => {
                        if !inner_json_intact(pv, rv) {
                            return false;
                        }
                    }
                    None => restored_only += 1,
                }
            }
            let placeholder_only: Vec<&str> = pm
                .keys()
                .filter(|k| !rm.contains_key(*k))
                .map(String::as_str)
                .collect();
            restored_only == placeholder_only.len()
                && placeholder_only.iter().all(|k| is_token_shaped_key(k))
        }
        // R8-18/D6：容器与非容器（Object↔String 等）类型漂移一律拒绝；标量
        // （Number/Bool/Null，还原不改写其类型）维持既有 `_ => true` 兜底口径。
        (Value::Object(_) | Value::Array(_), _) | (_, Value::Object(_) | Value::Array(_)) => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use {super::*, serde_json::json};

    #[test]
    fn restore_guard_ok_equivalence_frames_and_nonstream() {
        // F-2/D-2：帧路径（复用解析产物）与非流路径（内部解析）判定等价；
        // 内层 stringified JSON 破损 fail-closed。
        let placeholder = r#"{"arguments":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
        let intact = r#"{"arguments":"{\"k\":\"p@ss\"}"}"#;
        let broken = r#"{"arguments":"{\"k\":\"p@ss\"q\"}"}"#;
        let pv: Value = serde_json::from_str(placeholder).expect("占位符帧须可解析");
        for (restored, expect_ok) in [(intact, true), (broken, false), (placeholder, true)] {
            assert_eq!(
                restore_guard_ok(restored, placeholder, None),
                expect_ok,
                "非流路径（内部解析占位符）: {restored}"
            );
            assert_eq!(
                restore_guard_ok(restored, placeholder, Some(&pv)),
                expect_ok,
                "帧路径（复用解析产物）: {restored}"
            );
        }
        assert!(
            !restore_guard_ok("{not json", placeholder, None),
            "外层破损恒拒绝"
        );
        assert!(
            restore_guard_ok(r#"{"a":1}"#, "{not json", None),
            "占位符不可解析时无内层参照，维持外层口径"
        );
        assert!(
            restore_guard_ok("\u{feff}{\"a\":1}", "{not json", None),
            "BOM 前缀按帧路径口径剥离"
        );
    }

    #[test]
    fn restore_guard_bom_prefixed_valid_json_equivalent() {
        // R5-23/D1：BOM 前缀合法 JSON（外层与内层 stringified）判定与非 BOM 一致。
        let placeholder = r#"{"k":"__VG_CRED_000001__"}"#;
        let intact = r#"{"k":"secret"}"#;
        assert!(restore_guard_ok(intact, placeholder, None));
        assert!(restore_guard_ok(
            &format!("\u{feff}{intact}"),
            placeholder,
            None
        ));
        let placeholder_inner = r#"{"s":"{\"k\":\"__VG_CRED_000001__\"}"}"#;
        let restored_inner = r#"{"s":"{\"k\":\"p@ss\"}"}"#;
        assert!(restore_guard_ok(restored_inner, placeholder_inner, None));
        assert!(restore_guard_ok(
            &format!("\u{feff}{restored_inner}"),
            placeholder_inner,
            None
        ));
    }

    #[test]
    fn inner_json_intact_recursive_cases() {
        // R8-18/D6：键级还原（占位符键 → 明文键）在条目数相等、占位符侧为完整
        // token 形态、值与容器结构完好时接受；其余结构差异一律拒绝。
        // 正例：完整 token 键与还原侧新增明文键配对，值结构完好。
        assert!(inner_json_intact(
            &json!({"__VG_CRED_000001__": "v", "keep": [1, 2]}),
            &json!({"user_password": "v", "keep": [1, 2]})
        ));
        assert!(inner_json_intact(
            &json!({"__PII_12_ab12cd34__": {"k": 1}}),
            &json!({"email": {"k": 1}})
        ));
        assert!(inner_json_intact(&json!([1, 2]), &json!([1, 2])));
        // 正例：mint 序号 ≥1e6 后位数增长（`{n:06}`），仍属完整 token 形态。
        assert!(inner_json_intact(
            &json!({"__VG_CRED_1234567__": "v"}),
            &json!({"user_password": "v"})
        ));
        assert!(inner_json_intact(
            &json!({"s": "{\"k\": 1}"}),
            &json!({"s": "{\"k\": 1}"})
        ));
        // 负例：还原侧多一非 token 键（条目数不等；既有断言 `true` 按 D6 改判 `false`）。
        assert!(!inner_json_intact(
            &json!({"a": 1}),
            &json!({"a": 1, "b": 2})
        ));
        // 负例：非 token 形态的键改名（无配对依据）。
        assert!(!inner_json_intact(&json!({"a": 1}), &json!({"b": 1})));
        // 负例：条目数不等即便占位符侧为完整 token 形态。
        assert!(!inner_json_intact(
            &json!({"__VG_CRED_000001__": 1}),
            &json!({"a": 1, "b": 2})
        ));
        // 负例：前缀相同但非完整形态（6 位数字不满足）不得配对。
        assert!(!inner_json_intact(
            &json!({"__VG_CRED_0001__": 1}),
            &json!({"a": 1})
        ));
        // 负例：数组长度不等；内层 stringified JSON 破损；Object↔String 类型漂移。
        assert!(!inner_json_intact(&json!([1, 2]), &json!([1])));
        assert!(!inner_json_intact(
            &json!({"s": "{\"k\": 1}"}),
            &json!({"s": "{\"k\": }"})
        ));
        assert!(!inner_json_intact(&json!({"a": 1}), &json!("{\"a\": 1}")));
    }
}
