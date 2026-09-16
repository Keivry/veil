//! 还原守卫共享纯逻辑（F-2/D-2）：流式帧路径（`frame_feed.rs`）与非流路径
//! （`nonstream.rs`）共用的「还原后 JSON 完整性」谓词，原两份逐字拷贝收敛至此。
//! 零 axum 依赖（仅 `serde_json` 与 `json_walk`），判定与 handler 职责解耦。

use {super::super::json_walk::strip_bom, serde_json::Value};

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
    let Ok(rv) = serde_json::from_str::<Value>(strip_bom(restored)) else {
        return false;
    };
    match placeholder_parsed {
        Some(pv) => inner_json_intact(pv, &rv),
        None => match serde_json::from_str::<Value>(strip_bom(placeholder)) {
            Ok(pv) => inner_json_intact(&pv, &rv),
            Err(_) => true,
        },
    }
}

/// RED-1：递归比对占位符帧与还原帧的字符串值。占位符字符串值若为
/// stringified JSON，则还原后仍须可解析为同构容器（内层破损 fail-closed）。
pub(crate) fn inner_json_intact(placeholder: &Value, restored: &Value) -> bool {
    match (placeholder, restored) {
        (Value::String(p), Value::String(r)) => {
            let pt = strip_bom(p).trim();
            if (pt.starts_with('{') || pt.starts_with('['))
                && let Ok(pv) = serde_json::from_str::<Value>(pt)
                && matches!(pv, Value::Object(_) | Value::Array(_))
            {
                return serde_json::from_str::<Value>(strip_bom(r).trim())
                    .ok()
                    .filter(|rv| matches!(rv, Value::Object(_) | Value::Array(_)))
                    .is_some_and(|rv| inner_json_intact(&pv, &rv));
            }
            true
        }
        (Value::Array(pa), Value::Array(ra)) => {
            pa.len() == ra.len() && pa.iter().zip(ra).all(|(p, r)| inner_json_intact(p, r))
        }
        (Value::Object(pm), Value::Object(rm)) => pm
            .iter()
            .all(|(k, pv)| rm.get(k).is_some_and(|rv| inner_json_intact(pv, rv))),
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
    fn inner_json_intact_recursive_cases() {
        assert!(inner_json_intact(
            &json!({"a": 1}),
            &json!({"a": 1, "b": 2})
        ));
        assert!(!inner_json_intact(&json!({"a": 1}), &json!({"b": 1})));
        assert!(!inner_json_intact(&json!([1, 2]), &json!([1])));
        assert!(inner_json_intact(&json!([1, 2]), &json!([1, 2])));
        assert!(!inner_json_intact(
            &json!({"s": "{\"k\": 1}"}),
            &json!({"s": "{\"k\": }"})
        ));
        assert!(inner_json_intact(
            &json!({"s": "{\"k\": 1}"}),
            &json!({"s": "{\"k\": 1}"})
        ));
    }
}
