//! `trace` 纯函数单测（由 `trace.rs` 以 `#[cfg(test)] mod tests;` 门控声明）：
//! Responses 嵌套结束原因、超长文本叶子预算截断与摘要长度上界。

use {
    super::{
        SUMMARY_MAX_CHARS,
        SUMMARY_TEXT_CAP,
        finish_reason_of,
        project_summary,
        push_text_leaves,
    },
    crate::service::llm_gateway::Protocol,
    serde_json::{Value, json},
};

#[test]
fn finish_reason_reads_responses_stream_envelope() {
    // 流式 `response.completed`：`status` 位于 `response` 信封内，顶层无该键。
    let completed = json!({
        "type": "response.completed",
        "response": {"status": "completed", "incomplete_details": null},
    });
    assert_eq!(
        finish_reason_of(Protocol::Responses, &completed).as_deref(),
        Some("completed")
    );
    // `response.incomplete`：`incomplete_details.reason` 优先于 `status`。
    let incomplete = json!({
        "type": "response.incomplete",
        "response": {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
        },
    });
    assert_eq!(
        finish_reason_of(Protocol::Responses, &incomplete).as_deref(),
        Some("max_output_tokens")
    );
    // 非流响应体：字段仍在顶层，既有口径不变。
    assert_eq!(
        finish_reason_of(
            Protocol::Responses,
            &json!({"status": "completed", "incomplete_details": null})
        )
        .as_deref(),
        Some("completed")
    );
}

#[test]
fn oversized_text_leaf_is_truncated_to_budget() {
    // 单个 10MB 叶子不得整段进入中间串：入 `out` 的长度恒 ≤ 预算。
    let mut out = String::new();
    push_text_leaves(&Value::String("x".repeat(10 * 1024 * 1024)), &mut out);
    assert_eq!(out.len(), SUMMARY_TEXT_CAP, "单叶子须截断到预算上限");
}

#[test]
fn multibyte_leaf_truncates_on_char_boundary() {
    // 3 字节码点使预算尾端落在码点中间：回退到边界即可，不得 panic。
    let mut out = String::new();
    push_text_leaves(&Value::String("汉".repeat(SUMMARY_TEXT_CAP)), &mut out);
    assert!(out.len() <= SUMMARY_TEXT_CAP, "累计长度须 ≤ 预算");
    assert!(out.chars().all(|c| c == '汉'), "不得切出半个码点");
}

#[test]
fn summary_with_huge_leaf_stays_within_limit() {
    let body = json!({
        "model": "m",
        "messages": [{"role": "user", "content": "y".repeat(10 * 1024 * 1024)}],
    });
    let summary = project_summary(Some(&body)).expect("须产出摘要");
    assert!(
        summary.chars().count() <= SUMMARY_MAX_CHARS,
        "摘要长度须 ≤{SUMMARY_MAX_CHARS}: {}",
        summary.chars().count()
    );
}
