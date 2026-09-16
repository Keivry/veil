//! Responses 工具类型派生面（B-2 抽取）：item 类型与 delta 事件类型 → 派生工具名，
//! 供 `tool` 模块的 Responses 提取臂与非流 `output[]` 路径复用（流/非流同名同结论）。

use {
    super::tool::{ToolCall, retrieval_args, retrieval_tool_name, synth_tool_id_with},
    serde_json::Value,
};

/// RED-4：Responses 四类工具 delta 事件 → 派生工具名（流/非流统一，对齐 Python
/// `_llm.py:783-791` 将四者统一归 `function_call_arguments` 审计路径）；B 新增
/// computer 分支（`contains`）兼容 `computer_call`/`computer_call_output`/
/// `computer_use_preview` 型 delta 事件，属 DEFENSIVE 覆盖（无现行上游样本）。
pub(crate) fn responses_derived_tool_kind(ev_type: &str) -> Option<&'static str> {
    if ev_type.contains("code_interpreter_call_code") {
        Some("code_interpreter")
    } else if ev_type.contains("shell_call_command") {
        Some("shell")
    } else if ev_type.contains("mcp_call_arguments") {
        Some("mcp")
    } else if ev_type.contains("custom_tool_call_input") {
        Some("custom_tool")
    } else if ev_type.contains("computer") {
        Some("computer")
    } else {
        None
    }
}

/// RSP-6/2.30 + A/M-1：`response.output_item.done` 与非流 `output[]` 的非
/// function_call 工具 item 类型 → 派生工具名，覆盖内置工具（与
/// [`responses_derived_tool_kind`] 的 delta 路径同名，两路径经
/// [`derived_item_tool_call`] 同一实现同结论）；B 新增 computer 分支。
pub(crate) fn responses_item_tool_name(item_type: &str) -> Option<&'static str> {
    if item_type.contains("code_interpreter") {
        Some("code_interpreter")
    } else if item_type.contains("shell") {
        Some("shell")
    } else if item_type.contains("mcp") {
        Some("mcp")
    } else if item_type.contains("computer") {
        Some("computer")
    } else if item_type.contains("custom_tool") {
        Some("custom_tool")
    } else {
        None
    }
}

/// A/M-1 + G：Responses 非 function 工具条目（`response.output_item.done` 与非流
/// `output[]` 两路径共用）→ `ToolCall`：名由 `item.name` 优先、`responses_item_tool_name`
/// 或检索名派生；参数按 item-done 口径三级回退（`["arguments","code","command","input"]`
/// → [`retrieval_args`] → `item.action` 整体序列化）。两路径经同一实现保证同结论
/// （parity 测试 `responses_output_stream_nonstream_parity` 锁定）。
/// 无派生名且非检索类型时返回 `None`，function/custom 等形态由调用方既有路径处理。
pub(crate) fn derived_item_tool_call(
    emit_warn: bool,
    bucket: u32,
    item: &Value,
    type_str: &str,
) -> Option<ToolCall> {
    let derived = responses_item_tool_name(type_str);
    let retrieval = retrieval_tool_name(type_str);
    if derived.is_none() && retrieval.is_none() {
        return None;
    }
    let mut args = ["arguments", "code", "command", "input"]
        .iter()
        .find_map(|k| item.get(*k))
        .map(|a| {
            if let Some(s) = a.as_str() {
                s.to_string()
            } else {
                a.to_string()
            }
        })
        .unwrap_or_default();
    // C10：检索完成项参按 queries 回退；RSP-6：shell/computer 等内置工具参数位于
    // `action` 对象内。
    if args.is_empty()
        && let Some(obj) = item.as_object()
    {
        args = retrieval_args(obj);
    }
    if args.is_empty()
        && let Some(action) = item.get("action")
    {
        args = serde_json::to_string(action).unwrap_or_default();
    }
    let name = item
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| derived.map(str::to_string))
        .or_else(|| retrieval.map(str::to_string));
    if args.is_empty() && name.is_none() {
        return None;
    }
    let id_raw = item
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| item.get("call_id").and_then(|v| v.as_str()));
    let (id, id_synth) = synth_tool_id_with(emit_warn, bucket, id_raw);
    Some(ToolCall {
        index: bucket,
        id,
        name,
        args,
        id_synth,
    })
}
