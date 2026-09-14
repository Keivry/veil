//! tool 分片提取（D2 自 `pump.rs` 拆出；ARC-3 起为共享提取核心的薄适配层）。

use {
    crate::service::llm_gateway::{Protocol, tool::extract_tool_calls_with},
    serde_json::Value,
};

/// ARC-3/D3：`extract_tool_fragments` 薄适配——调用共享三协议提取核心后映射为
/// 既有元组 `(index, Some(id), name, args)`；碎片路径 `id` 恒 `Some`，`id_synth`
/// 不消费。返回类型与 `spawn.rs` 调用点不变。
pub(super) fn extract_tool_fragments(
    protocol: Protocol,
    v: &Value,
) -> Vec<(u32, Option<String>, Option<String>, String)> {
    extract_tool_calls_with(false, protocol, v)
        .into_iter()
        .map(|c| (c.index, Some(c.id), c.name, c.args))
        .collect()
}

#[cfg(test)]
mod tests;
