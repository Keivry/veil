//! 工具桶号派生（R5-16/D12）：三协议索引提取的单一实现——合法索引直用，
//! 越界索引（客户端/上游可控）路由至有界哈希溢出桶并记告警，SHALL NOT 以
//! `as u32` 静默截断致不同取值碰撞同一审计槽。

use serde_json::Value;

/// 溢出桶保留带基址：桶号最高 8 位保留给越界索引，合法桶域 `< 本值`。
const TOOL_BUCKET_OVERFLOW_BASE: u32 = 0xFF00_0000;
/// 有界哈希溢出桶数量 `K`（`hash(idx) % K`）。每个越界索引至多占用一个
/// `args_by_index` 槽，故溢出桶天然计入 `AUDIT_HOLD_MAX_ENTRIES` 容量。
pub(crate) const TOOL_BUCKET_OVERFLOW_K: u32 = 256;
/// Chat choice 合法上界：`(ci << 16) | idx` 须落在合法桶域内（不触及保留带）。
const CHAT_CHOICE_MAX: u64 = 0xFF00;
/// Chat tool index 合法上界：低位 16 位域。
const CHAT_TOOL_INDEX_MAX: u64 = 1 << 16;

/// splitmix64 finalizer（确定性、无依赖）：原始索引摘要。
fn bucket_digest(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// 越界索引 → 有界哈希溢出桶：`hash(idx) % K` 落于保留带，与合法索引域不相交。
fn overflow_bucket(raw: u64) -> u32 {
    TOOL_BUCKET_OVERFLOW_BASE | (bucket_digest(raw) % TOOL_BUCKET_OVERFLOW_K as u64) as u32
}

/// 原始索引（未截断的 `u64`）→ 桶号：合法域内直用，越界走有界哈希溢出桶。
fn bucket_from_raw_index(raw: u64) -> u32 {
    if raw < TOOL_BUCKET_OVERFLOW_BASE as u64 {
        raw as u32
    } else {
        tracing::warn!(index = raw, "工具桶索引越界，路由至有界哈希溢出桶");
        overflow_bucket(raw)
    }
}

/// 依次尝试 `keys` 中首个可解析 `u64` 索引；缺失回退 `fallback`；越界经溢出桶收敛。
pub(crate) fn bucket_index_of(v: &Value, keys: &[&str], fallback: u32) -> u32 {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_u64()))
        .map_or(fallback, bucket_from_raw_index)
}

/// Chat 桶键（F-P1b + CHC-6/2.25 + R5-16）：`choice` 序号与 tool `index` 位域
/// 拼接；声明域 `ci < 0xFF00 && idx < 2^16` 单射且不触及溢出桶保留带。越界值按
/// 原始 `(ci, idx)` 摘要分入有界哈希溢出桶并记告警（拒绝固定单一溢出桶）。
pub(crate) fn chat_bucket_raw(ci_raw: u64, idx_raw: u64) -> u32 {
    if ci_raw < CHAT_CHOICE_MAX && idx_raw < CHAT_TOOL_INDEX_MAX {
        ((ci_raw as u32) << 16) | (idx_raw as u32)
    } else {
        tracing::warn!(
            choice_index = ci_raw,
            tool_index = idx_raw,
            "chat 桶索引越界，路由至有界哈希溢出桶"
        );
        overflow_bucket(bucket_digest(
            ci_raw.rotate_left(17) ^ idx_raw.wrapping_mul(0x9E37_79B9_7F4A_7C15),
        ))
    }
}

/// Chat 桶键兼容入口（`chat_bucket(0, idx) == idx`，单 choice 快照不变）。
pub fn chat_bucket(ci: usize, idx: u32) -> u32 { chat_bucket_raw(ci as u64, idx as u64) }

/// Responses `output[]` 桶号唯一实现（P9/X2）：`item.output_index` 优先，缺失
/// 回退枚举下标；两路径共用防漂移，越界值经有界哈希溢出桶收敛。
pub(crate) fn responses_output_bucket(item: &Value, fallback: usize) -> u32 {
    item.get("output_index")
        .and_then(|x| x.as_u64())
        .map_or(fallback as u32, bucket_from_raw_index)
}

/// Anthropic 分桶唯一实现（P0-2.2 + R5-16）：外层事件 `index` > 内层块 `index` >
/// 枚举下标；流式与非流共用，越界值经有界哈希溢出桶收敛。
pub fn anthropic_bucket_index(outer: Option<u64>, block: &Value, fallback: u32) -> u32 {
    if let Some(raw) = outer {
        return bucket_from_raw_index(raw);
    }
    block
        .get("index")
        .and_then(|v| v.as_u64())
        .map_or(fallback, bucket_from_raw_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_bucket_stays_in_reserved_band() {
        // Responses/Anthropic 的原始索引越界域为 `>= 保留带基址`。
        for raw in [u64::MAX, 1u64 << 32, 0xFF00_0000, (1u64 << 40) | 7] {
            let b = bucket_from_raw_index(raw);
            assert!(
                (TOOL_BUCKET_OVERFLOW_BASE..TOOL_BUCKET_OVERFLOW_BASE + TOOL_BUCKET_OVERFLOW_K)
                    .contains(&b),
                "raw={raw} bucket={b:#x} 须落保留带"
            );
        }
    }

    #[test]
    fn distinct_out_of_range_indices_avoid_fixed_bucket() {
        let a = bucket_from_raw_index(u32::MAX as u64);
        let b = bucket_from_raw_index(1u64 << 32);
        assert_ne!(a, b, "不同越界索引须落各自溢出桶而非同一固定桶");
        assert_ne!(
            chat_bucket_raw(0, u32::MAX as u64),
            chat_bucket_raw(0, 65536),
            "Chat 越界 tool index 亦不得撞入同一固定桶"
        );
    }

    #[test]
    fn chat_legal_domain_keeps_single_choice_snapshot() {
        for idx in [0u64, 1, 63, 64, 255, 4095, 65535] {
            assert_eq!(chat_bucket_raw(0, idx), idx as u32);
        }
        assert_eq!(chat_bucket_raw(2, 5), (2 << 16) | 5);
        assert_ne!(chat_bucket_raw(0, 64), chat_bucket_raw(1, 0));
        assert_ne!(chat_bucket_raw(0, 65536), chat_bucket_raw(0, 0));
        assert_ne!(chat_bucket_raw(0, 4096), chat_bucket_raw(64, 0));
    }
}
