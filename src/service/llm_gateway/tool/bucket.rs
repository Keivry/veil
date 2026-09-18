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
/// R8-15/D10：Anthropic 数组项复合桶键基址（块内位置计入位域）。
const ANTHROPIC_ITEM_BASE: u32 = 1 << 24;
/// Anthropic 块键合法上界（高位 16 位域）。
const ANTHROPIC_BLOCK_MAX: u32 = 1 << 16;
/// Anthropic 块内位置合法上界（低位 8 位域，编码 `item_index - 1`）。
const ANTHROPIC_ITEM_MAX: u32 = 1 << 8;

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
/// R8-05：`pub(crate)` 供 `pump/event.rs::outer_event_index` 复用——越界索引
/// SHALL NOT 以 `u64 as u32` 静默截断后操作错误槽。
pub(crate) fn bucket_from_raw_index(raw: u64) -> u32 {
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

/// Anthropic 数组项复合桶键（R8-15/D10）：块键 + 块内位置位域单射。
/// `item_index == 0` 且块键在合法域时返回 `block_bucket`（对象分支等价）；
/// 合法域（`item_index >= 1`）为
/// `ANTHROPIC_ITEM_BASE | (block_bucket << 8) | (item_index - 1)`，
/// 上界 `0x01FF_FFFF < TOOL_BUCKET_OVERFLOW_BASE`；越界（含块键
/// `>= ANTHROPIC_BLOCK_MAX`，避免 `(block_bucket, 0)` 与 `(0, 1)` 桶碰撞）
/// 记告警并经有界哈希溢出桶收敛。
pub(crate) fn anthropic_item_bucket(block_bucket: u32, item_index: u32) -> u32 {
    if item_index == 0 && block_bucket < ANTHROPIC_BLOCK_MAX {
        return block_bucket;
    }
    if block_bucket < ANTHROPIC_BLOCK_MAX && item_index < ANTHROPIC_ITEM_MAX {
        return ANTHROPIC_ITEM_BASE | (block_bucket << 8) | (item_index - 1);
    }
    tracing::warn!(
        block_bucket,
        item_index,
        "anthropic 数组项桶索引越界，路由至有界哈希溢出桶"
    );
    overflow_bucket(bucket_digest(
        ((block_bucket as u64) << 32) ^ item_index as u64,
    ))
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

    #[test]
    fn anthropic_item_bucket_zero_index_equals_block_bucket() {
        // D10：`item_index == 0` 退化为纯块键（对象分支等价）。
        for bucket in [0u32, 1, 7, 4096, ANTHROPIC_BLOCK_MAX - 1] {
            assert_eq!(anthropic_item_bucket(bucket, 0), bucket);
        }
    }

    #[test]
    fn anthropic_item_bucket_legal_domain_injective() {
        // 合法域（块键 < 2^16、位置 < 256）位域单射：两两互异且不触及保留带。
        let mut seen = std::collections::HashSet::new();
        for block in [0u32, 1, 255, 256, ANTHROPIC_BLOCK_MAX - 1] {
            for item in 0..4u32 {
                let b = anthropic_item_bucket(block, item);
                assert!(
                    b < TOOL_BUCKET_OVERFLOW_BASE,
                    "合法域不得触及保留带: {b:#x}"
                );
                assert!(seen.insert(b), "({block}, {item}) 桶键碰撞: {b:#x}");
            }
        }
        assert_eq!(anthropic_item_bucket(0, 1), ANTHROPIC_ITEM_BASE);
        assert_eq!(
            anthropic_item_bucket(1, 2),
            ANTHROPIC_ITEM_BASE | (1 << 8) | 1
        );
        assert_eq!(
            anthropic_item_bucket(ANTHROPIC_BLOCK_MAX - 1, ANTHROPIC_ITEM_MAX - 1),
            0x01FF_FFFE,
            "合法域可达上界（域上界 0x01FF_FFFF 内）"
        );
        assert_ne!(anthropic_item_bucket(0, 1), anthropic_item_bucket(1, 0));
        assert_ne!(anthropic_item_bucket(5, 1), anthropic_item_bucket(5, 2));
    }

    #[test]
    fn anthropic_item_bucket_out_of_range_in_overflow_band() {
        // 越界（块键 >= 2^16 或位置 >= 256）经有界哈希溢出桶收敛。
        for (block, item) in [
            (ANTHROPIC_BLOCK_MAX, 0u32),
            (u32::MAX, 0),
            (0, ANTHROPIC_ITEM_MAX),
            (5, u32::MAX),
        ] {
            let b = anthropic_item_bucket(block, item);
            assert!(
                (TOOL_BUCKET_OVERFLOW_BASE..TOOL_BUCKET_OVERFLOW_BASE + TOOL_BUCKET_OVERFLOW_K)
                    .contains(&b),
                "({block}, {item}) 须落保留带: {b:#x}"
            );
        }
        assert_ne!(
            anthropic_item_bucket(ANTHROPIC_BLOCK_MAX, 0),
            anthropic_item_bucket(ANTHROPIC_BLOCK_MAX, 1),
            "不同越界组合不得共用固定溢出桶"
        );
    }
}
