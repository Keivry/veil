//! tool 分桶缓冲与泵入口钳位（D2 自 `pump.rs` 拆出）：hold-until-complete 取出语义。

/// TSS-03 缓冲取出（P0-3.1）：按到达序取出与 `slot` 相交的缓冲输入；
/// `slot` 为 `None` 时全取（全局完成），否则只取含该槽号的帧（按槽完成）。
/// 取出的是边界 hold 上游输入（还原/脱敏后、边界缝合前），调用方须按序
/// 重放进 `BoundaryHold::push` 再转发，保证缝合状态机时序不变。
pub(super) fn take_pending_tool_inputs(
    pending: &mut Vec<(Vec<u32>, String, String)>,
    slot: Option<u32>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut kept = Vec::new();
    for (buckets, prefix, data) in std::mem::take(pending) {
        if slot.is_none_or(|s| buckets.contains(&s)) {
            out.push((prefix, data));
        } else {
            kept.push((buckets, prefix, data));
        }
    }
    *pending = kept;
    out
}

/// 泵入口限值钳位（P0-4.1）：`hold_max == 0 → 1MB 默认并 warn`，超
/// `AUDIT_SUBLIMIT_CEILING` 截断至上限并 warn；
/// `pii_boundary_chars == 0` 为响应侧关闭直通信号（`StreamPumpCtx` 调用方契约，
/// 见字段注释与 `handler::llm` 接线），保留不钳位。
pub(super) fn clamp_pump_limits(hold_max: usize, pii_boundary_chars: usize) -> (usize, usize) {
    let hold_max = if hold_max == 0 {
        tracing::warn!("hold_max 非法 ({hold_max})，已回退 1MB 默认");
        crate::config::AUDIT_HOLD_MAX_BYTES_DEFAULT as usize
    } else if hold_max > crate::config::AUDIT_SUBLIMIT_CEILING_BYTES {
        tracing::warn!("hold_max 超限 ({hold_max})，已截断至 8MB 上限");
        crate::config::AUDIT_SUBLIMIT_CEILING_BYTES
    } else {
        hold_max
    };
    (hold_max, pii_boundary_chars)
}

#[cfg(test)]
mod toolbuf_tests {
    use super::*;

    #[test]
    fn dual_buffer_slot_handoff_e10() {
        // E10/D5 方案 B 锁定：`pending_tool_frames` 按槽取出保到达序，
        // 全局完成全取、按槽完成只取相交槽（他槽继续缓冲），去向可追踪。
        let mut pending = vec![
            (vec![0u32], "p0a".to_string(), "d0a".to_string()),
            (vec![1u32], "p1".to_string(), "d1".to_string()),
            (vec![0u32], "p0b".to_string(), "d0b".to_string()),
        ];
        let taken = take_pending_tool_inputs(&mut pending, Some(0));
        assert_eq!(
            taken,
            vec![
                ("p0a".to_string(), "d0a".to_string()),
                ("p0b".to_string(), "d0b".to_string()),
            ],
            "按槽 0 只取相交帧且保到达序"
        );
        assert_eq!(pending.len(), 1, "他槽帧须继续缓冲");
        let rest = take_pending_tool_inputs(&mut pending, None);
        assert_eq!(
            rest,
            vec![("p1".to_string(), "d1".to_string())],
            "全局完成全取剩余"
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn pump_entry_clamps_hold_limits() {
        // P0-4.1：0→1MB 默认，超 8MB→截断；pii 0（关闭直通）保留。
        use crate::config::{AUDIT_HOLD_MAX_BYTES_DEFAULT, AUDIT_SUBLIMIT_CEILING_BYTES};
        assert_eq!(
            clamp_pump_limits(0, 64),
            (AUDIT_HOLD_MAX_BYTES_DEFAULT as usize, 64)
        );
        assert_eq!(clamp_pump_limits(1_048_576, 64), (1_048_576, 64));
        assert_eq!(
            clamp_pump_limits(16 * 1024 * 1024, 64),
            (AUDIT_SUBLIMIT_CEILING_BYTES, 64)
        );
        assert_eq!(
            clamp_pump_limits(1_048_576, 0),
            (1_048_576, 0),
            "pii 0 为关闭直通信号，须保留"
        );
    }

    #[test]
    fn pending_tool_buffer_drains_by_slot_preserving_order() {
        // P0-3.1：缓冲按槽取出保到达序；全局完成全取，按槽完成只取对应槽。
        let mut pending: Vec<(Vec<u32>, String, String)> = vec![
            (vec![0], "e0".to_string(), "d0".to_string()),
            (vec![1], "e1".to_string(), "d1".to_string()),
            (vec![0, 1], "e2".to_string(), "d2".to_string()),
        ];
        let slot0 = take_pending_tool_inputs(&mut pending, Some(0));
        assert_eq!(slot0.len(), 2, "含槽 0 的两帧须取出");
        assert_eq!(pending.len(), 1, "纯槽 1 帧须保留");
        let rest = take_pending_tool_inputs(&mut pending, None);
        assert_eq!(rest.len(), 1, "全局完成取空剩余");
        assert!(pending.is_empty());
    }
}
