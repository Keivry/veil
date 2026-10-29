//! tool 分桶缓冲与泵入口钳位（自 `pump.rs` 拆出）：hold-until-complete 取出语义。

/// 一帧被审计 hold 暂存的 tool 事件。
///
/// `payload_bytes`/`envelope_bytes` 是入账时分别计费的两块字节，必须随帧
/// 保存：出账若不与入账同源，减多减少都会让 `pending_*` 计数器漂移，长流下
/// 迟早误判溢出或漏判内存占用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingToolFrame {
    /// 本帧涉及的 tool 槽号（到达序）。
    pub buckets: Vec<u32>,
    /// SSE 信封前缀（`event:`/`id:`/`retry:`）。
    pub prefix: String,
    /// 还原后的完整事件载荷。
    pub data: String,
    /// 入账时计费的**参数载荷**字节（各 `arguments` 分片文本之和，不含信封）。
    pub payload_bytes: usize,
    /// 入账时计费的信封字节（SSE 前缀 + JSON 外壳中不含载荷的部分）。
    pub envelope_bytes: usize,
}

/// 缓冲取出：按到达序取出与 `slot` 相交的缓冲输入；
/// `slot` 为 `None` 时全取（全局完成），否则只取含该槽号的帧（按槽完成）。
/// 取出的是还原后输入，调用方须按到达序重放进 `agg` 再转发。
pub(super) fn take_pending_tool_inputs(
    pending: &mut Vec<PendingToolFrame>,
    slot: Option<u32>,
) -> Vec<PendingToolFrame> {
    let mut out = Vec::new();
    let mut kept = Vec::new();
    for frame in std::mem::take(pending) {
        if slot.is_none_or(|s| frame.buckets.contains(&s)) {
            out.push(frame);
        } else {
            kept.push(frame);
        }
    }
    *pending = kept;
    out
}

/// 泵入口限值钳位：`hold_max == 0 → 1MB 默认并 warn`，超
/// `AUDIT_SUBLIMIT_CEILING` 截断至上限并 warn（仅审计 hold，与 PII 无关）。
pub(super) fn clamp_pump_limits(hold_max: usize) -> usize {
    if hold_max == 0 {
        tracing::warn!("hold_max 非法 ({hold_max})，已回退 1MB 默认");
        crate::config::AUDIT_HOLD_MAX_BYTES_DEFAULT as usize
    } else if hold_max > crate::config::AUDIT_SUBLIMIT_CEILING_BYTES {
        tracing::warn!("hold_max 超限 ({hold_max})，已截断至 8MB 上限");
        crate::config::AUDIT_SUBLIMIT_CEILING_BYTES
    } else {
        hold_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_buffer_slot_handoff_e10() {
        // 方案 B 锁定：`pending_tool_frames` 按槽取出保到达序，
        // 全局完成全取、按槽完成只取相交槽（他槽继续缓冲），去向可追踪。
        let frame = |b: &[u32], p: &str, d: &str| PendingToolFrame {
            buckets: b.to_vec(),
            prefix: p.to_string(),
            data: d.to_string(),
            payload_bytes: d.len(),
            envelope_bytes: p.len(),
        };
        let mut pending = vec![
            frame(&[0], "p0a", "d0a"),
            frame(&[1], "p1", "d1"),
            frame(&[0], "p0b", "d0b"),
        ];
        let taken = take_pending_tool_inputs(&mut pending, Some(0));
        assert_eq!(
            taken.iter().map(|f| f.data.as_str()).collect::<Vec<_>>(),
            vec!["d0a", "d0b"],
            "按槽 0 只取相交帧且保到达序"
        );
        assert_eq!(pending.len(), 1, "他槽帧须继续缓冲");
        let rest = take_pending_tool_inputs(&mut pending, None);
        assert_eq!(
            rest.iter().map(|f| f.data.as_str()).collect::<Vec<_>>(),
            vec!["d1"],
            "全局完成全取剩余"
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn pump_entry_clamps_hold_limits() {
        // 0→1MB 默认，超 8MB→截断。
        use crate::config::{AUDIT_HOLD_MAX_BYTES_DEFAULT, AUDIT_SUBLIMIT_CEILING_BYTES};
        assert_eq!(clamp_pump_limits(0), AUDIT_HOLD_MAX_BYTES_DEFAULT as usize);
        assert_eq!(clamp_pump_limits(1_048_576), 1_048_576);
        assert_eq!(
            clamp_pump_limits(16 * 1024 * 1024),
            AUDIT_SUBLIMIT_CEILING_BYTES
        );
    }

    #[test]
    fn pending_tool_buffer_drains_by_slot_preserving_order() {
        // 缓冲按槽取出保到达序；全局完成全取，按槽完成只取对应槽。
        let frame = |b: &[u32], p: &str, d: &str| PendingToolFrame {
            buckets: b.to_vec(),
            prefix: p.to_string(),
            data: d.to_string(),
            payload_bytes: d.len(),
            envelope_bytes: p.len(),
        };
        let mut pending = vec![
            frame(&[0], "e0", "d0"),
            frame(&[1], "e1", "d1"),
            frame(&[0, 1], "e2", "d2"),
        ];
        let slot0 = take_pending_tool_inputs(&mut pending, Some(0));
        assert_eq!(slot0.len(), 2, "含槽 0 的两帧须取出");
        assert_eq!(pending.len(), 1, "纯槽 1 帧须保留");
        let rest = take_pending_tool_inputs(&mut pending, None);
        assert_eq!(rest.len(), 1, "全局完成取空剩余");
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn toolbuf_interleaved_parallel_release_order() {
        // 两并行 tool 槽交错到达/完成——放行序定义为「每槽按到达序取出、
        // 由该槽完成事件驱动」；跨槽相对次序不被保证（锁实测：先完成者先放行，
        // 不按槽号/全局到达序排序）。
        use crate::{
            config::AuditMode,
            handler::llm::tests::{collect_pump, fresh_arcs, loopback_server, pump_ctx},
            service::llm_gateway::Protocol,
        };
        let sse = br#"data: {"type":"response.output_item.added","output_index":0,"sequence_number":1,"item":{"type":"function_call","id":"call-A","name":"get_weather","arguments":""}}

data: {"type":"response.output_item.added","output_index":1,"sequence_number":2,"item":{"type":"function_call","id":"call-B","name":"get_weather","arguments":""}}

data: {"type":"response.function_call_arguments.delta","item_id":"call-A","output_index":0,"sequence_number":3,"delta":"{\"city\":\"AAA"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-B","output_index":1,"sequence_number":4,"delta":"{\"city\":\"BBB"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-A","output_index":0,"sequence_number":5,"delta":" ZZZ\"}"}

data: {"type":"response.function_call_arguments.delta","item_id":"call-B","output_index":1,"sequence_number":6,"delta":" WWW\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-B","output_index":1,"sequence_number":7,"arguments":"{\"city\":\"BBB WWW\"}"}

data: {"type":"response.function_call_arguments.done","item_id":"call-A","output_index":0,"sequence_number":8,"arguments":"{\"city\":\"AAA ZZZ\"}"}

data: {"type":"response.completed","sequence_number":9,"response":{"id":"r1","status":"completed"}}

"#
        .to_vec();
        let (url, server) = loopback_server(200, "text/event-stream", sse).await;
        let upstream = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("回环上游须可达");
        let (scope, vault, detector) = fresh_arcs();
        let mut ctx = pump_ctx(Protocol::Responses, scope, vault, detector);
        ctx.req.audit_mode = AuditMode::Block;
        let (outcome, frames) = collect_pump(upstream, ctx).await;
        server.abort();
        assert!(!outcome.block_injected, "良性并行调用不得阻断");
        let joined = frames.join("");
        let a = joined.find("AAA").expect("槽 0 分片须放行");
        let b = joined.find("BBB").expect("槽 1 分片须放行");
        assert!(
            b < a,
            "放行由完成事件驱动（槽 1 先完成须先放行，不按到达序/槽号重排）: {joined}"
        );
        assert!(
            joined.find("AAA").unwrap() < joined.find("ZZZ").unwrap(),
            "槽 0 内须保到达序: {joined}"
        );
        assert!(
            joined.find("BBB").unwrap() < joined.find("WWW").unwrap(),
            "槽 1 内须保到达序: {joined}"
        );
        assert!(
            !joined.contains("rm -rf"),
            "测试向量不含危险参数（判别力集中于放行序）: {joined}"
        );
    }
}
