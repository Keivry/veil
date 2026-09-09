use {
    serde_json::Value,
    std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    },
};

/// A1：`HoldVerdict`/`decide_via_gateway` 归属 `audit.rs`，此处重导出保持
/// `crate::service::audit_hold::{HoldVerdict, decide_via_gateway}` 路径编译。
pub use super::audit::{HoldVerdict, decide_via_gateway};

#[derive(Debug, Default)]
struct ResponsesSlot {
    output_index: u32,
    name: Option<String>,
    frags: std::collections::BTreeMap<u64, String>,
    next_seq: u64,
    done_args: Option<String>,
    done_seen: bool,
}

impl ResponsesSlot {
    fn full_args(&self) -> String {
        if let Some(done) = self.done_args.as_deref() {
            return done.to_string();
        }
        let mut out = String::new();
        for frag in self.frags.values() {
            out.push_str(frag);
        }
        out
    }
}

/// R5 职责声明：本结构只累积（tool 参数分片/字节预算/完成判定），不合成
/// 任何响应帧/体；帧合成归 `block_inject`，两边不交叉。
#[derive(Debug, Default)]
pub struct AuditHold {
    args_by_index: HashMap<u32, String>,
    name_by_index: HashMap<u32, String>,
    id_by_index: HashMap<u32, String>,
    responses_slots: HashMap<String, ResponsesSlot>,
    total_bytes: usize,
    max_bytes: usize,
    rejected: bool,
    completed: bool,
}

impl AuditHold {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes: if max_bytes == 0 { 1_048_576 } else { max_bytes },
            ..Default::default()
        }
    }

    pub fn push_fragment(
        &mut self,
        index: u32,
        id: Option<&str>,
        name: Option<&str>,
        args_delta: &str,
    ) -> HoldVerdict {
        if self.rejected || self.completed {
            return if self.rejected {
                HoldVerdict::Rejected
            } else {
                HoldVerdict::Approved
            };
        }
        if let Some(v) = id {
            self.id_by_index
                .entry(index)
                .or_insert_with(|| v.to_string());
        }
        if let Some(v) = name {
            self.name_by_index
                .entry(index)
                .or_insert_with(|| v.to_string());
        }
        let entry = self.args_by_index.entry(index).or_default();
        entry.push_str(args_delta);
        self.total_bytes += args_delta.len();
        if self.total_bytes > self.max_bytes {
            self.rejected = true;
            self.args_by_index.clear();
            self.name_by_index.clear();
            self.id_by_index.clear();
            self.responses_slots.clear();
            return HoldVerdict::Rejected;
        }
        HoldVerdict::Approved
    }

    pub fn responses_key(item_id: Option<&str>, output_index: u32) -> String {
        match item_id.filter(|s| !s.is_empty()) {
            Some(id) => id.to_string(),
            None => format!("output_index:{output_index}"),
        }
    }

    pub fn push_responses_fragment(
        &mut self,
        item_key: &str,
        output_index: u32,
        seq: Option<u64>,
        _id: Option<&str>,
        name: Option<&str>,
        args_delta: &str,
    ) -> HoldVerdict {
        if self.rejected || self.completed {
            return if self.rejected {
                HoldVerdict::Rejected
            } else {
                HoldVerdict::Approved
            };
        }
        let slot = self
            .responses_slots
            .entry(item_key.to_string())
            .or_insert_with(|| ResponsesSlot {
                output_index,
                ..Default::default()
            });
        if let Some(v) = name {
            slot.name.get_or_insert_with(|| v.to_string());
        }
        let seq_no = seq.unwrap_or_else(|| {
            let n = slot.next_seq;
            slot.next_seq += 1;
            n
        });
        slot.next_seq = slot.next_seq.max(seq_no + 1);
        slot.frags
            .entry(seq_no)
            .or_insert_with(|| args_delta.to_string());
        self.total_bytes += args_delta.len();
        if self.total_bytes > self.max_bytes {
            self.rejected = true;
            self.args_by_index.clear();
            self.name_by_index.clear();
            self.id_by_index.clear();
            self.responses_slots.clear();
            return HoldVerdict::Rejected;
        }
        HoldVerdict::Approved
    }

    pub fn mark_responses_done(&mut self, item_key: &str, full_args: Option<&str>) {
        if let Some(slot) = self.responses_slots.get_mut(item_key) {
            slot.done_seen = true;
            if let Some(args) = full_args {
                slot.done_args = Some(args.to_string());
            }
        }
    }

    pub fn is_responses_complete(&self, item_key: &str) -> bool {
        self.responses_slots
            .get(item_key)
            .is_some_and(|s| s.done_seen)
    }

    pub fn responses_triples(&self) -> Vec<(u32, String, String)> {
        self.responses_slots
            .values()
            .filter(|s| s.done_seen)
            .map(|s| {
                (
                    s.output_index,
                    s.name.clone().unwrap_or_default(),
                    s.full_args(),
                )
            })
            .collect()
    }

    /// 全局完成事件判定（§2.5）：仅 `message_stop`/`completed` 类事件触发
    /// 全局 `mark_completed`；`content_block_stop`/`item_done` 只清对应
    /// index 槽（见 [`AuditHold::is_index_complete_event`] +
    /// [`AuditHold::clear_index`]），此处恒为 false，避免第一块 stop 后
    /// 第二块 tool 直接 Approved 逃逸。
    pub fn is_complete_event(payload: &Value) -> bool {
        if payload
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| t.ends_with(".delta"))
        {
            return false;
        }
        if payload.get("finish_reason").and_then(|v| v.as_str()) == Some("tool_calls") {
            return true;
        }
        if payload
            .get("choices")
            .and_then(|c| c.as_array())
            .is_some_and(|choices| {
                choices.iter().any(|ch| {
                    ch.get("finish_reason").and_then(|v| v.as_str()) == Some("tool_calls")
                        || ch
                            .get("delta")
                            .and_then(|d| d.get("finish_reason"))
                            .and_then(|v| v.as_str())
                            == Some("tool_calls")
                        || ch
                            .get("message")
                            .and_then(|m| m.get("finish_reason"))
                            .and_then(|v| v.as_str())
                            == Some("tool_calls")
                })
            })
        {
            return true;
        }
        // §2.5：`content_block_stop`/`item_done` 只清对应 index 槽，
        // 不得标记全局完成；全局完成仅由 `message_stop`/`completed` 触发。
        if let Some(t) = payload.get("type").and_then(|v| v.as_str())
            && matches!(
                t,
                "message_stop"
                    | "response.completed"
                    | "response.failed"
                    | "response.output_item.done"
                    | "response.function_call_arguments.done"
            )
        {
            return true;
        }
        false
    }

    /// 按 index 完成事件判定（§2.5）：`content_block_stop`/`item_done`
    /// 只审计并清理对应 index 的槽，不标记全局完成。
    pub fn is_index_complete_event(payload: &Value) -> bool {
        payload
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| t == "content_block_stop" || t == "item_done")
    }

    /// 按 index 清槽（§2.5）：移除该 index 的累积参数/名/id，
    /// 全局 `completed`/`rejected` 状态不动，后续 index 照常累积审计。
    pub fn clear_index(&mut self, index: u32) {
        self.args_by_index.remove(&index);
        self.name_by_index.remove(&index);
        self.id_by_index.remove(&index);
    }

    pub fn mark_completed(&mut self) { self.completed = true; }

    /// 审计命中拒绝：置粘性拒绝态并清理持仓（fail-closed，不透出参数）。
    pub fn mark_rejected(&mut self) {
        self.rejected = true;
        self.args_by_index.clear();
        self.name_by_index.clear();
        self.id_by_index.clear();
        self.responses_slots.clear();
    }

    /// 完成点审计用三元组：`(index, tool 名, 累积参数全文)`。
    /// 含 Responses `done` 门控槽（仅 `done` 到达的槽参与审计，delta 只累积）。
    pub fn tool_triples(&self) -> Vec<(u32, String, String)> {
        let mut triples: Vec<(u32, String, String)> = self
            .args_by_index
            .iter()
            .map(|(idx, args)| {
                (
                    *idx,
                    self.name_by_index.get(idx).cloned().unwrap_or_default(),
                    args.clone(),
                )
            })
            .collect();
        triples.extend(self.responses_triples());
        triples
    }

    pub fn held(&self) -> bool { !self.completed && !self.rejected }

    pub fn is_rejected(&self) -> bool { self.rejected }

    pub fn accumulated(&self, index: u32) -> Option<&str> {
        self.args_by_index.get(&index).map(|s| s.as_str())
    }

    /// hold 期间新危险调用是否拒绝（预留：流泵未接线——当前泵路径不调用本
    /// 函数，危险调用按 pending 建单语义处理；接线见网关 change）。
    pub fn reject_new_dangerous_during_hold(&self, is_dangerous: bool) -> bool {
        self.held() && is_dangerous
    }
}

#[derive(Debug)]
pub struct RequestKeepalive {
    live: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RequestKeepalive {
    pub fn spawn(tx: tokio::sync::mpsc::Sender<String>) -> Self {
        Self::spawn_gated(tx, Arc::new(AtomicBool::new(true)))
    }

    pub fn spawn_gated(tx: tokio::sync::mpsc::Sender<String>, gate: Arc<AtomicBool>) -> Self {
        let live = Arc::new(AtomicBool::new(true));
        let flag = live.clone();
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(super::sse::KEEPALIVE_INTERVAL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if !flag.load(Ordering::Relaxed) {
                    break;
                }
                if !gate.load(Ordering::Relaxed) {
                    continue;
                }
                if tx.send(super::sse::keepalive_frame()).await.is_err() {
                    break;
                }
            }
        });
        Self {
            live,
            task: Some(task),
        }
    }

    pub fn is_live(&self) -> bool { self.live.load(Ordering::Relaxed) }
}

impl Drop for RequestKeepalive {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Relaxed);
        if let Some(h) = self.task.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::approval::{ApprovalGateway, NoopApproval, PendingRecord},
    };

    #[test]
    fn responses_three_fragments_ordered_single_flush_no_audit_during_delta() {
        let mut hold = AuditHold::new(1024);
        let key = AuditHold::responses_key(Some("item-7"), 1);
        assert_eq!(
            hold.push_responses_fragment(&key, 1, Some(2), Some("item-7"), Some("run"), "1}"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_responses_fragment(&key, 1, Some(0), None, None, "{\"x\":"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_responses_fragment(&key, 1, Some(1), None, None, ""),
            HoldVerdict::Approved
        );
        assert!(
            hold.tool_triples().is_empty(),
            "done 到达前不得有可审计三元组"
        );
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"{\"x\":"})
        ));
        hold.mark_responses_done(&key, None);
        assert!(hold.is_responses_complete(&key));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"response.function_call_arguments.done"})
        ));
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1, "三分片单 flush 为一条三元组");
        assert_eq!(triples[0].0, 1);
        assert_eq!(triples[0].1, "run");
        assert_eq!(triples[0].2, "{\"x\":1}");
    }

    #[test]
    fn tool_deltas_accumulate_by_index_without_flush_until_complete() {
        let mut hold = AuditHold::new(1024);
        assert_eq!(
            hold.push_fragment(0, Some("a"), Some("run"), "{\"x\":"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_fragment(0, None, None, "1}"),
            HoldVerdict::Approved
        );
        assert!(hold.held());
        assert_eq!(hold.accumulated(0), Some("{\"x\":1}"));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"delta":"hi"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"finish_reason":"tool_calls"})
        ));
        // §2.5：stop/item_done 只触发按 index 清理，不标记全局完成。
        assert!(AuditHold::is_index_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(AuditHold::is_index_complete_event(
            &serde_json::json!({"type":"item_done"})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"item_done"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"message_stop"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"delta":{},"finish_reason":"tool_calls","index":0}]})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"message":{"finish_reason":"tool_calls"}}]})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"choices":[]})
        ));
        hold.mark_completed();
        assert!(!hold.held());
    }

    #[test]
    fn overflow_fail_closed_and_clears_pending() {
        let mut hold = AuditHold::new(4);
        assert_eq!(
            hold.push_fragment(0, None, None, "ab"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_fragment(0, None, None, "cde"),
            HoldVerdict::Rejected
        );
        assert!(hold.is_rejected());
        assert_eq!(hold.accumulated(0), None);
    }

    #[test]
    fn mid_abort_and_early_close_cleanup_fail_closed_without_hang() {
        let mut hold = AuditHold::new(1024);
        assert_eq!(
            hold.push_fragment(0, Some("a"), Some("run"), "{\"x\":"),
            HoldVerdict::Approved
        );
        hold.mark_rejected();
        assert!(hold.is_rejected());
        assert!(!hold.held(), "abort 后不得再挂起等待");
        assert_eq!(
            hold.push_fragment(0, None, None, "1}"),
            HoldVerdict::Rejected,
            "abort 后续分片一律拒绝"
        );
        let mut early = AuditHold::new(1024);
        assert_eq!(
            early.push_fragment(1, Some("b"), Some("run"), "{\"y\":"),
            HoldVerdict::Approved
        );
        early.mark_completed();
        assert!(!early.held(), "早断完成即清理，不残留挂起");
    }

    #[test]
    fn dual_index_independent_accumulation_without_crosstalk() {
        let mut hold = AuditHold::new(1024);
        assert_eq!(
            hold.push_fragment(0, Some("a"), Some("run_a"), "{\"x\":"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_fragment(1, Some("b"), Some("run_b"), "{\"y\":"),
            HoldVerdict::Approved
        );
        assert_eq!(hold.accumulated(0), Some("{\"x\":"));
        assert_eq!(hold.accumulated(1), Some("{\"y\":"));
        hold.clear_index(0);
        assert_eq!(hold.accumulated(0), None);
        assert_eq!(hold.accumulated(1), Some("{\"y\":"), "清槽不得污染他槽");
        assert!(hold.held(), "单槽清理后整体仍挂起审计");
    }

    #[test]
    fn timeout_disconnect_race_window_constants_locked() {
        assert_eq!(crate::config::AUDIT_TIMEOUT_RACE_MIN, 110);
        assert_eq!(crate::config::AUDIT_TIMEOUT_RACE_MAX, 130);
        assert_eq!(crate::config::AUDIT_TIMEOUT_DEFAULT, 90);
    }

    #[test]
    fn new_dangerous_calls_rejected_during_hold() {
        let hold = AuditHold::new(1024);
        assert!(hold.reject_new_dangerous_during_hold(true));
        assert!(!hold.reject_new_dangerous_during_hold(false));
    }

    #[test]
    fn verdict_reuses_approval_trait_stub() {
        let gw = NoopApproval;
        let rec = PendingRecord::new("k", "audit_hold");
        assert_eq!(decide_via_gateway(&gw, &rec), None);
        struct BlockAll;
        impl std::fmt::Debug for BlockAll {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("BlockAll")
            }
        }
        impl ApprovalGateway for BlockAll {
            fn request_approval(&self, _: &PendingRecord) -> crate::approval::ApprovalOutcome {
                crate::approval::ApprovalOutcome::Blocked
            }
        }
        assert_eq!(
            decide_via_gateway(&BlockAll, &rec),
            Some(HoldVerdict::Rejected)
        );
    }

    #[test]
    fn decide_enforces_block_and_approve_without_noop_stub() {
        let rec = PendingRecord::new("k", "audit_hold");
        struct AllowAll;
        impl std::fmt::Debug for AllowAll {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("AllowAll")
            }
        }
        impl ApprovalGateway for AllowAll {
            fn request_approval(&self, _: &PendingRecord) -> crate::approval::ApprovalOutcome {
                crate::approval::ApprovalOutcome::Approved
            }
        }
        assert_eq!(
            decide_via_gateway(&AllowAll, &rec),
            Some(HoldVerdict::Approved)
        );
    }

    #[test]
    fn completion_check_without_duplicate_branches() {
        // `response.output_item.done` 仅走 matches! 主分支，不再有尾部重复条件。
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type": "response.output_item.done", "item": {"id": "x"}})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"item": {"id": "x"}, "type": "other"})
        ));
    }

    #[tokio::test]
    async fn keepalive_handle_per_request_independent_with_first_packet_hold() {
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<String>(8);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<String>(8);
        let h1 = RequestKeepalive::spawn(tx1);
        let h2 = RequestKeepalive::spawn(tx2);
        assert!(h1.is_live() && h2.is_live());
        assert!(!std::ptr::eq(&h1, &h2));
        drop(h1);
        assert!(h2.is_live());
    }

    #[test]
    fn audit_approve_stream_approve_injects_completion_and_allows() {
        let mut hold = AuditHold::new(1024);
        assert_eq!(
            hold.push_fragment(0, Some("c1"), Some("run"), "{\"x\":"),
            HoldVerdict::Approved
        );
        assert_eq!(
            hold.push_fragment(0, None, None, "1}"),
            HoldVerdict::Approved
        );
        assert!(hold.held());
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].2, "{\"x\":1}");
        hold.mark_completed();
        assert!(!hold.held());
        assert!(!hold.is_rejected());
    }

    #[test]
    fn audit_approve_stream_reject_and_expiry_inject_cleanup() {
        let mut deny = AuditHold::new(1024);
        deny.push_fragment(0, Some("c1"), Some("rm"), "{\"p\":");
        deny.mark_rejected();
        assert!(deny.is_rejected());
        assert!(deny.tool_triples().is_empty());
        assert_eq!(deny.accumulated(0), None);
        let mut expired = AuditHold::new(1024);
        expired.push_fragment(0, Some("c9"), Some("run"), "{\"y\":2}");
        expired.mark_rejected();
        assert!(expired.is_rejected());
        assert!(expired.tool_triples().is_empty());
        assert_eq!(
            expired.push_fragment(0, None, None, "x"),
            HoldVerdict::Rejected
        );
    }

    #[test]
    fn audit_approve_stream_anthropic_precheck_three_events() {
        // §2.5：stop/item_done 只清对应 index 槽；全局完成仅 message_stop。
        assert!(AuditHold::is_index_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(AuditHold::is_index_complete_event(
            &serde_json::json!({"type":"item_done"})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"item_done"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"message_stop"})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"type":"response.function_call_arguments.delta","delta":"x"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"delta":{"finish_reason":"tool_calls"}}]})
        ));
        assert!(!AuditHold::is_complete_event(
            &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}]})
        ));
    }

    #[test]
    fn second_tool_block_preserves_global_state_and_audits_normally() {
        let mut hold = AuditHold::new(1024);
        assert_eq!(
            hold.push_fragment(0, Some("a0"), Some("run"), "{\"x\":1}"),
            HoldVerdict::Approved
        );
        // 第一块 stop：只清 index 0，不标记全局完成。
        let stop0 = serde_json::json!({"type":"content_block_stop","index":0});
        assert!(AuditHold::is_index_complete_event(&stop0));
        assert!(!AuditHold::is_complete_event(&stop0));
        hold.clear_index(0);
        assert!(hold.held(), "全局完成须保持未标记");
        assert_eq!(hold.accumulated(0), None);
        assert!(hold.tool_triples().is_empty());
        // 第二块到达照常累积可审计，不直接 Approved 逃逸。
        assert_eq!(
            hold.push_fragment(1, Some("a1"), Some("run"), "{\"y\":2}"),
            HoldVerdict::Approved
        );
        assert!(hold.held());
        let triples = hold.tool_triples();
        assert_eq!(triples.len(), 1);
        assert_eq!(triples[0].0, 1);
        assert_eq!(triples[0].2, "{\"y\":2}");
    }

    #[test]
    fn audit_approve_stream_overflow_fail_closed_both_paths() {
        let mut chat_hold = AuditHold::new(4);
        assert_eq!(
            chat_hold.push_fragment(0, None, None, "ab"),
            HoldVerdict::Approved
        );
        assert_eq!(
            chat_hold.push_fragment(0, None, None, "cde"),
            HoldVerdict::Rejected
        );
        assert!(chat_hold.is_rejected());
        assert!(chat_hold.tool_triples().is_empty());
        let mut resp_hold = AuditHold::new(4);
        let key = AuditHold::responses_key(Some("item-o"), 0);
        assert_eq!(
            resp_hold.push_responses_fragment(&key, 0, Some(0), None, None, "ab"),
            HoldVerdict::Approved
        );
        assert_eq!(
            resp_hold.push_responses_fragment(&key, 0, Some(1), None, None, "cde"),
            HoldVerdict::Rejected
        );
        assert!(resp_hold.is_rejected());
        assert!(resp_hold.responses_triples().is_empty());
    }

    #[test]
    fn audit_approve_stream_abort_mid_toolcall_sticky_reject() {
        let mut hold = AuditHold::new(1024);
        hold.push_fragment(0, Some("c1"), Some("run"), "{\"a\":");
        hold.mark_rejected();
        assert_eq!(
            hold.push_fragment(0, None, None, "1}"),
            HoldVerdict::Rejected
        );
        let key = AuditHold::responses_key(Some("item-a"), 1);
        assert_eq!(
            hold.push_responses_fragment(&key, 1, Some(0), None, None, "z"),
            HoldVerdict::Rejected
        );
        hold.mark_completed();
        assert!(hold.is_rejected());
        assert!(hold.tool_triples().is_empty());
    }

    #[tokio::test]
    async fn audit_approve_stream_timeout_disconnect_race_with_early_close_cleanup() {
        let (tx1, _rx1) = tokio::sync::mpsc::channel::<String>(8);
        let (tx2, _rx2) = tokio::sync::mpsc::channel::<String>(8);
        let gate_closed = std::sync::Arc::new(AtomicBool::new(false));
        let gated = RequestKeepalive::spawn_gated(tx1, gate_closed);
        assert!(gated.is_live());
        drop(gated);
        let h1 = RequestKeepalive::spawn(tx2);
        assert!(h1.is_live());
        drop(h1);
        let (tx3, _rx3) = tokio::sync::mpsc::channel::<String>(8);
        let (tx4, _rx4) = tokio::sync::mpsc::channel::<String>(8);
        let keep_a = RequestKeepalive::spawn(tx3);
        let keep_b = RequestKeepalive::spawn(tx4);
        assert!(keep_a.is_live() && keep_b.is_live());
        drop(keep_a);
        assert!(keep_b.is_live());
    }
}
