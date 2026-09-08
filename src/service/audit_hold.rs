use {
    crate::approval::{ApprovalGateway, PendingRecord},
    serde_json::Value,
    std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldVerdict {
    Approved,
    Rejected,
}

pub fn decide_via_gateway(
    gateway: &dyn ApprovalGateway,
    record: &PendingRecord,
) -> Option<HoldVerdict> {
    match gateway.request_approval(record) {
        crate::approval::ApprovalOutcome::Blocked => Some(HoldVerdict::Rejected),
        crate::approval::ApprovalOutcome::Pending => None,
    }
}

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
        if let Some(t) = payload.get("type").and_then(|v| v.as_str())
            && matches!(
                t,
                "content_block_stop"
                    | "item_done"
                    | "response.completed"
                    | "response.failed"
                    | "response.output_item.done"
                    | "response.function_call_arguments.done"
            )
        {
            return true;
        }
        payload.get("item").is_some()
            && payload.get("type").and_then(|v| v.as_str()) == Some("response.output_item.done")
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
    use {super::*, crate::approval::NoopApproval};

    #[test]
    fn responses三分片保序单flush且增量期不审计() {
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
    fn tool增量按index累积至完成前不flush() {
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
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"item_done"})
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
    fn 超限fail_closed且清理pending() {
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
    fn 挂起期新危险调用一律拒绝() {
        let hold = AuditHold::new(1024);
        assert!(hold.reject_new_dangerous_during_hold(true));
        assert!(!hold.reject_new_dangerous_during_hold(false));
    }

    #[test]
    fn verdict沿用审批trait占位() {
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

    #[tokio::test]
    async fn keepalive句柄per_request独立且首包挂起保活() {
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
    fn audit_approve_stream_批准注入完成放行() {
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
    fn audit_approve_stream_拒绝与过期注入清理() {
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
    fn audit_approve_stream_anthropic_precheck三事件() {
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"content_block_stop"})
        ));
        assert!(AuditHold::is_complete_event(
            &serde_json::json!({"type":"item_done"})
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
    fn audit_approve_stream_溢出failclosed双路径() {
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
    fn audit_approve_stream_abort_mid_toolcall粘性拒绝() {
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
    async fn audit_approve_stream_超时断连竞态与早断清理() {
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
