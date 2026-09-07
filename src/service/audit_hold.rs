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
pub struct AuditHold {
    args_by_index: HashMap<u32, String>,
    name_by_index: HashMap<u32, String>,
    id_by_index: HashMap<u32, String>,
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
            return HoldVerdict::Rejected;
        }
        HoldVerdict::Approved
    }

    pub fn is_complete_event(payload: &Value) -> bool {
        if payload.get("finish_reason").and_then(|v| v.as_str()) == Some("tool_calls") {
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
    }

    /// 完成点审计用三元组：`(index, tool 名, 累积参数全文)`。
    pub fn tool_triples(&self) -> Vec<(u32, String, String)> {
        self.args_by_index
            .iter()
            .map(|(idx, args)| {
                (
                    *idx,
                    self.name_by_index.get(idx).cloned().unwrap_or_default(),
                    args.clone(),
                )
            })
            .collect()
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
}
