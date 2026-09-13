//! hold 累积与流内保活（D2 自 `audit.rs` 拆出；D3 自 `audit_hold.rs` 并入后的归属）。

use {
    super::verdict::HoldVerdict,
    serde_json::Value,
    std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    },
};

/// D3 hold 累积与流内保活（自 `audit_hold.rs` 并入，判定归属本模块）：
/// `AuditHold` 只累积不合成帧，`RequestKeepalive` 为流内保活唯一实现。
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
    /// S7/D8：本槽已计入 `total_bytes` 的活跃分片字节（`done_args` 不重复计数）。
    fn held_bytes(&self) -> usize { self.frags.values().map(|s| s.len()).sum() }

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
            self.total_bytes = 0;
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
        let added_bytes = match slot.frags.entry(seq_no) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(args_delta.to_string());
                args_delta.len()
            }
            std::collections::btree_map::Entry::Occupied(_) => 0,
        };
        self.total_bytes += added_bytes;
        if self.total_bytes > self.max_bytes {
            self.rejected = true;
            self.total_bytes = 0;
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

    /// 全局完成事件判定（§2.5 / D2）：仅 `message_stop`/`response.completed`/
    /// `response.failed`/`response.incomplete` 与 Chat `finish_reason=tool_calls`
    /// 触发全局 `mark_completed`。`content_block_stop`/`item_done` 只清对应
    /// index 槽（见 [`AuditHold::is_index_complete_event`] +
    /// [`AuditHold::clear_index`]）；Responses 的 `response.output_item.done`/
    /// `response.function_call_arguments.done` 为**槽级**完成（见
    /// [`AuditHold::is_responses_slot_complete_event`]），不得标记全局完成，
    /// 否则首个 item done 后后续 item 的分片既不累积也不审计（危险参数逃逸）。
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
        // §2.5 / D2：全局完成仅由 `message_stop` 与 Responses 官方三元
        //（`completed`/`failed`/`incomplete`）触发；per-item `.done` 是槽级完成。
        if let Some(t) = payload.get("type").and_then(|v| v.as_str())
            && matches!(
                t,
                "message_stop" | "response.completed" | "response.failed" | "response.incomplete"
            )
        {
            return true;
        }
        false
    }

    /// D2 槽级完成事件判定：`response.output_item.done`/
    /// `response.function_call_arguments.done` 只完成对应 item 槽，
    /// 由调用方审计并清理该槽，不影响全局完成。
    pub fn is_responses_slot_complete_event(payload: &Value) -> bool {
        payload
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| {
                t == "response.output_item.done" || t == "response.function_call_arguments.done"
            })
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
        if let Some(args) = self.args_by_index.remove(&index) {
            self.total_bytes = self.total_bytes.saturating_sub(args.len());
        }
        self.name_by_index.remove(&index);
        self.id_by_index.remove(&index);
    }

    pub fn mark_completed(&mut self) {
        self.completed = true;
        self.total_bytes = 0;
    }

    /// 审计命中拒绝：置粘性拒绝态并清理持仓（fail-closed，不透出参数）。
    pub fn mark_rejected(&mut self) {
        self.rejected = true;
        self.total_bytes = 0;
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

    /// D1 pending 判据：Chat/Anthropic 存在未释放的 `args_by_index` 分片；
    /// Responses 存在 `!done_seen` 的槽。用于把抑制/keepalive 门控从流级
    /// 「未完成」（`held()` 在流开头即为真）收窄为「确有分片被持有」。
    pub fn has_pending_fragments(&self) -> bool {
        !self.args_by_index.is_empty() || self.responses_slots.values().any(|s| !s.done_seen)
    }

    /// D1 释放入口：完成事件审计（Allow 或 `NeedApproval` 建单，均算已判定）
    /// 后把已判定作用域移出抑制集——Chat/Anthropic 清空分片累积，Responses
    /// 移除 `done_seen` 槽。拒绝态 fail-closed 不释放。
    pub fn release_audited(&mut self) {
        if self.rejected {
            return;
        }
        let released: usize = self
            .args_by_index
            .values()
            .map(String::len)
            .chain(
                self.responses_slots
                    .values()
                    .filter(|slot| slot.done_seen)
                    .map(ResponsesSlot::held_bytes),
            )
            .sum();
        self.total_bytes = self.total_bytes.saturating_sub(released);
        self.args_by_index.clear();
        self.name_by_index.clear();
        self.id_by_index.clear();
        self.responses_slots.retain(|_, slot| !slot.done_seen);
    }

    pub fn is_rejected(&self) -> bool { self.rejected }

    pub fn accumulated(&self, index: u32) -> Option<&str> {
        self.args_by_index.get(&index).map(|s| s.as_str())
    }
}

/// D1/H7 锁序不变量：keepalive gate 仅经 `Arc<AtomicBool>` 无锁读写，**不获取
/// 任何 hold 锁**，故不存在与 hold/审计锁的逆序获取；不得改为持锁路径。
#[derive(Debug)]
pub struct RequestKeepalive {
    live: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RequestKeepalive {
    pub fn spawn(tx: tokio::sync::mpsc::Sender<String>) -> Self {
        Self::spawn_gated(tx, Arc::new(AtomicBool::new(false)))
    }

    pub fn spawn_gated(tx: tokio::sync::mpsc::Sender<String>, gate: Arc<AtomicBool>) -> Self {
        Self::spawn_gated_with_interval(tx, gate, super::super::sse::KEEPALIVE_INTERVAL)
    }

    /// D1 门控极性：`gate=true` 为**抑制**信号（存在未完成 tool 分片），
    /// `false` 时保活帧按周期发送。与 `spawn.rs` 的 `has_pending_fragments()`
    /// 判据同源；`interval` 供单测注入小周期，生产恒用 `KEEPALIVE_INTERVAL`。
    pub fn spawn_gated_with_interval(
        tx: tokio::sync::mpsc::Sender<String>,
        gate: Arc<AtomicBool>,
        interval: std::time::Duration,
    ) -> Self {
        let live = Arc::new(AtomicBool::new(true));
        let flag = live.clone();
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if !flag.load(Ordering::Relaxed) {
                    break;
                }
                if gate.load(Ordering::Relaxed) {
                    continue;
                }
                if tx
                    .send(crate::service::sse::keepalive_frame())
                    .await
                    .is_err()
                {
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

/// D3 hold 单测（自 `audit_hold.rs` 随实现体并入，语义不变；用例见 `hold/tests.rs`）。
#[cfg(test)]
mod tests;
