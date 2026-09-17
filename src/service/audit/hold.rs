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

/// STP-5/D6：hold **条目数上限**——与字节上限（`AUDIT_HOLD_MAX_BYTES`）并行的
/// 独立维度。零字节分片（`output_item.added`、空 `function_call` 等不计
/// `total_bytes` 的碎片）若只按字节记账可无限创建槽/条目，故以本上限约束活跃
/// 条目数（Chat/Anthropic 的 `args_by_index` + Responses 的 `responses_slots`）；
/// 超限与字节超限同语义 fail-closed 并清仓，使零字节洪泛下内存有界。
const AUDIT_HOLD_MAX_ENTRIES: usize = 4096;

/// D3 hold 累积与流内保活（自 `audit_hold.rs` 并入，判定归属本模块）：
/// `AuditHold` 只累积不合成帧，`RequestKeepalive` 为流内保活唯一实现。
#[derive(Debug, Default)]
struct ResponsesSlot {
    output_index: u32,
    name: Option<String>,
    /// RSP-5/2.29：以 `sequence_number` 为键（缺失按到达序补号），`full_args`
    /// 按键升序缝合——乱序/交错到达不放乱相对次序。
    frags: std::collections::BTreeMap<u64, String>,
    next_seq: u64,
    done_args: Option<String>,
    done_seen: bool,
}

impl ResponsesSlot {
    /// S7/D8：本槽已计入 `total_bytes` 的字节（RED-6：完整 `.done` 参数优先，
    /// 与 [`ResponsesSlot::full_args`] 同口径，保证释放时归还一致）。
    fn held_bytes(&self) -> usize {
        match self.done_args.as_deref() {
            Some(done) => done.len(),
            None => self.frags.values().map(|s| s.len()).sum(),
        }
    }

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
    /// C-3/D1（5.4）：`pending_tool_frames` 缓冲帧记账——条目与字节双维度与聚合
    /// 槽位（`args_by_index`/`responses_slots`）**独立**：同一 index 零字节分片
    /// 不创建聚合条目也不加聚合字节，聚合维度看不见该洪泛，故须独立计数。
    pending_frames: usize,
    pending_bytes: usize,
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
        // R5-17：字节记账饱和——接近类型上界时回绕会令超限判定误放行。
        self.total_bytes = self.total_bytes.saturating_add(args_delta.len());
        if self.total_bytes > self.max_bytes || self.entries_over_cap() {
            return self.reject_and_clear();
        }
        HoldVerdict::Approved
    }

    /// 条目数维度是否超限（零字节分片同样计入，见 [`AUDIT_HOLD_MAX_ENTRIES`]）。
    fn entries_over_cap(&self) -> bool {
        self.args_by_index.len() + self.responses_slots.len() > AUDIT_HOLD_MAX_ENTRIES
    }

    /// C-3/D1（5.4）：tool 缓冲帧入账——调用方在 `pending_tool_frames.push`
    /// **之前**调用；条目维度复用 [`AUDIT_HOLD_MAX_ENTRIES`]，字节维度以独立
    /// 计数器受 `max_bytes`（`AUDIT_HOLD_MAX_BYTES`）约束。超限与聚合超限同语义
    /// fail-closed 清仓（调用方据此走 `audit-hold-overflow` 阻断臂，不静默丢弃）。
    pub fn account_pending_frame(&mut self, bytes: usize) -> HoldVerdict {
        if self.rejected || self.completed {
            return if self.rejected {
                HoldVerdict::Rejected
            } else {
                HoldVerdict::Approved
            };
        }
        self.pending_frames = self.pending_frames.saturating_add(1);
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        if self.pending_frames > AUDIT_HOLD_MAX_ENTRIES || self.pending_bytes > self.max_bytes {
            return self.reject_and_clear();
        }
        HoldVerdict::Approved
    }

    /// C-3/D1（5.4）：tool 缓冲帧出账——缓冲帧重放（按槽取出）后归还对应条目
    /// 与字节，长流多轮 drain 不误判溢出。
    pub fn release_pending_frames(&mut self, count: usize, bytes: usize) {
        self.pending_frames = self.pending_frames.saturating_sub(count);
        self.pending_bytes = self.pending_bytes.saturating_sub(bytes);
    }

    #[cfg(test)]
    pub(crate) fn pending_accounting(&self) -> (usize, usize) {
        (self.pending_frames, self.pending_bytes)
    }

    /// 字节或条目超限共用的 fail-closed 清仓（拒绝态 + 归零 + 清空全部槽）。
    fn reject_and_clear(&mut self) -> HoldVerdict {
        self.rejected = true;
        self.total_bytes = 0;
        self.args_by_index.clear();
        self.name_by_index.clear();
        self.id_by_index.clear();
        self.responses_slots.clear();
        self.pending_frames = 0;
        self.pending_bytes = 0;
        HoldVerdict::Rejected
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
            // R5-17：游标饱和推进——`seq_no == u64::MAX` 时不得回绕复用 `BTreeMap` 键。
            slot.next_seq = slot.next_seq.saturating_add(1);
            n
        });
        slot.next_seq = slot.next_seq.max(seq_no.saturating_add(1));
        let added_bytes = match slot.frags.entry(seq_no) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(args_delta.to_string());
                args_delta.len()
            }
            std::collections::btree_map::Entry::Occupied(_) => 0,
        };
        self.total_bytes = self.total_bytes.saturating_add(added_bytes);
        if self.total_bytes > self.max_bytes || self.entries_over_cap() {
            return self.reject_and_clear();
        }
        HoldVerdict::Approved
    }

    pub fn mark_responses_done(&mut self, item_key: &str, full_args: Option<&str>) {
        let Some(slot) = self.responses_slots.get_mut(item_key) else {
            return;
        };
        slot.done_seen = true;
        // RED-4：空 `.done` 载荷（四类工具 delta 的 done 不携完整参数）不得
        // 覆盖已累积参数；只有非空完整参数才作为判定文本。
        let Some(args) = full_args.filter(|a| !a.is_empty()) else {
            return;
        };
        // RED-6：完整参数替代已累积分片文本，字节只计一次（先归还分片计数）。
        let old: usize = slot.frags.values().map(|s| s.len()).sum();
        slot.done_args = Some(args.to_string());
        slot.frags.clear();
        self.total_bytes = self
            .total_bytes
            .saturating_sub(old)
            .saturating_add(args.len());
        if self.total_bytes > self.max_bytes || self.entries_over_cap() {
            self.reject_and_clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn is_responses_complete(&self, item_key: &str) -> bool {
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

    /// D5/STP-1：仍缺 per-item `.done` 的 Responses 槽三元组（按已累积参数）。
    /// 供全局完成路径「先审后放」——与 [`AuditHold::responses_triples`] 的 done 槽
    /// 口径同源，仅筛选条件相反。
    pub fn responses_pending_triples(&self) -> Vec<(u32, String, String)> {
        self.responses_slots
            .values()
            .filter(|s| !s.done_seen)
            .map(|s| {
                (
                    s.output_index,
                    s.name.clone().unwrap_or_default(),
                    s.full_args(),
                )
            })
            .collect()
    }

    /// RED-5 全局完成判定（语义收窄）：仅 `message_stop`/`response.completed`/
    /// `response.failed`/`response.incomplete` 触发全局 `mark_completed`。
    /// Chat `finish_reason`（含 `tool_calls`）不再置全局完成——晚到 tool 分片
    /// 继续累积入槽并受审计（审计到期见 [`AuditHold::is_audit_due_event`]）。
    /// `content_block_stop`/`item_done` 只清对应 index 槽（见
    /// [`AuditHold::is_index_complete_event`] +
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
        payload
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| {
                matches!(
                    t,
                    "message_stop"
                        | "response.completed"
                        | "response.failed"
                        | "response.incomplete"
                )
            })
    }

    /// RED-5 审计到期判定（与全局完成分离）：Chat 任意非空 `finish_reason`
    /// （顶层、`choices[].finish_reason`、`delta.finish_reason`、`message.finish_reason`，
    /// `tool_calls` 在内）触发该轮 tool 参数审计评估与 `block` 阻断；非 Chat 以
    /// 官方完成事件为审计到期点（槽级/按 index 完成另经
    /// [`AuditHold::is_responses_slot_complete_event`]/[`AuditHold::is_index_complete_event`]）。
    pub fn is_audit_due_event(
        protocol: crate::service::llm_gateway::Protocol,
        payload: &Value,
    ) -> bool {
        if protocol == crate::service::llm_gateway::Protocol::Chat {
            return has_nonempty_finish_reason(payload);
        }
        Self::is_complete_event(payload)
    }

    /// CHC-5/2.24：Chat 任一非空 `finish_reason`（成功收尾信号）判定，供干净 EOF
    /// 与异常截断区分——干净收尾 SHALL NOT 记 `open_ended`。
    pub fn chat_finish_reason_present(payload: &Value) -> bool {
        has_nonempty_finish_reason(payload)
    }

    /// D2 槽级完成事件判定：`response.output_item.done`/
    /// `response.function_call_arguments.done` 只完成对应 item 槽，
    /// 由调用方审计并清理该槽，不影响全局完成。
    /// RED-4：四类工具 delta 的 `.done`（code_interpreter/shell/mcp/custom_tool）
    /// 同属槽级完成，使四类审计可达。
    pub fn is_responses_slot_complete_event(payload: &Value) -> bool {
        payload
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| {
                t == "response.output_item.done"
                    || t == "response.function_call_arguments.done"
                    || t == "response.code_interpreter_call_code.done"
                    || t == "response.shell_call_command.done"
                    || t == "response.mcp_call_arguments.done"
                    || t == "response.custom_tool_call_input.done"
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
        self.pending_frames = 0;
        self.pending_bytes = 0;
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

    #[cfg(test)]
    pub(crate) fn held(&self) -> bool { !self.completed && !self.rejected }

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

    #[cfg(test)]
    pub(crate) fn accumulated(&self, index: u32) -> Option<&str> {
        self.args_by_index.get(&index).map(|s| s.as_str())
    }
}

/// RED-5：Chat 任意非空 `finish_reason`（四处载体）判定，供审计到期使用。
fn has_nonempty_finish_reason(payload: &Value) -> bool {
    let nonempty = |v: Option<&Value>| v.and_then(|x| x.as_str()).is_some_and(|s| !s.is_empty());
    if nonempty(payload.get("finish_reason")) {
        return true;
    }
    payload
        .get("choices")
        .and_then(|c| c.as_array())
        .is_some_and(|choices| {
            choices.iter().any(|ch| {
                nonempty(ch.get("finish_reason"))
                    || nonempty(ch.get("delta").and_then(|d| d.get("finish_reason")))
                    || nonempty(ch.get("message").and_then(|m| m.get("finish_reason")))
            })
        })
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

    #[cfg(test)]
    pub(crate) fn is_live(&self) -> bool { self.live.load(Ordering::Relaxed) }
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

/// keepalive 门控与竞态常量测试（触 800 红线后按测试外迁模板独立成子模块）。
#[cfg(test)]
mod keepalive_tests;

/// 同 index 零字节分片洪泛记账测试（触 800 红线后按同一测试外迁模板独立成子模块）。
#[cfg(test)]
mod zero_byte_tests;
