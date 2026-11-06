//! 会话响应写回与响应级捕获计数（design D4 / D8）。
//!
//! 响应阶段**只绑定、不换键**：用请求到达时已确定的 `canonical` 把上游标识
//! 写入别名表，绝不重新解析身份、绝不迁移或替换 `PiiScope`。
//!
//! 两部分：
//! - [`ConversationWriteback`]：携带请求时的 [`SessionIdentity`]、HMAC 密钥与别名表， 负责把
//!   [`CapturedIds`] 绑到 canonical（`response.id` 恒绑定； `conversation.id` 仅在请求未携带
//!   `conversation` 时绑定，防抢先绑定）；
//! - [`CaptureTracker`]：响应级捕获状态机，保证 `conversation_writeback_miss` 与
//!   `session_bind_miss` **每响应至多一次**且互斥（写回失败优先占位）。
//!
//! 敏感值（上游 id、canonical、租户指纹、密钥）一律不落日志、不进 `Debug`。

use {
    super::{
        ConversationKey,
        Scope,
        session_alias::{BindOutcome, SessionAliasMap},
    },
    crate::service::{
        llm_gateway::{GatewayMetrics, Protocol},
        lock_recover::lock_or_recover,
        session_identity::{CapturedIds, ResponseShape, SessionIdentity, capture_response_ids},
    },
    serde_json::Value,
    std::{
        collections::HashSet,
        sync::{Arc, Mutex},
    },
};

/// 请求级会话写回上下文（挂在 [`Scope`] 上，供响应完成处绑定别名）。
///
/// 仅当请求解析出 `canonical` 时存在（`request` 模式下同样挂载，仅跳过
/// `ConversationScopeStore` 创建）。
#[derive(Clone)]
pub(crate) struct ConversationWriteback {
    identity: SessionIdentity,
    secret: Arc<[u8]>,
    alias: Arc<SessionAliasMap>,
    conflict_reported: Arc<Mutex<HashSet<String>>>,
}

/// 手工 `Debug`：会话键/租户指纹/HMAC 密钥/上游 id 均为敏感值，一律脱敏。
impl std::fmt::Debug for ConversationWriteback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWriteback")
            .field("identity", &"[redacted]")
            .field("secret", &"[redacted]")
            .field("alias", &"[redacted]")
            .finish()
    }
}

impl ConversationWriteback {
    pub(crate) fn new(
        identity: SessionIdentity,
        secret: Arc<[u8]>,
        alias: Arc<SessionAliasMap>,
    ) -> Self {
        Self {
            identity,
            secret,
            alias,
            conflict_reported: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// 绑定一次捕获结果（无 canonical 时 no-op；冲突/跳过只由别名表计数）。
    ///
    /// `response.id` 恒绑定到请求时的 canonical；`conversation.id` 仅在请求
    /// **未携带** `conversation` 字段时绑定（请求自带的值不写别名，防抢先绑定）。
    pub(crate) fn record(&self, captured: &CapturedIds) {
        let Some(canonical) = self.identity.canonical.as_ref() else {
            return;
        };
        if let Some(response_id) = captured.response_id.as_deref() {
            self.bind_and_report(response_id, canonical);
        }
        if !self.identity.request_carried_conversation
            && let Some(conversation_id) = captured.conversation_id.as_deref()
        {
            self.bind_and_report(conversation_id, canonical);
        }
    }

    /// 响应内按 upstream id 去重冲突上报：流式多帧重复同一 id 时只计一次指标/告警。
    fn bind_and_report(&self, upstream_id: &str, canonical: &ConversationKey) {
        let outcome = self.alias.bind_silent(
            self.secret.as_ref(),
            self.identity.tenant_fingerprint.as_str(),
            upstream_id,
            canonical,
        );
        if outcome != BindOutcome::Conflict {
            return;
        }
        let mut reported = lock_or_recover(self.conflict_reported.lock());
        if reported.insert(upstream_id.to_string()) {
            drop(reported);
            self.alias.report_conflict();
        }
    }
}

/// 响应级捕获状态机（非流/流式/透传三路共用）。
///
/// 每响应至多计一次 `conversation_writeback_miss`（`conversation` 模式、Responses 2xx
/// 且缺 `response.id`，以 `has_conversation_scope` 门控）或一次 `session_bind_miss`
/// （已取得可用上游 id 但无写回上下文）。二者按优先级互斥，不双计。
#[derive(Debug, Default)]
pub struct CaptureTracker {
    /// 本响应是否已计 `conversation_writeback_miss`（每响应至多一次）。
    writeback_miss_counted: bool,
    /// 本响应是否已计 `session_bind_miss`（每响应至多一次）。
    bind_miss_counted: bool,
    /// 流式跨帧累积：是否至少捕获到一个上游 id。
    captured_any: bool,
    /// 流式跨帧累积：是否捕获到 `response.id`（判定写回失败的依据）。
    captured_response_id: bool,
}

impl CaptureTracker {
    /// 单响应/单帧：捕获 → 绑定（**不做** miss 计数）。
    ///
    /// 非流路径随后调用 [`Self::observe`]（或直接 [`Self::finish`]）完成一次性计数；
    /// 流式路径每帧调用本方法，收尾时由 `finish.rs` 调 [`Self::finish`]。
    pub fn observe_frame(
        &mut self,
        scope: &Scope,
        protocol: Protocol,
        status: u16,
        value: &Value,
    ) -> CapturedIds {
        self.capture_into(scope, protocol, status, value, ResponseShape::StreamEvent)
    }

    fn capture_into(
        &mut self,
        scope: &Scope,
        protocol: Protocol,
        status: u16,
        value: &Value,
        shape: ResponseShape,
    ) -> CapturedIds {
        let captured = capture_response_ids(value, status, protocol, shape);
        if !captured.is_empty() {
            self.captured_any = true;
            scope.record_capture(&captured);
        }
        if captured.response_id.is_some() {
            self.captured_response_id = true;
        }
        captured
    }

    /// 单响应（非流/透传整包）：捕获 → 绑定 → 一次性 miss 计数。
    ///
    /// 返回捕获结果，供调用方做展示锚点提取（绑定**只用**本函数的捕获）。
    pub fn observe(
        &mut self,
        scope: &Scope,
        protocol: Protocol,
        status: u16,
        value: &Value,
        metrics: &GatewayMetrics,
    ) -> CapturedIds {
        let captured = self.capture_into(scope, protocol, status, value, ResponseShape::Complete);
        self.account(scope, protocol, status, metrics);
        captured
    }

    /// 流式收尾：按整响应累积状态做一次性 miss 计数。
    ///
    /// 调用方 MUST 仅在**非截断**的干净完成时调用（`finish.rs` 已按
    /// `stream_truncated` 门控），使中断流不计写回失败。
    pub fn finish(
        &mut self,
        scope: &Scope,
        protocol: Protocol,
        status: u16,
        metrics: &GatewayMetrics,
    ) {
        self.account(scope, protocol, status, metrics);
    }

    /// 每响应一次性 miss 计数（互斥 + 优先级：写回失败先占）。
    ///
    /// 仅 `Protocol::Responses` 且 2xx 时可能计数；Chat/Anthropic 与 4xx/5xx 恒不计数。
    fn account(
        &mut self,
        scope: &Scope,
        protocol: Protocol,
        status: u16,
        metrics: &GatewayMetrics,
    ) {
        if !protocol.is_responses() || !(200..=299).contains(&status) {
            return;
        }
        if !self.captured_response_id && scope.has_conversation_scope() {
            if !self.writeback_miss_counted {
                metrics.record_conversation_writeback_miss();
                self.writeback_miss_counted = true;
            }
            return;
        }
        if self.captured_any
            && !scope.has_writeback()
            && !self.bind_miss_counted
            && !self.writeback_miss_counted
        {
            metrics.record_session_bind_miss();
            self.bind_miss_counted = true;
        }
    }
}

#[cfg(test)]
mod tests;
