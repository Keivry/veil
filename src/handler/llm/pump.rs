//! 流泵单元：上游字节流泵为下游 SSE 帧流，保证终止闭合。
//!
//! 子模块划分（四桶映射）：`spawn` 主泵循环（透传臂/空流守门/hold 分支装配），
//! `event` 终止/次要事件判定 + SSE 响应装配，`toolbuf` tool 分桶缓冲与入口钳位，
//! `synth_flush` 合成终端前待发帧 flush（保序），
//! `carry` 跨帧占位符残缺前缀缝合，`decide` 主循环纯决策函数
//! （无 async/无 IO，供真值表断言）；旧路径经重导出兼容，对外 `handler::*` 不变。
//! tool 分片提取统一走 `service::llm_gateway::tool::extract_tool_calls_with`，不再保留薄适配模块。

use {
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            credential_vault::CredentialVault,
            llm_gateway::{GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::{Scope, leaf::RedactionTally},
        },
    },
    std::{sync::Arc, time::Instant},
};

pub mod carry;
pub mod event;
pub mod spawn;
pub mod synth_flush;
pub mod toolbuf;

pub mod decide;

#[cfg(test)]
mod tests;

/// 流式与非流共享的请求级上下文。由 `dispatch.rs` 单一装配点
/// 构造一次，供 `StreamPumpCtx`/`NonstreamCtx` 复用；SHALL NOT 在两条路径上
/// 各自重复装配同一请求字段（此前流/非流重叠 14 字段双份装配）。
#[derive(Clone)]
pub struct RequestCtx {
    pub protocol: Protocol,
    pub scope: Arc<Scope>,
    pub vault: Arc<CredentialVault>,
    pub detector: Arc<PiiDetector>,
    pub audit_mode: AuditMode,
    /// 启动期注入的共享策略实例（请求路径零读盘、零 env 快照）。
    pub audit_policy: Arc<crate::service::audit::AuditPolicy>,
    pub approval_whitelist: Vec<String>,
    /// 审计落盘单例（verdict 命中/放行经 `spawn_blocking` 写 JSONL）。
    pub audit_sink: Arc<crate::service::audit::AuditSink>,
    pub gateway_metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub pending: Arc<PendingApprovals>,
    pub normalized_out: bool,
    /// redact-only 对话变体标记（Anthropic `count_tokens`）——请求侧脱敏执行，
    /// 响应侧还原、审计判定、阻断合成、用量记账四类后处理显式跳过；
    /// **不并入** `is_passthrough`/`is_dialog`（由 `dispatch.rs` 装配点写入）。
    pub redact_only: bool,
    /// 请求侧三项脱敏计数（`request_rewrite` 报告透传；完成点只读，禁止重算）。
    /// 非对话/redact_only 路径恒为默认零值。
    pub redaction_tally: RedactionTally,
}

/// `stream_pump` 字节泵的上下文：共享请求上下文 + 流式专属字段。
pub struct StreamPumpCtx {
    /// 与 `NonstreamCtx` 共享的请求级字段（单一装配点构造）。
    pub req: RequestCtx,
    pub hold_max: usize,
    /// SSE 硬上限（配置 `SSE_FRAME_HARD_BYTES` 快照，默认 8MiB）：
    /// setup 经 [`crate::service::sse::SseParser::with_hard_bytes`] 注入解析器。
    pub sse_frame_hard_bytes: usize,
    pub init_conv: Option<String>,
    /// 请求侧 `model`；响应帧缺失有效 model 时回退分桶。
    pub req_model: String,
}

/// 流泵结束时的可观测结果（单测断言用）。
pub struct PumpOutcome {
    /// 转发出的 SSE 帧数（含最终 flush）。
    pub forwarded: usize,
    /// 是否注入过阻断帧。
    pub block_injected: bool,
    /// 终止标记是否落到 `StreamMeta`（`terminal_injected`）。
    pub terminal_injected: bool,
    /// 终端最终审计命中 `Block` 的 triple `output_index`（未命中为 `None`）。
    pub blocked_index: Option<u32>,
}

pub use {
    event::{build_sse_response, now_secs, should_synthesize_empty_stream},
    spawn::spawn_stream_pump,
};
