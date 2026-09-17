//! ARC-1：流泵 setup——`StreamPumpCtx` 解构、循环可变状态聚合与只读依赖装配。

use {
    super::{
        super::{RequestCtx, StreamPumpCtx, carry::TokenCarry, toolbuf::clamp_pump_limits},
        terminator::StreamTerminator,
    },
    crate::{
        approval::PendingApprovals,
        config::AuditMode,
        service::{
            audit::{AuditHold, AuditPolicy, AuditSink, RequestKeepalive},
            credential_vault::CredentialVault,
            llm_gateway::{self, GatewayMetrics, Protocol},
            metrics::MetricsStore,
            pii::PiiDetector,
            redaction::{BoundaryHold, PrefixHold, Scope, marker_cross_spans},
            sse::{Speed, SseParser, StreamMeta},
        },
    },
    std::{
        sync::{Arc, atomic::AtomicBool},
        time::Instant,
    },
};

/// ARC-1：单事件处理的只读依赖与出口通道（setup 装配，主循环/单事件处理共享）。
pub(super) struct PumpEnv {
    pub protocol: Protocol,
    pub resp_scope: Arc<Scope>,
    pub resp_vault: Arc<CredentialVault>,
    pub resp_detector: Arc<PiiDetector>,
    pub audit_mode: AuditMode,
    pub audit_policy: Arc<AuditPolicy>,
    pub approval_whitelist: Vec<String>,
    pub audit_sink: Arc<AuditSink>,
    pub metrics: Arc<GatewayMetrics>,
    pub admin_metrics: Arc<MetricsStore>,
    pub sqlite_precise: bool,
    pub req_start: Instant,
    pub audit_pending: Arc<PendingApprovals>,
    pub pump_tx: tokio::sync::mpsc::Sender<String>,
    pub speed: Speed,
    pub hold_gate: Arc<AtomicBool>,
    /// NLP-2/3.9：请求侧 `model`，流式响应帧缺失有效 model 时回退分桶。
    pub req_model: String,
    /// 保活任务句柄（持有即存活），仅供生命周期持有。
    pub _keepalive: RequestKeepalive,
}

/// ARC-1：循环可变状态（setup 构造，主循环与单事件处理共享）。
pub(super) struct PumpLoopState {
    pub conv_id: Option<String>,
    pub stream_first_id: Option<String>,
    pub stream_model: Option<String>,
    /// 响应帧是否已提供有效 model（用于请求侧 model 回退判定）。
    pub stream_model_from_resp: bool,
    pub stream_usage: Option<llm_gateway::Usage>,
    pub hold: AuditHold,
    pub carry: TokenCarry,
    pub prefix_hold: PrefixHold,
    pub boundary: BoundaryHold,
    pub pending_tool_frames: Vec<(Vec<u32>, String, String)>,
    pub meta: StreamMeta,
    pub agg: String,
    pub forwarded: usize,
    /// 1.2：终端状态机（`StreamTerminator` 为终端状态**唯一所有者**，取代此前 7 枚
    /// 散落 bool：`any_frame_sent`/`terminated`/`rejected_sticky`/`block_injected`/
    /// `audit_blocked`/`terminal_sent`/`responses_failed_sent`），经访问器/变更器读写。
    /// `decide.rs`/`event.rs` 中的同名项为**纯函数入参**，不构成第二份状态。
    pub terminator: StreamTerminator,
    /// A-2/F-02：Responses「已见上游序号上界」游标（仅 Responses 帧更新；
    /// 缺 `sequence_number` 不推进、回退忽略），供阻断/截断合成取 `base = max + 1`。
    pub responses_seq_cursor: Option<u64>,
    /// CHC-5/2.24：Chat 已见非空 `finish_reason`（干净收尾信号）。
    pub chat_finish_seen: bool,
}

/// ARC-1：setup 构造器——解构 `StreamPumpCtx`，钳位配置，装配环境、循环状态与解析器。
pub(super) fn setup(
    ctx: StreamPumpCtx,
    tx: tokio::sync::mpsc::Sender<String>,
) -> (PumpEnv, PumpLoopState, SseParser) {
    let StreamPumpCtx {
        req,
        hold_max,
        pii_boundary_chars,
        init_conv,
        req_model,
    } = ctx;
    let RequestCtx {
        protocol,
        scope: resp_scope,
        vault: resp_vault,
        detector: resp_detector,
        audit_mode,
        audit_policy,
        approval_whitelist,
        audit_sink,
        gateway_metrics: metrics,
        admin_metrics,
        sqlite_precise,
        req_start,
        pending: audit_pending,
        normalized_out: _,
        redact_only: _,
    } = req;
    let (hold_max, pii_boundary_chars) = clamp_pump_limits(hold_max, pii_boundary_chars);
    let speed = if matches!(audit_mode, AuditMode::Off) {
        Speed::Fast
    } else {
        Speed::Slow
    };
    let hold_gate = Arc::new(AtomicBool::new(false));
    let keepalive = RequestKeepalive::spawn_gated(tx.clone(), hold_gate.clone());
    let state = PumpLoopState {
        conv_id: init_conv.clone(),
        stream_first_id: init_conv,
        stream_model: None,
        stream_model_from_resp: false,
        stream_usage: None,
        hold: AuditHold::new(hold_max),
        carry: TokenCarry::new(),
        prefix_hold: PrefixHold::new(resp_detector.partial_prefix_hints()),
        boundary: BoundaryHold::new(pii_boundary_chars),
        pending_tool_frames: Vec::new(),
        meta: StreamMeta::default(),
        agg: String::new(),
        forwarded: 0,
        terminator: StreamTerminator::new(),
        responses_seq_cursor: None,
        chat_finish_seen: false,
    };
    let env = PumpEnv {
        protocol,
        resp_scope,
        resp_vault,
        resp_detector,
        audit_mode,
        audit_policy,
        approval_whitelist,
        audit_sink,
        metrics,
        admin_metrics,
        sqlite_precise,
        req_start,
        audit_pending,
        pump_tx: tx,
        speed,
        hold_gate,
        req_model,
        _keepalive: keepalive,
    };
    (env, state, SseParser::new())
}

/// ARC-1：边界 hold 跨缝 span 计算（原 `spawn_stream_pump` 内联闭包，抽为共享函数）。
pub(super) fn boundary_spans(env: &PumpEnv, window: &str, seam: usize) -> Vec<(usize, usize)> {
    let cred_map = env.resp_vault.p2t_snapshot();
    let mut spans: Vec<(usize, usize)> = env
        .resp_detector
        .scan_spans_sync(window, cred_map.map())
        .into_iter()
        .map(|(_, _, s, e)| (s, e))
        .collect();
    spans.extend(marker_cross_spans(window, seam));
    spans
}
