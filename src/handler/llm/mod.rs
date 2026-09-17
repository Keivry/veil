//! LLM 网关入口三单元装配（D1 拆分，D2 门面）：`rewrite`（请求改写）+ `nonstream`（一发一收）+
//! `pump`（流式字节泵）+ `dispatch`（入口分发）；本模块留守限值常量与共享小谓词，
//! 对外 `handler::*` 路径不变。

use {
    crate::service::{
        llm_gateway::{self, GatewayMetrics, Protocol},
        redaction::leaf::PROTOCOL_HEADER_NAME,
    },
    axum::{
        Json,
        http::{HeaderMap, StatusCode, header},
        response::{IntoResponse, Response},
    },
    serde_json::json,
};

pub mod dispatch;
pub mod nonstream;
pub mod pump;
pub mod rewrite;

#[cfg(test)]
mod gateway_tests;
#[cfg(test)]
mod proto_closeout_tests;
#[cfg(test)]
mod stream_fidelity_tests;
#[cfg(test)]
mod stream_tests;

/// 限值常量归属 `config.rs`（D1 下沉），此处原位转发防外部引用断裂。
pub use crate::config::{AUDIT_SUBLIMIT_CEILING_BYTES, GATEWAY_BODY_LIMIT_BYTES};

/// 审计/扫描类体长归属判定（spec 8MB 上限的回归锚点，不接请求路径）。
#[cfg(test)]
pub(crate) fn audit_scan_body_over_limit(len: usize) -> bool { len > AUDIT_SUBLIMIT_CEILING_BYTES }

/// 上游转发头：剥 `host`/`content-length`/`content-encoding` 与下游
/// `accept-encoding`（M1/D4：reqwest 仅在其请求头缺席时注入网关支持集
/// `gzip/br/deflate`，从而保证上游只回可解码编码），再做 hop 头过滤并计数。
pub fn forward_headers(incoming: &HeaderMap, metrics: &GatewayMetrics) -> HeaderMap {
    let mut fwd = incoming.clone();
    fwd.remove(header::HOST);
    fwd.remove(header::CONTENT_LENGTH);
    fwd.remove(header::CONTENT_ENCODING);
    fwd.remove(header::ACCEPT_ENCODING);
    // NLP-8：请求方向同样剔除下游 `x-veil-*` 内部头（大小写不敏感），防内部头外传上游。
    llm_gateway::strip_veil_internal_headers(&mut fwd);
    llm_gateway::filter_hop_headers_counted(
        &mut fwd,
        "upstream",
        llm_gateway::DECODE_ENABLED,
        Some(metrics),
    );
    fwd
}

pub(crate) fn protocol_header_value(protocol: Protocol) -> &'static str { protocol.wire_name() }

/// T10/D9：非流对话路径 + 流式错误透传路径由网关生成的响应置
/// `x-veil-protocol`（与成功的非流分支/阻断分支口径一致）；SSE 成功路径（`build_sse_response`）与
/// NonDialog 透传不置该头。
pub(crate) fn with_protocol_header(mut resp: Response, protocol: Protocol) -> Response {
    resp.headers_mut().insert(
        PROTOCOL_HEADER_NAME,
        header::HeaderValue::from_static(protocol_header_value(protocol)),
    );
    resp
}

pub(crate) fn empty_body_response(protocol: Protocol) -> Response {
    with_protocol_header(
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":{"code":"E_EMPTY_BODY","message":"上游返回空响应体"}})),
        )
            .into_response(),
        protocol,
    )
}

/// F-09：`Content-Type` 是否为 `text/event-stream`——仅取 `;` 前段、trim 后
/// 大小写不敏感比较，供 pump 路由与非流分类共用，消除第二决策站点。
pub(crate) fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// 流泵路由判定（D5 定稿：客户端 `stream` 意图优先）：上游 `Content-Type`
/// 为 `event-stream` 或请求 `stream==true` 即转流泵；`stream:true` 配
/// `application/json` 组合亦走流泵，由泵内残余分类保证不丢帧。
pub fn should_pump_stream(resp_content_type: &str, stream_flag: bool) -> bool {
    is_event_stream(resp_content_type) || stream_flag
}

pub use {
    dispatch::llm_proxy_handler,
    nonstream::{NonstreamCtx, NonstreamOutcome, serve_nondialog_passthrough, serve_nonstream},
    pump::{PumpOutcome, RequestCtx, StreamPumpCtx, build_sse_response, spawn_stream_pump},
    rewrite::{RewriteOutput, request_rewrite},
};
