//! 单帧 JSON 观测写回：会话/模型/用量/上游错误终端的集中记账（自 `event_loop.rs`
//! 拆出，纯搬移行为不变）。

use {
    crate::{
        handler::llm::pump::{
            event::{is_terminal_event, is_upstream_error_terminal, stream_model_of},
            spawn::setup::{PumpEnv, PumpLoopState},
        },
        service::{
            audit::AuditHold,
            llm_gateway,
            sse::{TruncatedMode, set_truncated},
        },
    },
    serde_json::Value,
};

/// ARH-2（6.1/7.1）：每帧单次全量 JSON 解析后的观测写回（`handle_event` 调用，
/// 空帧/`[DONE]`/非法 JSON 不进入本函数）。
pub(super) fn observe_parsed_frame(state: &mut PumpLoopState, env: &PumpEnv, v: &Value) {
    let response_id = llm_gateway::extract_conv_id(v);
    let wrote = response_id
        .as_deref()
        .is_some_and(|id| env.resp_scope.record_response_id(env.protocol, id));
    // R5-09/D10：写回失败仅「响应 id 缺失/为空」计一次；无写回上下文（`request`
    // 模式/键未推导）与非 Responses 协议门控 MUST NOT 计入。计数点取 Responses
    // 官方终端帧且本流从未见过 id，保证一次响应恰一次（不回退为逐帧误计）。
    if !wrote
        && env.protocol.is_responses()
        && response_id.is_none()
        && env.resp_scope.has_conversation()
        && state.conv_id.is_none()
        && is_terminal_event(env.protocol, v)
    {
        env.metrics.record_conversation_writeback_miss();
    }
    if let Some(id) = response_id {
        if state.stream_first_id.is_none() {
            state.stream_first_id = Some(id.clone());
        }
        state.conv_id = Some(id);
    }
    if let Some(m) = stream_model_of(v).filter(|m| !m.is_empty()) {
        state.stream_model = Some(m.to_string());
        state.stream_model_from_resp = true;
    } else if !state.stream_model_from_resp && !env.req_model.is_empty() {
        state.stream_model = Some(env.req_model.clone());
    }
    llm_gateway::accumulate_usage(
        &mut state.stream_usage,
        llm_gateway::extract_usage_stream(env.protocol, v),
    );
    if env.protocol.is_chat() && AuditHold::chat_finish_reason_present(v) {
        state.chat_finish_seen = true;
    }
    // A-6/F-08 + R5-04：上游错误即终端（Chat 顶层 `error` 无 `choices`；Anthropic
    // `type:"error"`）——观测记 `upstream_error`（区别于 `open_ended`）；本帧仍作
    // 终端帧透出，其后数据帧由终端守卫丢弃，流末不再补合成终端。
    if is_upstream_error_terminal(env.protocol, v) && !state.terminator.terminal_sent() {
        let _ = set_truncated(
            &mut state.meta,
            env.protocol,
            TruncatedMode::UpstreamError,
            Some(&env.metrics),
        );
    }
}
