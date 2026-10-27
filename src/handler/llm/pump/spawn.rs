//! 流泵主循环（自 `pump.rs` 拆出；收敛为薄壳）：setup → run_pump → finish。

use super::{PumpOutcome, StreamPumpCtx};

mod event_loop;
mod finish;
mod frames;
mod release;
mod setup;
mod terminal;
// 类型 `pub(in crate::handler::llm::pump)`，模块须同宽以供兄弟测试命名。
pub(in crate::handler::llm::pump) mod terminator;
#[cfg(test)]
pub(crate) use frames::guard_restored_frame;

/// `spawn_stream_pump`：把上游字节流泵为下游 SSE 帧流，保证终止闭合；
/// 阻断或合成终止时注入终止标记。`upstream` 所有权移入 task，不解析业务语义之外的状态。
/// 薄壳——建 setup、驱动主循环、收尾三段委托子模块。
pub fn spawn_stream_pump(
    upstream: reqwest::Response,
    tx: tokio::sync::mpsc::Sender<String>,
    ctx: StreamPumpCtx,
) -> tokio::task::JoinHandle<PumpOutcome> {
    crate::logging::spawn_in_request_span(async move {
        let mut upstream = upstream;
        let (env, mut state, mut parser): (
            setup::PumpEnv,
            setup::PumpLoopState,
            crate::service::sse::SseParser,
        ) = setup::setup(ctx, tx);
        let transport_error =
            event_loop::run_pump(&mut upstream, &mut parser, &mut state, &env).await;
        finish::finish(&env, state, &mut parser, transport_error).await
    })
}
