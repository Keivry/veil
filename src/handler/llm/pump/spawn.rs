//! 流泵主循环（D2 自 `pump.rs` 拆出；ARC-1 收敛为薄壳）：setup → run_pump → finish。

use super::{PumpOutcome, StreamPumpCtx};

mod event_loop;
mod finish;
mod frame_feed;
mod setup;
mod terminal;
pub(crate) use frame_feed::guard_restored_frame;

/// 2.3 `spawn_stream_pump`：把上游字节流泵为下游 SSE 帧流，保证终止闭合；
/// 阻断或合成终止时注入终止标记。`upstream` 所有权移入 task，不解析业务语义之外的状态。
/// ARC-1：薄壳——建 setup、驱动主循环、收尾三段委托子模块。
pub fn spawn_stream_pump(
    upstream: reqwest::Response,
    tx: tokio::sync::mpsc::Sender<String>,
    ctx: StreamPumpCtx,
) -> tokio::task::JoinHandle<PumpOutcome> {
    tokio::spawn(async move {
        let mut upstream = upstream;
        let (env, mut state, mut parser): (
            setup::PumpEnv,
            setup::PumpLoopState,
            crate::service::sse::SseParser,
        ) = setup::setup(ctx, tx);
        let spans = |window: &str, seam: usize| setup::boundary_spans(&env, window, seam);
        let transport_error =
            event_loop::run_pump(&mut upstream, &mut parser, &mut state, &env, &spans).await;
        finish::finish(&env, state, &mut parser, transport_error, &spans).await
    })
}
