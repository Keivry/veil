//! SSE 门面：常量转发 + 子模块重导出，对外 `service::sse::*` 路径不变。
//!
//! 子模块划分：`meta` 截断元数据（`TruncatedMode/StreamMeta/set_truncated`），
//! `parser` 切行解析 + 超长行截断 + 残余分类（`SseParser/Utf8ByteBuffer/SseEvent`），
//! `emit` 保活帧 + 快慢径发送（`keepalive_frame/Speed/select_emit`）。
//! 单测：解析门面聚合于 `tests`（`super::*` 经重导出解析），快慢径/delta 切分回补、
//! data_frame 行终止为 `tests/` 主题子模块，门面零内联测试；各文件均 ≤ 本类红线。

/// 单测经 `super::*` 取 `GatewayMetrics/Protocol`，生产构建不引入（防 unused 警告）。
#[cfg(test)]
use super::llm_gateway::{GatewayMetrics, Protocol};
/// SSE 常量唯一定义归属 `config`（只搬不改值），此处原位转发防外部引用断裂。
pub use crate::config::{
    EVENT_IDLE_TIMEOUT,
    KEEPALIVE_INTERVAL,
    SSE_FRAME_HARD_BYTES,
    SSE_FRAME_SOFT_BYTES,
};
/// `KeepaliveTracker`（时间戳自检形态，生产零接线）已删除，保活唯一实现为
/// `RequestKeepalive`（`service::audit::RequestKeepalive::spawn_gated` 接线，接线点
/// `src/handler/llm/pump/spawn/setup.rs`，间隔消费 `KEEPALIVE_INTERVAL` 10s）。
pub mod emit;
pub mod meta;
pub mod parser;

pub use {emit::*, meta::*, parser::*};

#[cfg(test)]
mod tests;
