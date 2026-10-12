//! 阻断帧/体合成门面：子模块重导出，对外 `service::block_inject::*` 路径不变。
//!
//! 子模块划分：`frames` 三协议帧/体合成（流式阻断帧 + 非流阻断体 + 截断/空流合成），
//! `terminal` 去重终结（终端去重 + 计数 + `mark_terminal`）。
//! 单测外置同级 `tests.rs`（`super::*` 经重导出解析）。

pub mod frames;
pub mod terminal;

pub use {frames::*, terminal::*};

#[cfg(test)]
mod tests;
