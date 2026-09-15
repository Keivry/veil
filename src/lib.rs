//! veil——Rust 实现的安全网关。
//!
//! crate 职责：凭据 API（三因子认证 + Matrix 审批）与 LLM 脱敏反向代理
//! （SSE 流式还原 + 输出审计），单端口 `8877` 同时承载两者（部署与行为见 README）。
//!
//! 模块组成：
//! - [`config`]/[`auth`]/[`error`]：配置解析、鉴权原语与统一错误类型；
//! - [`registry`]：调用方注册表（条目/ACL/持久化/旧格式迁移）；
//! - [`keepass`]：kdbx 库访问后端（真实 / CI Mock）；
//! - [`service`]：业务服务层（凭据、审计、脱敏、Matrix、指标、LLM 网关等）；
//! - [`handler`]：HTTP handler（凭据面 / LLM 代理 / 管理面）；
//! - [`router`]/[`state`]：路由装配与共享运行时状态。

pub mod approval;
pub mod auth;
pub mod config;
pub mod error;
pub mod fs_perm;
pub mod handler;
pub mod keepass;
pub mod registry;
pub mod router;
pub mod service;
pub mod state;

#[cfg(test)]
mod test_support;
