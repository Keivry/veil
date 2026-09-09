//! 服务层索引：仅模块声明与旧路径重导出（A1 解耦后本文件零业务逻辑）。
//!
//! 依赖方向：`state` 聚合本层类型（`state -> service`）；本层业务经
//! [`credential::AppStateParts`] trait 读态，不再命名 `crate::state`
//! （`service -> state` 边已断，单向无环）。

pub mod admin;
pub mod audit;
pub mod audit_hold;
pub mod block_inject;
pub mod credential;
/// §3 脱敏子模块（单向依赖：只读 `state` 经调用方注入，不触网络与路由）。
pub mod credential_vault;
pub mod json_walk;
pub mod llm_gateway;
pub mod matrix;
pub mod metrics;
pub mod pii;
pub mod redaction;
pub mod sse;
pub mod tpm;

/// 旧路径兼容：`crate::service::{handle_credential, RateTable, ...}`
/// 一律经本重导出解析，调用方零改。
pub use credential::*;
