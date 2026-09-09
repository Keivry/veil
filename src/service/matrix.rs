//! §6.2 审批流转（Matrix pending/超时）+ §6.5 Matrix Bot（D2 门面拆分）。
//!
//! - 白名单 MXID 精确匹配 + 发送者校验 + event id 精确匹配 + 幂等。
//! - 超时：凭据 300s / 审计 90s（`AUDIT_TIMEOUT` 禁 110-130 沿用 config 校验，默认拒绝）。
//! - `_ask` 返回 None 即 rejected 并清理；孤儿 pending 60s 清扫 tokio 任务。
//! - Bot 经 `reqwest` 长轮询 sync 实现，不引入 matrix-sdk 重依赖；五分支
//!   解锁/注册/哈希变更/凭据/审计 + ✅❎🔓 映射 + 摘要脱敏无明文。
//!
//! 接线：`AppState.approval` 持有本网关（白名单/`AUDIT_TIMEOUT` 来自 `Config`）；
//! 凭据 handler 经 `service::record_pending` 建单（submit + Bot best-effort 发送，
//! 立即返回 202）；问询经 `service::await_credential_approval`（300s）/
//! `await_audit_approval`（90s 口径）；`main` 启动 `spawn_sweeper` 常驻清扫 +
//! `MatrixBot::spawn_sync_loop` 常驻同步（since 持久化 + 指数退避 + 启动时间戳过滤）。
//!
//! 子模块划分（D2）：`branch` 分支/白名单/reaction 纯函数，`approval` 审批网关，
//! `bot` 长轮询 Bot；旧路径经重导出兼容，对外 `service::matrix::*` 不变。

pub mod approval;
pub mod bot;
pub mod branch;

pub use {approval::*, bot::*, branch::*};
