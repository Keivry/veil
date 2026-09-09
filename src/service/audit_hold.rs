//! D3 垫片：`AuditHold`/`RequestKeepalive` 实现体已并入 `super::audit`，
//! `HoldVerdict`/`decide_via_gateway` 归属本就相同；此处仅重导出，
//! 对外 `crate::service::audit_hold::*` 四符号路径不变。
//!
//! H3.1 owner 锁定：实现 owner 为 `service::audit::hold`（经 `service::audit`
//! 重导出）；本文件恒仅重导出垫片，新代码 MUST 经 `crate::service::audit::*`
//! 引用，不得新增本路径引用（存量 `pump` 等引用兼容保留，不强制迁移）。

pub use super::audit::{AuditHold, HoldVerdict, RequestKeepalive, decide_via_gateway};
