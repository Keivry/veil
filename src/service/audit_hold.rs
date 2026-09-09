//! D3 垫片：`AuditHold`/`RequestKeepalive` 实现体已并入 `super::audit`，
//! `HoldVerdict`/`decide_via_gateway` 归属本就相同；此处仅重导出，
//! 对外 `crate::service::audit_hold::*` 四符号路径不变。

pub use super::audit::{AuditHold, HoldVerdict, RequestKeepalive, decide_via_gateway};
