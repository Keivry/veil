//! 兼容垫片（DEPRECATED）：`AuditHold`/`RequestKeepalive`/`HoldVerdict` 实现体
//! 归 `super::audit`；本文件恒仅重导出，**新代码 MUST 经
//! `crate::service::audit::{AuditHold, HoldVerdict, RequestKeepalive}` 引用，
//! MUST NOT 新增 `crate::service::audit_hold::*` 字面**——X9 收口后生产引用已
//! 全部迁至新路径，本路径仅为存量/外部兼容保留（grep `audit_hold::` 仅本文件
//! 自述命中）。

pub use super::audit::{AuditHold, HoldVerdict, RequestKeepalive};
