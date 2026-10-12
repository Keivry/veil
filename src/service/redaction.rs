//! 脱敏外观（编排，门面拆分）：请求级 `Scope` + 全出口残缺清理 +
//! 凭据优先 + json-aware 双侧脱敏。
//!
//! 管线（凭据替换 → PII 替换 → json-walk 全量扫描 → roundtrip 校验）：
//! - 请求侧：凭据明文→`__CRED_NNNNNN__`，PII→`__PII_<seq>_<rand8>__`（本 Scope 注册）；
//! - 响应侧：先还原本 Scope 请求 token 与凭据 token，未注册/未授权完整 token 原样透传，最后
//!   `_strip_partials` 残缺清理接全出口；上游新吐出的明文 PII 原样透出，不再二次脱敏；
//! - 单向依赖：本模块只读 `state` 经调用方注入的 vault/detector，不触网络与路由。
//!
//! 子模块划分：`scope` 请求/响应双侧编排，`leaf` 叶回调与请求字节选择；
//! 旧路径经重导出兼容，对外 `redaction::*` 不变。

pub mod conversation_key;
pub mod conversation_store;
pub mod leaf;
pub mod restore_guard;
pub mod scope;

pub use {conversation_key::*, conversation_store::*, scope::*};

/// 上游 prompt cache 保真与注入位置测试（4.1–4.4，聚合单测入口）。
#[cfg(test)]
mod tests;
