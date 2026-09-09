//! 脱敏外观（§3.1–§3.4 编排，D2 门面拆分）：请求级 `Scope` + 全出口残缺清理 +
//! 凭据优先 + json-aware 双侧脱敏。
//!
//! 管线（对标 design D3：凭据替换 → PII 替换 → json-walk 全量扫描 → roundtrip 校验）：
//! - 请求侧：凭据明文→`__VG_CRED_NNNNNN__`，PII→`__PII_<seq>_<rand8>__`（本 Scope 注册）；
//! - 响应侧：先还原本 Scope 请求 token 与凭据 token，再剥离幻觉完整凭据 token， 最后
//!   `_strip_partials` 残缺清理接全出口；响应期新检出 PII 注册进响应表， 原样保留不还原；
//! - 单向依赖：本模块只读 `state` 经调用方注入的 vault/detector，不触网络与路由。
//!
//! 子模块划分（D2）：`scope` 请求/响应双侧编排，`seam` 跨帧边界 hold，
//! `leaf` 叶回调与请求字节选择；旧路径经重导出兼容，对外 `redaction::*` 不变。

pub mod leaf;
pub mod scope;
pub mod seam;

pub use {leaf::*, scope::*, seam::*};
