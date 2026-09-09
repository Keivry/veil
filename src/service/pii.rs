//! PII 检测器 + 请求级 PII token（§3.2 / §3.3）。
//!
//! 子模块划分（A2）：`detector` 内置原语 + 检测器核心，`scope`
//! 请求级 token 容器，`chunk` 分块扫描，`custom` 自定义规则与字典；
//! 旧路径 `crate::service::pii::X` 经重导出兼容。

pub mod chunk;
pub mod custom;
pub mod detector;
pub mod scope;

pub use {chunk::*, detector::*, scope::*};
