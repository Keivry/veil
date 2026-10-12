//! fail-closed 配置加载：缺必填项或非法值直接拒绝启动。
//!
//! 校验顺序：先可观测 token，
//! 再 Matrix 三件套，最后 PII 与审计。
//!
//! 子模块划分：`env_parse` 环境解析 + 类型，`file_layer` TOML 配置文件
//! 补充层，`targets` 文件专属上游覆盖 schema，`custom_file` 自定义文件加载，
//! `validate` 校验器；旧路径经重导出兼容。

pub mod custom_file;
pub mod env_parse;
pub mod env_surface;
pub mod file_layer;
pub mod targets;
pub mod validate;

pub use {custom_file::*, env_parse::*, file_layer::*, targets::*, validate::*};
