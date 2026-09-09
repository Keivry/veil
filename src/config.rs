//! fail-closed 配置加载：缺必填项或非法值直接拒绝启动。
//!
//! 校验顺序对标原仓 `proxy.py __init__`：先可观测 token，
//! 再 Matrix 三件套，最后 PII 与审计。
//!
//! 子模块划分（A2）：`env_parse` 环境解析 + 类型，`custom_file`
//! 自定义文件加载，`validate` 校验器；旧路径经重导出兼容。

pub mod custom_file;
pub mod env_parse;
pub mod validate;

pub use {custom_file::*, env_parse::*, validate::*};
