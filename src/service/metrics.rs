//! §7.1 指标聚合 + §7.3 摘要脱敏 + §7.4 PII 值级掩码采样。
//!
//! 口径对标原仓 `_metrics.py`（内存环 10k + sqlite 日/小时聚合），详见各子模块。
//! 子模块划分（A2）：`store` 存储与落盘，`aggregate` 聚合类型与查询，
//! `sample` 值级采样，`summarize` 摘要脱敏；旧路径经重导出兼容。
//!
//! A4 `TODO(metrics)` 闭环声明（wont-measure）：请求隔离（跨请求 PII 不互见）
//! vs 全局复用的 prompt-cache 命中率差异不在本地测量——命中率是上游 provider
//! 侧计费指标，网关侧只能看到请求体字节去重率，两者不等价，本地测不出真值；
//! 且请求隔离是隐私硬要求，即使代价未知也不回退。故显式不测，接受未知代价；
//! 待上游提供 cache-hit 计费数据时另立任务对账（README §7.3 原 `TODO(metrics)`
//! 标注归 docs change 收尾，本模块不再持有 TODO）。

pub mod aggregate;
pub mod sample;
pub mod store;
pub mod summarize;

pub use {aggregate::*, sample::*, store::*, summarize::*};
