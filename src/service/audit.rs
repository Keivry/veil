//! §6.1 策略引擎 + §6.2 阻断/审批判定 + §6.3 审计日志（D2 门面拆分）。
//!
//! - 三模式：`off`（默认放行）/`block`（命中直接拒绝）/`approve`（命中转人工审批）。
//! - 审计读上游原文：verdict 判定一律基于上游原始 tool 名/参数（未还原、未掩码），
//!   防占位符混淆审计；非流 `evaluate_nonstream` 与流泵 `tool_triples` 均以原文为准。
//! - 危险规则：危险 shell、敏感路径写入、网络外传（子串判定，禁全文正则回溯）。
//! - 参数规范化：空白合并 / `\uXXXX`+`\xXX` 转义 / 拆链 / 单层变量展开 / 别名折叠 / `..` O(n)
//!   词法规范化。
//! - `AUDIT_POLICY_FILE` 加载；热重载为 Non-Goal（改配置重启生效）。
//! - 审计日志：`DATA_DIR/audit.log` JSONL，先脱敏后截断，零明文，剥 `\x00-\x1f`， 0600，10MB x 5
//!   轮转，写失败双层 fail-closed + 熔断计数。
//!
//! 子模块划分（D2 三切 + D3 hold）：`policy` 策略加载，`normalize` 参数规范化，
//! `rules` 危险规则与顶层判定，`verdict` 双入口 verdict，`log` 日志落盘，
//! `hold` 累积与保活；旧路径经重导出兼容，对外 `service::audit::*` 不变。

pub mod hold;
pub mod log;
pub mod normalize;
pub mod policy;
pub mod rules;
pub mod sink;
pub mod verdict;

pub use {hold::*, log::*, normalize::*, policy::*, rules::*, sink::*, verdict::*};

/// 单测专用：非空审批白名单（T2/D2 调用点统一口径；空白名单降级用例显式传 `&[]`，
/// 生产不可达由启动门禁保证，见 `src/config/env_parse.rs:307-310`）。
#[cfg(test)]
pub(crate) fn test_whitelist() -> &'static [String] {
    static TEST_WHITELIST: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    TEST_WHITELIST.get_or_init(|| vec!["@admin:example.com".to_string()])
}
