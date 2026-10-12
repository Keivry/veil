//! 审计判定单入口（自 `audit.rs` 拆出，单入口收敛）：唯一公开入口 `evaluate_with_whitelist`。

use {
    super::{log::sanitize_for_log, policy::AuditPolicy, rules::is_dangerous},
    crate::config::AuditMode,
};

/// 审计判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerdict {
    /// 放行（含 `off` 模式与未命中规则）。
    Allow,
    /// 直接拒绝（`block` 模式命中）。
    Block { reason: String },
    /// 转人工审批（`approve` 模式命中；调用方经 Matrix 审批流转）。
    NeedApproval { reason: String, summary: String },
}

/// 审批网关转 hold 判定（自 `audit_hold.rs` 上移至审计归属模块）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldVerdict {
    Approved,
    Rejected,
}

/// 审计判定唯一公开入口（单入口收敛）：按审计模式给出最终 verdict，
/// 含 MXID 白名单校验——`approve` 模式须配非空白名单，否则降级为 `block`
/// （防御性校验，防“空白名单跳过校验致任何房间成员可审批”）；
/// `approve` 空白名单的生产不可达由启动门禁保证（`src/config/env_parse.rs:493`
/// 的 `validate_approve_whitelist` 与 `src/main.rs:46` 的 `preflight_whitelist`）。
/// 收敛声明：判定单核为 `is_dangerous` + `evaluate_inner`；流式、非流与测试
/// 调用点统一走本函数，不得新增绕过白名单的公开判定入口。
/// 网关接线人注意：allow 名单命中与默认放行的区分（`allow-list` vs 默认事件）
/// 由网关侧审计日志调用点记录，本函数两者均返回 [`AuditVerdict::Allow`]。
pub fn evaluate_with_whitelist(
    mode: AuditMode,
    tool_name: &str,
    args: &str,
    policy: &AuditPolicy,
    whitelist: &[String],
) -> AuditVerdict {
    let mode = match mode {
        AuditMode::Approve if whitelist.is_empty() => {
            tracing::error!("AUDIT_MODE=approve 必须配置 APPROVAL_WHITELIST，降级为 block 模式");
            AuditMode::Block
        }
        m => m,
    };
    evaluate_inner(mode, tool_name, args, policy)
}

fn evaluate_inner(
    mode: AuditMode,
    tool_name: &str,
    args: &str,
    policy: &AuditPolicy,
) -> AuditVerdict {
    match mode {
        AuditMode::Off => AuditVerdict::Allow,
        AuditMode::Block => match is_dangerous(tool_name, args, policy) {
            Some(reason) => AuditVerdict::Block { reason },
            None => AuditVerdict::Allow,
        },
        AuditMode::Approve => match is_dangerous(tool_name, args, policy) {
            Some(reason) => {
                let summary = sanitize_for_log(&format!("{tool_name}: {args}"));
                AuditVerdict::NeedApproval { reason, summary }
            }
            None => AuditVerdict::Allow,
        },
    }
}

#[cfg(test)]
mod tests;
