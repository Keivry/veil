# nonstream-audit-align Specification

## Purpose

统一非流审计与流式同口径（白名单单入口），修正错误状态下阻断合成边界，使下游状态码与正文不被掩盖。

## ADDED Requirements

### Requirement: 非流与流式白名单同口径

非流审计 SHALL 经与流式相同的白名单入口 `evaluate_with_whitelist` 判定；`AUDIT_MODE=approve` 且白名单为空时非流 SHALL 与流式一致降级为 block。

#### Scenario: approve 非空白名单 → NeedApproval 透传

- **WHEN** `AUDIT_MODE=approve`、白名单非空、非流响应命中危险调用
- **THEN** 记 pending 且上游响应透传（不断链、不合成阻断体）

#### Scenario: approve 空白名单直调 → block 降级

- **WHEN** 直接以空 `approval_whitelist` 调用非流判定且命中危险调用
- **THEN** 判定为 Block（生产不可达由启动门禁保证，测试注明）

#### Scenario: 流/非流 verdict 对照一致

- **WHEN** 同一危险调用分别经流式与非流路径判定
- **THEN** 两者 verdict 一致（Block 或 NeedApproval 同值）

### Requirement: 错误状态不合成阻断体

非流上游为错误状态（4xx/5xx，除既有非 JSON 502/401 豁免）且审计命中 Block 时，系统 SHALL 保留上游状态码与正文，SHALL NOT 合成 200 阻断体；审计 SHALL 照常记录。

#### Scenario: 400 JSON 危险调用保留状态

- **WHEN** 上游 400 JSON 体含危险 tool_call，审计模式为 block
- **THEN** 下游收 400 与原始正文；审计日志/指标含该次命中

#### Scenario: 2xx 危险调用仍合成阻断体

- **WHEN** 上游 200 命中 Block
- **THEN** 下游收 200 + `nonstream_block_body`（既有声明行为）

### Requirement: 单入口判定函数

全仓 SHALL 仅保留 `evaluate_with_whitelist` 作为审计判定入口；SHALL NOT 存在忽略白名单的公开判定函数。

#### Scenario: 无绕白名单入口

- **WHEN** grep 审计判定调用点
- **THEN** 所有调用均携带白名单参数，无裸 `evaluate(` 调用
