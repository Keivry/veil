# Spec Delta

## MODIFIED Requirements

### Requirement: 非流还原回退前残缺重试

系统 SHALL 在非流还原后 JSON 校验失败时先经 `strip_partials` 重试一次；仍失败时 SHALL 回退**已应用响应侧新 PII 掩码**的文本（对占位符帧执行 `redact_response_new_pii*` 所得单帧），SHALL NOT 回退未掩码的上游原文或未掩码占位符帧（`R8-03`）。掩码回退本身失败（如 PII 注册熵源故障）时，系统 SHALL 以 `502` + `E_PII_UNAVAILABLE` fail-closed 收尾，SHALL NOT 以未掩码正文收尾。守卫失败 SHALL 记 warn 与 `record_restore_fallback` 指标（恰一次），使回退可观测。

#### Scenario: 残缺可挽回不丢还原

- **WHEN** 还原后 JSON 破裂但剥离残缺形态后可解析
- **THEN** 下游收到剥离后还原体而非上游原文

#### Scenario: 仍失败回退可观测

- **WHEN** 重试后仍不可解析
- **THEN** 下游收到**已应用响应侧新 PII 掩码**的回退体（零新检出 PII 明文），并记 warn/metrics 恰一次；SHALL NOT 收到未掩码上游原文

#### Scenario: 掩码回退失败 fail-closed

- **WHEN** 掩码回退本身失败（如 PII 注册不可用）
- **THEN** 下游收到 `502 E_PII_UNAVAILABLE`，不收到未掩码正文
