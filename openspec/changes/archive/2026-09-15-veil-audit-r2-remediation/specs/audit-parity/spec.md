# audit-parity Specification — delta

## MODIFIED Requirements

### Requirement: 日志脱敏口径对齐

审计日志 SHALL 先脱敏后截断；截断长度/控字符/secret 模式 SHALL 与原仓一致（120 语义或文档化差异）；强化层异常 SHALL 返回 `[REDACTED:unverified]` 而非明文。`Block`/`Allow` 两类审计记录 SHALL 均携带参数脱敏摘要（复用 ten-form 摘要引擎），与 Python 每条记录均含摘要一致；摘要生成 SHALL 先于落盘（先脱敏后写），日志文件权限 SHALL 维持 `0600`。

#### Scenario: 强化层异常零明文

- **WHEN** PII 强化层异常
- **THEN** 日志落盘为占位符而非明文

#### Scenario: Block/Allow 记录含参数摘要

- **WHEN** 审计判定为 Block 或 Allow 并落盘
- **THEN** 两类记录均含脱敏后的参数摘要，且先脱敏后写、文件权限为 0600
