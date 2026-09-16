## ADDED Requirements

### Requirement: PII 作用域模式与复用/淘汰计数

系统 SHALL 经 `GET /_admin/metrics` 暴露 PII 作用域只读观测：当前作用域模式（`request`/`conversation`）与会话作用域计数——会话复用次数、会话条目淘汰累计、回退请求级次数。计数 SHALL 以既有固定键原子计数风格承载（`GatewayMetrics` / `KeyedCounters`），SHALL NOT 改变既有指标键与语义；计数缺失或锁不可用时 SHALL 降级为 `0` 且不影响其余指标。该观测 SHALL NOT 暴露会话键、明文或 token 原值。不可泄露约束 SHALL 同样覆盖 **`tracing` 日志层**：会话键、会话键头值、明文与 token MUST NOT 出现在任一日志行（含 debug 级），强度与指标面一致。

#### Scenario: 模式可观测

- **WHEN** `/_admin/metrics` 读取快照
- **THEN** 响应含当前作用域模式（`request`/`conversation`）

#### Scenario: 复用/淘汰/回退计数

- **WHEN** `conversation` 模式下发生会话复用、条目淘汰与回退
- **THEN** 对应计数递增；默认 `request` 模式下复用与淘汰恒为 `0`

#### Scenario: 既有指标键不变

- **WHEN** 对比本 change 前后的指标快照
- **THEN** 既有键 SHALL 不变，仅新增只读项

#### Scenario: 不泄露键与明文

- **WHEN** 检查观测输出
- **THEN** 不含会话键、明文或 token 原值

#### Scenario: 日志层同强度不泄露

- **WHEN** `conversation` 模式下检查 `tracing` 日志（含 debug 级）
- **THEN** 任一日志行不含会话键、会话键头值、明文或 token 原值
