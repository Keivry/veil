# behavior-changes Specification

## Purpose
把脱敏总开关默认开启、PII 值采样持久落盘、凭据淘汰策略等已发生的默认值与语义漂移显式化为 BREAKING 条目并给出可执行迁移步骤，避免旧部署被静默变严或出现隐私回退。

## Requirements

### Requirement: 脱敏默认与采样持久与淘汰策略

脱敏总开关默认开启（原仓默认关闭）为 **BREAKING**：迁移 SHALL 说明旧 compose 不显式关闭将被静默变严；PII 值采样持久默认开启落盘（原仓内存-only）为 **BREAKING**：迁移 SHALL 说明隐私影响与关闭方法；凭据淘汰 FIFO 改 LRU（含 5000/1000 容量分表声明）为 **BREAKING**：迁移 SHALL 说明容量语义。

#### Scenario: 迁移可执行

- **WHEN** 用户按迁移说明调整旧配置
- **THEN** 行为回到预期且无静默变严或明文落盘增量

#### Scenario: 容量可查

- **WHEN** 查询 vault/PII 容量语义
- **THEN** 文档明确两表容量与淘汰策略
