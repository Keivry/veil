# behavior-changes Specification

## Purpose
把脱敏总开关默认开启、PII 值采样持久落盘等已发生的默认值与语义漂移显式化为 BREAKING 条目，并对凭据淘汰策略作非 BREAKING 容量分表确认，给出可执行迁移步骤，避免旧部署被静默变严或出现隐私回退。

## Requirements

### Requirement: 脱敏默认与采样持久与淘汰策略

脱敏总开关默认开启（原仓默认关闭）为 **BREAKING**：迁移 SHALL 说明旧 compose 不显式关闭将被静默变严；PII 值采样持久默认开启落盘（原仓内存-only）为 **BREAKING**：迁移 SHALL 说明隐私影响与关闭方法。

凭据淘汰 FIFO 改 LRU（含 5000/1000 容量分表声明）为**非 BREAKING 容量分表确认**：原仓自 v0.9.6 起凭据与 PII 均已是真 LRU（`_token.py:231`、`:523-538`），容量凭据 `MAX_TOKEN_ENTRIES=5000`（`_token.py:102`）/PII `PII_MAX_ENTRIES=1000`（`_token.py:141`）与本仓一致，非行为漂移，故不计入 BREAKING 清单；基线 commit `46f6ff665c869b02c154c10df431c638c2177fd9`（2026-09-07，bump version v0.9.47）。

#### Scenario: 迁移可执行

- **WHEN** 用户按迁移说明调整旧配置
- **THEN** 行为回到预期且无静默变严或明文落盘增量

#### Scenario: 容量可查

- **WHEN** 查询 vault/PII 容量语义
- **THEN** 文档明确两表容量与淘汰策略
