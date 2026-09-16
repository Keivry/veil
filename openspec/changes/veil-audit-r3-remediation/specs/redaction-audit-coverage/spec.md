## MODIFIED Requirements

### Requirement: Chat 审计按声明 index 分桶

系统 SHALL 以 Chat `choices[].index` 声明值参与审计分桶（缺省回退枚举位置）；SHALL NOT 仅用位置序号导致乱序或跳号 `index` 时槽归属错位。分桶键 SHALL 采用位域公式 `(ci << 16) | (idx & 0xFFFF)`（`ci, idx < 2^16` 时单射无碰撞），SHALL NOT 使用历史 `ci*64+declared_index`（该式在 `idx >= 64` 时与下一 choice 的桶 0 碰撞）。`ci=0` 时位域公式与历史公式等值。

#### Scenario: 乱序/跳号 index 分桶正确

- **WHEN** Chat 响应 `choices[].index` 乱序或跳号（如 2、0、5）
- **THEN** 各 choice 的 tool 分片按声明 index 归入各自槽，审计对象与实际 choice 匹配

#### Scenario: 分桶无碰撞

- **WHEN** 两个不同 `(ci, idx)` 组合、其中 `idx >= 64`
- **THEN** 位域公式产出互异桶键，不映射到同一槽

#### Scenario: ci=0 等价锚点

- **WHEN** `ci=0` 且 `idx` 任意（`< 2^16`）
- **THEN** 位域公式结果与历史 `ci*64+idx` 等值，单 choice 快照不回归

#### Scenario: 单 choice 快照不变

- **WHEN** 单 choice（`index=0`）常规流
- **THEN** 分桶键与既有行为等值，审计结果不回归
