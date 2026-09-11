# pii-parity Specification

## Purpose
恢复 PII 检测的 fuzzy/hardened 语义、自定义规则校验与三槽叠加、按 kind 定制的采样掩码与占位符关闭条件，使脱敏行为与原仓一致，同时收束实现分支避免爆炸式回退。

## Requirements

### Requirement: fuzzy 与 hardened 对齐

fuzzy SHALL 恢复 `IGNORECASE` 语义（序号回查另作独立开关）；hardened SHALL 补字典 CJK 边界、保留前缀 `ip_network` 兜底、ReDoS 守卫、`lru_cache` differentiations。

#### Scenario: 大小写变体被还原

- **WHEN** fuzzy 开启且响应含占位符大小写变体
- **THEN** 系统按忽略大小写还原

### Requirement: 自定义规则口径与叠加

自定义命名组校验 SHALL 放宽到原仓口径（name 与内组同名、禁 `\b`/嵌套/内置重名、跨文件去重、重叠跳过、凭据优先、1MB 分块、超时停用）；字典 SHALL 独立扫描不并入联合正则；`PII_CUSTOM_RULES/PATTERNS/DICT` 三槽 SHALL 叠加加载。

#### Scenario: 三文件叠加生效

- **WHEN** 三槽各配一文件
- **THEN** 三文件规则同时生效

### Requirement: 掩码与占位符对齐

采样掩码 SHALL 按 kind 六分支（phone/email/bank/ipv4/ipv6/api_key）定制；占位符关闭条件 SHALL 与原仓一致；`PII_HOLD_MAX` 校验保持。

#### Scenario: bank 掩码形态正确

- **WHEN** 银行卡命中采样
- **THEN** 掩码形如 `**** **** **** 后4` 而非通用截断
