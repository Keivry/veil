# pii-custom-compat Specification

## Purpose
恢复与原仓一致的自定义脱敏规则加载能力：支持合并文件与分离文件、JSON/极简 YAML/TXT 名单及四个历史别名，严格校验命名组、禁用 `\b` 与嵌套、跨文件去重与重叠跳过，并以显式 BREAKING 收敛差异并给出迁移路径。

## Requirements

### Requirement: 文件格式与别名

系统 SHALL 支持合并文件与分离文件两种配置（`PII_CUSTOM_RULES_FILE` 优先并可与 `PII_CUSTOM_PATTERNS_FILE/PII_CUSTOM_DICT_FILE` 叠加），SHALL 支持 JSON 与极简 YAML 与 TXT 名单（每行一名，`#` 注释忽略），SHALL 兼容 4 别名（`PII_CUSTOM_PATTERN_FILE/PII_SENSITIVE_DICT_FILE/PII_SENSITIVE_NAMES_FILE/PII_RULES_FILE`）；已配置但缺文件/不可读/解析失败/形态非法 SHALL 拒启动，空文件/零命中仅 warn。

#### Scenario: YAML 可用

- **WHEN** 以 YAML 合并文件配置自定义规则并启动
- **THEN** 系统正常加载且命中后指标出现自定义 kind

#### Scenario: 缺文件拒启动

- **WHEN** 已配置路径但文件不存在
- **THEN** 系统拒绝启动而非静默未加载

### Requirement: 约束校验与管线语义

`name` SHALL 与 `(?P<name>...)` 内同名；禁止 `\b`（须用 lookaround）；禁止嵌套命名组；与 6 内置重名 SHALL 拒绝；跨文件重名 SHALL 去重；命中区间与 `__PII_*__/__VG_CRED_*__` 重叠 SHALL 跳过；凭据值优先；超长输入按 1MB 分块；单规则超时守卫连续 3 次停用；字典独立扫描且 `name/person` 走 CJK 边界。上述通过校验的自定义规则/模式/字典 SHALL 在运行时注入检测器并生效：启动装配 SHALL 以 `PII_CUSTOM_RULES_FILE`/`PII_CUSTOM_PATTERNS_FILE`/`PII_CUSTOM_DICT_FILE`（含短名内联槽与全部别名）调用运行时加载并注入检测器，MUST NOT 仅做启动校验而在运行时零接线。加载失败 SHALL 沿用既有 fail-closed 语义（缺文件/不可读/解析失败/形态非法拒启动），MUST NOT 静默降级为空规则集。运行时命中 SHALL 可观测（命中 kind 反映到指标/审计面，停用计数反映到健康检查 `pii_custom_disabled`）。

#### Scenario: 违规被拒

- **WHEN** 自定义规则含 `\b` 或与内置 `phone` 重名
- **THEN** 系统拒绝该规则并告警，不静默加载

#### Scenario: 自定义规则运行时命中

- **WHEN** 配置自定义规则/模式/字典文件（或内联槽）且启动成功
- **THEN** 命中自定义规则时扫描返回对应 kind，且该命中在指标/审计面可观测，证明规则已在运行时注入生效（非仅启动校验）
