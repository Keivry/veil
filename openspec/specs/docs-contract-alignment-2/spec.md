# docs-contract-alignment-2 Specification

## Purpose
修正 README、代码注释与 spec 三源之间未声明的漂移，覆盖 HOP 头集、TPM 超时、桶边界、限流值、采样掩码、fuzzy、custom 叠加与 usage 口径，并清理注释错数与不可达分支，使新人按文档即可启动且阈值表零漂移。

## Requirements

### Requirement: 三源一致性修正

HOP 头集、TPM 超时、桶边界、限流值、采样掩码、fuzzy、custom 叠加、usage 口径等未声明漂移 SHALL 在 README 显式声明或改回；`BUILTIN_NAMES` 注释错数、`&&/||` 无括号、不可达分支等注释/代码异味 SHALL 修复；`secret` 比较、`is_private_ip`、`AUDIT_SUBLIMIT` 锚点 SHALL 注释明确。

#### Scenario: 文档驱动启动

- **WHEN** 新人按 README 配置启动
- **THEN** 行为与阈值表一致，无静默变严
