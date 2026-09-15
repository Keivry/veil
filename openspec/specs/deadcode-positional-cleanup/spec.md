# deadcode-positional-cleanup Specification

## Purpose

清除生产零引用符号与残留空码，移除不可达分支，确定化缺省上游选择，闭合 ENV 回环免 token 的未声明项。

## Requirements

### Requirement: 零生产引用符号清零

系统 SHALL NOT 保留以下生产零引用符号：`CredentialVault::contains_token`、`CredentialVault::global`、`CredentialVault::snapshot`/`VaultSnapshot`（除非 `#[cfg(test)]` 收编并注释）、`CredentialVault::redact`、`has_chat_terminal`、`should_discard_after_terminal`、`reject_new_dangerous_during_hold`、`AUDIT_TIMEOUT_SECS`、leaf 三测试辅助（`#[cfg(test)]` 收编即可）。该清单 SHALL 扩展覆盖死亡抽象 `ApprovalGateway` trait、`NoopApproval`、`ApprovalOutcome`（SHALL 删除或接线到生产路径），以及全部仅测试引用的 `pub` API（现 20 个，含 6 个 metrics getter）。仅测试引用的 `pub` API SHALL 收敛可见性（降为 `pub(crate)`/`#[cfg(test)]`）或接线到生产；其中 metrics getter（6 个）SHALL 随运行时可靠性指标在 `/_admin/metrics` 暴露（见 `runtime-reliability`），SHALL NOT 停留于仅测试引用。测试引用 SHALL 同步清理；保留者均为 `#[cfg(test)]` 收编且有注释。

#### Scenario: 符号面收敛

- **WHEN** grep 上述符号的定义与引用
- **THEN** 无生产引用残留；保留者均为 `#[cfg(test)]` 收编且有注释

#### Scenario: 死抽象清零或接线

- **WHEN** grep `ApprovalGateway` / `NoopApproval` / `ApprovalOutcome`
- **THEN** 无生产零引用残留（删除）或已在生产路径接线，测试引用同步清理

#### Scenario: 仅测试 pub API 收敛或接线

- **WHEN** grep 仅测试引用的 `pub` API（含 6 个 metrics getter）的定义与引用
- **THEN** 无仅测试引用残留：可见性已收敛或已接入生产；6 个 metrics getter 经 `/_admin/metrics` 暴露

### Requirement: 残留空码清除

`credential/auth.rs` 的丢弃赋值（`let _ = effective;`）与 `credential/approval.rs` 的丢弃调用（`let _ = gateway.request_approval(...)`）SHALL 被移除，行为不变。

#### Scenario: 空码零命中

- **WHEN** grep `let _ = effective` / `let _ = gateway.request_approval`
- **THEN** 零命中，相关单测全绿

### Requirement: classify_empty 无死分支

`classify_empty` SHALL NOT 含生产不可达的 `StreamInjectThen502` 变体与 `is_stream` 参数；流式空流策略 SHALL 唯一归 `should_synthesize_empty_stream`。

#### Scenario: 三分支收敛

- **WHEN** 查阅并测试 `classify_empty`
- **THEN** 仅存生产可达分支；注释指向 `should_synthesize_empty_stream`

### Requirement: 缺省上游确定性

`resolve_upstream` 无默认上游时 SHALL 按端口升序取首个并记录 warn，SHALL NOT 依赖 HashMap 迭代序。

#### Scenario: 多端口缺省确定

- **WHEN** 配置两个 `LLM_<port>` 且无默认上游
- **THEN** 选择最小端口，warn 一次；重复运行结果一致

### Requirement: ENV 回环免 token 声明闭合

`ENV=dev` / `ALLOW_LOOPBACK_NO_TOKEN` 回环免 token 未迁移 SHALL 以 README §6.6 BREAKING 与 §7.4 表行声明；§6 首句计数 SHALL 与 README 当前口径一致（现为「十处」，`veil-docs-test-parity` 同步）。

#### Scenario: 声明可查

- **WHEN** 查阅 README §6.6 与 §7.4
- **THEN** 均含「回环免 token 未迁移」条目；§6 首句为「十处」

### Requirement: 矩阵授权死代码与注释清理

`authorize_entry` 与 `TurnToApproval` 的生产零引用死代码 SHALL 被清理或接线到生产路径；其相关注释 SHALL 与实现一致，SHALL NOT 保留误导性描述。

#### Scenario: 死代码清零或接线

- **WHEN** grep `authorize_entry` / `TurnToApproval`
- **THEN** 无生产零引用残留（删除）或已在生产路径接线

#### Scenario: 注释与实现一致

- **WHEN** 查阅上述符号相关注释
- **THEN** 注释描述与实现一致，无误导性描述

### Requirement: MXID 校验单一实现

`is_valid_mxid` SHALL 由单一实现承载，各调用点 SHALL 复用同一实现（经重导出）；SHALL NOT 保留逐字复制的多份实现。行为 SHALL 不变。

#### Scenario: 单一实现无副本

- **WHEN** grep `is_valid_mxid` 的定义
- **THEN** 仅一处定义，调用点复用，无逐字复制副本

#### Scenario: 校验行为等价

- **WHEN** 运行等价测试
- **THEN** 校验结果与合并前逐例一致

### Requirement: YAML 去引号单一实现

`strip_yaml_quotes` 与 `unquote` SHALL 合并为单一实现，SHALL NOT 保留两份重复逻辑；行为 SHALL 不变。

#### Scenario: 合并为单一实现

- **WHEN** grep `strip_yaml_quotes` / `unquote`
- **THEN** 仅存在单一实现（另一名称为重导出或已移除），无重复逻辑

#### Scenario: 去引号行为不变

- **WHEN** 运行去引号相关测试
- **THEN** 行为与合并前逐例一致

### Requirement: 锁中毒 helper 单一实现

重复的 poison helper（现三份）SHALL 合并为单一 helper，SHALL NOT 保留多份逐字复制实现；行为 SHALL 不变。

#### Scenario: 合并为单一 helper

- **WHEN** grep poison helper
- **THEN** 仅一处实现，各调用点复用

#### Scenario: 锁中毒行为不变

- **WHEN** 运行锁中毒相关测试
- **THEN** 行为与合并前逐例一致

### Requirement: 测试支撑 helper 提取共享模块

`file_len_under_800_or_split`（现复制 18 份）SHALL 提取至共享测试支撑模块并由各测试复用，SHALL NOT 保留逐字复制副本。

#### Scenario: helper 单一来源

- **WHEN** grep `file_len_under_800_or_split`
- **THEN** 仅一处定义（共享模块），各测试引用同一实现

#### Scenario: 测试行为不变

- **WHEN** 运行文件大小/拆分相关测试
- **THEN** 全部通过，行为不变
