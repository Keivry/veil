# deadcode-positional-cleanup Specification

## Purpose

清除生产零引用符号与残留空码，移除不可达分支，确定化缺省上游选择，闭合 ENV 回环免 token 的未声明项。

## Requirements

### Requirement: 零生产引用符号清零

系统 SHALL NOT 保留以下生产零引用符号：`CredentialVault::contains_token`、`CredentialVault::global`、`CredentialVault::snapshot`/`VaultSnapshot`（除非 `#[cfg(test)]` 收编并注释）、`CredentialVault::redact`、`has_chat_terminal`、`should_discard_after_terminal`、`reject_new_dangerous_during_hold`、`AUDIT_TIMEOUT_SECS`、leaf 三测试辅助（`#[cfg(test)]` 收编即可）。

#### Scenario: 符号面收敛

- **WHEN** grep 上述符号的定义与引用
- **THEN** 无生产引用残留；保留者均为 `#[cfg(test)]` 收编且有注释

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

`ENV=dev` / `ALLOW_LOOPBACK_NO_TOKEN` 回环免 token 未迁移 SHALL 以 README §6.6 BREAKING 与 §7.4 表行声明；§6 首句 SHALL 由「五处」更新为「六处」。

#### Scenario: 声明可查

- **WHEN** 查阅 README §6.6 与 §7.4
- **THEN** 均含「回环免 token 未迁移」条目；§6 首句为「六处」
