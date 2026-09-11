# credential-vault-singleton Specification

## Purpose
恢复凭据与 PII 映射的跨请求稳定性，使同一秘密在多次查询与网关转发中映射到同一占位符，保证还原不断链。

## Requirements

### Requirement: 全局 Vault 单例与快照透传

系统 SHALL 持有进程级全局 `CredentialVault`（LRU 5000）与全局 PII 注册表；凭据查询命中复用同一 token；LLM 网关请求侧脱敏 SHALL 只读快照透传已注册映射，不得每请求新建空 Vault/Detector。

#### Scenario: 同一秘密跨请求同 token

- **WHEN** 两次查询同一 entry/field 明文相同
- **THEN** 两次返回同一 `__VG_CRED_NNNNNN__` 且网关侧可还原

#### Scenario: 网关命中已注册凭据

- **WHEN** 网关收到含已注册凭据明文的请求
- **THEN** 请求被替换为已存在 token 而非新 token

### Requirement: PII 全局持久双模

系统 SHALL 提供 PII 全局持久开关（默认关闭保持请求隔离）；开启时同明文跨请求映射至同一 `__PII_*__`；关闭时跨请求不互见。`resp` 表注册 SHALL 不还原为明文，仅请求期映射可还原。

#### Scenario: 全局开时 prompt-cache 关联

- **WHEN** 全局持久开启且两请求含同一手机号
- **THEN** 两请求脱敏为同一占位符

#### Scenario: 响应侧命中不泄漏

- **WHEN** 响应命中新 PII 明文
- **THEN** 系统注册响应侧占位符但不将其还原为明文
