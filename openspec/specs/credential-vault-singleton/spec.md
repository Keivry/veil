# credential-vault-singleton Specification

## Purpose
凭据映射跨请求稳定（进程单例）；PII 默认请求级隔离，并允许经另立 change 交付的有界、非持久会话级（conversation）稳定模式。

## Requirements

### Requirement: 全局 Vault 单例与快照透传

系统 SHALL 持有进程级全局 `CredentialVault`（LRU 5000）作为**凭据**映射单例；凭据查询命中复用同一 token；LLM 网关请求侧脱敏 SHALL 只读快照透传已注册映射，不得每请求新建空 Vault/Detector。系统 SHALL NOT 持有或依赖「全局 PII 注册表」——PII 映射默认 SHALL 为请求级容器（见「PII 全局持久双模」的收窄口径），凭据 `vault` 与 PII 映射 SHALL NOT 混为同一全局注册表。

**有界例外（`veil-pii-conversation-cache`；本 change 即 canonical「须另立 change 交付」所指的那个 change）**：上面 SHALL NOT 的语义 SHALL 被理解为「MUST NOT 持有**无界的、可跨租户/跨会话命中的、持久化的**全局 PII 注册表」。**当且仅当** `PII_SCOPE_MODE=conversation` 显式启用时，系统 MAY 持有 `ConversationScopeStore` 作为 **进程内、有界（会话数上限 × 单会话条目上限 × 2 张表）、租户+会话作用域、非持久（不落盘、进程重启即失效、空闲 TTL 到期即销毁）** 的会话存储；该存储 SHALL NOT 被任何「全局 PII 注册表」语义复用为跨租户/跨会话查找面，且 MUST NOT 承载凭据映射（凭据仍为进程单例 + 请求级 minted-set 授权）。默认 `PII_SCOPE_MODE=request` 时行为 SHALL 与本条原语义逐项一致。

**canonical Purpose 对齐（已知内部张力）**：canonical `credential-vault-singleton` 的 Purpose 现行文本仍称「凭据与 PII 映射的跨请求稳定性」，与本 requirement 的**默认请求级**模型存在内部张力。本 change SHALL 在对齐批内**手工修订**该 Purpose 为「凭据映射跨请求稳定（进程单例）；PII 默认请求级隔离，并允许经另立 change 交付的有界、非持久会话级（conversation）稳定模式」。机制：delta `## Purpose` 对**已存在**的 canonical spec **不生效**（openspec `archive` 仅用 delta Purpose 初始化新 spec；对既有 Purpose 会忽略并告警），故须直接编辑 canonical 文件（见 tasks 6.4）。

#### Scenario: 同一秘密跨请求同 token

- **WHEN** 两次查询同一 entry/field 明文相同
- **THEN** 两次返回同一 `__VG_CRED_NNNNNN__` 且网关侧可还原

#### Scenario: 网关命中已注册凭据

- **WHEN** 网关收到含已注册凭据明文的请求
- **THEN** 请求被替换为已存在 token 而非新 token

#### Scenario: 凭据单例不含全局 PII 注册表

- **WHEN** 检查进程级共享映射，且 `PII_SCOPE_MODE=request`（默认）
- **THEN** 仅凭据 `CredentialVault` 为全局单例；不存在全局 PII 注册表，PII 映射随请求销毁

#### Scenario: conversation 模式的有界会话存储不构成全局注册表

- **WHEN** `PII_SCOPE_MODE=conversation` 且检查进程级共享映射
- **THEN** 存在 `ConversationScopeStore`，但其为有界、租户+会话作用域、非持久的会话存储（非「全局 PII 注册表」）；跨会话键与跨租户 MUST NOT 互见；默认 `request` 模式下该存储不被构造/使用

### Requirement: PII 全局持久双模

PII 映射 SHALL 默认为请求级容器（`Scope::pii`，随请求销毁），跨请求 SHALL NOT 互见；系统 SHALL NOT 提供或依赖「PII 全局持久开关」，SHALL NOT 持有「全局 PII 注册表」（`src/config/env_parse.rs` 无该开关）。`resp` 表注册 SHALL 不还原为明文，仅请求期映射可还原。请求级隔离 SHALL 为 PII 的**默认与回退**映射模型；**当且仅当** `PII_SCOPE_MODE=conversation` 显式启用**且**会话键成功推导时，PII 映射 MAY 收窄为**有界、租户+会话作用域、非持久**的会话级共享作用域——本 change `veil-pii-conversation-cache` 即该「另立 change」交付；无界/跨租户/持久化的全局稳定映射仍 SHALL NOT 提供。

#### Scenario: 全局开时 prompt-cache 关联

- **WHEN** 检查 PII 映射的跨请求行为
- **THEN** 默认 `PII_SCOPE_MODE=request` 下不存在全局持久模式，同一明文跨请求不映射至同一占位符，网关侧不提供跨请求 prompt-cache 关联；仅 `conversation` 显式启用且会话键推导成功时，**同一会话键内**跨轮可映射至同一占位符（有界、非持久、跨会话键/跨租户不可见）

#### Scenario: 响应侧命中不泄漏

- **WHEN** 响应命中新 PII 明文
- **THEN** 系统注册响应侧占位符但不将其还原为明文

#### Scenario: conversation 例外有界非持久且默认不变

- **WHEN** `PII_SCOPE_MODE=conversation` 且检查会话级映射边界
- **THEN** 映射受会话数上限与空闲 TTL 约束、进程重启即失效、不落盘，跨会话键与跨租户 MUST NOT 互见；凭据映射仍为进程单例 + 请求级 minted-set 授权（B3 不变）；`PII_SCOPE_MODE=request` 时行为与既有请求级隔离逐项一致

### Requirement: 响应侧凭据还原请求级授权

系统 SHALL 在请求级 `Scope` 内维护「本请求脱敏**实际产出**的凭据 token 集合」（minted-set，随请求结束销毁），并在请求侧脱敏实际产生凭据替换（明文 → `__VG_CRED_<序号>__`）处记录该 token。响应侧凭据还原（`Scope::restore_response_one` 与 `restore_cred_tokens`）SHALL 仅在 `token ∈ minted-set` 时调用 `CredentialVault::restore_one` / 全量还原。

系统 SHALL NOT 以「请求体中出现过的 token」作为还原授权依据：调用方自带的 `__VG_CRED_\d{4,}__` 字面量 SHALL NOT 被授权还原；响应中出现而未被授权的 token 形态 SHALL 按幻觉 token 剥离（`strip_hallucinated` 施加 allowed 过滤，fail-closed），SHALL NOT 透出下游。

`CredentialVault` SHALL 保持进程级全局单例与跨请求同 token 语义；`make_cred_token` 六位零填充、还原侧 `token_re` `\d{4,}`、占位符说明注入门控 `\d{6,}`、prompt-cache 关联语义 SHALL 均不变。本要求为对既有「网关侧可还原」口径的请求级授权收窄，属安全修复而非兼容回归。

#### Scenario: 本请求产出的 token 可还原

- **WHEN** 请求侧脱敏实际将某凭据明文替换为 token T，且响应回传 T
- **THEN** 因 T ∈ minted-set，响应侧将其还原为原文，下游收到明文

#### Scenario: 调用方自带字面 token 不还原

- **WHEN** 请求体自带 `__VG_CRED_000123__` 字面量（未被本请求脱敏产出）且响应回传该字面量
- **THEN** 该 token 不在 minted-set，系统按幻觉 token 剥离，SHALL NOT 还原为任意历史请求的凭据明文

#### Scenario: 跨请求不借用他请求 token

- **WHEN** 请求 B 的响应出现请求 A 曾产出的 token 形态
- **THEN** 该 token 不在 B 的 minted-set，B SHALL NOT 还原它，仅按未授权剥离

#### Scenario: 单例与同 token 语义不变

- **WHEN** 两次查询同一 entry/field 明文相同
- **THEN** 两次仍返回同一 `__VG_CRED_NNNNNN__`（进程单例复用），还原授权按本要求的请求级 minted-set 判定
