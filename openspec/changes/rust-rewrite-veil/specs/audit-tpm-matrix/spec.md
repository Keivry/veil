## Purpose

审计、TPM 与 Matrix 三位一体：审计模式决定放行策略，TPM 提供硬件级密钥派生，Matrix 通道承载人工审批与通知，审计日志脱敏轮转可查。凭据侧 300s 审批见 credential-api spec，本 spec 只收敛审计侧 90s 审批与 Matrix 五分支业务语义。

## ADDED Requirements

### Requirement: 审计三模式默认 off

系统 SHALL 支持审计三模式：`off`（不审计直接放行）、`block`（命中规则直接拒绝）、`approve`（命中规则转人工审批）；模式 SHALL 可配置，默认 SHALL 为 `off`。

#### Scenario: off 默认放行
- **WHEN** 审计模式为 `off`（默认）
- **THEN** 请求不经审计直接放行

#### Scenario: block 模式拒绝
- **WHEN** 审计模式为 `block` 且请求命中拒绝规则
- **THEN** 系统直接返回 403 并记审计事件

#### Scenario: approve 模式转审批
- **WHEN** 审计模式为 `approve` 且请求命中审批规则
- **THEN** 系统创建审批单，凭据或流量暂缓下发，审计审批超时按 90s 计

### Requirement: AUDIT_TIMEOUT 禁止 110-130 与审计 90s

`AUDIT_TIMEOUT` 配置 SHALL 禁止取值 110-130（含端点）；落入该区间 SHALL 启动失败并报错；审计审批超时 SHALL 为 90s（与凭据审批 300s 分表，见 credential-api spec）。有效超时 SHALL 为禁区外正整数秒。

#### Scenario: 禁区取值启动失败
- **WHEN** `AUDIT_TIMEOUT` 配置为 110-130 区间内任意值
- **THEN** 系统启动时报错并退出

#### Scenario: 审计 90s 超时拒绝
- **WHEN** 审计审批单 90s 内无人审批
- **THEN** 系统自动拒绝并记审计事件

### Requirement: 审批白名单 MXID 正则 + 发送者校验 + event id 精确匹配 + 幂等

Matrix 审批白名单 SHALL 以 MXID 正则表达（如 `^@admin:example\.com$`）；审批 SHALL 校验发送者 MXID 在白名单内；reaction SHALL 按 event id 精确匹配到审批单；同一审批单的重复审批 SHALL 幂等（不重复流转）。非白名单用户审批 SHALL 视为无效，不改变审批单状态。

#### Scenario: 白名单审批有效
- **WHEN** 白名单内 MXID 对精确 event id 发送审批指令
- **THEN** 审批单状态更新，重复发送不重复流转

#### Scenario: 非白名单审批无效
- **WHEN** 白名单外用户发送审批指令
- **THEN** 系统忽略该指令，审批单状态不变并记审计事件

#### Scenario: event id 失配忽略
- **WHEN** reaction 的 event id 与审批单精确匹配失败
- **THEN** 系统忽略并记审计事件，审批单状态不变

### Requirement: JSONL 脱敏轮转审计日志

审计日志 SHALL 为 JSONL 格式，每行一条事件；落盘 SHALL 先脱敏后截断，凭据明文与 PII SHALL 脱敏后落盘，零明文；控制字符 `\x00-\x1f` SHALL 剥离；单文件 SHALL 为 10MB，保留 5 份（10MB x 5），文件权限 SHALL 为 0600；写失败 SHALL 双层 fail-closed（先重试缓冲，仍失败则拒绝主请求）并记熔断计数。

#### Scenario: 明文不落盘
- **WHEN** 审计事件含凭据明文或 PII
- **THEN** 落盘内容为先脱敏后截断的摘要，明文不出现，`\x00-\x1f` 已剥离

#### Scenario: 10MB x 5 轮转与 0600
- **WHEN** 日志达到 10MB
- **THEN** 系统轮转出新文件，旧文件按 5 份保留，权限 0600

#### Scenario: 写失败双层 fail-closed
- **WHEN** 审计日志写失败
- **THEN** 系统先重试缓冲，仍失败则拒绝主请求并记熔断计数

### Requirement: TPM 强制硬件

涉及凭据加解密的密钥 SHALL 由 TPM 现场派生，不在磁盘持久化存储；TPM 不可用 SHALL 启动失败，MUST NOT 软件回退。

#### Scenario: TPM 正常派生
- **WHEN** 系统启动且 TPM 可用
- **THEN** 运行期密钥由 TPM 派生，磁盘无密钥明文

#### Scenario: TPM 缺失启动失败
- **WHEN** TPM 不可用
- **THEN** 系统报错退出，不以降级密钥运行

### Requirement: Matrix 五分支业务语义与标识映射

Matrix 审批 SHALL 恰为五分支业务之一：解锁 / 注册 / 哈希变更 / 凭据 / 审计；状态标识映射 SHALL 为 `✅`（已启用/通过）、`❎`（已禁用/拒绝/吊销）、`🔓`（未启用/待审批）；未知分支 SHALL 被忽略并记审计事件。本 spec 不得使用批准 / 拒绝 / 弃权 / 转交 / 加急旧五分支命名。

#### Scenario: 五分支各生效
- **WHEN** 审批事件属解锁 / 注册 / 哈希变更 / 凭据 / 审计之一
- **THEN** 审批单按对应业务语义流转并呈现 `✅` / `❎` / `🔓` 之一

#### Scenario: 未知分支忽略
- **WHEN** 收到五分支外的审批事件
- **THEN** 系统忽略并记审计事件，审批单状态不变
