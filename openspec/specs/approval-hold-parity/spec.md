# approval-hold-parity Specification

## Purpose
锁定凭据审批与危险工具调用的 approve 语义、跨 `data:` 分片的 PII hold 取舍、usage 审计隔离三口径，并约束流式挂起声明、采样默认与 HMAC 告警，保证任何分支都不出现静默降级或明文泄漏。

## Requirements

### Requirement: approve 语义显式

系统 SHALL 按 B 案执行（挂起声明：流式网关危险调用转 pending 记录、不阻塞流、不合成阻断帧；拒绝/过期语义由凭据审批链承载），README SHALL 有 BREAKING 条目声明与 Python 同步阻塞的差异；e2e SHALL 按挂起语义断言（pending 建单可查 + 流内不断链 + 无原文泄漏判定按同步/挂起分别定义）。

#### Scenario: 危险调用不泄漏

- **WHEN** 流式工具调用命中拒绝
- **THEN** 下游不见原始危险参数（同步案见阻断帧，挂起案见 pending 建单且流内无原文）

#### Scenario: 批准释放载荷精确

- **WHEN** 审批通过
- **THEN** 危险 args 原样释放（同步案），挂起案按凭据链语义文档化

### Requirement: 跨片 PII 不提前透出或显式接受

系统 SHALL 实现跨 `data:` 半截 hold（A 案）或在威胁模型中显式声明不防护（B 案），二者居其一。

#### Scenario: 切片回放无半截泄漏（A 案）

- **WHEN** PII 被切在两帧（如 `138` + `12345678`）
- **THEN** 半截不提前透出，完整后一次性输出或脱敏输出

### Requirement: usage审计隔离口径锁定

系统 SHALL 以 `usage max`、审计读原文、PII 请求隔离为准，dashboard SHALL 有迁移注释，审计 SHALL 声明对抗理由。

#### Scenario: 双段 usage 不双计

- **WHEN** 流式 `message_start + delta` 双段上报 usage
- **THEN** 累计值为 max 而非 sum

#### Scenario: 非流 Responses usage 双层可记

- **WHEN** 非流 Responses 体为 `{"response":{"usage":...}}` 双层形态
- **THEN** tokens 正常归档不漏记（单测锁定，与流式双层回退同口径）

### Requirement: 采样默认与 HMAC 告警锁定

系统 SHALL 在采样开启且 HMAC 缺失时启动 warn，且 SHALL 有旧关闭语料回归（显式关闭全链路无落盘）；`REDACTION_ENABLED` 两者皆空默认开启 SHALL 有旧关闭回归（显式 `REDACTION_ENABLED=0` 全链路无脱敏）。

#### Scenario: 无盐采样可发现

- **WHEN** `ENABLED=1` 且 `HMAC_KEY` 为空启动
- **THEN** 日志含无盐可枚举 warn 且单测锁定

#### Scenario: 脱敏默认开可回退

- **WHEN** 显式 `REDACTION_ENABLED=0` 且请求含 PII/凭据明文
- **THEN** 请求原文透传无脱敏且单测锁定（防旧 compose 静默变严）
