## REMOVED Requirements

### Requirement: Empty streams stay open-ended for chat/anthropic

**Reason**: 该条款与 canonical `llm-protocol-hardening` 的「Chat 终止帧补发」与「Anthropic 真空流最小终止」直接冲突（双 canonical 真相源矛盾，审查发现 F-06）。现行行为真相源为 `openspec/specs/llm-protocol-hardening/spec.md`：三协议真空流均补最小可解析终止，不再保持开放结尾。

**Migration**: 迁移为如下口径——Chat 真空流补恰一 `data: [DONE]`；Anthropic 真空流补最小 `message_start` + `message_stop`；Responses 真空流补恰一 `response.failed`。`truncated_mode` 的 `open_ended`/`synthesized_failed` 仍保留为**观测口径**；系统 SHALL NOT 依据本历史文本实现开放结尾。下游若依赖「真空流零帧」旧行为，须改按三协议最小终止解析。

## MODIFIED Requirements

### Requirement: hold 放行保持 sequence_number 相对序

系统 SHALL 在 hold 放行时按「每槽按到达序取出、由该槽完成事件驱动」执行：同一槽内帧的相对次序 SHALL 保持（按到达序）。**跨槽并行 item 的相对 `sequence_number` 次序 SHALL NOT 被保证**；该不保证范围 SHALL 显式声明并由交错并行 item 用例锁定实际放行序。系统 SHALL NOT 为追求跨槽严格排序而等待可能永不到达的槽完成事件（与 hold-until-complete 的 fail-closed 语义一致）。

#### Scenario: 槽内到达序保持

- **WHEN** 同一槽的多个帧被 hold 后放行
- **THEN** 该槽内帧按到达序放行，相对次序不颠倒

#### Scenario: 交错并行 item 保序

- **WHEN** 多个并行 item 的帧交错到达并被 hold 后放行
- **THEN** 同一槽内按到达序放行；跨槽相对 `sequence_number` 次序**不被保证**（为显式声明的例外），实际放行序由锁定用例断言

#### Scenario: 无法保序时显式声明

- **WHEN** 检查跨槽并行 item 的放行序契约
- **THEN** 「每槽到达序 + 该槽完成事件驱动、跨槽不保证相对序」被显式声明，并由交错并行 item 用例锁定实际行为

#### Scenario: 不为保序等待未完成槽

- **WHEN** 某槽尚未收到完成事件
- **THEN** 系统不因等待跨槽排序而阻塞其它已就绪槽的放行，无悬挂
