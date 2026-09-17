# Spec Delta

## MODIFIED Requirements

### Requirement: Chat 分桶无碰撞与阻断帧多 choice 覆盖

系统 SHALL 对 Chat 用量/事件分桶采用无碰撞口径，SHALL NOT 因固定步长饱和导致不同取值映射到同一桶键。合成 Chat 阻断帧 SHALL 按显式声明覆盖范围处理 choice：当前声明为仅覆盖 `choices[].index == 0` 单 choice（审计阻断为流级动作，替换整条流，多 choice 流的其余 choice 不逐条重建），SHALL NOT 静默丢失阻断语义。合成 Chat 流式阻断帧 SHALL 回显已知的会话标识与请求/归一模型名（会话标识缺失时回退 `blocked-0`，模型名缺失时回退 `unknown_model`），与非流阻断体 `nonstream_block_body` 的回显口径对齐；SHALL NOT 恒以 `blocked-0`/`unknown_model` 覆盖，避免按会话/模型聚合的审计与 metrics 断链。

该模型回显口径 SHALL **覆盖三协议**的流式阻断帧：Anthropic 与 Responses 的合成阻断帧（生产入口 `src/service/block_inject/frames.rs::anthropic_block_frames_modeled`、`::responses_failed_frame_modeled`、`::responses_block_frames_at_modeled`，均经内部 `::responses_sequence` 写入 `model`）此前硬编码 `unknown_model`，与非流 `src/service/block_inject/frames.rs::nonstream_block_body` 三协议均按上游值回显模型的口径不对称；本要求 SHALL 使三协议流式阻断帧同样回显请求/归一模型名（模型不可得时才回退 `unknown_model`），SHALL NOT 保留 Chat 已对齐而 Anthropic/Responses 仍硬编码的残余不对称。

模型回显口径 SHALL **同样覆盖非阻断的合成终止帧**（`R5-03`/`R5-39`）：Responses 中途断流的 `src/service/block_inject/frames.rs::synthesize_truncation_modeled` 与真空流的 `::empty_stream_frames_modeled` SHALL 将已知流模型名写入 `response.failed.response.model`；此前该合成路径恒 `unknown_model`，故修复后 Responses 截断/真空合成的 `response.failed.response.model` 由 `unknown_model` 变为真实模型名（用户可见变更，登记于 README §7.12）。上述合成一律经 `*_modeled` 生产入口；legacy 非 modeled 包装（`chat_block_frames`/`protocol_block_frames`/`anthropic_block_frames`/`anthropic_block_frames_full`/`responses_block_frames`/`responses_block_frames_at`/`responses_truncated_frames`/`responses_failed_frame`/`synthesize_truncation`/`empty_stream_frames`）现已 `#[cfg(test)]` 收编，SHALL NOT 被生产路径调用，以防模型回显被静默回退（`chat_block_frames_full` 例外：仍由 `protocol_block_frames_modeled` 在生产内调用）。

#### Scenario: 分桶无碰撞

- **WHEN** 两个不同取值落在饱和边界附近
- **THEN** 分桶键可区分、不碰撞

#### Scenario: 阻断帧覆盖多 choice

- **WHEN** 上游流含多个 choice 且命中阻断
- **THEN** 合成阻断帧按显式声明范围（当前 `index == 0` 单 choice、流级替换）覆盖，不静默遗漏阻断语义

#### Scenario: 流式 Chat 阻断帧回显会话与模型

- **WHEN** 流式 Chat 命中阻断且会话标识/请求模型已知
- **THEN** 合成阻断帧的 `id`/`model` 回显该会话标识与归一模型名（缺失才回退 `blocked-0`/`unknown_model`），与非流阻断体口径一致

#### Scenario: Anthropic/Responses 流式阻断帧回显模型

- **WHEN** 流式 Anthropic 或 Responses 命中阻断且请求/归一模型名已知
- **THEN** 合成阻断帧（生产入口 `anthropic_block_frames_modeled`/`responses_failed_frame_modeled`/`responses_block_frames_at_modeled`）回显该模型名而非硬编码 `unknown_model`（不可得时才回退），与非流 `nonstream_block_body` 三协议回显口径对齐；Responses 截断/真空合成（`synthesize_truncation_modeled`/`empty_stream_frames_modeled`）的 `response.failed.response.model` 同样回显真实模型名

### Requirement: Model and cache columns restored

`record_chat` SHALL bucket by model (truncated 128, control chars removed) and usage SHALL expose `cached_read/cached_write`. 流式模型提取 SHALL 按顶层 `model` → Anthropic 嵌套 `message.model` → Responses 嵌套 `response.model` 三级回退（与 `response.id` 会话标识回退对称），使 Responses `response.completed` 携带的 `response.model` 被读取用于分桶；SHALL NOT 仅查顶层 `model` 与 `message.model` 而令 Responses 流式恒回退请求模型、与非流上游回显口径分裂。

#### Scenario: Block body echoes upstream model

- **WHEN** a block body is synthesized
- **THEN** its model field echoes the upstream value, never the literal `blocked`

#### Scenario: Responses 流式读取嵌套 response.model

- **WHEN** Responses 流式事件（如 `response.completed`）的模型名位于嵌套 `response.model` 而顶层无 `model`
- **THEN** 流式模型提取返回该值用于分桶，与非流路径的上游回显口径一致，不再回退请求模型

### Requirement: hold 放行保持 sequence_number 相对序

系统 SHALL 在 hold 放行时按「每槽按到达序取出、由该槽完成事件驱动」执行：同一槽内帧的相对次序 SHALL 保持（按到达序）。**跨槽并行 item 的相对 `sequence_number` 次序 SHALL NOT 被保证**；该不保证范围 SHALL 显式声明并由交错并行 item 用例锁定实际放行序。系统 SHALL NOT 为追求跨槽严格排序而等待可能永不到达的槽完成事件（与 hold-until-complete 的 fail-closed 语义一致）。槽内保序状态（下一序号游标与字节计数）SHALL 以饱和算术推进：上游 `sequence_number` 取极值（如 `u64::MAX`）时 SHALL NOT 溢出回绕、SHALL NOT panic、SHALL NOT 因回绕复用 `BTreeMap` 键致审计分片错位或互相覆盖。实现点 SHALL 覆盖 `src/service/audit/hold.rs::push_responses_fragment` 内三处裸算术——`slot.next_seq + 1`、`.max(seq_no + 1)` 与 `total_bytes +=`；与 `stream-fidelity-fix`「审计 hold 字节按槽回收」的字节饱和要求同源同义（两处措辞 MUST NOT 漂移）。上游 `seq_no == u64::MAX` 的**极值入参分支** SHALL 由单元测试显式锁定。

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

#### Scenario: 极值序号不溢出不复用键

- **WHEN** 上游某槽的 `sequence_number` 为 `u64::MAX` 或紧邻极值，hold 推进该槽的保序游标
- **THEN** 游标按饱和算术推进：不 panic、不回绕、不复用既有 `BTreeMap` 键，审计分片仍按到达序缝合且互不覆盖；`seq_no == u64::MAX` 极值分支由单元测试锁定（`slot.next_seq + 1`/`.max(seq_no + 1)`/`total_bytes +=` 三处裸算术全部饱和化）
