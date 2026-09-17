# stream-protocol-parity Specification

## Purpose
Close remaining streaming-protocol edge semantics and restore observability columns so truncation never escapes audit and dashboards regain model/cache dimensions.

## Requirements

> **迁移声明（F-06）**：原「空流保持开放结尾（chat/anthropic）」条款已删除。三协议真空流（零字节零残余）SHALL 均走最小可解析终止——Chat 补恰一 `data: [DONE]`；Anthropic 补最小 `message_start` + `message_stop`；Responses 补恰一 `response.failed`。`truncated_mode` 的 `open_ended`/`synthesized_failed` SHALL 保留为**观测口径**；系统 SHALL NOT 依据历史文本实现开放结尾。行为真相源见 canonical `openspec/specs/llm-protocol-hardening/spec.md`，差异与原仓对照见 README §8.6。

### Requirement: Responses start events create audit slots

`response.output_item.added` carrying function_call name/id SHALL create an audit slot so truncation before `.done` is still auditable. Global completion events（`response.completed` 等）SHALL 对仍存在、未收到 per-item `.done` 的槽按已累积参数执行与逐-item done 路径相同的审计判定后再放行或阻断，SHALL NOT 因缺少 per-item `.done` 而绕过审计直接重放；缺 per-item done 且累积危险参数时 SHALL 阻断。

#### Scenario: Truncation after added is audited

- **WHEN** only `output_item.added` arrives before truncation
- **THEN** an audit record exists for the pending function call

#### Scenario: 全局完成补审缺 done 槽

- **WHEN** 某工具槽未收到 per-item `.done`，流到达全局完成事件且该槽已累积危险参数
- **THEN** 全局完成重放前对该槽执行同一审计判定，命中阻断则筛除/阻断，危险参数不透传

### Requirement: Tool verdicts agree across stream modes

The same `file_search/web_search` invocation SHALL yield the same audit verdict in streaming and non-streaming modes. `output_item.done` 提取 SHALL 覆盖所有工具 item 类型（非仅 `function_call`），或显式声明覆盖范围；同一调用在流式 item-done 路径与非流提取 SHALL 得出同一审计 verdict。

#### Scenario: Same call same verdict

- **WHEN** a `file_search_call` arrives via stream vs non-stream
- **THEN** both paths reach identical audit conclusions

#### Scenario: item-done 覆盖非 function_call 类型

- **WHEN** `output_item.done` 为非 `function_call` 的工具 item 类型（如检索/自定义工具）
- **THEN** 该 item 在 item-done 路径同样进入审计判定，或按其显式声明范围处理

#### Scenario: 缺 per-item done 与完成路径同 verdict

- **WHEN** 同一工具调用分别经逐-item done 路径与全局完成补审路径
- **THEN** 两条路径得出相同 audit verdict

### Requirement: Overlong lines are marked not silently dropped

SSE lines over 16KB SHALL be truncated with a `truncated_line_dropped_bytes` counter and remain visible to audit.

#### Scenario: Long tool fragment is counted

- **WHEN** a 20KB tool fragment arrives
- **THEN** it is truncated with counter increment, never silently cleared

### Requirement: Inline BOM is stripped before parsing

`\uFEFFdata:` frames SHALL be BOM-stripped before DONE/JSON evaluation.

#### Scenario: BOM frame parses

- **WHEN** upstream sends a BOM-prefixed data frame
- **THEN** it parses exactly like the non-BOM equivalent

### Requirement: Model and cache columns restored

`record_chat` SHALL bucket by model (truncated 128, control chars removed) and usage SHALL expose `cached_read/cached_write`. 流式模型提取 SHALL 按顶层 `model` → Anthropic 嵌套 `message.model` → Responses 嵌套 `response.model` 三级回退（与 `response.id` 会话标识回退对称），使 Responses `response.completed` 携带的 `response.model` 被读取用于分桶；SHALL NOT 仅查顶层 `model` 与 `message.model` 而令 Responses 流式恒回退请求模型、与非流上游回显口径分裂。

#### Scenario: Block body echoes upstream model

- **WHEN** a block body is synthesized
- **THEN** its model field echoes the upstream value, never the literal `blocked`

#### Scenario: Responses 流式读取嵌套 response.model

- **WHEN** Responses 流式事件（如 `response.completed`）的模型名位于嵌套 `response.model` 而顶层无 `model`
- **THEN** 流式模型提取返回该值用于分桶，与非流路径的上游回显口径一致，不再回退请求模型

### Requirement: Chat 次要事件判定不得将 refusal:null 视为次要

系统 SHALL NOT 仅因 Chat 帧不含文本内容或 `refusal` 字段为 `null` 就将其判为次要（minor）事件；`refusal:null` SHALL NOT 作为次要判据，仅当 `refusal` 为非 null 且非空等确有次要语义时才可判为次要。次要判定 SHALL NOT 导致含工具/参数信息的帧跳过审计。

#### Scenario: refusal:null 非次要

- **WHEN** Chat 帧含 `refusal: null` 且属于需审计的内容
- **THEN** 该帧不被判为次要，审计照常执行

#### Scenario: 非空 refusal 仍可次要

- **WHEN** 帧含非 null 且非空的 `refusal`
- **THEN** 按次要语义处理

### Requirement: 干净收尾不误记 open_ended

系统 SHALL 区分「干净完成」与「异常截断」：当流已出现非 null `finish_reason`（成功收尾信号）后干净 EOF，即使未收到 `data: [DONE]`，SHALL NOT 记为 `open_ended`；`open_ended` SHALL 仅用于无成功收尾信号的异常结束。

#### Scenario: finish_reason 后干净 EOF 不记 open_ended

- **WHEN** Chat 流已发非 null `finish_reason` 后干净 EOF 且未发 `[DONE]`
- **THEN** 记录为干净完成，`truncated_mode` 不置 `open_ended`

#### Scenario: 无 finish_reason 异常 EOF 记 open_ended

- **WHEN** 流无成功收尾信号即异常 EOF
- **THEN** `open_ended` 照常记录

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

### Requirement: 无 event: 行的 data 帧不注入 event

系统 SHALL 对不带 `event:` 行的 data 帧保持原形态，SHALL NOT 合成或注入 `event: message` 或其它事件名；仅当上游确实提供 `event:` 时，出口才按该字段重建。

#### Scenario: 无 event 不注入

- **WHEN** 上游 data 帧无 `event:` 行
- **THEN** 下游该帧不含被注入的 `event:` 字段

#### Scenario: 有 event 保真

- **WHEN** 上游提供 `event: x`
- **THEN** 下游保留 `event: x`
