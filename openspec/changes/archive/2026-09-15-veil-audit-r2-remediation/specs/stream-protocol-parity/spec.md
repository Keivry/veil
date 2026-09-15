## ADDED Requirements

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

系统 SHALL 对 Chat 用量/事件分桶采用无碰撞口径，SHALL NOT 因固定步长饱和导致不同取值映射到同一桶键。合成 Chat 阻断帧 SHALL 覆盖相应全部 choice（或按显式声明覆盖范围），SHALL NOT 仅覆盖 choice 0 而静默丢失其它 choice 的阻断语义。

#### Scenario: 分桶无碰撞

- **WHEN** 两个不同取值落在饱和边界附近
- **THEN** 分桶键可区分、不碰撞

#### Scenario: 阻断帧覆盖多 choice

- **WHEN** 上游流含多个 choice 且命中阻断
- **THEN** 合成阻断帧覆盖相应 choice（或按声明范围），不静默遗漏

### Requirement: hold 放行保持 sequence_number 相对序

系统 SHALL 在 hold 放行（含并行 item 交错）时保持各 item 帧的相对 `sequence_number` 次序，SHALL NOT 因延迟放行使并行 item 的相对顺序颠倒或乱序；若实现无法保序，SHALL 显式声明该范围并锁定测试。

#### Scenario: 交错并行 item 保序

- **WHEN** 多个并行 item 的帧被 hold 后放行
- **THEN** 放行顺序保持原相对 `sequence_number` 次序

#### Scenario: 无法保序时显式声明

- **WHEN** 实现无法保证相对次序
- **THEN** 该范围被显式声明并由测试锁定

### Requirement: 无 event: 行的 data 帧不注入 event

系统 SHALL 对不带 `event:` 行的 data 帧保持原形态，SHALL NOT 合成或注入 `event: message` 或其它事件名；仅当上游确实提供 `event:` 时，出口才按该字段重建。

#### Scenario: 无 event 不注入

- **WHEN** 上游 data 帧无 `event:` 行
- **THEN** 下游该帧不含被注入的 `event:` 字段

#### Scenario: 有 event 保真

- **WHEN** 上游提供 `event: x`
- **THEN** 下游保留 `event: x`

## MODIFIED Requirements

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
