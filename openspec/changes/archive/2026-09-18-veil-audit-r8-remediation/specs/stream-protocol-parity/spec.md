# Spec Delta

## MODIFIED Requirements

### Requirement: Overlong lines are marked not silently dropped

SSE lines over 16KB SHALL be truncated with a `truncated_line_dropped_bytes` counter and remain visible to audit. The counter SHALL be readable from the running process（getter）and SHALL be exposed in `/_admin/metrics` as an additive field alongside `sse_events`（`R8-13`）；write-only counters SHALL NOT be considered observable.

#### Scenario: Long tool fragment is counted

- **WHEN** a 20KB tool fragment arrives
- **THEN** it is truncated with counter increment, never silently cleared

#### Scenario: Counter is observable

- **WHEN** the truncation counter is read via the metrics API
- **THEN** the `truncated_line_dropped_bytes` field is present and reflects the accumulated dropped bytes

## ADDED Requirements

### Requirement: 终端后残余帧恒丢弃

系统 SHALL 在任一终端已发出或审计阻断已注入后，丢弃解析器残余的全部帧；SHALL NOT 在终端之后向下游下发任何数据帧（`R8-02`）。残余半帧本 SHALL 按既有口径丢弃。仅在「正常 EOF 收尾且尚无终端」时，残余帧 SHALL 按既有放行语义处理。

#### Scenario: 阻断终端后残余 JSON 被丢弃

- **WHEN** 审计阻断已注入且上游同一 chunk 末尾残留一个可解析完整 JSON（无终止空行）
- **THEN** 该残余帧不下发，下游在阻断终端后零数据帧

#### Scenario: 上游终端后残余被丢弃

- **WHEN** 上游已发官方终端帧（Anthropic `message_stop` / Responses `response.completed`）后到达残余帧
- **THEN** 下游在终端后零数据帧，终端恰一

#### Scenario: 正常 EOF 残余放行不变

- **WHEN** 上游正常 EOF 且尚无任何终端，末尾残余为可解析完整帧
- **THEN** 按既有残余放行/还原语义处理，行为与修复前一致

### Requirement: 上游终端帧即时送达

系统 SHALL 在上游终端帧（Anthropic `message_stop`、Responses `response.completed`/`response.failed`/`response.incomplete`）经边界滞留后立即送达下游，SHALL NOT 依赖上游 EOF（`R8-06`）：终端帧发出后系统 SHALL flush 边界滞留帧并推进泵循环终止，使下游流尽快闭合。Chat `data: [DONE]` 路径的既有 flush 语义（保留 usage 尾帧）SHALL NOT 改变。

#### Scenario: 上游终端后保持连接不挂起

- **WHEN** 上游发出终端帧后保持连接（心跳/延迟关闭）而不 EOF
- **THEN** 下游立即收到终端帧且响应流闭合，不无限期挂起

#### Scenario: Chat DONE 语义不变

- **WHEN** Chat 上游发出 `[DONE]` 且随后仍有 usage 尾帧
- **THEN** 既有 flush 与尾帧透传语义不变

### Requirement: 审计阻断后停止拉取上游

系统 SHALL 在审计阻断帧提交成功后停止拉取上游响应体，并尽快闭合下游流（`R8-07`）：阻断 SHALL 终止泵读取循环（标记循环终止），使下游 mpsc 通道随泵任务结束而关闭；SHALL NOT 保持下游连接打开等待上游 EOF。阻断触发前已累计的用量/审计观测 SHALL NOT 丢失。

#### Scenario: 阻断后上游不 EOF 仍尽快闭合

- **WHEN** 审计阻断已提交且上游继续产出数据但不 EOF
- **THEN** 泵任务在阻断帧之后结束、下游流闭合，恰一终端

#### Scenario: 阻断前用量不丢失

- **WHEN** 阻断触发前已有用量帧被处理
- **THEN** 已累计用量/观测保留，不因提前终止而丢失
