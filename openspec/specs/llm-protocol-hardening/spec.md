# llm-protocol-hardening Specification

## Purpose
锁定 LLM 网关三协议（Chat / Anthropic / Responses）流式与非流式在修复后的线级行为契约：恒恰一终端、真空流最小终止、Responses `incomplete` 原样透传、非 JSON 错误体原样透传、SSE CRLF 跨块正确性、脱敏回退 fail-closed、工具桶流/非流一致。

## Requirements

### Requirement: Chat 终止帧补发

系统 SHALL 在 Chat 流出现非 null `finish_reason` 且流结束时仍未收到 `data: [DONE]` 的情况下，于流结束处补发恰一 `data: [DONE]`；零帧真空流同样 SHALL 补发恰一 `data: [DONE]`。系统 SHALL NOT 伪造 `finish_reason`、内容或 usage；`finish_reason` 之后到达的 usage 尾帧（`choices: []`）SHALL 照常透传，不得提前截断。上游已发 `[DONE]` 时 SHALL NOT 重复补发。

#### Scenario: finish_reason 后断流补 DONE

- **WHEN** 上游发出含非 null `finish_reason` 的分片后断流且从未发 `data: [DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，且此前内容帧与 usage 尾帧均已透传

#### Scenario: 真空流补 DONE

- **WHEN** Chat 上游返回 200 且流式体零帧
- **THEN** 下游收到恰一 `data: [DONE]`，无内容帧

#### Scenario: 自带 DONE 不重复

- **WHEN** 上游正常发送 `data: [DONE]` 收尾
- **THEN** 下游收到恰一 `data: [DONE]`，网关不再补充

### Requirement: Anthropic 真空流最小终止

系统 SHALL 在 Anthropic 真空流（零帧）时发出最小可解析终止序列 `message_start` + `message_stop`；`message_start` SHALL 携带空 `content` 数组与 null `stop_reason`，SHALL NOT 注入任何 `content_block_*` 事件、SHALL NOT 声称语义 stop_reason 或正 usage。系统 SHALL 将 `type:"error"` 事件视为终端：一旦透传 `error`，SHALL NOT 在其后注入 `message_stop` 或任何数据帧。

#### Scenario: 真空流最小终止

- **WHEN** Anthropic 上游返回 200 且流式体零帧
- **THEN** 下游收到 `message_start` 与 `message_stop` 各恰一，且无 `content_block_*` 事件

#### Scenario: error 即终端不补 stop

- **WHEN** 上游流中透传 `type:"error"` 事件
- **THEN** 下游不再收到任何帧（含 `message_stop`）

### Requirement: Responses 恒恰一终端

系统 SHALL 保证 Responses 流下游恰一终端帧，终端集合为 `response.completed` / `response.failed` / `response.incomplete`。已发出任一终端后到达的 `error`/`incomplete`/数据帧 SHALL 被忽略。`response.incomplete` SHALL 原样透传（保留 `incomplete_details`）并作为唯一终端，SHALL NOT 转换为 `response.failed`。`type:"error"` SHALL 合成为单帧 `response.failed`（携带上游 error message），SHALL NOT 注入含 `output_index` 的合成序列；含 `output_index` 的 7 帧全序列 SHALL 仅用于零帧真空流。

#### Scenario: completed 后 error 忽略

- **WHEN** 上游先发 `response.completed` 再发 `type:"error"`
- **THEN** 下游恰一终端（`response.completed`），无 `response.failed`

#### Scenario: incomplete 原样透传

- **WHEN** 上游发出 `response.incomplete` 且带 `incomplete_details`
- **THEN** 下游原字节收到该帧，其后无数据帧，无合成 `response.failed`

#### Scenario: error 单帧 failed

- **WHEN** 上游流中发出 `type:"error"` 且此前未发终端
- **THEN** 下游收到恰一 `response.failed` 单帧，无 `output_index` 合成序列，无重复序号

#### Scenario: 真空流全序列恰一终端

- **WHEN** Responses 上游返回 200 且流式体零帧
- **THEN** 下游收到 7 帧全序列且终端恰一（`response.failed`）

### Requirement: 非 JSON 错误体原样透传

系统 SHALL 对上游 `status>=400` 且响应体非 JSON 的响应原样透传状态码与正文字节；SHALL NOT 以合成 `502 E_EMPTY_BODY` 替换。`status<400` 的非 JSON 空体处理维持现状；502/401 的 JSON 完整后处理链维持不变。

#### Scenario: 429 文本错误体

- **WHEN** 上游返回 429 且 `content-type: text/plain` 非 JSON 体
- **THEN** 下游收到 429 与同字节正文

#### Scenario: 500 HTML 错误体

- **WHEN** 上游返回 500 且 HTML 非 JSON 体
- **THEN** 下游收到 500 与同字节正文，不被替换为 502

#### Scenario: 404 非 JSON 错误体

- **WHEN** 上游返回 404 且非 JSON 体
- **THEN** 下游收到 404 与同字节正文

### Requirement: SSE 跨块行解析正确

系统 SHALL 在 SSE 解析中把跨块的 `\r\n` 视为单一行终止：块末孤立 `\r` 的 CRLF 判定 SHALL 延后到下一块合并（下一块首字节为 `\n` 时按单一行终止消费，否则按孤立 `\r` 处理）。系统 SHALL 使 `event:` 与 `data:` 在同一块内归属同一事件，SHALL NOT 因 TCP 分片提前分发。无冒号的 `data` 行 SHALL 按空值 `data` 字段处理。

#### Scenario: CRLF 跨块不分裂

- **WHEN** 先推送 `event: x\r` 再推送 `\ndata: y\r\n\r\n`
- **THEN** 恰产生一个事件，`event_type=="x"` 且 `data=="y"`

#### Scenario: 块末 CR 后首字节非 LF

- **WHEN** 先推送 `data: z\r` 再推送非 `\n` 起始的下一块
- **THEN** 前一块按孤立 `\r` 终止解析，事件字段归属不变

#### Scenario: 无冒号 data 行

- **WHEN** 块内出现无冒号的 `data` 行
- **THEN** 该行按空值 data 字段参与合并（如 `data\ndata: x` 得 `\nx`）

### Requirement: 脱敏回退 fail-closed

系统 SHALL 在 `stream_options` 注入路径重解析脱敏文本失败时，回退转发已脱敏字节；SHALL NOT 回退转发未脱敏原文。`x-veil-normalized` 声明头 SHALL 仅在请求体成功重序列化时置位。

#### Scenario: 重解析失败不泄漏

- **WHEN** 脱敏文本无法重解析为 JSON 且原请求体可解析
- **THEN** 转发体含占位符、不含原文，且无 `x-veil-normalized` 头

### Requirement: 工具桶流/非流一致

系统 SHALL 使 Responses `output[]` 的流式分片桶号与非流提取同键：取 `item.output_index`，缺失回退枚举下标。系统 SHALL 使流式 `extract_tool_fragments` 与非流 `extract_tool_calls` 对同一输入的字段值（id/name/args）与桶号一致，仅日志告警可因入口不同而有无。

#### Scenario: output_index 存在同键

- **WHEN** Responses `output[]` 条目带 `output_index: 3`
- **THEN** 流式与非流提取桶号均为 3

#### Scenario: output_index 缺失回退下标

- **WHEN** `output[]` 条目缺失 `output_index`
- **THEN** 两路径均回退枚举下标，结论一致

#### Scenario: 缺参缺 id 结论一致

- **WHEN** tool 调用缺 `arguments`/`id`
- **THEN** 流式与非流 args 归一与合成 id 结果一致（非流可 warn，流式静默）
