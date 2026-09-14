## Purpose

锁定 LLM 网关传输面的字节/字段保真契约：SSE 出口信封（`id`/`retry`/跨块 `event`）、Anthropic `message_start` 会话与模型提取、Responses `error` 事件双形态诊断字段、流式上游错误透传的有界读与内部头隔离、`stream_options` 三态保留、Anthropic 阻断帧真实 index 与参数累积清洁。

## ADDED Requirements

### Requirement: SSE 出口信封字段保真

系统 SHALL 在 SSE 出口按 WHATWG 字段语义保真重放信封字段：`id:` SHALL 随所在事件透出（last-event-id 语义，最近值对后续事件持续有效）；`retry:` SHALL 以合法整数形态透出；`event:` SHALL 与后续 `data:` 保持配对。当上游把 `event:`/`id:` 与 `data:` 分置于不同块或被空行隔开时，系统 SHALL 暂存 `event`（FIFO 配对）与最近 `id`，与后续 `data` 在同一输出块重建，SHALL NOT 弃置 `id`/`retry`、SHALL NOT 让 `event:` 成为无 `data` 的孤立块。跨块暂存 SHALL 仅影响出口块重建，SHALL NOT 改变既有事件/帧计数语义：分块信封流的事件计数（`sse_event_count`）与出口转发帧计数（审计与 metrics）SHALL 与同内容非分块流逐一致，SHALL NOT 额外增加或吞并事件/帧。

#### Scenario: `id:` 直通

- **WHEN** 上游事件含 `id: 42` 与 `data: {...}`（同块）
- **THEN** 下游收到含 `id: 42` 的同一输出块，`id` 不被丢弃

#### Scenario: `retry:` 直通

- **WHEN** 上游事件含 `retry: 3000` 与 `data: {...}`
- **THEN** 下游收到 `retry: 3000`，且非数字值不被透出

#### Scenario: 跨块 `event:`/`data:` 配对

- **WHEN** 上游先发仅含 `event: content_block_delta` 的块，随后在下一块发 `data: {...}`
- **THEN** 下游收到 `event: content_block_delta` 与 `data: {...}` 在同一输出块，配对不丢失

#### Scenario: 分块暂存不改变计数

- **WHEN** 同一组 `event:`/`data:` 内容分别以分块信封形态与非分块同块形态投递
- **THEN** 两者的 `sse_event_count` 与出口转发帧计数（审计/metrics）逐一致，无额外增删

### Requirement: Anthropic message_start 会话与模型提取

系统 SHALL 从 Anthropic `message_start` 事件的嵌套 `message.id` 与 `message.model` 提取会话标识与模型名，SHALL NOT 仅依赖顶层 `id`/`model`。提取到的会话标识 SHALL 注入审计关联，模型名 SHALL 注入指标 model 分桶，使 `message_start` 之后不再恒为 `unknown_model`。

#### Scenario: message_start 提取 message.id

- **WHEN** 上游发 `{"type":"message_start","message":{"id":"msg_abc","model":"claude-x"}}`
- **THEN** 该流的会话标识为 `msg_abc`，审计/指标按该会话关联

#### Scenario: message_start 提取 message.model

- **WHEN** `message_start.message.model` 为 `claude-x` 且顶层无 `model`
- **THEN** model 分桶记录 `claude-x`，不记为 `unknown_model`

### Requirement: Responses error 事件双形态诊断字段

系统 SHALL 兼容 Responses `error` 事件的两种形态：官方 `ResponseErrorEvent`（`code`/`message`/`param`/`sequence_number` 位于**顶层**）与既有嵌套 `error` 对象形态。合成 `response.failed` 时 SHALL 保留可得的上游 `code`/`message`/`param`，并在可得时携带 `sequence_number`；缺失字段 SHALL NOT 以空值噪声填充。

#### Scenario: 官方顶层形态保留 code/param

- **WHEN** 上游发 `{"type":"error","code":"server_error","message":"boom","param":"p","sequence_number":7}`
- **THEN** 合成 `response.failed` 保留 `code=server_error`、`param=p`，且携带 `sequence_number=7`

#### Scenario: 嵌套形态仍被支持

- **WHEN** 上游发 `{"type":"error","error":{"code":"rate_limit_exceeded","message":"slow"}}`
- **THEN** 合成 `response.failed` 保留 `code=rate_limit_exceeded` 与 `message`

### Requirement: 流式上游错误透传有界读

系统 SHALL 对 `stream_upstream_passthrough` 的响应读取施加硬上限：SHALL 先检查上游 `content-length`，再读取至多 `NONSTREAM_MAX_BYTES + 1` 字节；SHALL NOT 在未设上限前调用全量 `bytes()` 缓冲。仅当响应为**非错误状态（`status < 400`）**且读取量严格超过 `NONSTREAM_MAX_BYTES` 时，系统 SHALL 返回 502 `response_too_large`（fail-closed），不透传超限体、不发生内存放大。响应为**错误状态（`status >= 400`）**时，系统 SHALL 保持错误体透传语义：SHALL NOT 把上游状态码或正文改写成 502，有界读/计数仅用于内存安全，下游 SHALL 收到与上游一致的状态码与正文字节（与 README §4「错误体按透传语义不改写」一致）。

#### Scenario: 非错误大 body 受上限约束

- **WHEN** 上游非错误（`status < 400`）正文超过 `NONSTREAM_MAX_BYTES`
- **THEN** 网关不 OOM，返回 502 `response_too_large`，不转发超限字节

#### Scenario: 4xx/5xx 超限仍透传不改写

- **WHEN** 上游错误（`status >= 400`）正文超过 `NONSTREAM_MAX_BYTES`
- **THEN** 下游收到与上游一致的状态码与正文字节，网关不返回 502、不改写错误体，且内存受上限约束

#### Scenario: 上限内正文保状态保字节

- **WHEN** 上游正文在 `NONSTREAM_MAX_BYTES` 之内
- **THEN** 下游收到与上游一致的状态码与正文字节

### Requirement: 内部响应头隔离

系统 SHALL 在流式错误透传路径转发上游响应头前，剔除所有 `x-veil-*` 内部头（大小写不敏感）；网关自置的 `x-veil-protocol`/`x-veil-normalized` SHALL 在剔除后由网关写入，SHALL NOT 被上游同名声明的值覆盖。上游注入的 `x-veil-*` SHALL NOT 泄漏到下游。

#### Scenario: 上游注入内部头不泄漏

- **WHEN** 上游响应含 `x-veil-debug: leak` 且流式透传路径命中
- **THEN** 下游响应不含 `x-veil-debug`，且 `x-veil-protocol` 为网关自置值

### Requirement: stream_options 三态保留

系统 SHALL 对 Chat 请求的 `stream_options` 按三态处理：键缺失时 SHALL 注入 `{"include_usage":true}`；值为 `null` 时 SHALL 原样保留 `null` 且 SHALL NOT 注入或替换；值为对象时 SHALL 仅在缺 `include_usage` 时按 key 合并注入，已含 `include_usage` 时 SHALL 原样保留其值（含 `false`）。系统 SHALL NOT 把 `null` 当作缺失而整体替换。

#### Scenario: null 保留不替换

- **WHEN** Chat 流式请求体含 `"stream_options": null`
- **THEN** 转发体保留 `"stream_options": null`，不注入 `include_usage`

#### Scenario: 对象按 key 合并

- **WHEN** Chat 流式请求体含 `"stream_options": {"other": 1}`
- **THEN** 转发体为 `{"other":1,"include_usage":true}`，用户键保留

#### Scenario: 显式 false 保留

- **WHEN** Chat 流式请求体含 `"stream_options": {"include_usage": false}`
- **THEN** 转发体保留 `false`，不覆写为 `true`

### Requirement: Anthropic 阻断帧真实 index 与参数累积清洁

系统 SHALL 在 Anthropic 阻断帧合成时使用触发本次阻断的真实 content block index；仅在无法获知真实 index 时才回退 `0`。系统 SHALL 在 Anthropic 流式参数累积中排除 `content_block_start` 的空占位 `input`（如 `{}`/空串），使 `content_block_delta.partial_json` 不与其拼接；审计参数 SHALL NOT 出现 `"{}{...}"` 前缀污染。

#### Scenario: 阻断帧使用真实 index

- **WHEN** 上游在 `index: 2` 的 tool_use 块命中阻断
- **THEN** 下游阻断帧的 `content_block_start`/`content_block_stop` 的 `index` 为 `2`；仅当真实 index 未知时回退 `0`

#### Scenario: 空 input 不污染参数

- **WHEN** 上游发 `content_block_start`（`content_block.input={}`、`index:0`）后发 `content_block_delta`（`partial_json="{\"cmd\":\"ls\"}"`）
- **THEN** 审计累积参数为 `{"cmd":"ls"}`，无 `{}{` 前缀
