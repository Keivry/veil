## MODIFIED Requirements

### Requirement: SSE 出口信封字段保真

系统 SHALL 在 SSE 出口按 WHATWG 字段语义保真重放信封字段：`id:` SHALL 随所在事件透出（last-event-id 语义，最近值对后续事件持续有效）；`retry:` SHALL 以合法整数形态透出；`event:` SHALL 与后续 `data:` 保持配对。当上游把 `event:`/`id:` 与 `data:` 分置于不同块或被空行隔开时，系统 SHALL 暂存 `event`（FIFO 配对）与最近 `id`，与后续 `data` 在同一输出块重建，SHALL NOT 弃置 `id`/`retry`、SHALL NOT 让 `event:` 成为无 `data` 的孤立块。跨块暂存 SHALL 仅影响出口块重建，SHALL NOT 改变既有事件/帧计数语义：分块信封流的事件计数（`sse_event_count`）与出口转发帧计数（审计与 metrics）SHALL 与同内容非分块流逐一致，SHALL NOT 额外增加或吞并事件/帧。

出口的跨块 `event` FIFO 待处理队列 SHALL 施加硬上限 `PENDING_EVENTS_MAX=8`：超限 SHALL 丢弃最旧项并递增 `pending_events_dropped` 计数，且每流首次超限 SHALL 记 warn；SHALL NOT 新增导出指标（畸形输入、warn 可观测）。该上限 SHALL 仅作用于连续超量的 `event:`-only 畸形块；`id` 最近值语义与 `pending_retry` 单值语义 SHALL 不变。

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

#### Scenario: 待处理队列超限丢最旧

- **WHEN** 上游连续投递超过 `PENDING_EVENTS_MAX` 个 `event:`-only 畸形块
- **THEN** 超出部分按最旧优先丢弃并递增 `pending_events_dropped`，每流首次记 warn，内存有界

#### Scenario: 正常配对不受上限影响

- **WHEN** `event:`/`data:` 正常配对且待处理队列未超上限
- **THEN** 配对与计数语义与既有口径逐一致

## ADDED Requirements

### Requirement: 事件流 Content-Type 判定大小写不敏感

系统 SHALL 以统一谓词 `is_event_stream(content_type)` 判定响应是否为事件流：取 `;` 前段、`trim` 后与 `text/event-stream` 做 `eq_ignore_ascii_case` 比较。流式泵判定站点（`should_pump_stream` 与 `dispatch`）SHALL 同批改用该谓词，SHALL NOT 保留裸 `contains` 判定；`stream_flag` 回退语义 SHALL 不变。

#### Scenario: 大小写与参数均识别

- **WHEN** 上游响应 `content-type` 为 `Text/Event-Stream`、`text/event-stream; charset=utf-8` 或带前后空白
- **THEN** 均被识别为事件流并进入 SSE 泵

#### Scenario: 非事件流不误判

- **WHEN** 上游响应 `content-type` 为 `application/json` 或其它非事件流类型
- **THEN** 不进入 SSE 泵，按非流口径处理
