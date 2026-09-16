## MODIFIED Requirements

### Requirement: SSE 出口信封字段保真

系统 SHALL 在 SSE 出口按 WHATWG 字段语义保真重放信封字段：`id:` SHALL 随所在事件透出（last-event-id 语义，最近值对后续事件持续有效）；`retry:` SHALL 以合法整数形态透出；`event:` SHALL 与后续 `data:` 保持配对。当上游把 `event:`/`id:` 与 `data:` 分置于不同块或被空行隔开时，系统 SHALL 暂存 `event`（FIFO 配对）与最近 `id`，与后续 `data` 在同一输出块重建，SHALL NOT 弃置 `id`/`retry`、SHALL NOT 让 `event:` 成为无 `data` 的孤立块。跨块暂存 SHALL 仅影响出口块重建，SHALL NOT 改变既有事件/帧计数语义：分块信封流的事件计数（`sse_event_count`）与出口转发帧计数（审计与 metrics）SHALL 与同内容非分块流逐一致，SHALL NOT 额外增加或吞并事件/帧。

出口的跨块 `event` FIFO 待处理队列 SHALL 施加硬上限 `PENDING_EVENTS_MAX=8`；超限时 SHALL **清空整队**（SHALL NOT 仅丢弃最旧项后保留部分队列）并递增 `pending_events_dropped` 计数、每流首次记 warn——语义为 **fail-safe：宁缺信封不错标**（避免保留的残余 `event` 被后续 `data` 块错误配对）。队列清空后同块后续含 `data` 帧 SHALL NOT 携带 `event:` 标签，SHALL NOT 携带错误的 `event:` 名。该上限 SHALL 仅作用于连续超量的 `event:`-only 畸形块；正常 `event:`/`data:` 配对流 SHALL 不受影响，`id` 最近值语义与 `pending_retry` 单值语义 SHALL 不变。系统 SHALL NOT 新增导出指标（畸形输入、warn 与 `pending_events_dropped` 访问器可观测）。

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
- **THEN** 历史场景名**必须原样保留**（OpenSpec MODIFIED 要求场景保全：改名即掉场景并使 `openspec validate --strict` 失败），故本场景仅作名称保全锚点；实际语义见相邻场景「待处理队列超限丢最旧（已取代）」

#### Scenario: 待处理队列超限丢最旧（已取代）

- **WHEN** 上游连续投递超过 `PENDING_EVENTS_MAX` 个 `event:`-only 畸形块
- **THEN** 该历史「丢最旧」行为已由本 change 取代为「清空整队」（fail-safe）；本场景名追加「（已取代）」以消除名称与新语义的矛盾，实际 THEN 见相邻场景「待处理队列超限清空整队」

#### Scenario: 待处理队列超限清空整队

- **WHEN** 上游连续投递超过 `PENDING_EVENTS_MAX` 个 `event:`-only 畸形块（如 9 个），随后发 `data: {...}` 块
- **THEN** 队列被清空、`pending_events_dropped` 递增、每流首次 warn；后续 `data` 帧无 `event:` 标签（SHALL NOT 错配为任一残留 `event:` 名），内存有界

#### Scenario: 正常配对不受上限影响

- **WHEN** `event:`/`data:` 正常配对（非连续超量的 `event:`-only 畸形块）且待处理队列未超上限
- **THEN** 配对与计数语义与既有口径逐一致，清空整队逻辑不触发

## ADDED Requirements

### Requirement: 传输面既有差异声明

系统 SHALL 显式登记以下传输面既有差异（均为有意设计，`SHALL NOT` 视为缺陷或在本 change 内变更）：

1. **非流 `String::from_utf8_lossy` 非字节保真**：非流对话响应体经 `String::from_utf8_lossy`（`src/handler/llm/nonstream.rs:257`）转为文本，非法 UTF-8 字节被替换，非逐字节保真；正确性由还原守卫（`restore_guard_ok`）与失败回退（回退上游原文 + metrics + warn）兜底。
2. **流式错误体透传不设上限 vs 非流有界**：流式上游错误状态（`status>=400`）经 `Body::from_stream` **惰性**转发（`src/handler/llm/dispatch.rs:369-372`），不整块缓冲、**非**内存无界；非流错误体经有界读（`src/handler/llm/dispatch.rs:375`）。二者为有意策略差异。
3. **Chat `stream_options` 畸形态整体替换 + warn**：值为字符串/数组等畸形形态时整体替换为 `{"include_usage":true}` + warn（`src/service/llm_gateway/protocol.rs:194-197`）；`README.md:605-608` 已同字声明，行为维持现状。
4. **非流 `restore_guard_ok(..., None)` 二次解析仅性能**：`None` 时守卫内部解析占位符并执行 `inner_json_intact`（`src/service/redaction/restore_guard.rs:20-26`），存在一次额外解析，属性能成本，正确性无缺口，不在本 change 内优化。

#### Scenario: 非流非字节保真已被兜底

- **WHEN** 非流响应体含非法 UTF-8 字节
- **THEN** 经 `from_utf8_lossy` 后进入还原链，还原守卫失败时回退上游原文并记 metrics/warn，不产生非法输出

#### Scenario: 流式错误体惰性转发不为内存无界

- **WHEN** 流式上游 `status>=400` 返回大错误体
- **THEN** 经 `Body::from_stream` 惰性转发，不整块缓冲（内存有界由流式读取保证），与非流有界读的区别为有意声明

#### Scenario: stream_options 畸形态口径一致

- **WHEN** Chat 请求 `stream_options` 为字符串/数组等畸形态
- **THEN** 整体替换为 `{"include_usage":true}` 并 warn，与 `README.md:605-608` 声明一致（本 change 不改行为）

#### Scenario: 二次解析为性能项

- **WHEN** 非流路径以 `placeholder_parsed=None` 调用守卫
- **THEN** 守卫内部解析占位符并执行 `inner_json_intact`，正确性成立；该二次解析仅登记为性能成本
