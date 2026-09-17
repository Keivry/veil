# llm-critical-compliance Specification

## Purpose
锁定 6 项 LLM 关键合规修复的可验证行为：混帧工具优先、终止精确判定、conv 优先流内、false 语义声明、双字段独立回退、阻断状态码对称。

## Requirements

### Requirement: E7 thinking 混帧工具优先进审

系统 SHALL 对同时含 thinking 增量与工具 `partial_json` 增量的帧优先提取工具片段，非空时 SHALL 走 tool 通道进 hold 审计，仅剩余 thinking 部分 SHALL 走 minor 透传。

#### Scenario: 混帧工具增量不漏审

- **WHEN** Anthropic `content_block_delta` 同时含 `thinking_delta` 与 `partial_json`
- **THEN** 工具片段进 hold 审计，thinking 部分透传不审计

#### Scenario: 纯 thinking 仍为次要事件

- **WHEN** 帧只含 `thinking_delta` 无工具片段
- **THEN** 整帧标 minor 透传且不进 hold

### Requirement: E8 Responses 终止按 type 精确判定

系统 SHALL 对 Responses 终止判定经 `serde_json` 解析后按 `type` 字段精确匹配（`response.completed/response.failed/response.incomplete/error`），SHALL 不再依赖 `contains` 字符串匹配。

#### Scenario: 空格变体不漏判

- **WHEN** 错误帧为 `{"type": "error"}`（冒号后带空格）
- **THEN** 判定为终结并合成截断帧

#### Scenario: 正文含关键词不误判

- **WHEN** 文本内容含 `response.completed` 字符串但 `type` 非终结类型
- **THEN** 不触发终结，流继续转发

### Requirement: E9 incomplete 合成优先流内 conv_id

系统 SHALL 在合成 `incomplete/error` 截断帧时优先采用流内首见 `id`，仅缺失时 SHALL 回退 `resolve_conv_id` 归档值。

#### Scenario: 流内 id 优先

- **WHEN** 流内已见 `response.created` 带 `id=resp_123` 后出现 `incomplete`
- **THEN** 合成截断帧用 `resp_123`，下游可关联

#### Scenario: 缺失才归档

- **WHEN** 流内从未出现可用 `id`
- **THEN** 回退归档值并记 `conv_missing` 计数

### Requirement: E1 显式 false 用量语义文档化

系统 SHALL 在 `README §7.2` 声明“`stream_options.include_usage` 显式 false 即用户放弃流式用量”，且 SHALL 说明 metrics 空 usage 桶为预期告警而非异常。

#### Scenario: false 保留可预期

- **WHEN** 请求自带 `stream_options={"include_usage":false}`
- **THEN** 转发体保留 false，文档解释无流式 usage 帧

#### Scenario: 空 usage 桶不误报

- **WHEN** metrics 观测到某模型空 usage 桶
- **THEN** 按文档先查请求是否显式 false，再判异常

### Requirement: E2 Responses 双字段独立注入独立回退

系统 SHALL 对 Responses `input` 与 `instructions` 按字段独立注入占位说明，各字段独立校验独立回退，一字段非法 SHALL 不丢弃另一合法字段的改动。

#### Scenario: 部分非法不连坐

- **WHEN** `input` 为合法 string 且 `instructions` 为非法 number
- **THEN** `input` 注入保留，`instructions` 保持原值

#### Scenario: 双非法整体回退

- **WHEN** `input` 与 `instructions` 均非法
- **THEN** 整体回退不注入，返回原体

### Requirement: E4 非流与流式阻断状态码对称

系统 SHALL 使非流阻断与流式阻断在**阻断帧正文**上对称（非流用 `nonstream_block_body`、流式按协议注入阻断帧），**状态码不构成对称判据**（本 requirement 名中的「状态码对称」为历史命名锚点，正文口径为「阻断帧正文对称」，名称保留为工具锚点）：非流上游 2xx 命中阻断时下游恒收 `200 + nonstream_block_body`（既有口径），流式上游 2xx（`status < 400` 且 `content-type: text/event-stream`）SHALL 逐字透传上游原状态码（如 `201`/`202`/`206`）至下游，SHALL NOT 硬编码为 `200`（见 `src/handler/llm/pump/event.rs::build_sse_response` 与 `src/handler/llm/dispatch.rs::stream_upstream_passthrough`）；阻断命中同样保留上游 2xx 状态码。README §7.2 的「与流式恒 200 闭合对称」表述已被本 change 取代（superseded），一律以「阻断帧正文对称」为准。该口径 SHALL 由单测锁定。

#### Scenario: 对称恒 200

- **WHEN** 非流命中阻断且上游状态为 2xx，或流式命中阻断且上游状态为 2xx
- **THEN** 两路径的阻断帧正文按协议对称（非流 `nonstream_block_body`、流式注入阻断帧），状态码各自逐字跟随上游 2xx 原码，不再主张「状态码恒 200」

#### Scenario: 差异声明锁定

- **WHEN** 需要声明流式与非流的状态码差异
- **THEN** 文档写明「对称的是阻断帧正文而非状态码，流式 2xx 原状态码透传」的原因，单测断言该口径

#### Scenario: 2xx 原状态码透传

- **WHEN** 上游以 `status < 400` 且 `content-type: text/event-stream` 进入 SSE 泵（如 `201`/`202`/`206`），含该流被审计阻断的情形
- **THEN** 下游流式响应携带上游原 2xx 状态码（不被改写为 `200`），阻断帧正文按协议注入、流式正文字节不变
