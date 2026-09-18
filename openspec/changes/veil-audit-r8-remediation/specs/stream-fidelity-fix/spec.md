# Spec Delta

## MODIFIED Requirements

### Requirement: 流式上游错误状态透传

系统 SHALL 在流式请求的上游响应 `status>=400` 时，透传上游状态码与正文字节（与非流路径语义一致）；SHALL NOT 不看状态码一律转入 SSE 泵并恒定回 200。README §7.2 SHALL 同步该透传口径。

对 `stream:true` 且上游 `status < 400`、但 `content-type` 非 `text/event-stream` 的响应（`R8-16`）：系统 SHALL 按「JSON 走完整后处理、非 JSON 字节透传」分流——正文可解析为 JSON 时，SHALL 复用非流完整后处理链（用量记录 + 工具审计判定 + 还原 + 响应侧新 PII 掩码），审计命中 `Block` 时下游 SHALL 收到 `nonstream_block_body`；正文非 JSON 时 SHALL 按字节透传原状态码与正文，并记 warn 与内部非导出计数（复用 `GatewayMetrics` 同层透传类计数；SHALL NOT 新增 admin 字段）。该分支 SHALL NOT 跳过审计与响应侧新 PII 掩码（安全控制 fail-closed），SHALL NOT 重发上游请求（非幂等）。零替换/零掩码时该链 SHALL 逐字节保真。

对进入 SSE 泵的上游 2xx 响应（`status < 400` 且 `content-type` 为 `text/event-stream`），下游流式响应 SHALL 逐字携带上游的 2xx 原状态码（如 `201`/`202`/`206`），SHALL NOT 硬编码改写为 `200`；`<400` 的入泵门控 SHALL NOT 放宽。

#### Scenario: 500 JSON 错误体

- **WHEN** `stream:true` 请求上游返回 500 且正文为 JSON
- **THEN** 下游收到 500 与同一 JSON 正文字节

#### Scenario: 500 HTML 错误体

- **WHEN** 上游返回 500 且正文为 HTML（非 `text/event-stream`）
- **THEN** 下游收到 500 与同一 HTML 正文字节，不被改写为 200 SSE

#### Scenario: 2xx 非 200 状态透传

- **WHEN** 上游以 `status < 400` 且 `content-type: text/event-stream` 进入 SSE 泵，状态码为 `201`/`202`/`206` 之一
- **THEN** 下游流式响应携带上游原 2xx 状态码（不被改写为 `200`），流式正文字节不变

#### Scenario: 2xx 非 SSE JSON 走完整后处理链

- **WHEN** `stream:true` 请求上游返回 `status<400` 且 `content-type: application/json`，正文含危险 tool 调用
- **THEN** 系统经非流完整后处理链判定，命中 `Block` 时下游收到 `nonstream_block_body`；审计判定与响应侧新 PII 掩码 SHALL NOT 被跳过

#### Scenario: 2xx 非 SSE 非 JSON 维持字节透传

- **WHEN** `stream:true` 请求上游返回 `status<400` 且正文非 JSON（非 `text/event-stream`）
- **THEN** 下游收到原状态码与逐字节正文，并记 warn 与计数

#### Scenario: 2xx 非 SSE JSON 零命中字节不变

- **WHEN** 上述 JSON 分支零审计命中、零还原、零响应侧新 PII 掩码
- **THEN** 下游字节与上游逐字节一致

### Requirement: SSE 事件计数口径一致

系统 SHALL 对 SSE 事件计数采用统一口径并显式声明两侧覆盖范围：`SseParser::sse_event_count` 仅统计解析路径产出的数据事件（分块/同块等价口径基准）；审计 hold 阻断、截断收尾、真空流最小终止等路径注入的合成帧 SHALL NOT 计入解析读取计数，该排除 SHALL 由本条显式声明并与实现一致。生产注入帧的计数唯一来源为 `GatewayMetrics::add_sse_event`，其覆盖下游实际发出的全部帧（含合成帧）。系统 SHALL NOT 断言两口径在含合成帧的流上逐帧相等，SHALL NOT 出现未声明的「只读计数与生产指标口径不一致」。

#### Scenario: 注入帧纳入计数

- **WHEN** 阻断路径注入合成 SSE 帧
- **THEN** 该注入帧经生产指标 `GatewayMetrics::add_sse_event` 纳入计数，且按本条声明 SHALL NOT 计入 `sse_event_count`；声明与实现一致

#### Scenario: 计数口径一致

- **WHEN** 同一上游流分别经解析读取计数与运行时指标计数
- **THEN** 合成帧 SHALL NOT 计入 `sse_event_count`；除该声明排除项外 SHALL NOT 存在其他未声明差异（不再要求数值相等或逐帧相等）
