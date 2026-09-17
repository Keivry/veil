# Spec Delta

## MODIFIED Requirements

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
