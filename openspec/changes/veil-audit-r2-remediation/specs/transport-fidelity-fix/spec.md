## MODIFIED Requirements

### Requirement: 非流响应体有界读取

系统 SHALL 在非流对话路径对上游响应体执行有界读取：`content-length` 声明严格大于 `NONSTREAM_MAX_BYTES` 且 `status < 400` 时 SHALL 直接返回 502 `response_too_large`，SHALL NOT 先全量读入内存；无 `content-length` 或分块传输时 SHALL 以累计字节有界读取并在超过上限时停止读取并返回 502。`status >= 400` 的错误体 SHALL 维持既有语义（按状态与字节透传，不受超限改写）。边界 `len == cap` SHALL 放行。

错误状态响应体的读取 SHALL 同样受有界约束、SHALL NOT 无界全量缓冲：`status >= 400` 时系统 SHALL NOT 以一次性缓冲整个错误体的方式（无界读取）读取上游正文；SHALL 采用累计字节有界读取，并在累计超过上限时按 design 既定策略截断或转为流式转发，保证内存占用不随错误体体积线性增长。有界读取仅为内存安全手段，SHALL NOT 改变错误臂的可观测语义——下行状态码 SHALL 保持上游原值、正文 SHALL NOT 被改写为 502 `response_too_large`（与「错误状态不受超限改写」一致）；截断或流式转发的具体选择 SHALL 在 design 固定并以回归测试锁定。

#### Scenario: content-length 预检

- **WHEN** 上游 200 响应 `content-length` 严格大于 `NONSTREAM_MAX_BYTES`
- **THEN** 网关立即返回 502 `response_too_large`，不读取响应体

#### Scenario: 分块超限停止读取

- **WHEN** 上游以 `transfer-encoding: chunked` 持续输出超过 `NONSTREAM_MAX_BYTES` 的 200 响应体
- **THEN** 网关在累计超限处停止读取并返回 502，内存占用不随响应体线性增长

#### Scenario: 错误状态不受超限改写

- **WHEN** 上游 `status >= 400` 且响应体超过 `NONSTREAM_MAX_BYTES`
- **THEN** 网关按状态码与正文字节透传，不改写为 502 `response_too_large`

#### Scenario: 错误大体积有界读不改语义

- **WHEN** 上游 `status >= 400` 返回超大错误体（超过 `NONSTREAM_MAX_BYTES`）
- **THEN** 网关读取过程内存有界（不一次性全量缓冲），下行保持上游状态码、不合成 502
