# Spec Delta

## MODIFIED Requirements

### Requirement: 非流上游响应头透传

系统 SHALL 在非流对话响应路径（含 `status>=400` 非 JSON 错误体透传分支与 JSON 后处理分支）消费上游 body 前快照上游响应头，按逐跳（HOP）过滤规则过滤后转发；SHALL 保留上游 `content-type`（如 `application/json`、`text/plain`）与 `retry-after`、`x-request-id`、rate-limit 类头；SHALL NOT 由框架默认值（`text/plain; charset=utf-8`、`application/octet-stream`）覆盖上游声明。网关自有 `x-veil-*` 头 SHALL 在过滤后追加，SHALL NOT 从上游透传同名头。上游无 `content-type` 时，JSON 后处理分支 SHALL 回退 `application/json`。

同名多值响应头 SHALL 逐值保留（`append` 语义），SHALL NOT 因 `insert` 折叠为末值（`R6-03`）：快照与转发两段 SHALL 均保持多值（`http::response::Builder::header` 为 append 语义，装配端无需额外改写）；网关自置 `x-veil-protocol`/`x-veil-normalized` 头 SHALL 仍按覆盖语义写入（单值）。该口径覆盖复用同一快照 helper 的非流对话与非对话透传两条臂。

#### Scenario: 200 JSON content-type 保留

- **WHEN** 上游 200 返回 `content-type: application/json` 的对话响应
- **THEN** 下游响应 `content-type` 为 `application/json`，不再被强制为 `text/plain; charset=utf-8`

#### Scenario: 429 Retry-After 透传

- **WHEN** 上游 429 返回 `retry-after: 30` 与 `text/plain` 体
- **THEN** 下游收到 429、`retry-after: 30` 与同字节正文

#### Scenario: 逐跳头过滤

- **WHEN** 上游响应携带 `connection`、`transfer-encoding` 等逐跳头
- **THEN** 下游不出现这些逐跳头，且 `hop_filtered_total` 计数递增

#### Scenario: x-veil 头不被上游覆盖

- **WHEN** 上游响应自带 `x-veil-protocol` 头
- **THEN** 下游该头为网关派生值，上游值不生效

#### Scenario: 同名多值响应头逐值透传

- **WHEN** 上游非流响应携带两条同名多值头（如两条 `Set-Cookie` 或两条 `warning`）
- **THEN** 下游 `get_all` 得两条同值头，SHALL NOT 只剩末值；网关自置头仍为单值

### Requirement: 网关生成非流错误响应统一协议头

系统 SHALL 对非流对话路径由网关生成的响应统一置 `x-veil-protocol` 头（取值为请求协议派生 `chat`/`anthropic`/`responses`），至少覆盖：`status>=400` 非 JSON 错误体透传、超限 502 `response_too_large`、空体/非 JSON 502 `E_EMPTY_BODY`；与非流成功分支、阻断分支口径一致。上游响应头转发时该头 SHALL 以网关派生值覆盖同名上游头。

适用范围 SHALL 为「非流对话路径 + 流式错误透传路径」：SSE 成功路径（`src/handler/llm/pump/event.rs::build_sse_response`）与 NonDialog 透传 SHALL NOT 置该头；README 与源码注释 SHALL NOT 以「统一/全部路径」措辞声称覆盖 SSE 成功臂（`R6-05`），SHALL NOT 为此给 SSE 成功响应新增该头（不引入新 wire 行为）。

#### Scenario: 429 透传含协议头

- **WHEN** 上游 429 非 JSON 错误体经网关透传
- **THEN** 下游响应含 `x-veil-protocol: chat`（随请求协议）

#### Scenario: 502 超限含协议头

- **WHEN** 非流对话响应超限返回 502 `response_too_large`
- **THEN** 下游响应含对应协议的 `x-veil-protocol`

#### Scenario: 空体 502 含协议头

- **WHEN** 非流对话上游返回空体/非 JSON 触发 `E_EMPTY_BODY`
- **THEN** 下游响应含对应协议的 `x-veil-protocol`

#### Scenario: 范围声明与实现一致

- **WHEN** 核查 README 与 `src/handler/llm/mod.rs` 注释对 `x-veil-protocol` 置位范围的表述
- **THEN** 表述限「非流对话 + 流式错误透传」，零命中「统一置」式全路径声称；SSE 成功响应实测不含该头（既有行为，未新增）
