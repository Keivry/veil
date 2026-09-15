## MODIFIED Requirements

### Requirement: 错误状态不合成阻断体

非流上游为错误状态（4xx/5xx，除既有非 JSON 502/401 豁免）且审计命中 Block 时，系统 SHALL 保留上游状态码与正文，SHALL NOT 合成 200 阻断体；审计 SHALL 照常记录。

错误状态透传 SHALL 先于响应内容类型（SSE）判定生效：上游 `status >= 400` 时，无论响应 `content-type` 是否为 `text/event-stream`、正文形态是否疑似 SSE 事件流，系统 SHALL 一律按错误体透传**状态码与正文字节**，SHALL NOT 将其改写为 200 假 SSE 流，亦 SHALL NOT 经 SSE 合成路径（输出硬编码 200）输出。SSE 形态分支 SHALL 前置 `status < 400` 守卫，与流式分支既有 `status >= 400` 守卫同口径；Python 对照语义（`_llm.py:6127-6135`）为保留上游状态码，本仓 SHALL 对齐。审计命中 SHALL 照常记录，但 SHALL NOT 因此改变下行状态码与正文。

#### Scenario: 400 JSON 危险调用保留状态

- **WHEN** 上游 400 JSON 体含危险 tool_call，审计模式为 block
- **THEN** 下游收 400 与原始正文；审计日志/指标含该次命中

#### Scenario: 2xx 危险调用仍合成阻断体

- **WHEN** 上游 200 命中 Block
- **THEN** 下游收 200 + `nonstream_block_body`（既有声明行为）

#### Scenario: 4xx 携带 SSE 内容类型不伪造 200 流

- **WHEN** 非流请求上游返回 `status=429` 且响应 `content-type: text/event-stream`
- **THEN** 下游收到 429 与上游正文字节，不出现 200 假 SSE 流

#### Scenario: 5xx 疑似 SSE 正文不改写

- **WHEN** 上游 500 返回形态疑似 SSE 事件的正文
- **THEN** 网关按 500 与原始正文字节透传，不合成 200 SSE 响应

## ADDED Requirements

### Requirement: 空体与非 JSON 502 门控边界

非流对话路径的空体/非 JSON 502 门控（`E_EMPTY_BODY` 口径）SHALL 仅在上游 `status == 200` 时生效，与 Python 对照口径一致：`status == 200` 且响应体为空或非 JSON（且未被既有的超限判定或 SSE 形态分支先行处理）时 SHALL 返回 502 `E_EMPTY_BODY`，行为与既有保持一致。`status != 200` 的非错误状态（如 `201`/`204`/`304` 等，均可能合法携带空体）SHALL NOT 被该门控改写为 502，SHALL 按原状态码与正文字节透传。错误状态（`status >= 400`）继续按错误体透传语义处理，SHALL NOT 被本门控改写为 502。更宽的既有门控（Rust 现网位于 `src/handler/llm/mod.rs:220-227`）SHALL 收窄至本边界，SHALL NOT 保留未登记的静默差异。

#### Scenario: 200 空体触发 502

- **WHEN** 上游 200 对话响应体为空或非 JSON
- **THEN** 网关返回 502（`E_EMPTY_BODY`），与既有行为一致

#### Scenario: 非 200 非错误状态空体不被门控改写

- **WHEN** 上游返回 `304`（或 `204`）空体响应
- **THEN** 网关按 304（或 204）状态与空正文透传，不合成 502

#### Scenario: 错误状态不受门控影响

- **WHEN** 上游 404 返回空体
- **THEN** 网关按 404 与空正文透传，不合成 502
