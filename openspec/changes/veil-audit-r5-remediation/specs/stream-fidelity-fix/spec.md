# Spec Delta

## MODIFIED Requirements

### Requirement: 流式上游错误状态透传

系统 SHALL 在流式请求的上游响应 `status>=400` 或 `content-type` 非 `text/event-stream` 时，透传上游状态码与正文字节（与非流路径语义一致）；SHALL NOT 不看状态码一律转入 SSE 泵并恒定回 200。README §7.2 SHALL 同步该透传口径。

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

### Requirement: 审计 hold 字节按槽回收

系统 SHALL 按槽记账审计持有字节，并在槽完成/清理时回收：Chat/Anthropic 的槽清理（`clear_index`）、Responses 的 per-item `done` 槽审计清理、`mark_completed`/`mark_rejected` SHALL 归还对应字节。长流多工具调用 SHALL NOT 因累计不回收而误判溢出 fail-closed；真实超限 SHALL 仍拒绝并清仓。hold 记账 SHALL 同时施加条目数（或零字节分片计数）维度上限，SHALL NOT 仅按累计字节计数；零字节分片（`output_item.added`、空 `function_call` 等不计 `total_bytes` 的碎片）SHALL 同样受限，使零字节分片洪泛下内存有界。条目数超限 SHALL 与字节超限同样 fail-closed 并清仓。

hold 的字节记账（累计 `total_bytes`、待定帧字节计数及归还）SHALL 使用饱和算术（`saturating_add`/`saturating_sub`）；SHALL NOT 以裸 `+=`/`-=` 在 `u64`/`usize` 上累加/归还致溢出回绕，SHALL NOT 在接近类型上界时 panic。与 `stream-protocol-parity`「hold 放行保持 sequence_number 相对序」同源同义（措辞 MUST NOT 漂移）：`src/service/audit/hold.rs::push_responses_fragment` 内 `slot.next_seq + 1`、`.max(seq_no + 1)` 与 `total_bytes +=` 三处裸算术 SHALL 全部饱和化——不回绕、不 panic、不复用 `BTreeMap` 键；上游 `seq_no == u64::MAX` 的极值入参分支 SHALL 由单元测试显式锁定。饱和后的超限判定 SHALL 仍按既有语义 fail-closed 并清仓。

#### Scenario: 长流多工具不误判溢出

- **WHEN** 长流中多个 tool 调用依次完成并清槽，单次与同时活跃分片均未超上限
- **THEN** 不触发 overflow 拒绝，审计按槽正常放行

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 单个调用分片累计超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 拒绝并清理持仓，不透出参数

#### Scenario: 零字节分片洪泛有界

- **WHEN** 上游洪泛零字节 tool 分片（不增加累计字节）
- **THEN** 条目数维度上限生效，hold 内存有界并 fail-closed，不无界增长

#### Scenario: 字节记账饱和不溢出

- **WHEN** 审计 hold 的累计字节接近类型上界并继续累加（含归还后再累加），或某槽 `sequence_number` 达 `u64::MAX` 推进保序游标
- **THEN** 记账饱和（不回绕为小值、不 panic、不复用 `BTreeMap` 键），`seq_no == u64::MAX` 极值分支由单元测试锁定，超限判定仍按既有语义触发 fail-closed 并清仓
