## MODIFIED Requirements

### Requirement: 协议尾判定排除官方子资源

系统 SHALL 仅将对话尾本身（`/chat/completions`、`/v1/messages`、`/v1/responses`）与既有尾斜杠/一层标点宽容命中判为对话协议；对尾后缀额外路径段的官方子资源 SHALL 判 `Protocol::NonDialog` 字节透传，SHALL NOT 触发请求改写、占位符注入、用量记录或审计判定：至少包含 Anthropic `v1/messages/batches`，以及 Responses `v1/responses/{任意单段}`（响应对象检索）。`v1/responses/{id}/cancel`、`v1/responses/{id}/input_items` 等更深子资源 SHALL 同样为 `NonDialog`。

**例外（`count_tokens`）**：Anthropic `v1/messages/count_tokens` SHALL **不**判为 `NonDialog` 字节透传，而收窄为 **redact-only 对话变体**——该端点携带与正式 `/v1/messages` 相同的 `messages`/`system`/`tools` 负载，系统 SHALL：① 执行请求侧脱敏并应用占位符说明注入门控；② 跳过审计判定；③ 跳过响应侧还原与新 PII 扫描；④ 跳过阻断合成；⑤ 跳过用量记账；⑥ 保留 hop 过滤与有界读（受 `NONSTREAM_MAX_BYTES` 约束）。`batches` SHALL 保持 `NonDialog` 字节透传（显式例外：异步批处理元数据端点，响应为分页对象、不含对话机密；脱敏评估另立 change）。

**形态锁定**：redact-only SHALL 以实现为 `Protocol::Anthropic` + 请求上下文 `redact_only` 布尔标记（**SHALL NOT** 新增 `Protocol` 变体）；`is_passthrough`/`is_dialog` 语义 SHALL 不变（redact-only 分流 SHALL NOT 并入透传判定）。

**wire 级副作用声明**：`count_tokens` 收窄后协议值由 `NonDialog` 变为 `Protocol::Anthropic`，下游 `x-veil-protocol` 头值 SHALL 由 `passthrough` 变为 `anthropic`；且请求侧 `scope.redact_request` 的 loads→walk→dumps 紧凑重序列化会置位 `normalized_out`，故 `x-veil-normalized: json-whitespace` **可能新出现**（原透传路径不置位）。二者为可观测 wire 变化，属本收窄的已知副作用。

#### Scenario: count_tokens 判 NonDialog

- **WHEN** 请求 `POST /v1/messages/count_tokens`
- **THEN** 历史场景名**必须原样保留**（OpenSpec MODIFIED 要求场景保全：改名即掉场景并使 `openspec validate --strict` 失败），故本场景仅作名称保全锚点；实际语义见相邻场景「count_tokens 判 NonDialog（已取代）」与「count_tokens 判 redact-only」

#### Scenario: count_tokens 判 NonDialog（已取代）

- **WHEN** 请求 `POST /v1/messages/count_tokens`
- **THEN** 该历史「判 `NonDialog` 字节透传」口径已由本 change 取代为 **redact-only 对话变体**（不再字节透传）；本场景名追加「（已取代）」以消除名称与新语义的矛盾，实际 THEN 见相邻场景「count_tokens 判 redact-only」

#### Scenario: count_tokens 判 redact-only

- **WHEN** 请求 `POST /v1/messages/count_tokens`，请求体 `messages`/`system`/`tools` 内含 PII 或凭据
- **THEN** 网关执行请求侧脱敏（占位符替换 + 说明注入门控），但**不**记录对话用量、**不**做审计判定、**不**合成阻断体

#### Scenario: count_tokens 响应不还原

- **WHEN** 上游返回 `count_tokens` 响应
- **THEN** 网关不执行响应侧还原与新 PII 扫描（无占位符泄漏入响应），保留 hop 过滤与有界读

#### Scenario: count_tokens wire 级副作用

- **WHEN** 请求 `POST /v1/messages/count_tokens`，请求体经请求侧脱敏重序列化
- **THEN** 下游 `x-veil-protocol` 为 `anthropic`（不再为 `passthrough`），且 `x-veil-normalized: json-whitespace` 可能新出现（按实际重序列化置位）

#### Scenario: 响应对象检索判 NonDialog

- **WHEN** 请求 `GET /v1/responses/{id}`
- **THEN** 协议为 `NonDialog`，响应原字节透传，不合成阻断体、不触发审计后处理

#### Scenario: 子资源取消/输入项判 NonDialog

- **WHEN** 请求 `POST /v1/responses/{id}/cancel` 或 `GET /v1/responses/{id}/input_items`
- **THEN** 协议为 `NonDialog`，字节透传

#### Scenario: batches 判 NonDialog

- **WHEN** 请求 `GET /v1/messages/batches`
- **THEN** 协议为 `NonDialog`，字节透传；该例外与 `count_tokens` 收窄并存

#### Scenario: 既有宽容语义保持

- **WHEN** 请求 `/v1/chat/completions/extra`（非官方子资源的一层宽容形态）
- **THEN** 仍判 `Chat` 并记宽容计数，既有 `llm-gateway` 一层宽容契约不回退

## ADDED Requirements

### Requirement: 非对话子资源透传观测计数

系统 SHALL 沿用既有**单一** `nondialog_passthrough` 原子计数器（`GatewayMetrics::nondialog_passthrough`，`src/service/llm_gateway/metrics.rs:77,98,149-157`）登记 `Protocol::NonDialog` 透传；本 change 明确**登记现状、不新增端点维度**（`M-2`，`veil-audit-r4-remediation` 决策）：既有计数器为无参原子（`record_nondialog_passthrough()` / `nondialog_passthrough_count()`），**SHALL NOT** 被改为按端点的键控计数器、SHALL NOT 新增导出指标族。`count_tokens` 收窄为 redact-only 后 SHALL NOT 计入 NonDialog 透传；`batches` 与其他 NonDialog 端点 SHALL 继续计数。

#### Scenario: batches 仍计透传

- **WHEN** `GET /v1/messages/batches` 经 NonDialog 臂透传
- **THEN** 既有单一 `nondialog_passthrough` 计数递增 1（不引入端点标签）

#### Scenario: count_tokens 不计透传

- **WHEN** `POST /v1/messages/count_tokens` 经 redact-only 变体处理
- **THEN** `nondialog_passthrough` 计数不递增（非字节透传）

#### Scenario: 不新增端点维度

- **WHEN** 检查 NonDialog 观测计数 API
- **THEN** 仍为无参单原子计数（`record_nondialog_passthrough`/`nondialog_passthrough_count`），无端点键控参数、无新增导出指标族
