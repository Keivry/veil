# Spec Delta

## MODIFIED Requirements

### Requirement: PII 作用域模式与复用/淘汰计数

系统 SHALL 经 `GET /_admin/metrics` 暴露 PII 作用域只读观测：当前作用域模式（`request`/`conversation`）与会话作用域计数——会话复用次数、会话条目淘汰累计、回退请求级次数。计数 SHALL 以既有固定键原子计数风格承载（`GatewayMetrics` / `KeyedCounters`），SHALL NOT 改变既有指标键与语义；计数缺失或锁不可用时 SHALL 降级为 `0` 且不影响其余指标。该观测 SHALL NOT 暴露会话键、明文或 token 原值。不可泄露约束 SHALL 同样覆盖 **`tracing` 日志层**：会话键、会话键头值、明文与 token MUST NOT 出现在任一日志行（含 debug 级），强度与指标面一致。

会话键回退 SHALL 可观测（`R5-08`，`veil-audit-r5-remediation` 决策 D9）：`conversation` 模式下，**可判定**的降级事件 SHALL 在既有个数计数（`record_request_fallback`）之外记 `tracing::warn!`，范围仅限三类：(a) 键推导返回 `None` 落第 4 级逐请求（`src/service/redaction/conversation_key.rs::derive_conversation_key`）；(b) `ConversationScopeStore` 缺失回退（`src/handler/llm/dispatch.rs::build_request_scope`）；(c) 显式会话键头存在但非法经 `src/service/redaction/conversation_key.rs::valid_explicit_header` 静默丢弃而本可命中第 1 级。该 warn SHALL NOT 包含会话键值、会话键头值、明文或 token 原值（与指标面同强度）。

**非目标（显式登记，`R5-08`/D9）**：键推导为**逐请求无状态纯函数**，网关不保留「上次命中级别/上次键」状态，故「同一会话在非首轮静默换键或级别变化」**不可观测**，SHALL NOT 作为本要求条款（不引入不可验证的观测承诺）；若确需该语义，须新增每租户/会话状态面并另立 change。

该可观测性 SHALL NOT 引入新的下游响应头（决策 D9）：`x-veil-scope` 及任何等价的下游可观测响应头登记为**非目标**，SHALL NOT 新增；观测只经 `tracing::warn!` 与内部计数承载。既有计数键（`conversation_reuse`/`conversation_eviction`/`request_fallback`）SHALL 保留，SHALL NOT 删除或重命名。

#### Scenario: 模式可观测

- **WHEN** `/_admin/metrics` 读取快照
- **THEN** 响应含当前作用域模式（`request`/`conversation`）

#### Scenario: 复用/淘汰/回退计数

- **WHEN** `conversation` 模式下发生会话复用、条目淘汰与回退
- **THEN** 对应计数递增；默认 `request` 模式下复用与淘汰恒为 `0`

#### Scenario: 既有指标键不变

- **WHEN** 对比本 change 前后的指标快照
- **THEN** 既有键 SHALL 不变，仅新增只读项

#### Scenario: 不泄露键与明文

- **WHEN** 检查观测输出
- **THEN** 不含会话键、明文或 token 原值

#### Scenario: 日志层同强度不泄露

- **WHEN** `conversation` 模式下检查 `tracing` 日志（含 debug 级）
- **THEN** 任一日志行不含会话键、会话键头值、明文或 token 原值

#### Scenario: 回退与换键记 warn 且不泄露

- **WHEN** `conversation` 模式下发生任一**可判定**降级事件：键推导返回 `None` 落第 4 级、`ConversationScopeStore` 缺失，或显式会话键头存在但非法被静默丢弃
- **THEN** 记 `tracing::warn!`，且该日志行不含会话键值、会话键头值、明文或 token 原值；既有回退/复用/淘汰计数照常递增

#### Scenario: 静默换键不可观测（非目标）

- **WHEN** 检查「同一会话非首轮因级别变化而静默换键」的观测条款
- **THEN** 明确声明键推导为逐请求无状态纯函数、换键不可观测，SHALL NOT 存在对应 warn/计数条款（须新增状态面并另立 change 方可观测）

#### Scenario: 不新增下游响应头

- **WHEN** 发生会话键回退或换键并记 warn
- **THEN** 下游响应头集合不含 `x-veil-scope` 或任何新增可观测头；观测仅经 warn 与内部计数承载

## ADDED Requirements

### Requirement: previous_response_id 写回失败与映射逐出计数

`previous_response_id` → 会话键映射（`PreviousResponseMap`）的写回与逐出 SHALL 可观测，且其容量 SHALL 与 PII 会话容量解耦（`R5-09`/`R5-10`，`veil-audit-r5-remediation` 决策 D10）。

**写回失败计数**：`conversation_writeback_miss` SHALL 仅计**响应 id 缺失或为空**这一类真实写回失败，SHALL NOT 静默吞掉（现状为 `let _ =`，见 `src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/nonstream.rs`）。`record_response_id`（`src/service/redaction/conversation_key.rs`，由 `ConversationWriteback::record` 与 `Scope::record_response_id` 转发）返回 `false` 有三种成因，SHALL 在计数前区分：(a) **无写回上下文**——`request` 模式或会话键未推导，`Scope::record_response_id` 在上下文缺失时返回 `false`，属既定降级，SHALL NOT 计入；(b) **非 Responses 协议门控**——`record_response_id` 内 `!protocol.is_responses()` 早退（Chat/Anthropic 的响应 id 不入映射），属协议门控既定行为，SHALL NOT 计入；(c) **响应 id 缺失或为空**——SHALL 计一次 `conversation_writeback_miss`。若不加区分地对任意 `false` 计数，默认 `request` 模式下每个 Responses 响应都会被误计。

**计数范围精确定义（D7）**：`conversation_writeback_miss` SHALL **至多每响应计一次**。流式路径 SHALL 在官方 Responses 终端帧（`response.completed`/`response.failed`/`response.incomplete`）处判定，且仅当该流**从未见过可用响应 id**时才计一次；非流路径 SHALL 仅对 `status < 400` 且响应体为 JSON、缺少 id 的情形计一次。**声明范围之外**：状态码 `>= 400` 的错误响应（错误体按透传语义处理，不构成写回失败）与**流中段截断**（未达官方终端帧）SHALL NOT 计入 `conversation_writeback_miss`。

**映射逐出计数**：`PreviousResponseMap` 因条目数达容量上限而逐出最旧条目时 SHALL 计一次映射逐出计数，SHALL NOT 静默逐出。

**容量独立**：映射容量 SHALL 由独立配置项 `PII_PREV_ID_MAX_ENTRIES` 承载；`PII_PREV_ID_MAX_ENTRIES` **未设置时** SHALL 取 `PII_SCOPE_MAX_CONVERSATIONS` 的**生效值**（配置相关默认，非固定字面 `1024`），以保证任意配置下（含 `PII_SCOPE_MAX_CONVERSATIONS=2048` 等非默认配置）零行为变化；SHALL NOT 继续复用 `PII_SCOPE_MAX_CONVERSATIONS` 作映射容量（现状见 `src/state.rs::try_new` 的 `PreviousResponseMap::new`）。`PII_PREV_ID_MAX_ENTRIES` 非法值（非 ≥1 正整数）SHALL 拒启动，与 `PII_SCOPE_MAX_CONVERSATIONS` 同口径。既有阈值（含 `PII_SCOPE_MAX_CONVERSATIONS` 默认值）MUST NOT 变更。

新增计数 SHALL 经既有 `KeyedCounters`/固定键原子计数风格承载；SHALL NOT 新增导出的指标族（metric family）——内部计数与 `warn` 足以。计数 SHALL NOT 暴露会话键、`previous_response_id` 原值、明文或 token 原值。

#### Scenario: Responses 写回失败计数

- **WHEN** Responses 流式或非流式响应完成且响应 id 缺失/为空，`record_response_id` 返回 `false`
- **THEN** `conversation_writeback_miss` 计数递增，不静默吞掉

#### Scenario: 非 Responses 写回不计入失败

- **WHEN** Chat（`chatcmpl-*`）或 Anthropic（`msg_*`）响应完成经同一入口写回
- **THEN** 协议门控使其返回 `false` 且 SHALL NOT 计入 `conversation_writeback_miss`

#### Scenario: 无写回上下文不计入失败

- **WHEN** 默认 `request` 模式（或会话键未推导、写回上下文缺失）下 Responses 响应完成经同一入口写回
- **THEN** 因无写回上下文返回 `false`，SHALL NOT 计入 `conversation_writeback_miss`（否则默认模式下每个 Responses 响应都会误计）

#### Scenario: 映射逐出计数

- **WHEN** `PreviousResponseMap` 条目数达 `PII_PREV_ID_MAX_ENTRIES` 并逐出最旧条目
- **THEN** 映射逐出计数递增，且不影响其余计数

#### Scenario: 容量独立且默认零行为变化

- **WHEN** 未设置 `PII_PREV_ID_MAX_ENTRIES` 启动（含 `PII_SCOPE_MAX_CONVERSATIONS` 为默认值 `1024` 或非默认值如 `2048`）
- **THEN** 映射容量等于 `PII_SCOPE_MAX_CONVERSATIONS` 的**生效值**（配置相关默认；如后者为 `2048` 则映射容量为 `2048`），行为与变更前逐项一致；显式设置 `PII_PREV_ID_MAX_ENTRIES` 时仅映射容量变化，PII 会话容量不受影响

#### Scenario: 非法容量拒启动

- **WHEN** 以非 ≥1 正整数的 `PII_PREV_ID_MAX_ENTRIES` 启动
- **THEN** 启动 fail-closed 拒绝，错误信息指明合法取值形态
