## MODIFIED Requirements

### Requirement: 审批决策表受管状态与仅驱逐终态

审批决策表 SHALL 由进程级 `static`（`src/service/credential/approval.rs` 的 `DECISIONS: OnceLock<Mutex<DecisionTable>>`）改为受管状态（经 `AppState`/`Arc` 注入）；容量 SHALL 为**软上限**（阈值取值与饱和拒绝映射见 canonical `credential-approval-dual-mode` spec「审批决策表软上限与饱和拒绝」；本要求 SHALL NOT 重复定义阈值、状态码与指标键，软上限仅约束可回收的终态条目数）——容量驱逐 SHALL 仅针对终态 `Decided` 条目：按 `Decided.created` 升序（同刻以 key 字典序 tie-break）驱逐最早者，循环至出现空位；SHALL NOT 驱逐任何 `InFlight` 条目。当表内存在可驱逐终态条目时，驱逐后条目数 SHALL 不超过软上限（有界性在终态条目存在时恢复）；若驱逐尽全部可驱逐 `Decided` 后表已满且仅余 `InFlight`，系统 SHALL 返回 `BeginOutcome::Saturated` 并按 canonical `credential-approval-dual-mode` spec「审批决策表软上限与饱和拒绝」映射为限流响应（阈值、状态码与饱和计数指标键在该处唯一定义，本要求 SHALL NOT 重复定义），SHALL NOT 驱逐 `InFlight`、SHALL NOT 无界超出、SHALL NOT 对新键伪造 `202 + E_PENDING`；同一键在途请求仍 SHALL 返回 `202 + E_PENDING`（复用既有票）。

系统 SHALL NOT 再以「`InFlight` 数量由 Matrix 审批票并发度天然约束」作为软上限不被突破的最终 backstop——该理由不成立（Matrix 无并发上限，`InFlight` 可无界累积），本要求以其为失效声明予以取代。驱逐策略 SHALL 确定性且可测。`DecisionTable` SHALL 提供只读计数访问器，其软上限溢出累计与当前条目数 SHALL 经 `GET /_admin/metrics` 以 canonical `credential-approval-dual-mode` spec 定义的数值键暴露（键名与语义在该处唯一定义，本要求 SHALL NOT 重复定义），SHALL NOT 影响既有指标键；锁不可用时该两项 SHALL 降级为 `0` 且不影响其余指标。对外审批语义（一次性消费、`202 + E_PENDING` 复用、阻塞 TTL、终态三态）SHALL 不变。

#### Scenario: InFlight 不被软上限驱逐

- **WHEN** 决策表达到软上限并触发一次驱逐，且表内存在尚未落定的 `InFlight` 条目
- **THEN** `InFlight` 条目保留（不被驱逐），驱逐仅命中按 `Decided.created` 升序选择的终态 `Decided` 条目

#### Scenario: 软上限行为可测

- **WHEN** 注入软上限并写入超过软上限的终态条目（表内存在可驱逐 `Decided`）
- **THEN** 表中条目数不超过软上限，被驱逐者恒为终态 `Decided` 条目（确定性、可断言），有界性在终态条目存在时恢复

#### Scenario: 仅剩 InFlight 时饱和拒绝（429）

- **WHEN** 表已满且驱逐尽全部可驱逐 `Decided` 后仅余 `InFlight`，此时带新键 `begin`
- **THEN** 不驱逐 `InFlight`；`begin` 返回 `Saturated` 并按 `credential-approval-dual-mode` 映射为限流响应（`429 + Retry-After`），SHALL NOT 伪造 `202 + E_PENDING`

#### Scenario: 仅剩 InFlight 时允许暂时超出

- **WHEN** 检查该历史 backstop 场景
- **THEN** 旧「允许暂时无界超出」语义已被饱和拒绝取代：表 SHALL NOT 无界超出，新键按饱和拒绝处理（响应与指标键定义见 `credential-approval-dual-mode`）

#### Scenario: 软上限计数经管理指标只读暴露

- **WHEN** `GET /_admin/metrics` 读取指标快照
- **THEN** 响应体 SHALL 含 canonical `credential-approval-dual-mode` spec 定义的两项只读数值键（软上限饱和累计与当前条目数；键名与语义在该处唯一定义），既有键 SHALL 不变；空窗时两者 SHALL 为 `0`，饱和发生后软上限饱和累计 SHALL 递增且当前条目数 SHALL 反映真实值

#### Scenario: 对外审批语义不变

- **WHEN** 运行凭据审批相关单测与 e2e（默认 `202` 抛单、阻塞模式、批准/拒绝/超时三态）
- **THEN** 全部通过且对外行为与重构前一致

### Requirement: 协议分派单一入口

协议**判定/分派谓词** SHALL 收敛为单一分派点（或类型化方法）供全仓复用；谓词集合 SHALL 限定为 `Protocol` 类型化方法（`is_chat`/`is_responses`/`is_dialog`/终态判定/审计到期/次要事件/`wire_name`），SHALL NOT 保留同一谓词语义的重复扩散实现。逐协议**差异产物构造**（帧序列、usage 累计、placeholder 处理、tool 提取分支等）SHALL NOT 视为重复分派，其 `match protocol` 分支 SHALL 允许保留。收敛 SHALL 保持分派结果等价。

#### Scenario: 分派点收敛

- **WHEN** 检查全仓协议判定/分派谓词
- **THEN** 谓词经单一入口或 `Protocol` 类型化方法承载，无同一谓词语义的重复扩散

#### Scenario: 差异产物构造不被误判

- **WHEN** 检查逐协议差异产物构造的 `match protocol` 分支
- **THEN** 其保留被本 spec 认可，不视为重复分派缺陷

#### Scenario: 分派结果不变

- **WHEN** 运行三协议分派回归
- **THEN** 分派结果与收敛前一致

### Requirement: 上游状态码受约束类型

上游状态码 SHALL 以受约束类型（`src/service/llm_gateway/` 的 newtype/带校验）承载，SHALL NOT 以裸 `u16` 在服务层无约束传递。该强制范围 SHALL 限定为网关**边界/分发点**（`src/handler/llm/dispatch.rs` 的上游状态处理）；纯谓词 `classify_empty` 的 `u16` 入参 SHALL 为例外（调用方保证其来自 reqwest `StatusCode` 派生值）。非法状态值的处理（不 panic、不改写对外语义）SHALL 与现状一致。

#### Scenario: 合法状态码经受约束类型

- **WHEN** 上游返回合法 HTTP 状态码
- **THEN** 经受约束类型构造并正常参与透传/判定

#### Scenario: 边界谓词例外被认可

- **WHEN** 检查 `classify_empty` 的 `u16` 入参
- **THEN** 该例外被本 spec 认可（调用方保证来源受约束），不视为违规

#### Scenario: 非法状态值处理一致

- **WHEN** 构造或接收非法状态值
- **THEN** 处理与现状一致，不 panic，不改变对外行为

### Requirement: 服务层不变量守护补齐

服务层 SHALL 以 `debug_assert` 或类型约束承载其职责范围内的不变量守护；SHALL NOT 使部分不变量仅存于 handler 层而服务层无守护。守护范围 SHALL 限定为**已枚举不变量**：hop 方向、tool 位域、carry 剥离；SHALL NOT 承诺覆盖未枚举不变量。守护补齐 SHALL NOT 改变 release 构建的对外行为。

#### Scenario: debug 构建暴露调用约定

- **WHEN** debug 构建下以违反不变量的输入调用服务层入口
- **THEN** 触发守护断言（或类型层拒绝），暴露调用约定

#### Scenario: 未枚举项不被承诺

- **WHEN** 检查服务层守护清单
- **THEN** 仅覆盖已枚举不变量（hop 方向、tool 位域、carry 剥离），无对未枚举项的覆盖承诺

#### Scenario: release 行为不变

- **WHEN** release 构建运行既有测试
- **THEN** 对外行为与补齐前一致

### Requirement: 单帧单次 JSON 解析

系统对每个 SSE 帧 SHALL 至多执行一次完整 JSON 解析，并复用该解析产物承载审计判定、内层 stringified-JSON 递归校验与转发决策；SHALL NOT 对同一帧重复解析。解析 SHALL 收敛为 `event.rs::parse_event_data` 单点；`sticky_terminal_event`、`responses_failed_incomplete`、`responses_error_object` SHALL 接收该解析产物（`Option<&Value>`），其原字符串签名 SHALL 降为 `#[cfg(test)]` 包装。解析复用 SHALL NOT 改变帧序、帧内容、审计判定、还原结果与终端恰一语义。

守护 SHALL 为双守卫：① `parse_event_data` 的 `#[cfg(test)]` 解析计数与 `take_parse_count`，在泵 e2e 断言每帧恰 1 次；② 源码守护断言 `event.rs` **生产段**（首个 `#[cfg(test)]` 之前）的 `from_str` 计数为 0。

#### Scenario: 单帧仅解析一次

- **WHEN** 上游投递单帧 SSE 数据（含需内层递归校验的嵌套 JSON）
- **THEN** 该帧仅解析一次，审计/还原/转发决策复用同一解析结果（解析计数证据可见该帧解析次数为 1）

#### Scenario: 生产段零 from_str

- **WHEN** 检查 `event.rs` 首个 `#[cfg(test)]` 之前的生产前缀
- **THEN** `from_str` 计数为 0，解析仅经 `parse_event_data` 单点

#### Scenario: 解析复用行为逐字节不变

- **WHEN** 对复用解析的实现运行全部流式相关回归
- **THEN** 帧序、帧内容、审计时序与终端恰一语义与复用前逐项一致

## ADDED Requirements

### Requirement: 逐跳过滤键复用与性能声明

`filter_hop_headers_counted` SHALL 以 `Vec<HeaderName>`（`.keys().cloned()`）承载固定逐跳头键，使用 `is_hop(k.as_str())` 直比与 `remove(&k)` 直取，SHALL NOT 对 `HeaderMap` 键做 `to_lowercase()` 或字符串重解析（`HeaderMap` 插入即把自定义头名规范化为小写，该不变量由既有单测锁定）。`Connection` 头内动态项 SHALL 保持自由文本处理（lower + trim）。剥离计数与方向 `debug_assert` 语义 SHALL 不变。

性能收益（每请求少 N 次 `String` 分配与 N 次名字重解析）SHALL 标注为**假设**，SHALL NOT 作为对外性能承诺。等价性测试 SHALL 显式声明「锁行为等价，不锁分配属性」。

#### Scenario: 键直取无重解析

- **WHEN** 执行逐跳头过滤
- **THEN** 固定头键以 `HeaderName` 直比/直取，无 `to_lowercase()` 重解析；动态项仍按自由文本 lower+trim

#### Scenario: 过滤计数与保留头不变

- **WHEN** 运行逐跳过滤与等价性测试
- **THEN** 剥离计数、方向与保留头集合与既有口径逐项一致

### Requirement: 服务层 axum 依赖声明锁与注册参数构造下沉

`src/service` 生产代码 SHALL 仅允许 `axum::http::HeaderMap` 这一纯数据白名单类型（`src/service/llm_gateway/mod.rs` 的 `axum::body::Bytes` SHALL 改为 `bytes::Bytes`）。声明锁守护 SHALL 在**首个 `#[cfg(test)]` 之前的生产前缀**上 token-scan `axum::`：非白名单文件命中即失败；白名单文件（`hop.rs`、`llm_gateway/mod.rs`）内每个 `axum::` 之后 SHALL 为 `http::`。`RegisterParams` 的字段 trim 与构造 SHALL 下沉为 `service::register_map::parse_register_params`，handler SHALL 仅调用；`registry::HashChangeOutcome::from_reaction` SHALL 保留为领域解析器并声明为已知边界。

#### Scenario: 非白名单 axum 命中即失败

- **WHEN** 服务层非白名单文件的生产前缀出现 `axum::` 用法
- **THEN** 声明锁守护失败；白名单文件内仅允许 `axum::http::*`

#### Scenario: 注册参数构造下沉

- **WHEN** 检查注册参数构造路径
- **THEN** trim 与构造经 `service::register_map::parse_register_params`，handler 仅调用，行为不变

### Requirement: 同步内置扫描边界声明

内置 PII 扫描（`boundary_spans`）SHALL 在 pump async 任务内同步执行，但 SHALL NOT 接收整帧：窗口由 `BoundaryHold::push` 构造为 `tail_window(held) + head_window(data)`，上界为 `2×PII_HOLD_MAX`（默认 128 字符；配置上界 1MiB），且 `window == 0` 时 SHALL NOT 调用。该热路径的同步 CPU 复杂度 SHALL 为 O(PII_HOLD_MAX) 而非 O(帧)。系统 SHALL NOT 为每帧新增 `spawn_blocking`（派发开销大于扫描，且与单批 offload 设计相悖）。

#### Scenario: 窗口有界不随帧增长

- **WHEN** 上游持续投递大帧
- **THEN** 同步扫描窗口恒受 `2×PII_HOLD_MAX` 约束，CPU 不随帧大小线性增长

#### Scenario: window 为零不扫描

- **WHEN** `window == 0`
- **THEN** 不调用同步内置扫描，直接放行

#### Scenario: 不新增每帧 spawn_blocking

- **WHEN** 检查 seam 扫描接线
- **THEN** 无每帧新增的 `spawn_blocking` 调用

### Requirement: shutdown_wired 源码字符串守护声明

`shutdown_wired` 守护 SHALL 以源码字符串断言（`include_str!` + `find`/`contains`）校验优雅停机接线顺序、禁止二次构造 `AppState`、要求复用 `CleanupHandles`；该守护 SHALL 被显式声明为**非行为覆盖**（等价重写可绕过），优雅停机的刷盘行为 SHALL 由既有行为测试锁定。系统 SHALL NOT 在本 change 引入进程级 harness。升级触发条件 SHALL 登记：若停机接线再现静默断链且源码守护未拦截，另立 change。

#### Scenario: 声明局限存在

- **WHEN** 查阅 `shutdown_wired` 相关 spec 与守护
- **THEN** 明确标注其源码字符串守护属性与非行为覆盖局限

#### Scenario: 源码守护仍绿色

- **WHEN** 运行 `shutdown_wired` 守护
- **THEN** 通过；声明与既有守护一致，行为由既有测试锁定
