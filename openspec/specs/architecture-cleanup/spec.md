# architecture-cleanup Specification

## Purpose
锁定 veil 架构清洁度契约：巨型函数按职责拆分且行为保持、审批决策表移入受管状态且驱逐仅限终态（`InFlight` 永不误逐）、三协议 tool 提取器单一实现、上游响应头克隆与逐跳过滤单一 helper、生产零引用死代码清除。该 capability 为结构性/可维护性契约，所有 REQUIREMENT 以纯重构（behavior-preserving）为前提，不改变对外运行时行为。

## Requirements

### Requirement: 巨型函数按职责拆分且行为保持

系统 SHALL 将 `spawn_stream_pump`（`src/handler/llm/pump/spawn.rs`）按职责拆分为内聚单元：参数/设置（setup）、主循环（含单帧/单事件处理）、收尾合成与 finalize 三段；`spawn_stream_pump` SHALL 收敛为薄壳（建立循环状态并驱动子单元）。拆分 SHALL 为纯重构：帧序、帧内容、终端恰一语义、审计与阻断时序、`PumpOutcome` 字段 SHALL 与拆分前逐项一致。拆分后新增/提取的每个函数 SHALL 远低于单文件 800 行上限。

#### Scenario: 流式行为零回退

- **WHEN** 对拆分后的流泵运行全部流式相关测试（含截断矩阵、审计阻断、审批不挂起、增量到达）
- **THEN** 全部通过，且断言帧序/终端/`truncated_mode`/`PumpOutcome` 的既有用例无一回退

#### Scenario: 单文件行数受上限约束

- **WHEN** 运行 `python3 scripts/check_file_sizes.py`
- **THEN** 退出 0，拆分产出的各文件与函数均低于 800 行上限

### Requirement: 审批决策表受管状态与仅驱逐终态

审批决策表 SHALL 由进程级 `static`（`src/service/credential/approval.rs` 的 `DECISIONS: OnceLock<Mutex<DecisionTable>>`）改为受管状态（经 `AppState`/`Arc` 注入）；容量 SHALL 为**软上限**（`DECISION_TABLE_MAX_ENTRIES=4096`，仅约束可回收的终态条目数）——容量驱逐 SHALL 仅针对终态 `Decided` 条目：按 `Decided.created` 升序（同刻以 key 字典序 tie-break）驱逐最早者，循环至不超软上限；SHALL NOT 驱逐任何 `InFlight` 条目。当表内存在可驱逐终态条目时，驱逐后条目数 SHALL 不超过软上限（有界性在终态条目存在时恢复）；若驱逐尽全部可驱逐 `Decided` 后仍超软上限（仅余 `InFlight`），SHALL 不驱逐 `InFlight`、记 warn 并递增超软上限计数指标（`approval_decision_overflow_total`），允许暂时超出（软上限的显式理由：不静默驱逐在途审批，避免破坏 `InFlight` 去重而重复建单）。`InFlight` 数量 SHALL 由 Matrix 审批票并发度天然约束，作为软上限不被突破的最终 backstop；`InFlight` 落定产生终态条目后条目数 SHALL 自动恢复不超过软上限。驱逐策略 SHALL 确定性且可测。`DecisionTable` SHALL 提供只读计数访问器，其软上限溢出累计与当前条目数 SHALL 经 `GET /_admin/metrics` 以数值键 `approval_decision_overflow_total`（u64）与 `decision_table_size`（usize）暴露，SHALL NOT 影响既有指标键；锁不可用时该两项 SHALL 降级为 `0` 且不影响其余指标。对外审批语义（一次性消费、`202 + E_PENDING` 复用、阻塞 TTL、终态三态）SHALL 不变。

#### Scenario: InFlight 不被软上限驱逐

- **WHEN** 决策表达到软上限并触发一次驱逐，且表内存在尚未落定的 `InFlight` 条目
- **THEN** `InFlight` 条目保留（不被驱逐），驱逐仅命中按 `Decided.created` 升序选择的终态 `Decided` 条目

#### Scenario: 软上限行为可测

- **WHEN** 注入软上限并写入超过软上限的终态条目（表内存在可驱逐 `Decided`）
- **THEN** 表中条目数不超过软上限，被驱逐者恒为终态 `Decided` 条目（确定性、可断言），有界性在终态条目存在时恢复

#### Scenario: 仅剩 InFlight 时允许暂时超出

- **WHEN** 表超软上限且驱逐尽全部可驱逐 `Decided` 后仅余 `InFlight`
- **THEN** 不驱逐 `InFlight`、记 warn 且递增 `approval_decision_overflow_total`，允许暂时超出（软上限，不静默驱逐在途审批），直至 `InFlight` 落定产生终态条目后条目数恢复不超过软上限

#### Scenario: 软上限计数经管理指标只读暴露

- **WHEN** `GET /_admin/metrics` 读取指标快照
- **THEN** 响应体 SHALL 含数值键 `approval_decision_overflow_total`（软上限溢出累计）与 `decision_table_size`（当前条目数），既有键 SHALL 不变；空窗时两者 SHALL 为 `0`，软上限溢出后 `approval_decision_overflow_total` SHALL 递增且 `decision_table_size` SHALL 反映当前条目数（含暂时超限的 `InFlight`）

#### Scenario: 对外审批语义不变

- **WHEN** 运行凭据审批相关单测与 e2e（默认 `202` 抛单、阻塞模式、批准/拒绝/超时三态）
- **THEN** 全部通过且对外行为与重构前一致

### Requirement: 三协议 tool 提取器单一实现

三协议（Chat/Anthropic/Responses）tool 调用提取 SHALL 由单一共享实现承载，供流式分片（`extract_tool_fragments`）与非流（`extract_tool_calls`）两路径复用；SHALL NOT 保留两套并行的三臂 walk 实现。分桶（`chat_bucket`/`anthropic_bucket_index`/`responses_output_bucket`）、合成 id、字段优先级、检索事件派生、`.delta`/`.done` 语义 SHALL 逐项等价；两路径对同一输入的提取结果 SHALL 一致（由既有 frag↔calls 对照用例锁定）。

#### Scenario: 流/非流提取一致

- **WHEN** 对同一 payload 分别经流式分片路径与非流路径提取
- **THEN** 分桶、id、name、args 结果与重构前一致（既有对照用例全绿）

#### Scenario: 三协议无遗漏

- **WHEN** 运行 Chat/Anthropic/Responses 三协议 tool 提取相关单测
- **THEN** 全部通过，且统一实现无协议/字段分支遗漏

### Requirement: 上游响应头克隆与逐跳过滤单一 helper

`src/handler/llm/nonstream.rs` 中上游响应头克隆与逐跳（hop）过滤的两处逐字重复逻辑 SHALL 抽取为单一 helper，供 `passthrough_upstream_response` 与 `snapshot_downstream_headers` 复用；SHALL NOT 保留两份并行的头克隆 + 解码配对 + hop 过滤实现。helper SHALL 保持 decoded/undecoded 配对语义（`downstream_decode_enabled` + `filter_hop_headers_counted`）与既有计数副作用不变。

#### Scenario: 两调用点共用 helper

- **WHEN** 检查 `nonstream.rs` 的非对话透传与快照路径
- **THEN** 两处均调用同一 helper，头克隆/hop 过滤无重复实现

#### Scenario: 头过滤行为不变

- **WHEN** 运行非流/非对话透传相关测试（含编码配对与 `x-veil-*` 剔除）
- **THEN** 全部通过，下游响应头集合与重构前一致

### Requirement: 生产零引用死代码清除

`filter_hop_headers`（`src/service/llm_gateway/hop.rs`）及其在 `src/service/llm_gateway/mod.rs` 的重导出 SHALL 被删除；生产路径 SHALL 仅经 `filter_hop_headers_counted` 过滤。删除后全仓 SHALL 无 `filter_hop_headers`（非 `_counted`）引用，`cargo clippy --tests --all-targets -- -D warnings` SHALL 无 `dead_code` 警告。

#### Scenario: 零引用确认

- **WHEN** 执行 `grep -rn "filter_hop_headers" src/ tests/`
- **THEN** 仅命中 `filter_hop_headers_counted`（及其调用点），无裸 `filter_hop_headers` 定义或引用

#### Scenario: clippy 无死代码告警

- **WHEN** 运行 `cargo clippy --tests --all-targets -- -D warnings`
- **THEN** 退出 0，无 `dead_code` 警告
