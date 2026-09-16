## ADDED Requirements

### Requirement: 审批决策表软上限与饱和拒绝

审批决策表 `DecisionTable::begin` SHALL 先执行 `sweep(now)`，再按终态 `Decided` 的 `created` 升序（同刻以 key 字典序 tie-break）循环驱逐直至出现空位。当驱逐尽全部可驱逐终态条目后表已满且**仅余 `InFlight`** 时，`begin` SHALL 返回 `BeginOutcome::Saturated`，三个调用点 SHALL 映射为 `VeilError::RateLimited{retry_after_secs: 60}`（`429` + `Retry-After: 60`），并递增软上限溢出计数 `approval_decision_overflow_total` 且记 warn。

系统 SHALL NOT 驱逐任何 `InFlight` 条目；SHALL NOT 对新键（无既有票）返回伪造的 `202 + E_PENDING`（新键无票，伪 pending 会使客户端退避轮询不存在的单据直至超时）。同一键的在途请求 SHALL 继续返回 `202 + E_PENDING`（复用既有票）。容量 SHALL 沿用 `DECISION_TABLE_MAX_ENTRIES=4096`。

饱和计数与当前条目数 SHALL 经 `GET /_admin/metrics` 以数值键 `approval_decision_overflow_total`（u64，软上限饱和累计）与 `decision_table_size`（usize，当前条目数）暴露，SHALL NOT 影响既有指标键；锁不可用时该两项 SHALL 降级为 `0`。本要求为阈值、状态码与指标键的**唯一规范承载**，`architecture-cleanup` spec 的决策表条款 SHALL 引用本要求而不重复定义。

本要求取代既有「`InFlight` 由 Matrix 审批票并发度天然约束」的 backstop 理由：该理由不成立——Matrix 无并发上限，`begin(Reserved)` 会 tracked 发送并预置 reaction，`tokio::spawn` 的 waiter 最长存活 `300s`，`InFlight` 可无界累积。

#### Scenario: 满表仅余 InFlight 时新键饱和拒绝

- **WHEN** 决策表已满且驱逐尽全部终态 `Decided` 后仅余 `InFlight`，此时带新键调用 `begin`
- **THEN** 返回 `Saturated`，映射为 `429 + Retry-After: 60`，递增 `approval_decision_overflow_total` 并记 warn

#### Scenario: InFlight 不被驱逐

- **WHEN** 触发容量驱逐且表内含 `InFlight`
- **THEN** 驱逐仅命中终态 `Decided`，`InFlight` 恒保留

#### Scenario: 同键在途仍返回 202

- **WHEN** 同一键已有在途票且在默认模式下再次发起
- **THEN** 返回 `202 + E_PENDING` 复用既有票，不因软上限被 `Saturated` 拒绝

#### Scenario: 不伪造 pending

- **WHEN** 新键到达且无空位可驱逐
- **THEN** 系统不返回伪造的 `202 + E_PENDING`，而是 `429 + Retry-After: 60`
