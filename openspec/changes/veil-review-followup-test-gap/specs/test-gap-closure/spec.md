## Purpose

锁定测试缺口补齐与口径注明的覆盖要求：每缺项有 e2e/单测或书面承接，无第三状态。

## ADDED Requirements

### Requirement: T-M1 metrics 筛选滚动覆盖

系统 SHALL 以单测锁 `QueueFull` 丢最老、`flush` 2s 去抖、`hourly/daily` 跨窗、`model :@` 白名单，以 e2e 锁 `series?granularity/model/upstream` 与空窗快照形状。

#### Scenario: 满队列保最新

- **WHEN** 队列满时新事件到达
- **THEN** 丢最老且最新可查

#### Scenario: 筛选 e2e

- **WHEN** 以 `series?granularity=hourly&model=x` 查询
- **THEN** 形状与快照一致，空窗不崩

### Requirement: T-M2 NonDialog 透传 e2e

系统 SHALL 以 e2e 断言未知尾缀字节透传并记 `nondialog_passthrough`，且 SHALL 无用量/审计/还原。

#### Scenario: 模型列表透传

- **WHEN** 请求 `/v1/models`
- **THEN** 原文转发且计数加一

### Requirement: T-M3 并发与 T-M4 稳定 e2e

系统 SHALL 以 e2e 断言 100 并发下标不冲突，vault LRU 与 5000/1000 容量 SHALL 有回归。

#### Scenario: 并发不串扰

- **WHEN** 100 并发脱敏还原
- **THEN** 下标无冲突、无串扰

#### Scenario: LRU 逐出

- **WHEN** 容量超限
- **THEN** 最久未用优先淘汰

### Requirement: T-M5 Matrix 与 T-M6 Go 承接登记

系统 SHALL 在 tasks 登记 Matrix 真链路缺件与 Go 5.1-5.3 承接 owner，不在本 change 闭环但 SHALL 可追踪。

#### Scenario: 可追踪

- **WHEN** 查阅 tasks 承接表
- **THEN** 可定位到 `veil-hardening 5.x` 与缺件说明

### Requirement: T-M7 替代与 T-M9 口径注明，T-M8 hook 薄项

系统 SHALL 在 README 注明 `sentinel_record.py → sentinel_* e2e` 替代关系与 conformance 12 vs 20 口径差异；hook/env 薄项 SHALL 有最小 e2e 或书面豁免。

#### Scenario: 注明可查

- **WHEN**  grep 替代句与口径差异句
- **THEN** 命中且与实现一致
