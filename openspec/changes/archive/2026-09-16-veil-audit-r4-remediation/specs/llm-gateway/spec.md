## MODIFIED Requirements

### Requirement: 截断三态（唯一值）

流截断/终止状态 SHALL 仅为以下四态之一：`silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`。其中 `synthesized_failed` 仅 responses 可用（协议适用范围口径不变）；`upstream_error` 用于「上游错误载荷帧即终端」的观测（带顶层 `error` 且无 `choices` 的帧）。网关 SHALL 在 `stream_meta.truncated_mode` 记录该值并落 metrics（截断计数按 mode 分标签）。四态之外的值 SHALL NOT 落该指标。本 spec 不得使用 `complete` / `truncated` / `aborted` 旧三态命名。

「唯一值」口径 SHALL 端到端一致：四态白名单 SHALL 在所有落点全量齐备，SHALL NOT 任一落点仅覆盖其中三态而把 `upstream_error` 归入 `other`/丢弃桶。至少以下四类落点 SHALL 四态齐备（`N`，`veil-audit-r4-remediation`）：

1. **进程内固定键计数**：`TRUNCATED_MODE_KEYS`（`src/service/llm_gateway/metrics.rs:54-55`）SHALL 为长度 4 的键数组，派生 `KeyedCounters` 容量同步为 4；`upstream_error` 调用 SHALL 命中具名键递增，SHALL NOT 落 `other` 桶，SHALL NOT 触发未知键 warn（`src/service/llm_gateway/metrics.rs:26-41` 的未知键路径）。
2. **落盘合法性白名单与聚合**：`TRUNCATED_MODES`（`src/service/metrics/aggregate.rs:30-31`）SHALL 为长度 4；`MetricsStore::record_chat_extended`（`src/service/metrics/store.rs:109-116`）SHALL NOT 对 `upstream_error` 走「非法值不落指标」分支或记该 warn；`WindowAgg` 截断列与聚合落标签分支（`src/service/metrics/aggregate.rs:175-177`、`src/service/metrics/store.rs:168-173`）SHALL 各含 `upstream_error` 独立槽。
3. **持久化与快照/时序**：`MetricsSnapshot` 与 `SeriesPoint` 的截断字段（`src/service/metrics/aggregate.rs:271-273,296-298`）、`snapshot()` 环标签分支（`src/service/metrics/aggregate.rs:337-342`）、SQL 表列/UPSERT（`src/service/metrics/store.rs:310-312,327-329,344-346,431-465`）与读取/回填（`src/service/metrics/aggregate.rs:412-470,473-523`）与派生 SQL 的稳定列序。持久化 SHALL 采用加列式（见 canonical `observability-admin`「truncated_mode 三态落 metrics 分标签计数」）。每个状态 SHALL 只递增自身列/标签，SHALL NOT 借其他状态的列承载。
4. **管理面导出**：`/_admin/metrics` 的 `truncated` 对象（`src/handler/admin.rs:129-133`）SHALL 含四态标签，SHALL NOT 仅导出三态而令 `upstream_error` 不可见。

每个状态 SHALL 使「自身标签计数」递增（进程内计数与持久化列各自独立），SHALL NOT 计入其他状态的标签。

#### Scenario: silent_discard 静默丢弃

- **WHEN** 超限尾部命中静默丢弃策略
- **THEN** `stream_meta.truncated_mode=silent_discard` 并记 metrics

#### Scenario: open_ended 保持开放

- **WHEN** 流保持开放等待后续
- **THEN** `stream_meta.truncated_mode=open_ended` 并记 metrics

#### Scenario: synthesized_failed 仅 responses

- **WHEN** responses 流需合成失败终止
- **THEN** `stream_meta.truncated_mode=synthesized_failed` 并记 metrics；chat 与 Anthropic 不得取该值

#### Scenario: upstream_error 上游错误终端

- **WHEN** 带顶层 `error` 且无 `choices` 的 Chat 错误载荷帧被判定为终端
- **THEN** `stream_meta.truncated_mode=upstream_error` 并记 metrics，区别于 `open_ended`

#### Scenario: 四态白名单唯一

- **WHEN** 检查 `stream_meta.truncated_mode` 的合法取值集
- **THEN** 仅 `silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error` 四态；四态之外的值 SHALL NOT 落该指标

#### Scenario: upstream_error 命中具名键不落 other

- **WHEN** 以 `upstream_error` 调用进程内截断计数（`record_truncated("upstream_error")`）
- **THEN** `upstream_error` 具名键计数递增为 1，`other` 桶保持 0，未知键 warn 不触发（`upstream_error` 已在 `TRUNCATED_MODE_KEYS` 白名单内）

#### Scenario: upstream_error 落盘与导出各标签独立

- **WHEN** 一次 `upstream_error` 截断经 `record_chat_extended` 记录并刷盘、快照与 `/_admin/series` 查询
- **THEN** 持久化 `upstream_error` 独立列、快照 `truncated.upstream_error`（`/_admin/metrics`）与 series 对应字段各自递增 1；`silent_discard`/`open_ended`/`synthesized_failed` 三者不受影响；不产生「truncated_mode 非法值不落指标」warn

#### Scenario: 四态各自独立计数

- **WHEN** 依次以四种 mode 各记录一次截断
- **THEN** 四枚标签各自为 1、互不串计；四态之外的值四枚标签均不递增并记告警
