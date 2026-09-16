## MODIFIED Requirements

### Requirement: truncated_mode 三态落 metrics 分标签计数

`stream_meta.truncated_mode` 四态（`silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`）SHALL 落 metrics 分标签计数（按 mode 分标签）；四态之外的值 SHALL NOT 落该指标。其中 `upstream_error` 用于「上游错误载荷帧即终端」的观测，与 `open_ended` 区分（阈值、状态码与指标键定义以 canonical `llm-gateway` 与 `credential-approval-dual-mode` 为准）。

四态分标签 SHALL 端到端可观测，SHALL NOT 仅导出其中三态：`/_admin/metrics` 快照的 `truncated` 对象与 `/_admin/series` 行 SHALL 各自含 `silent_discard`/`open_ended`/`synthesized_failed`/`upstream_error` 四枚独立标签。

持久化 SHALL 采用**加列式（additive）**方案（`N`，`veil-audit-r4-remediation` 决策）：在既有 `t_silent`/`t_open`/`t_synth` 列之外新增 `upstream_error` 独立列（`DEFAULT 0`）；旧库 SHALL 经启动期 `ALTER TABLE ... ADD COLUMN` 缺列补列（沿用 `src/service/metrics/store.rs:350-365` 既有补列循环模式），旧行读回 0；SHALL NOT 删除/重命名既有列，SHALL NOT 使旧读者（旧三标签字段与旧 `/_admin/series`/`/_admin/metrics` 消费方）断链——新列为只加不改，旧大盘忽略即可。`upstream_error` SHALL NOT 复用 `open_ended` 或 `silent_discard` 列承载。

#### Scenario: 三态分标签计数

- **WHEN** 检查旧三态口径
- **THEN** 该历史场景名仅用于 delta 场景对齐；口径已扩为四态（见相邻场景「四态分标签计数」），旧『三态之外不落指标』改写为四态之外不落指标

#### Scenario: 四态分标签计数

- **WHEN** 流以 `silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error` 之一截断或终止
- **THEN** metrics 按对应 mode 标签计数加一

#### Scenario: upstream_error 分标签计数

- **WHEN** Chat 上游错误载荷帧（带顶层 `error` 且无 `choices`）被判定为终端
- **THEN** metrics 以 `upstream_error` 标签计数加一，不落 `open_ended`

#### Scenario: 非法值不落指标

- **WHEN** 截断状态为四态之外的值
- **THEN** 系统不落该指标并记告警

#### Scenario: 四态快照与导出口径

- **WHEN** 检查 `/_admin/metrics` 的 `truncated` 对象与 `/_admin/series` 行
- **THEN** 四态各含独立标签（含 `upstream_error`），不出现仅三态导出；`upstream_error` 不借 `open_ended` 列承载

#### Scenario: 加列迁移不改旧列

- **WHEN** 以缺 `upstream_error` 列的旧库启动，并写入一次 `upstream_error` 截断
- **THEN** 启动期补列成功（`DEFAULT 0`），既有三列值与旧字段读取保持不变；超限/审计等其余行为不受影响

#### Scenario: upstream_error 落盘不记非法值告警

- **WHEN** `upstream_error` 经 `MetricsStore::record_chat_extended` 记录
- **THEN** 走合法白名单分支落 `upstream_error` 独立列，不产生「truncated_mode 非法值不落指标」warn、不被丢弃
