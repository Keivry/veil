## MODIFIED Requirements

### Requirement: truncated_mode 三态落 metrics 分标签计数

`stream_meta.truncated_mode` 四态（`silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`）SHALL 落 metrics 分标签计数（按 mode 分标签）；四态之外的值 SHALL NOT 落该指标。其中 `upstream_error` 用于「上游错误载荷帧即终端」的观测，与 `open_ended` 区分（阈值、状态码与指标键定义以 canonical `llm-gateway` 与 `credential-approval-dual-mode` 为准）。

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

## ADDED Requirements

### Requirement: series since 取值形态校验

`GET /_admin/series` 的 `since` 查询参数 SHALL 仅接受 `[dhm]<整数>` 形态（与 `day_key`/`hour_key`/`five_min_key` 产出同形）；非法值 SHALL 返回 `400 + E_BAD_REQUEST`，错误消息 SHALL 列明合法取值形态。系统 SHALL NOT 以 `i64::MIN` 回退为全量无过滤。该口径 SHALL 与既有 `granularity`/`range` 非法即 `400` 一致。epoch 或日期形态的支持 SHALL NOT 由本要求承载（须另立 change）。

#### Scenario: 非法 since 返回 400

- **WHEN** 请求 `/_admin/series?since=<非法值>`
- **THEN** 返回 `400 + E_BAD_REQUEST`，消息列明合法形态，不返回全量无过滤数据

#### Scenario: 合法 since 正常过滤

- **WHEN** 请求 `/_admin/series?since=<[dhm]<整数>>`
- **THEN** 按该值正常过滤，行为与既有口径一致

### Requirement: 宽限去重表 TTL 驱逐

宽限通知去重表 SHALL 以 `OnceLock<Mutex<HashMap<String, u64>>>` 承载（value 为 `expires_at`）。`first_grace_notification(dedup_key, expires_at, now_secs)` 命中 SHALL 返回 false；当表长达到 `GRACE_NOTIFY_DEDUP_MAX=4096` 时，系统 SHALL 先 `retain` 清扫已过期项（`expires_at <= now`），仍满时 SHALL 逐出 `expires_at` 最小者并记 warn 后再插入。系统 SHALL NOT 整表清空。

#### Scenario: 达上限先清扫过期

- **WHEN** 去重表达上限且含已过期项
- **THEN** 过期项被清扫，新键可插入，未过期项保留

#### Scenario: 仍满逐出最小 expires_at

- **WHEN** 清扫后仍满且无过期项
- **THEN** 逐出 `expires_at` 最小者并记 warn，表不清空

#### Scenario: 命中不重复通知

- **WHEN** 同一 `dedup_key` 在同一宽限窗口内再次出现
- **THEN** 返回 false，不重复发送通知
