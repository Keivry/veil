# observability-admin Specification

## Purpose
运维可观测与管理面：`/_admin` 管理路由统一鉴权与限流，SSE 推送运行指标，sqlite 口径统一用量统计。本 spec 只收敛可观测 admin 六路由，凭据吊销类路由（`/revoke`、`/revoke/emergency`、`POST /credential` 等）归 credential-api spec，本 spec MUST NOT 写入凭据吊销语义。

## Requirements

### Requirement: /_admin 六路由唯一表

`/_admin` SHALL 暴露恰六条管理路由，唯一表如下；未知子路径 SHALL 返回 404：`/_admin/`（JSON 索引占位：返回六路由表与就绪说明）、`/_admin/health`（存活探针）、`/_admin/metrics`（指标快照）、`/_admin/series`（时序查询）、`/_admin/events`（审计事件查询）、`/_admin/events/stream`（SSE 实时推送）。

独立 `admin.html` 静态文件 SHALL 为本 change Non-Goal：`/_admin/` 终态即 JSON 索引占位，不再交付静态页；后续如需静态控制台由新 change 交付。

#### Scenario: 六路由可达
- **WHEN** 鉴权通过后访问唯一表中六条路由之一
- **THEN** 系统返回对应管理功能结果

#### Scenario: 未知子路径 404
- **WHEN** 请求 `/_admin` 下不存在的子路径
- **THEN** 系统返回 404

### Requirement: 管理鉴权优先级与 token 名映射

管理鉴权 SHALL 按优先级判定：`X-Admin-Token` 请求头 > `__Host-admin_token` Cookie > `?access_token`（仅 SSE）；高优先级通过 SHALL 不再校验低优先级；全部失败 SHALL 返回 401。token 名映射表：服务端环境变量为 `OBSERVABILITY_ADMIN_TOKEN`，客户端请求头为 `X-Admin-Token`，Cookie 名为 `__Host-admin_token`，SSE query 参数为 `access_token`。

#### Scenario: X-Admin-Token 优先
- **WHEN** 请求携带有效 `X-Admin-Token`
- **THEN** 系统直接放行，不校验 Cookie 与 query

#### Scenario: Cookie 次优
- **WHEN** 请求头缺失但 `__Host-admin_token` Cookie 有效
- **THEN** 系统放行

#### Scenario: SSE query 仅 SSE 有效
- **WHEN** SSE 路由 `/_admin/events/stream` 以 `?access_token` 携带有效 token
- **THEN** 系统放行；非 SSE 路由以 query 携带 SHALL 恒 401（见下条）

#### Scenario: 全失败 401
- **WHEN** 三种鉴权全部失败
- **THEN** 系统返回 401

### Requirement: 非 SSE 管理接口带 query 恒 401

非 SSE 管理接口 SHALL NOT 接受 query 携带鉴权；以 query 传 token 的非 SSE 请求 SHALL 恒返回 401（强制使用请求头或 Cookie）。

#### Scenario: query 传 token 被拒
- **WHEN** 非 SSE 管理接口以 query 参数携带 token
- **THEN** 系统返回 401，即使 token 有效

### Requirement: HMAC 等长比较

管理 token 比对 SHALL 使用 HMAC 等长比较，MUST NOT 使用短路字符串比较；比较失败 SHALL 返回 401，不泄露失败位置信息。

#### Scenario: 等长比较防时序探测
- **WHEN** 攻击者以不同前缀 token 探测比对耗时
- **THEN** 各次失败耗时无显著差异，不泄露匹配前缀长度

### Requirement: 管理限流按 remote 不读 XFF 与 SSE 5/IP

管理接口限流 SHALL 按 TCP `remote` 地址计数，MUST NOT 信任 `X-Forwarded-For`；SSE 通道 SHALL 按每 IP 限 5 并发；通用管理接口限流为 10/min/IP，触发 SHALL 返回 429 并带 `Retry-After`。

#### Scenario: XFF 伪造不限流逃逸
- **WHEN** 客户端伪造 `XFF` 变换身份高频请求管理接口
- **THEN** 系统仍按 `remote` 计数并触发限流

#### Scenario: SSE 每 IP 5 并发
- **WHEN** 同一 IP 建立第 6 路 SSE 连接
- **THEN** 系统拒绝第 6 路并返回 429

### Requirement: sqlite 用量口径与 is_precise

用量统计 SHALL 以 sqlite 为准口径：内存环 10k（最近 10k 样本）+ `daily` 表保留 30 天 + `hourly` 表保留 7 天 + `5min` 表覆盖式 UPSERT（只留最新窗口）；计数 SHALL 仅含对话端点（`is_chat_tail` 为真），非对话不计数；延迟 SHALL 以 12 桶直方图近似 p95；`is_precise` 为真 SHALL 表示精确计数（可直接对账），为假 SHALL 表示近似计数（仅趋势参考）。窗口键比较 SHALL 使用与内存侧一致的有序整数序（`window_ord`：按窗口粒度归一的单调可比整数），`since` 过滤与 sqlite retention 驱逐 SHALL 同用该整数序，SHALL NOT 以窗口键字符串比较替代整数值比较（避免位数进位如 `9`→`10`、`99`→`100` 造成的时序错位与过滤失真）。

#### Scenario: 精确口径对账
- **WHEN** `is_precise` 为真
- **THEN** 调用方可用该数值直接对账

#### Scenario: 近似口径提示
- **WHEN** `is_precise` 为假
- **THEN** 调用方仅可作趋势参考，不可直接对账

#### Scenario: 非对话不计数
- **WHEN** 请求为非对话尾
- **THEN** 不计入对话用量，`other` 桶不再混入非对话数据

#### Scenario: 跨位数窗口序正确
- **WHEN** 窗口键发生位数进位（如窗口 `9` 与 `10`、`99` 与 `100`），并对 sqlite 执行 `since` 过滤或 retention 驱逐
- **THEN** 判定按整数序而非字符串序，过滤与保留/驱逐结果与内存侧 `window_ord` 一致

### Requirement: 具体限制表（代际限制展开）

管理面限制 SHALL 按下表执行（旧代际限制已展开为具体条目，本 spec 不得使用代号引用）：

| # | 受限操作 | 限制 |
|---|----------|------|
| 1 | 通用管理接口频率 | 10/min/IP，超限 429 + `Retry-After` |
| 2 | SSE 并发 | 5/IP，超限 429，第 6 路拒绝 |
| 3 | SSE 保活 | 60s ping，5min 强制重连 |
| 4 | 非 SSE query 鉴权 | 恒 401 |
| 5 | token 比对 | HMAC 等长比较 |
| 6 | 限流键 | 按 TCP remote，不读 XFF |
| 7 | `/_admin/events` 查询 limit | 默认 50，最大 200（取值超 200 收敛至 200） |

新版受限操作 SHALL 保持同等或更严限制，MUST NOT 借版本升级放宽。

#### Scenario: 限制表执行
- **WHEN** 任一受限操作到达边界
- **THEN** 系统按上表对应限制执行

#### Scenario: events limit 边界收敛
- **WHEN** 请求 `/_admin/events` 未给出 `limit`，或给出的 `limit` 超过 200
- **THEN** 未给出时默认取 50；超过 200 时有效取值收敛为 200（不静默使用超上限值）

### Requirement: metrics 快照 / ring / 覆盖 UPSERT 继承声明

`metrics` 快照、`ring` 环、`5min` 覆盖 UPSERT 口径 SHALL 为范围外继承行为，本 change SHALL NOT 重定义其内部实现；调用方 SHALL 引用既有 sqlite 口径条（内存环 10k + `daily` 30 天 + `hourly` 7 天 + `5min` 覆盖 UPSERT）；本 change 只收敛计数范围与标签语义（仅对话端点、`is_precise`、`truncated_mode` 分标签）。

#### Scenario: 继承口径不重定义
- **WHEN** 实现 metrics 快照、ring 写入或 `5min` 覆盖 UPSERT
- **THEN** 沿用既有 sqlite 口径行为，本 change 不新增语义

#### Scenario: 本 change 只收敛标签
- **WHEN** 落计数时涉及对话范围或模式标签
- **THEN** 按本 spec 的对话端点、`is_precise`、`truncated_mode` 分标签条执行

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

### Requirement: 管理面响应安全头

管理面六路由（`/_admin/`、`/_admin/health`、`/_admin/metrics`、`/_admin/series`、`/_admin/events`、`/_admin/events/stream`）的响应 SHALL 统一携带 `Cache-Control: no-store`（与 Python 对齐的防缓存安全头，至少包含此项）；SHALL NOT 允许浏览器或中间代理缓存管理面响应。该约束 SHALL 对成功与失败（如 `401`、`OBSERVABILITY_DISABLE=1` 下的 `404`）响应一致生效；SSE 路由 SHALL 同样携带，不豁免。

#### Scenario: 成功响应携带安全头
- **WHEN** 鉴权通过后请求任一无状态管理路由（如 `/_admin/metrics`）
- **THEN** 响应含 `Cache-Control: no-store`

#### Scenario: SSE 不豁免
- **WHEN** 建立 `/_admin/events/stream` 连接
- **THEN** 响应头含 `Cache-Control: no-store`

#### Scenario: 未鉴权响应同样不缓存
- **WHEN** 未携带有效 token 请求管理面路由
- **THEN** `401`（或 `OBSERVABILITY_DISABLE=1` 时 `404`）响应同样含 `Cache-Control: no-store`

### Requirement: 管理面 SSE 事件帧契约

`/_admin/events/stream` 的业务事件 SHALL 以 SSE 字段名 `event:`（事件名取值 `event`，与 Python `_admin.py` 同字）命名，SHALL NOT 使用 `message` 作为事件名；每次连接收尾 SHALL 发送恰一个 `done` 终止帧，使下游可判定流结束。既有消费方（含 Python 侧 `admin.html`）的事件监听 SHALL 相应迁移为监听 `event`/`done`，SHALL NOT 继续依赖 `message`。

#### Scenario: 业务事件名为 event
- **WHEN** 管理面 SSE 推送一条业务快照事件
- **THEN** 帧使用 `event: event`（Python 同字），不出现 `event: message`

#### Scenario: done 终止帧恰一
- **WHEN** SSE 连接由服务端正常收尾
- **THEN** 客户端收到恰一个 `done` 终止帧，据此判定流结束

#### Scenario: 消费方按新事件名迁移
- **WHEN** 既有消费方（含 Python 侧 `admin.html`）监听 `/_admin/events/stream`
- **THEN** 其监听事件改为 `event`/`done`，不再依赖 `message`

### Requirement: 管理面 pii_value_samples 形状契约

值级采样样本 `pii_value_samples` SHALL 以与 Python 一致的**嵌套形态**置于 `/_admin/metrics` 快照的 metrics 对象内（作为其字段），SHALL NOT 以扁平数组形式挂在 `/_admin/events` 事件流响应上。字段名与嵌套层级 SHALL 与 Python 对齐，使既有大盘按同一路径读取，消除形状与字段位置的双重漂移。

#### Scenario: metrics 快照嵌套呈现
- **WHEN** 值采样已开启并请求 `/_admin/metrics`
- **THEN** 响应在 metrics 对象内以嵌套字段携带 `pii_value_samples`，形状与 Python 一致

#### Scenario: events 不再承载扁平样本数组
- **WHEN** 请求 `/_admin/events`
- **THEN** 事件条目不再携带扁平的 `pii_value_samples` 数组

### Requirement: SSE broadcast Lagged 可恢复

`/_admin/events/stream` 的广播订阅在读取时遇到 `Lagged` SHALL 可恢复：SHALL 跳过缺口并继续消费后续事件（可记 warn 或发送提示信号），SHALL NOT 因单次 `Lagged` 主动断开连接或返回错误。连接 SHALL 仅在客户端断开或服务端正常收尾（含恰一 `done` 终止帧）时结束。

#### Scenario: Lagged 后连接保持
- **WHEN** 订阅者因突发量落后而收到一次 `Lagged`
- **THEN** 连接保持打开，后续新事件继续推送，不出现断连

#### Scenario: 跳帧而非终止
- **WHEN** `Lagged` 表示丢失了若干事件
- **THEN** 系统跳过缺口事件并继续处理后续事件（可记录告警），不以错误帧或断连收场

### Requirement: 管理面 granularity 校验与快照字段完整性

管理面 `granularity` 查询参数（`/_admin/series` 及相关 SSE 增量查询）收到非法取值时 SHALL NOT 静默回退默认粒度；SHALL 显式拒绝（`4xx` 并附明确错误码与合法取值说明），SHALL NOT 无信号地按默认粒度返回数据。SSE 推送的 metrics 快照 SHALL 包含完整字段集（不得缺失任一既有字段）。SSE 响应 SHALL 携带 `X-Accel-Buffering: no` 以禁用反向代理缓冲。

#### Scenario: 非法 granularity 显式拒绝
- **WHEN** 请求 `/_admin/series?granularity=<非法值>`
- **THEN** 返回 `4xx` 并附明确错误码/合法取值说明，不静默按默认粒度返回数据

#### Scenario: SSE 快照字段完整
- **WHEN** SSE 推送 metrics 快照
- **THEN** 快照包含既有完整字段集，不缺失任何既有字段
#### Scenario: SSE 禁用代理缓冲

- **WHEN** 建立 `/_admin/events/stream` 连接
- **THEN** 响应头含 `X-Accel-Buffering: no`

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

### Requirement: PII 作用域模式与复用/淘汰计数

系统 SHALL 经 `GET /_admin/metrics` 暴露 PII 作用域只读观测：当前作用域模式（`request`/`conversation`）与会话作用域计数——会话复用次数、会话条目淘汰累计、回退请求级次数。计数 SHALL 以既有固定键原子计数风格承载（`GatewayMetrics` / `KeyedCounters`），SHALL NOT 改变既有指标键与语义；计数缺失或锁不可用时 SHALL 降级为 `0` 且不影响其余指标。该观测 SHALL NOT 暴露会话键、明文或 token 原值。不可泄露约束 SHALL 同样覆盖 **`tracing` 日志层**：会话键、会话键头值、明文与 token MUST NOT 出现在任一日志行（含 debug 级），强度与指标面一致。

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
