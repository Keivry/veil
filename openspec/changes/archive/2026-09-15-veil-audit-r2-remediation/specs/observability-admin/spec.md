## ADDED Requirements

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

## MODIFIED Requirements

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
