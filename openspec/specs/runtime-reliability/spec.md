# runtime-reliability Specification

## Purpose
锁定网关运行时可靠性契约：指标按周期与关闭时刷盘、重启后已刷盘窗口可回填、指标聚合与限流状态内存有界、审批等待事件驱动无忙轮询、上游读取错误可观测且对外语义不变。

## Requirements

### Requirement: 指标按周期与关闭刷盘

系统 SHALL 以固定周期（默认 `60s`）把内存聚合窗口覆盖式刷入 sqlite，SHALL 在进程正常退出（含 `SIGINT`/`SIGTERM` 触发）时执行一次最终刷盘；刷盘 SHALL 为非阻塞异步路径（快照后下沉阻塞线程），SHALL NOT 在请求处理 async 上下文直接调用 rusqlite。刷盘失败 SHALL 记 warn 且不使服务退出（指标降级为内存累计，接口照常服务）。

#### Scenario: 周期刷盘落盘

- **WHEN** 服务运行超过一个刷盘周期且期间记录了对话观测
- **THEN** sqlite 聚合表出现对应窗口记录（无需进程退出）

#### Scenario: 关闭时刷盘

- **WHEN** 进程收到 `SIGINT`/`SIGTERM` 并正常退出
- **THEN** 退出前执行一次刷盘，已刷窗口可从 sqlite 回填

#### Scenario: 刷盘失败不致命

- **WHEN** 刷盘时 sqlite 不可写
- **THEN** 记录 warn 告警，服务继续运行，指标在内存继续累计

### Requirement: 重启后指标保留

系统 SHALL 在启动时从 sqlite 回填聚合窗口，使周期刷盘写入的窗口在重启后仍可查询；回填 SHALL 为覆盖式（不翻倍）。重启保留只覆盖「已成功刷盘」的窗口，未刷盘窗口（如被强杀）不承诺保留。

#### Scenario: 写入→重启→保留

- **WHEN** 记录指标、等待一次周期刷盘完成、重启进程并回填
- **THEN** 重启后的指标快照包含重启前已刷盘的窗口数值，数值不翻倍

#### Scenario: 覆盖式回填不翻倍

- **WHEN** sqlite 中已有窗口记录，进程启动回填同一窗口
- **THEN** 内存窗口与 sqlite 该窗口等值（覆盖式，非累加）

### Requirement: 指标聚合内存有界

系统 SHALL 对内存聚合窗口 `aggs` 施加有界策略：SHALL 按既有 retention 口径驱逐过期窗口（daily/hourly 超出保留窗数、five_min 只留最新窗口），SHALL 另有硬上限 `AGGS_MAX_ENTRIES`，达到上限时按 LRU 驱逐最久未更新的窗口；驱逐 SHALL 计入可观测计数（dropped/evicted）且被驱逐窗口 SHALL NOT 影响 sqlite 已刷盘数据。窗口键随运行时长增长 SHALL NOT 使内存无界。

#### Scenario: 过期窗口被驱逐

- **WHEN** 内存中存在超出 retention 保留窗数的窗口键
- **THEN** 这些窗口被清除，`aggs` 条目数回落到保留范围内

#### Scenario: 达硬上限后内存有界

- **WHEN** 持续写入使 `aggs` 条目数尝试超过 `AGGS_MAX_ENTRIES`
- **THEN** 条目数不超过上限，最久未更新窗口被驱逐，驱逐计数递增

#### Scenario: 驱逐不破坏重启保留

- **WHEN** 某窗口已被刷盘后被内存驱逐
- **THEN** 重启回填后该窗口仍可从 sqlite 恢复

### Requirement: 管理面限流状态有界

系统 SHALL 对管理面通用限流的 per-IP 状态施加有界管理：SHALL 周期清扫窗内无命中的条目（TTL 到期即删），SHALL 有硬上限并在达到上限时驱逐，SHALL NOT 因驱逐放宽或收紧 `10/min/IP` 限流判定与 `Retry-After` 取值。大量不同源 IP 的请求 SHALL NOT 使限流状态内存无界。周期清扫 SHALL 在生产启动路径实际接线并运行（spawn 周期任务，与容量驱逐共同构成有界策略），SHALL NOT 仅以注释声称周期清扫而缺少生产调用点。

#### Scenario: 大量不同 IP 内存有界

- **WHEN** 短时间内出现远超硬上限的不同源 IP 请求
- **THEN** 限流状态条目数不超过上限，进程内存不持续增长

#### Scenario: 清扫后限流仍生效

- **WHEN** 同一 IP 在一分钟窗口内第 11 次调用通用 admin 接口
- **THEN** 仍返回 `429` 且携带正确 `Retry-After`，与清扫策略无关

#### Scenario: 过期条目被清理

- **WHEN** 某 IP 的限流窗口内已无命中且超过 TTL
- **THEN** 该 IP 条目被清除，不再占用状态内存

#### Scenario: 周期清扫在生产接线

- **WHEN** 服务以生产模式启动（非仅测试装配）
- **THEN** 周期清扫任务被实际 spawn 并按 TTL 清除过期条目；若仅保留容量驱逐，则 SHALL 以显式声明（注释/文档）明示，SHALL NOT 声称存在未接线的周期清扫

### Requirement: 审批等待事件驱动

系统 SHALL 以决议事件（而非固定间隔轮询）唤醒审批等待者：等待中的 `ask` SHALL 在决议写入时被即时唤醒并返回决议值。**决议写入 SHALL 覆盖全部决议路径——reaction 落定（`resolve`）与 `lock` 指令的拒绝落定/全清（`lock_reject_all`/`lock_clear_all`）；各路径 SHALL 经同一唤醒机制在同一临界区完成决议写入与通知，SHALL NOT 存在绕过通知直接写决议的路径。** 超时 SHALL 按既有口径返回 `None` 并清理票据。等待期间 SHALL NOT 以固定短间隔（如 `50ms`）忙轮询空转。返回语义、超时归并（按拒绝处理）与清理时序 SHALL 与改动前逐字一致。

#### Scenario: 决议即时唤醒

- **WHEN** 调用方阻塞等待某审批票，随后该票被写入决议
- **THEN** 等待者在决议写入后即时返回对应决议值，无固定轮询间隔引入的额外延迟

#### Scenario: 锁定即时唤醒

- **WHEN** 调用方阻塞等待某未决审批票，随后 `lock` 指令把该票按拒绝落定
- **THEN** 等待者在远小于其阻塞 TTL 的时间内即时返回拒绝值（`Some(false)`），不因 `lock` 路径绕过通知而空等至超时

#### Scenario: 超时行为不变

- **WHEN** 等待在超时前无任何决议
- **THEN** 返回 `None`、清理票据，与改动前一致

#### Scenario: 无忙轮询

- **WHEN** 一次完整的审批等待结束（决议或超时）
- **THEN** 等待期内不产生固定 50ms 间隔的重复唤醒（忙碌轮询计数为零或不增长）

### Requirement: 上游读取错误可观测

系统 SHALL 在上游响应体读取失败（流式 `chunk()` 返回 `Err`）时记录 warn 日志（含错误信息与已读字节数）并累加可观测指标；SHALL NOT 静默按空体/正常结束处理而不留任何信号。对外语义 SHALL 保持不变（读取失败仍退化为空体并走既有空体/错误分类路径，不改为向调用方返回新错误码）。

#### Scenario: 读取错误记 warn

- **WHEN** mock 上游在响应体读取中连接中断
- **THEN** 日志含读取错误告警与已读字节数

#### Scenario: 读取错误累加指标

- **WHEN** 上游响应体读取失败
- **THEN** 对应可观测计数递增，运维可从指标感知失败次数

#### Scenario: 对外语义不变

- **WHEN** 上游读取失败发生在非流对话路径
- **THEN** 下游仍按既有空体/错误分类路径处理，不出现新的错误码或状态码改写

### Requirement: 运行时可靠性计数在管理面可见

系统 SHALL 在 `/_admin/metrics` 暴露运行时可靠性计数器 `upstream_read_errors`（上游响应体读取失败次数）、`admin_rate_evicted`（管理限流状态驱逐次数）、`aggs_evicted`（聚合窗口驱逐次数）；三者 SHALL 为只增计数，SHALL 随对应事件递增并在管理面快照可读，SHALL NOT 仅内存累加而不输出。既有 metrics 字段 SHALL 保持只增不改。

#### Scenario: 上游读取错误计数可见

- **WHEN** 上游响应体读取失败（流式 `chunk()` 返回 `Err`）
- **THEN** `/_admin/metrics` 的 `upstream_read_errors` 计数递增

#### Scenario: 限流状态驱逐计数可见

- **WHEN** 管理限流状态因达到硬上限而发生驱逐
- **THEN** `/_admin/metrics` 的 `admin_rate_evicted` 计数递增

#### Scenario: 聚合窗口驱逐计数可见

- **WHEN** 内存聚合窗口因过期或达硬上限被驱逐
- **THEN** `/_admin/metrics` 的 `aggs_evicted` 计数递增

#### Scenario: 无事件时不虚增

- **WHEN** 未发生对应事件
- **THEN** 三计数保持为零或不增长，既有 metrics 字段不缺失
