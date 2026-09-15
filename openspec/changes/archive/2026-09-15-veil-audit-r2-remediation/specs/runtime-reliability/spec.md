## ADDED Requirements

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

## MODIFIED Requirements

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
