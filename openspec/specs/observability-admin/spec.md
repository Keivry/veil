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

用量统计 SHALL 以 sqlite 为准口径：内存环 10k（最近 10k 样本）+ `daily` 表保留 30 天 + `hourly` 表保留 7 天 + `5min` 表覆盖式 UPSERT（只留最新窗口）；计数 SHALL 仅含对话端点（`is_chat_tail` 为真），非对话不计数；延迟 SHALL 以 12 桶直方图近似 p95；`is_precise` 为真 SHALL 表示精确计数（可直接对账），为假 SHALL 表示近似计数（仅趋势参考）。

#### Scenario: 精确口径对账
- **WHEN** `is_precise` 为真
- **THEN** 调用方可用该数值直接对账

#### Scenario: 近似口径提示
- **WHEN** `is_precise` 为假
- **THEN** 调用方仅可作趋势参考，不可直接对账

#### Scenario: 非对话不计数
- **WHEN** 请求为非对话尾
- **THEN** 不计入对话用量，`other` 桶不再混入非对话数据

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

新版受限操作 SHALL 保持同等或更严限制，MUST NOT 借版本升级放宽。

#### Scenario: 限制表执行
- **WHEN** 任一受限操作到达边界
- **THEN** 系统按上表对应限制执行

### Requirement: metrics 快照 / ring / 覆盖 UPSERT 继承声明

`metrics` 快照、`ring` 环、`5min` 覆盖 UPSERT 口径 SHALL 为范围外继承行为，本 change SHALL NOT 重定义其内部实现；调用方 SHALL 引用既有 sqlite 口径条（内存环 10k + `daily` 30 天 + `hourly` 7 天 + `5min` 覆盖 UPSERT）；本 change 只收敛计数范围与标签语义（仅对话端点、`is_precise`、`truncated_mode` 分标签）。

#### Scenario: 继承口径不重定义
- **WHEN** 实现 metrics 快照、ring 写入或 `5min` 覆盖 UPSERT
- **THEN** 沿用既有 sqlite 口径行为，本 change 不新增语义

#### Scenario: 本 change 只收敛标签
- **WHEN** 落计数时涉及对话范围或模式标签
- **THEN** 按本 spec 的对话端点、`is_precise`、`truncated_mode` 分标签条执行

### Requirement: truncated_mode 三态落 metrics 分标签计数

`stream_meta.truncated_mode` 三态（`silent_discard` / `open_ended` / `synthesized_failed`）SHALL 落 metrics 分标签计数（按 mode 分标签）；三态之外的值 SHALL NOT 落该指标。

#### Scenario: 三态分标签计数
- **WHEN** 流以三态之一截断
- **THEN** metrics 按对应 mode 标签计数加一

#### Scenario: 非法值不落指标
- **WHEN** 截断状态为三态之外的值
- **THEN** 系统不落该指标并记告警
