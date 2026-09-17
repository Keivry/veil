# admin-ratelimit-contract Specification

## Purpose
显式声明管理面限流与请求体上限契约，澄清通用限流与 SSE 并发、不同 body 上限取值的差异为有意设计。

## Requirements

### Requirement: Admin 通用限流十每分

系统 SHALL 对通用 admin 接口按源 IP 限流 `10/min`，超限 SHALL 返回 `429` 并携带 `Retry-After` 头。

系统 SHALL 将 `/_admin/health` 作为**唯一豁免**通用限流的路径；豁免集 SHALL 由 `src/service/admin/ratelimit.rs::admin_rate_exempt_paths()` 单一承载，`is_rate_exempt()` 为其声明式判定。**豁免的可验证语义为行为面**：health handler（`src/handler/admin.rs::admin_health`）SHALL NOT 调用通用限流门，故 `/_admin/health` 恒不被 429；`is_rate_exempt()` 当前仅被 `src/handler/admin.rs::admin_health` 内一条 `debug_assert!` 引用（生产构建被剥离），属**声明/文档用途**，SHALL NOT 被作为豁免生效的实现依据，SHALL NOT 新增仅与豁免集自身互为镜像的常量断言充作行为验收。该豁免 SHALL 由**行为断言**锁定（连续多轮 `/_admin/health` 不被 429，且非豁免 admin 路由在第 11 次被 429 并携带 `retry-after`），SHALL NOT 仅凭生产构建中被剥离的 `debug_assert`。阈值 `10/min` SHALL NOT 改变。

#### Scenario: 通用接口超限

- **WHEN** 同一 IP 在一分钟内第 11 次调用通用 admin 接口
- **THEN** 系统返回 429 且响应含 Retry-After 头

#### Scenario: 限流按远端计数

- **WHEN** 请求携带代理类头且远端 IP 不同
- **THEN** 限流计数仍按 TCP 远端地址而不采信代理头

#### Scenario: health 豁免与非豁免路由限流的行为断言

- **WHEN** 同一 IP 在一分钟窗口内连续多次调用 `/_admin/health`（次数超过 `10/min`），随后调用非豁免路由 `/_admin/metrics`
- **THEN** `/_admin/health` 全部不返回 429；`/_admin/metrics` 在该窗口内第 11 次返回 429 且携带 `retry-after`，豁免集与行为一致

### Requirement: SSE 并发五每 IP

系统 SHALL 对 `/_admin/events/stream` 按 IP 限制并发 `5`，超限 SHALL 拒绝新连接而不影响已建连接。

#### Scenario: SSE 超并发拒绝

- **WHEN** 同一 IP 已有 5 条 SSE 连接并再建第 6 条
- **THEN** 第 6 条被拒绝且前 5 条保持正常

#### Scenario: 限流与并发维度正交声明

- **WHEN** 查阅限流契约文档
- **THEN** 文档显式说明 10/min 为速率维度、5/IP 为并发维度，两者正交且均为有意设计

### Requirement: Body 上限分级声明

系统 SHALL 声明通用请求体上限与审计类上限的差异为有意设计，超限 SHALL 返回 `413`。

#### Scenario: 通用体超限

- **WHEN** 通用请求体超过其声明上限
- **THEN** 系统返回 413 并拒绝继续处理

#### Scenario: 上限差异有据可查

- **WHEN** 查阅契约中 10MB 与 8MB 取值说明
- **THEN** 文档给出各自适用检查点与差异理由，不再是未解释的巧合值
