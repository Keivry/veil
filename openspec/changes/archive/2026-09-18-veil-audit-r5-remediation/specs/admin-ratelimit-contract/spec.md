# Spec Delta

## MODIFIED Requirements

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
