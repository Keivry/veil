# caller-field-acl Specification

## Purpose
恢复调用方字段级授权语义，堵住已注册调用方越权访问未授权条目/字段的缺口，并明确注册审批与限流口径。

## Requirements

### Requirement: 注册模型与字段级授权

系统 SHALL 在注册表中保存调用方名称、描述、条目到字段的授权映射、自动放行模式与启用/吊销状态；查询凭据时 SHALL 校验请求条目/字段是否在该调用方授权范围内，未授权 SHALL 拒绝或转审批（MUST NOT 直接放行）；哈希变更 SHALL 保留旧哈希宽限语义并触发变更通知。

#### Scenario: 越权被拦

- **WHEN** 已注册调用方请求其未授权的条目字段
- **THEN** 系统拒绝或转 Matrix 审批，不返回凭据

#### Scenario: 哈希篡改转审

- **WHEN** 已注册调用方的脚本哈希与期望不一致
- **THEN** 系统建单转审批并通知哈希变更，不直接放行

### Requirement: 三因子与限流通路

系统 SHALL 保持三因子核验（`X-Get-Binary-Hash`、`X-Get-Binary-Secret` 或 `body.secret` 兼容、`body.auth.caller_hash/caller_path`，含 Go 别名 `body.auth.get_binary_hash/secret`）；`caller_hash == GET_BINARY_HASH` 的终端直调 SHALL 拒绝；凭据查询限流 2s、注册限流 1s，超限返回 429；注册表落盘 SHALL 原子写入且权限 0600。

#### Scenario: 终端直调拒绝

- **WHEN** `caller_hash` 等于 `GET_BINARY_HASH`
- **THEN** 系统返回 403 而非放行

#### Scenario: 限流生效

- **WHEN** 同一调用方在 2s 内重复查询凭据
- **THEN** 第二次返回 429
