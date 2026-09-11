# credential-approval-dual-mode Specification

## Purpose
在保持现有 202 抛单异步模式的同时恢复原仓 300s 阻塞审批，使存量 Go 客户端无需改造即可用。

## Requirements

### Requirement: 凭据审批双模

系统 SHALL 支持双模：默认 202 抛单（建单 + best-effort 发 Matrix 消息即返回）；当 `CREDENTIAL_BLOCK_WAIT=1` 且请求命中 enrolled 篡改或未 enrolled 时 SHALL 阻塞等待 reaction，最长 300s，批准放行、拒绝/超时按原语义返回。

#### Scenario: 阻塞模批准放行

- **WHEN** `CREDENTIAL_BLOCK_WAIT=1` 且审批人在 300s 内 ✅
- **THEN** 同一请求返回凭据而非 202

#### Scenario: 默认抛单不断链

- **WHEN** 未设 `CREDENTIAL_BLOCK_WAIT`
- **THEN** 系统保持 202 建单行为

### Requirement: 审批死分支可达

`matches_old_hash` 失败后的 revoked/enabled 检查 SHALL 可达；检查顺序 SHALL 为先查启用再比 hash。

#### Scenario: 已吊销调用方被拒

- **WHEN** 调用方已吊销但 hash 亦失配
- **THEN** 系统返回吊销拒绝而非转审批
