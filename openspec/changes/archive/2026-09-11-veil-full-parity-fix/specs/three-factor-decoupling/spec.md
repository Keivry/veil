## Purpose

修复三因子认证的字段耦合误判，恢复与 Go `get` 客户端的互操作，使正常脚本请求不再被误转审批。

## ADDED Requirements

### Requirement: header 与 caller 解耦校验

系统 SHALL 分开校验三因子：`X-Get-Binary-Hash` 比对服务端 `GET_BINARY_HASH`；部署密钥（`X-Get-Binary-Secret` 或 `body.secret`）独立校验；`body.auth.caller_hash/caller_path` 独立走注册/审批。不得要求 `header_hash == caller_hash` 才继续。

#### Scenario: 正常脚本放行

- **WHEN** header 为 get 二进制 hash、caller 为脚本 hash、secret 正确且已注册匹配
- **THEN** 系统放行而非转审批

#### Scenario: 纯 body 形态兼容

- **WHEN** 请求无 header 但 `body.auth` 含 `get_binary_hash/get_binary_secret/caller_hash`
- **THEN** 系统按 body 字段完成三因子校验

### Requirement: --raw 终端拦截补 use_token 条件

系统 SHALL 仅当 `caller_hash == GET_BINARY_HASH` 且本次取用为原始值（非 token 化）时拒绝终端直调；token 化取用不受此限。

#### Scenario: 终端 token 取用放行

- **WHEN** 终端直调但取用脱敏值
- **THEN** 系统不以终端直调为由拒绝
