# go-client-interop Specification

## Purpose
说明 Go get 客户端如何零改动对接 Rust 网关，锁定路径、鉴权头、三因子字段与 SSE 语义。

## Requirements

### Requirement: Go 客户端路径零改动对接

网关 SHALL 保持 Go `get` 客户端所用路径与方法不变，使其无需修改即可对接。`GET /registrations`
（Go `get list`）要求管理面鉴权，接受 `X-Admin-Token` 或部署密钥 `X-Get-Binary-Secret`；Go 存量客户端
携带部署密钥即可通过，两者均缺失或不匹配时返回 401。

#### Scenario: 存量 Go 客户端直连

- **WHEN** 未修改的 Go get 客户端按原路径与方法发起调用
- **THEN** 网关正确路由并返回与既有语义一致的响应（含 `get list` 经部署密钥 `X-Get-Binary-Secret` 返回注册列表）

#### Scenario: 缺少管理面凭据

- **WHEN** 未携带 `X-Admin-Token` 且未携带 `X-Get-Binary-Secret` 调用 `GET /registrations`
- **THEN** 网关返回 401（管理面鉴权门禁），凭据缺失或不匹配即拒绝

### Requirement: 三因子鉴权字段兼容

网关 SHALL 兼容三因子鉴权字段（哈希头、密钥头或体、调用方标识），缺失或不匹配时按既有语义拒绝或转审。

#### Scenario: 三因子齐全通过

- **WHEN** Go 客户端携带完整三因子字段发起取用
- **THEN** 网关按既有语义放行或进入审批而不报协议错误

#### Scenario: 三因子缺失可诊断

- **WHEN** Go 客户端缺失任一因子字段
- **THEN** 网关返回明确的鉴权失败而不是空响应或挂起

### Requirement: SSE 语义对 Go 透明

网关 SHALL 保证 SSE 帧语义对 Go 客户端透明，阻断终止闭合行为与既有约定一致。

#### Scenario: Go 消费阻断流正常结束

- **WHEN** Go 客户端消费一条被审计阻断的流
- **THEN** 客户端收到终止帧并视为正常结束而不重试或挂起

### Requirement: 注册与状态响应对存量 Go 客户端可解析

`POST /register-caller` 成功响应 SHALL 含非空 `reg_id`，且 SHALL NOT 删除既有 `ok`/`registration`/`name`/`script_path`/`script_hash`/`entries`/`allow_mode` 字段；`GET /health` SHALL 含 `status`/`unlocked`/`pending`/`llm_secrets` 字段，且 SHALL NOT 删除既有 `ok`/`sqlite_ok`/`sqlite_error` 字段。

#### Scenario: 注册成功返回非空 reg_id

- **WHEN** Go 客户端以完整字段调用 `POST /register-caller` 且注册成功（无重名冲突）
- **THEN** 响应含非空 `reg_id`，既有字段保持不变，重名 409 语义不变

#### Scenario: 健康检查返回 Go 侧所需字段

- **WHEN** 客户端调用 `GET /health`
- **THEN** 响应含 `status`（字符串）、`unlocked`（布尔）、`pending`（数值）、`llm_secrets`（数值），且既有字段保持
