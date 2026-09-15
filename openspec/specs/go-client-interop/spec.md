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

### Requirement: revoke 异步 202 轮询契约

默认模式（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）下 `POST /revoke`（含紧急吊销转常规审批路径）SHALL 以 `202 + E_PENDING`（`{"error":{"code":"E_PENDING",...}}`）表示已建单待审批，口径与 `POST /credential` 一致；调用方 SHALL NOT 将 `202` 视为吊销已完成，SHALL 对同一请求轮询重试（建议指数退避）直至批准（吊销生效）或拒绝/超时。`CREDENTIAL_BLOCK_WAIT=1` 时 SHALL 同请求阻塞返回终态，无需轮询。Go 客户端把 `202` 当吊销成功属外部仓库缺陷，其轮询修复登记于本 change 的外部章节（Go `get/internal/proxy.go:341-344`、`revoke.go:25-29`；veil 侧见 `src/service/credential/vault_ops.rs:398-419`）。

#### Scenario: revoke 返回 202 待审

- **WHEN** 默认模式下发起 `POST /revoke` 且尚未落定
- **THEN** 返回 `202 + E_PENDING`，条目状态不变，不代表吊销成功

#### Scenario: 轮询至终态

- **WHEN** 调用方对同一 revoke 请求轮询重试
- **THEN** 批准后吊销生效（条目 `revoked=true`）、拒绝/超时返回 `403`，且不重复建单

### Requirement: registrations 响应形状契约

`GET /registrations` 响应中每条注册条目 SHALL 含 Go 契约字段 `type`（字段存在且非空，取值与条目类型一致且稳定）；`allow_mode` 输出词汇 SHALL 为 `auto`/`manual`（不再输出布尔或 `none`）。输入兼容 SHALL 保留三态：`auto` → 自动放行、`manual` → 人工审批、未知值回退 `auto` 并记 `warn`。既有字段（如 `ok`/`registration`/`name`/`script_path`/`script_hash`/`entries`/`allow_mode`）SHALL NOT 删除（`src/handler/credential.rs:147-183`）。

#### Scenario: 响应含 type 与 auto/manual

- **WHEN** Go 客户端调用 `GET /registrations` 获取注册列表
- **THEN** 每条条目含非空 `type` 字段，`allow_mode` 取值为 `auto` 或 `manual`

#### Scenario: 输入兼容三态保持

- **WHEN** 注册请求以 `auto`/`manual`/未知值作 `allow_mode` 输入
- **THEN** `auto`/`manual` 正确映射，未知值回退 `auto` 并记 `warn`，不报协议错误
