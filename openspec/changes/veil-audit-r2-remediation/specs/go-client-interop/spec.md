## ADDED Requirements

### Requirement: revoke 异步 202 轮询契约

默认模式（`CREDENTIAL_BLOCK_WAIT` 未设或非真值）下 `POST /revoke`（含紧急吊销转常规审批路径）SHALL 以 `202 + E_PENDING`（`{"error":{"code":"E_PENDING",...}}`）表示已建单待审批，口径与 `POST /credential` 一致；调用方 SHALL NOT 将 `202` 视为吊销已完成，SHALL 对同一请求轮询重试（建议指数退避）直至批准（吊销生效）或拒绝/超时。`CREDENTIAL_BLOCK_WAIT=1` 时 SHALL 同请求阻塞返回终态，无需轮询。Go 客户端把 `202` 当吊销成功属外部仓库缺陷，其轮询修复登记于本 change 的外部章节（Go `get/internal/proxy.go:341-344`、`revoke.go:25-29`；veil 侧见 `src/service/credential/vault_ops.rs:398-419`）。

#### Scenario: revoke 返回 202 待审

- **WHEN** 默认模式下发起 `POST /revoke` 且尚未落定
- **THEN** 返回 `202 + E_PENDING`，条目状态不变，不代表吊销成功

#### Scenario: 轮询至终态

- **WHEN** 调用方对同一 revoke 请求轮询重试
- **THEN** 批准后吊销生效（条目 `revoked=true`）、拒绝/超时返回 `403`，且不重复建单

### Requirement: registrations 响应形状契约

`GET /registrations` 响应中每条注册条目 SHALL 含 Go 契约字段 `type`（字段存在且非空，取值与条目类型一致且稳定）；`allow_mode` 输出词汇 SHALL 为 `auto`/`manual`（不再输出布尔或 `none`）。输入兼容 SHALL 保留三态：`auto` → 自动放行、`manual` → 人工审批、未知值回退 `auto` 并记 `warn`。既有字段（如 `ok`/`registration`/`name`/`script_path`/`script_hash`/`entries`/`allow_mode`）SHALL NOT 删除（`src/handler/credential/mod.rs:147-183`）。

#### Scenario: 响应含 type 与 auto/manual

- **WHEN** Go 客户端调用 `GET /registrations` 获取注册列表
- **THEN** 每条条目含非空 `type` 字段，`allow_mode` 取值为 `auto` 或 `manual`

#### Scenario: 输入兼容三态保持

- **WHEN** 注册请求以 `auto`/`manual`/未知值作 `allow_mode` 输入
- **THEN** `auto`/`manual` 正确映射，未知值回退 `auto` 并记 `warn`，不报协议错误
