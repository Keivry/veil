# credential-api Specification

## Purpose
凭据网关对外暴露的 HTTP 凭据 API：调用方经三因子身份核验后获取凭据明文，注册、吊销、哈希变更审批全流程可审计、可限流，健康检查与注册查询接口鉴权语义明确。自动放行三态、审批超时、吊销免审口径与 audit-tpm-matrix spec 分表说明，本 spec 只收敛凭据侧。

## Requirements

### Requirement: POST /credential 三因子身份核验

系统 SHALL 对 `POST /credential` 执行三因子核验：请求头 `X-Get-Binary-Hash`（调用二进制哈希）、请求头 `X-Get-Binary-Secret`（调用方密钥，兼容 `body.secret`）、请求体 `body.auth.caller_hash` / `caller_path`（调用方标识）三方一致；`hmac.compare_digest` 时序安全比较；任一因子缺失或不一致 SHALL 返回 403。当服务端对应调用方未配置任何期望哈希（未 enrolled）时，系统 SHALL 默认转入 Matrix 审批（`202 + E_PENDING`），仅当 `AUTO_APPROVE=false` 时 SHALL 返回 `403`；Secret 校验 SHALL 继续执行，Secret 失败 SHALL 返回 `403`。系统 SHALL NOT 因未 enrolled 而直接自动放行。已 enrolled 调用方的哈希不一致 SHALL 走自动放行三态的 `None` 分支（hash_mismatch 转 Matrix）。未 enrolled 语义的真相源 SHALL 为 canonical `openspec/specs/credential-auth-hardening/spec.md`。

#### Scenario: 三因子一致放行
- **WHEN** 客户端以正确的 `X-Get-Binary-Hash`、`X-Get-Binary-Secret`、`body.auth.caller_hash` / `caller_path` 请求 `POST /credential`
- **THEN** 系统返回 200 与凭据明文（或占位符载荷）

#### Scenario: 任一因子不一致拒绝
- **WHEN** 三因子中任一值与注册记录不匹配
- **THEN** 系统返回 403，不返回凭据内容
#### Scenario: 空配置仅未 enrolled 放行且 Secret 仍校验

- **WHEN** 服务端该调用方未配置任何期望哈希（未 enrolled）且 Secret 正确
- **THEN** 系统 SHALL NOT 直接放行：默认转入 Matrix 审批（`202 + E_PENDING`），仅当 `AUTO_APPROVE=false` 时返回 `403`；Secret 失败仍返回 `403`

#### Scenario: body.secret 兼容
- **WHEN** 客户端将密钥置于 `body.secret` 而非 `X-Get-Binary-Secret` 头
- **THEN** 系统兼容读取并按同一 Secret 口径校验

### Requirement: --raw 可测契约

`--raw` 终端直调 SHALL 满足可测契约：`caller_hash==GET_BINARY_HASH`（调用方冒用 get 自身哈希直调）SHALL 拒 403；文档 SHALL 声明 `--raw` 仅用于受控管道，不得持久化。

#### Scenario: 冒用 get 自身 hash 直调被拒
- **WHEN** `POST /credential` 的 `caller_hash==GET_BINARY_HASH`
- **THEN** 系统返回 403 并记审计事件

#### Scenario: 正常 --raw 管道放行
- **WHEN** 三因子通过且非冒用 get 自身哈希
- **THEN** 系统按正常语义下发 `--raw` 载荷

### Requirement: 自动放行三态 True / False / None

系统 SHALL 支持自动放行三态：`True`（自动放行，直接返回凭据）、`False`（自动拒绝，返回 403 并记审计）、`None`（hash_mismatch 转 Matrix 人工审批，返回 202）。本 spec 不得使用 `allow` / `deny` / `approve` 虚构三态命名。

#### Scenario: True 自动放行
- **WHEN** 调用方配置为 `True` 且三因子通过
- **THEN** 系统直接返回凭据，不产生审批单

#### Scenario: False 自动拒绝
- **WHEN** 调用方配置为 `False`
- **THEN** 系统返回 403 并记审计事件，不产生审批单

#### Scenario: None 转 Matrix 审批
- **WHEN** 调用方配置为 `None`（含 hash_mismatch）
- **THEN** 系统创建 Matrix 审批单并返回 202，凭据暂不下发

### Requirement: 凭据审批 300s 与审计审批 90s 分表

凭据侧 Matrix 审批超时 SHALL 为 300s；审计侧审批超时 SHALL 为 90s（`AUDIT_TIMEOUT` 禁 110-130，见 audit-tpm-matrix spec）。两者 SHALL 分表说明，MUST NOT 混用同一超时值；超时未审批 SHALL 自动拒绝并记审计事件。

#### Scenario: 凭据审批 300s 超时拒绝
- **WHEN** 凭据审批单 300s 内无人审批
- **THEN** 系统自动拒绝并记审计事件

#### Scenario: 审计审批 90s 独立计时
- **WHEN** 审计审批单到达 90s 超时
- **THEN** 系统按审计超时路径拒绝，不受凭据 300s 影响

### Requirement: 限流 2s / 1s + 429 Retry-After + 窗口说明

系统 SHALL 对 `POST /credential` 按调用方限流（同一调用方滑动窗口内间隔不小于 2s），对注册类接口按源限流（间隔不小于 1s）；触发限流 SHALL 返回 429 并带 `Retry-After` 头；窗口 SHALL 为滑动窗口，计数按调用方（凭据）与按源（注册）分别说明。

#### Scenario: 凭据接口 2s 限流
- **WHEN** 同一调用方在 2s 窗口内重复请求 `POST /credential`
- **THEN** 系统返回 429 并带 `Retry-After`

#### Scenario: 注册接口 1s 限流
- **WHEN** 同一来源在 1s 窗口内重复调用注册接口
- **THEN** 系统返回 429 并带 `Retry-After`

### Requirement: GET /health 无鉴权与 GET /registrations 需鉴权

`GET /health` SHALL 无需鉴权，始终返回 200 存活状态；`GET /registrations` SHALL 要求鉴权，未鉴权请求 SHALL 返回 401。

#### Scenario: 健康检查无鉴权
- **WHEN** 未携带任何凭据请求 `GET /health`
- **THEN** 系统返回 200

#### Scenario: 注册查询需鉴权
- **WHEN** 未携带鉴权信息请求 `GET /registrations`
- **THEN** 系统返回 401

### Requirement: POST /register-caller 注册与三态标识

`POST /register-caller` SHALL 注册新调用方；调用方已存在 SHALL 返回 409，不覆盖原记录；新注册调用方默认 `enabled=False`。注册状态 SHALL 以三态标识呈现：`🔓`（未启用）、`✅`（已启用）、`❎`（已禁用/吊销）。

#### Scenario: 新调用方注册
- **WHEN** 注册不存在的调用方
- **THEN** 系统创建记录，`enabled=False`，状态标识为 `🔓`

#### Scenario: 重复注册判重
- **WHEN** 注册已存在的调用方
- **THEN** 系统返回 409，不覆盖原记录

#### Scenario: 三态标识呈现
- **WHEN** 查询调用方注册状态
- **THEN** 系统按启用状态返回 `🔓`、`✅`、`❎` 之一

### Requirement: POST /revoke 吊销

`POST /revoke` SHALL 吊销指定调用方凭据；吊销后该调用方 SHALL 置为禁用（`❎`），后续 `POST /credential` SHALL 返回 403。

#### Scenario: 吊销后拒绝
- **WHEN** 调用方被吊销后再次请求 `POST /credential`
- **THEN** 系统返回 403

### Requirement: POST /revoke/emergency 紧急吊销三免审与 admin 鉴权分表

`POST /revoke/emergency` SHALL 为紧急吊销通道，三免审条件任一满足即免审批执行：携带有效 admin 鉴权、持有紧急吊销文件、来源为内网 IP；否则 SHALL 转常规审批。本 Requirement 只定义凭据侧三免审，admin 鉴权优先级（`X-Admin-Token` > `__Host-admin_token` Cookie > `?access_token` 仅 SSE）以 observability-admin spec 为准，两者 SHALL 分表说明，MUST NOT 在本 spec 复写 admin 鉴权表。

#### Scenario: 免审即执行
- **WHEN** 紧急吊销请求满足三免审之一
- **THEN** 系统立即执行吊销，不走审批

#### Scenario: 非免审转审批
- **WHEN** 紧急吊销请求无免审条件
- **THEN** 系统转常规审批流程

### Requirement: POST /approve-hash-change 哈希变更审批

调用方二进制哈希变更 SHALL 经 `POST /approve-hash-change` 审批；未经审批的变更哈希请求 `POST /credential` SHALL 返回 403；审批通过后新哈希 SHALL 生效。

#### Scenario: 未审批新哈希被拒
- **WHEN** 调用方以未审批的新二进制哈希请求凭据
- **THEN** 系统返回 403

#### Scenario: 审批后新哈希生效
- **WHEN** 管理员经 `POST /approve-hash-change` 批准新哈希
- **THEN** 后续以新哈希的请求恢复 200

### Requirement: KeePass 真实 kdbx 后端 Non-Goal（Mock 边界）

本 change SHALL NOT 接入真实 KeePass kdbx 后端（不引入新 kdbx 依赖）；凭据下发 SHALL 经 `KeePassBackend` trait 由 `MockKeePass` 占位实现：未解锁返回 503，已解锁返回 `__MOCK_CRED_<caller>__` 占位载荷。生产风险：占位载荷非真实密钥，生产部署 MUST 先完成真实 kdbx 后端 change 并经 TPM 派生主密钥（见 audit-tpm-matrix spec TPM 条），否则 SHALL NOT 上线。

#### Scenario: 未解锁 503
- **WHEN** `MockKeePass` 未解锁时请求 `POST /credential`
- **THEN** 系统返回 503，不返回占位载荷

#### Scenario: 真实 kdbx 延后
- **WHEN** 调用方需要真实 kdbx 密钥
- **THEN** 本 change 仅返回占位载荷，真实后端由后续 change 交付
