## Purpose

锁定凭据面鉴权与生命周期修复后的契约：所有写端点接入三因子鉴权且在未配置部署密钥时 fail-closed、紧急吊销仅认管理 token 与内网来源且不接受客户端自证、未注册调用方默认转审批、`lock` 清除 TPM 派生主密码缓存、注册审批发送失败原子回滚、吊销后 `caller_path` 复用语义明确、KeePass 内部错误对外脱敏、审批票 TTL 口径单一来源、`allow_mode` 的 `auto`/`manual` 兼容。

## ADDED Requirements

### Requirement: 哈希变更端点的三因子鉴权

系统 SHALL 对 `POST /approve-hash-change` 实施与 `POST /credential` 相同的三因子核验（`X-Get-Binary-Hash`、部署密钥 `X-Get-Binary-Secret` 或 `body.secret`、`body.auth.caller_hash`/`caller_path`）；任一因子缺失或不一致时 SHALL 返回 `401`/`403` 且 SHALL NOT 执行任何哈希变更。鉴权通过时 SHALL 保留既有 `🔓/✅/❎` 三态落定语义不变。现有「无鉴权头请求返回 200」的测试期望 SHALL 修正为鉴权拒绝。

#### Scenario: 未鉴权哈希变更被拒

- **WHEN** 请求 `POST /approve-hash-change` 未携带任何三因子头/字段
- **THEN** 响应为 `401`/`403`，注册表 `expected_hash` 与 `allow_mode` 均不被修改

#### Scenario: 鉴权通过三态语义不变

- **WHEN** 请求三因子齐全且合法，携带合法 `reaction`
- **THEN** 按既有 `🔓/✅/❎` 语义落定（`🔓` 保持自动、`✅` 降级人工、`❎`/超时禁用），行为与修复前一致

#### Scenario: 因子不一致被拒

- **WHEN** 三因子中部署密钥或调用者身份与期望不一致
- **THEN** 返回 `403` 且不执行哈希变更

### Requirement: 紧急吊销通道仅认管理 token 与内网来源

系统 SHALL 使紧急吊销 `POST /revoke/emergency` 仅接受两类放行依据：有效管理 token（`admin_token` 或 `X-Admin-Token`）与内网来源（仅按 TCP 远端地址判定，不采信代理头）。系统 SHALL NOT 接受客户端在请求体中声明的「文件在位」之类的自证依据，SHALL NOT 将任何纯客户端布尔字段作为放行条件。未命中放行依据时 SHALL 转常规审批而非直接吊销。

#### Scenario: 伪造文件在位不放行

- **WHEN** 公网来源请求携带 `{"file_present":true}` 且无有效管理 token
- **THEN** 不执行吊销，转常规审批（`202`），条目状态不变

#### Scenario: 管理 token 放行

- **WHEN** 请求携带有效管理 token
- **THEN** 直接执行吊销（`revoked=true`、`enabled=false`），不建审批单

#### Scenario: 内网来源放行

- **WHEN** 请求 TCP 远端为内网地址（如 `127.0.0.1`、`10.0.0.0/8`、`192.168.0.0/16`）
- **THEN** 直接执行吊销，不要求管理 token

### Requirement: 注册与常规吊销端点的三因子鉴权

系统 SHALL 对 `POST /register-caller` 与 `POST /revoke` 实施与 `POST /credential` 相同的三因子核验；任一因子缺失或不一致时 SHALL 返回 `401`/`403` 且 SHALL NOT 落注册/吊销动作。鉴权通过后 SHALL 保留既有 Matrix 审批语义（`Register` 分支、默认 `202` 抛单与 `CREDENTIAL_BLOCK_WAIT=1` 阻塞双模）不变。

#### Scenario: 未鉴权注册被拒

- **WHEN** `POST /register-caller` 未携带三因子
- **THEN** 返回 `401`/`403`，注册表不新增条目

#### Scenario: 未鉴权吊销被拒

- **WHEN** `POST /revoke` 未携带三因子
- **THEN** 返回 `401`/`403`，目标条目状态不变

#### Scenario: 鉴权通过进入审批链

- **WHEN** `POST /register-caller` 三因子齐全且合法
- **THEN** 按既有审批链处理（默认 `202 + E_PENDING` 或阻塞落定），语义与修复前一致

### Requirement: 写端点部署密钥强制（fail-closed）

系统 SHALL 使所有使用三因子守卫的写端点（`POST /approve-hash-change`、`POST /register-caller`、`POST /revoke`）在部署未配置部署密钥（`GET_BINARY_SECRET`/`CREDENTIAL_SECRET` 均为空）时 fail-closed：SHALL 返回 `403`（`E_AUTH`）且 SHALL NOT 执行任何注册、吊销或哈希变更动作。部署配置了非空部署密钥时，三因子复核行为 SHALL 与既有口径完全一致（`X-Get-Binary-Hash`、部署密钥 `X-Get-Binary-Secret`/`body.secret`、`body.auth.caller_hash`/`caller_path`）。`POST /credential` 读路径 SHALL NOT 受本要求约束，保持 Python 兼容语义（未配置部署密钥时跳过 Secret 因子）。本要求相对 Python 原仓对特权写端点为**有意偏离**，属 BREAKING，部署迁移 SHALL 配置 `GET_BINARY_SECRET` 或 `CREDENTIAL_SECRET`。

#### Scenario: 未配置部署密钥写端点全拒

- **WHEN** 部署未配置 `GET_BINARY_SECRET`/`CREDENTIAL_SECRET`，且请求 `POST /approve-hash-change`、`POST /register-caller` 或 `POST /revoke`
- **THEN** 三端点均返回 `403`（`E_AUTH`），注册表与待审表均不发生变化

#### Scenario: 配置部署密钥后三因子行为不变

- **WHEN** 部署配置了非空部署密钥，且请求三因子齐全合法
- **THEN** 三端点按既有三因子与审批/三态语义处理，行为与收紧前一致

#### Scenario: 读路径不受影响

- **WHEN** 部署未配置部署密钥，且请求 `POST /credential`
- **THEN** 按 Python 兼容语义跳过 Secret 因子，不因本要求被拒

### Requirement: 未注册调用方默认转审批

系统 SHALL 在调用者身份未匹配任何已注册条目时，默认转入 Matrix 审批（或按配置拒绝），SHALL NOT 因未注册而直接自动放行。自动放行 SHALL 仅在显式配置放行策略且调用方已注册时生效。

#### Scenario: 未注册默认转审批

- **WHEN** 三因子合法但 `caller_hash`/`caller_path` 未匹配任何注册条目，且未显式配置放行
- **THEN** 请求转入审批（`202 + E_PENDING`）或被拒绝，不返回凭据明文

#### Scenario: 已注册显式放行仍生效

- **WHEN** 调用方已注册且被显式配置为自动放行
- **THEN** 按既有自动放行语义返回凭据

### Requirement: lock 清除 TPM 派生主密码缓存

系统 SHALL 在 `lock` 清理时清除并零化 TPM 派生的主密码缓存，同时清除 KeePass 会话、口令缓存与内存/矩阵待审。`lock` 之后 SHALL NOT 存在可用主密码缓存；`unlock` SHALL 重新经 TPM 解封主密码。

#### Scenario: lock 后主密码缓存清空

- **WHEN** 系统已解锁并经 TPM 派生主密码，随后收到 `lock`
- **THEN** 主密码缓存被清除并零化，凭据取用因未解锁被拒

#### Scenario: 再次锁定后可重新解锁

- **WHEN** `lock` 之后再次执行 unlock
- **THEN** 重新经 TPM 解封主密码成功，凭据取用恢复

### Requirement: 注册审批发送失败的原子回滚

系统 SHALL 使注册审批链具备原子性：当注册条目已落盘但审批建单/发送失败时，SHALL 回滚该条目（删除或置为吊销），SHALL NOT 遗留不可决的孤儿注册条目；被回滚的 `caller_path` SHALL 可被重试注册。

#### Scenario: 发送失败无孤儿条目

- **WHEN** 注册落盘后审批消息发送失败（取不到真实 `event_id`）
- **THEN** 注册表无该条目的残留，`caller_path` 可再次发起注册

#### Scenario: 发送成功注册正常进入审批

- **WHEN** 审批消息发送成功并取得真实 `event_id`
- **THEN** 条目按既有三态落定，行为不变

### Requirement: 吊销后 caller_path 复用语义

系统 SHALL 允许已吊销条目的同一 `caller_path` 重新注册；对已吊销 `caller_path` 的注册请求 SHALL NOT 返回 `409`，重注册 SHALL 走既有注册审批链。重注册条目 SHALL 按全新条目初始化（`enabled=false`、`revoked=false`、`old_hash` 宽限清空），SHALL NOT 继承已吊销条目的哈希或宽限。`caller_path` 与已释放的 `name` 的复用语义 SHALL 内部一致；仅对未吊销条目的重名/重路径注册保留 `409`。

#### Scenario: 已吊销路径可复用重新注册

- **WHEN** 对已吊销的 `caller_path` 重新发起注册
- **THEN** 注册成功进入审批（不返回 `409`），新条目为全新初始化（`enabled=false`、`revoked=false`、无旧哈希宽限）

### Requirement: KeePass 内部错误对外脱敏

系统 SHALL 在 KeePass 路径失败时对外仅返回通用错误（固定文案/错误码），SHALL NOT 在响应体中回传 KDBX 路径、解密失败细节等内部实现信息；内部错误细节 SHALL 仅记录于服务端日志。

#### Scenario: 内部错误不泄漏

- **WHEN** KeePass 查询因内部错误（如解密失败/库不可读）返回 500
- **THEN** 响应体不含内部路径或异常细节，服务端日志保留完整错误

### Requirement: 审批票 TTL 口径单一来源

系统 SHALL 使审批票存活时长具有单一、可验证的口径：凭据/注册/哈希变更类存在阻塞等待者的未决票 SHALL 保留至其阻塞超时（`300s`）；空闲/审计/解锁类无等待者的孤儿票 SHALL 按 `60s` 上限清扫；两者 SHALL NOT 互相覆盖。`GET /health` 的 `pending` 计数与内存清扫行为 SHALL 与该口径一致，README §4/§8.4 SHALL 与实现同批同步。

#### Scenario: 凭据阻塞票不被 60s 误收

- **WHEN** 凭据类请求已建单且存在阻塞等待者，等待未超过 `300s`
- **THEN** 该票在内存侧不被 60s 清扫回收，等待可正常落定

#### Scenario: 空闲孤儿票按 60s 回收

- **WHEN** 无阻塞等待者的孤儿票超过 `60s`
- **THEN** 被清扫回收，内存有界

#### Scenario: 文档与实现一致

- **WHEN** 核对 README §4/§8.4 声明与 `PENDING_TTL_SECS`/阻塞超时的实现
- **THEN** 两处口径一致，无「声明 300s、实现 60s 回收」的矛盾

### Requirement: allow_mode 兼容 auto 与 manual

系统 SHALL 在注册接口的 `allow_mode` 中接受 `auto`（映射既有自动放行语义）与 `manual`（映射既有转审批语义），与 Go 客户端 `get register --auto` 契约保持同步。对未知值 SHALL NOT 静默忽略：系统 SHALL 记录显式 `warn` 日志并按文档声明的回退处理。解析结果 SHALL 反映到注册条目的放行模式。

#### Scenario: auto 生效

- **WHEN** 注册请求 `allow_mode` 为 `auto`
- **THEN** 条目放行模式为自动放行，Go `--auto` 不再静默失效

#### Scenario: manual 生效

- **WHEN** 注册请求 `allow_mode` 为 `manual`
- **THEN** 条目放行模式为人工审批（转审批）

#### Scenario: 未知值显式处理

- **WHEN** 注册请求 `allow_mode` 为未知值
- **THEN** 记录显式 `warn` 日志并按文档声明的回退处理，不出现无告警的静默失效
