## MODIFIED Requirements

### Requirement: 紧急吊销通道仅认管理 token 与内网来源

系统 SHALL 使紧急吊销 `POST /revoke/emergency` 仅接受两类放行依据：有效管理 token（`admin_token` 或 `X-Admin-Token`）与内网来源（仅按 TCP 远端地址判定，不采信代理头）。系统 SHALL NOT 接受客户端在请求体中声明的「文件在位」之类的自证依据，SHALL NOT 将任何纯客户端布尔字段作为放行条件。未命中放行依据时 SHALL 转常规审批而非直接吊销。管理 token 源 SHALL 为 `OBSERVABILITY_ADMIN_TOKEN`（与 `/_admin` 同一 token）；相对原仓/早期实现使用 `CREDENTIAL_ADMIN_TOKEN` 属**有意变更，BREAKING**——`CREDENTIAL_ADMIN_TOKEN` SHALL NOT 再作为紧急吊销的放行依据。迁移：将 `OBSERVABILITY_ADMIN_TOKEN` 配置为有效值并与调用方对齐（`src/service/credential/vault_ops.rs:555-561`）。

#### Scenario: 伪造文件在位不放行

- **WHEN** 公网来源请求携带 `{"file_present":true}` 且无有效管理 token
- **THEN** 不执行吊销，转常规审批（`202`），条目状态不变

#### Scenario: 管理 token 放行

- **WHEN** 请求携带有效管理 token
- **THEN** 直接执行吊销（`revoked=true`、`enabled=false`），不建审批单

#### Scenario: 内网来源放行

- **WHEN** 请求 TCP 远端为内网地址（如 `127.0.0.1`、`10.0.0.0/8`、`192.168.0.0/16`）
- **THEN** 直接执行吊销，不要求管理 token

#### Scenario: 旧 token 源不再放行（迁移）

- **WHEN** 请求仅携带旧 `CREDENTIAL_ADMIN_TOKEN` 值且来源非内网
- **THEN** 不按管理 token 放行，转常规审批而非直接吊销
