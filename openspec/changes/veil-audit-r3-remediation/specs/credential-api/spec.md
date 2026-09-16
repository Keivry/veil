## MODIFIED Requirements

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
