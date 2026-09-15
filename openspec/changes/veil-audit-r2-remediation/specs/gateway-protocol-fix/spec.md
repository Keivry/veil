## ADDED Requirements

### Requirement: 协议尾匹配大小写口径

系统 SHALL 对协议尾判定的宽容匹配采用**大小写不敏感**语义：同一路径仅字符大小写不同时，协议归类 SHALL 保持一致，SHALL NOT 因大小写差异将对话尾回落为 `Protocol::NonDialog`。该语义相对 Python 原仓大小写敏感口径为**有意声明**（更严，防借用大小写变体规避请求改写、占位符注入、用量记录与审计判定），SHALL 在 design 登记并以大小写用例锁定。大小写不敏感 SHALL 与既有尾斜杠/一层标点宽容命中叠加生效，且 SHALL NOT 放宽官方子资源排除规则：官方子资源（如 Anthropic `v1/messages/count_tokens`、`v1/messages/batches`）SHALL 仍判 `Protocol::NonDialog`，不因大小写宽容进入对话处理。

#### Scenario: 大写对话尾仍判对话协议

- **WHEN** 请求 `/V1/Chat/Completions`
- **THEN** 协议判为 `Chat`，正常进入请求改写、占位符注入、用量记录与审计判定

#### Scenario: 混合大小写 Anthropic 尾仍判对话

- **WHEN** 请求 `/v1/MESSAGES` 或 `/V1/messages`
- **THEN** 协议判为 `Anthropic`，不回落 `Protocol::NonDialog`

#### Scenario: 大小写变体归类不变

- **WHEN** 对同一对话尾路径仅改变字符大小写
- **THEN** 协议归类结果一致，且有回归测试锁定该不变式

#### Scenario: 大小写宽容不放宽子资源排除

- **WHEN** 请求 `/v1/MESSAGES/count_tokens`
- **THEN** 仍判 `Protocol::NonDialog`（官方子资源排除不回退），不因大小写宽容进入对话处理
