## MODIFIED Requirements

### Requirement: reaction 接线与五分支处理

系统 SHALL 将收到的 reaction 事件按原因映射到五分支（unlock / 注册自动放行 / 注册普通审批 / 注册拒绝 / 哈希变更 / 凭据审批 / 审计审批），仅白名单成员的 ✅/❎/🔓 生效，未知分支与失配 `event_id` MUST 以 no-op 忽略。创建审批单后系统 SHALL 按分支预置提示 reaction（表情列表与 Python `_matrix.py:282-331` 对齐，含 `🔓`），使审批人无需手输即可发现并点选；预置/reaction 提示的发送失败 SHALL 仅记 `warn`，SHALL NOT 阻断审批建单、SHALL NOT 使接口返回错误（`src/service/credential/approval.rs:79-95`）。

#### Scenario: 批准放行

- **WHEN** 白名单成员对某 pending 单发送 ✅（或注册场景 🔓）
- **THEN** 对应 `ask/ask_audit` 返回批准且摘要中无明文

#### Scenario: 失配忽略

- **WHEN** reaction 指向不存在的 `event_id` 或非成员发送
- **THEN** 系统忽略且不改变任何 pending 状态

#### Scenario: 审批消息预置 reaction

- **WHEN** 审批单创建成功
- **THEN** 系统按分支预置提示 reaction（含 `🔓`），审批人可发现并点选

#### Scenario: 预置发送失败不阻断

- **WHEN** 预置 reaction 的发送调用失败
- **THEN** 仅记 `warn`，审批单仍有效可决，接口不返回错误
