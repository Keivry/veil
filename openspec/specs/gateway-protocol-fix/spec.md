# gateway-protocol-fix Specification

## Purpose
使 Chat、Anthropic、Responses 三协议的阻断、截断与终端帧形态向官方规范收敛，加固空流守门、跨缝掩码与 usage 累计等状态机残留风险，同时保持阻断文案与「终端恰一」约束不变。

## Requirements

### Requirement: Chat 流阻断为 delta 形态且无 event 行

系统 SHALL 以 `delta` 增量形态合成 Chat 流阻断帧，Chat 帧 SHALL 无 `event:` 行，终止 SHALL 为裸 `[DONE]` 恰一。

#### Scenario: 严格 SDK 可拼接阻断文本

- **WHEN** 上游流被审计阻断且协议为 Chat
- **THEN** 首帧为 `choices[].delta.content="[blocked: reason]"` 而非 `message` 形态，且全流 `count_done==1`

#### Scenario: Chat 帧无 event 补全

- **WHEN** `ensure_event_lines` 处理 Chat 帧
- **THEN** 不补 `event:` 行，`[DONE]` 裸帧豁免保持

### Requirement: Anthropic 阻断为 text 块且 message_stop 为空对象

系统 SHALL 以 `text` 块合成 Anthropic 阻断，四件套顺序 SHALL 锁定，`message_stop` SHALL 为空对象。

#### Scenario: 文本期望方不误触发 tool 链

- **WHEN** 阻断帧进入下游
- **THEN** 首块 `type=="text"` 且无 `tool_use` 形态，`message_stop` 数据不含自造字段

### Requirement: Responses 全序列闭合且非流 Chat 阻断字段完整

系统 SHALL 发出 `output_item/content_part` 全序列阻断/截断帧，非流 Chat 阻断体 SHALL 含 `id/object/created/model/usage`。

#### Scenario: 按 output_index 对齐的客户端正常闭合

- **WHEN** Responses 流被阻断或截断
- **THEN** 帧序列含 `added/delta/done/completed|failed` 全链路且 `terminal_count==1`

#### Scenario: 严格 Chat SDK 接受非流阻断体

- **WHEN** 非流 Chat 响应被阻断
- **THEN** 阻断体含非空 `id` 与 `object=="chat.completion"`

### Requirement: 空流守门以终端状态为准

系统 SHALL 以是否已发终端/任意帧作为空流合成条件，不依赖 `forwarded` 计数。

#### Scenario: 残余已发不再补空流帧

- **WHEN** 残余路径已发送帧但计数器未增
- **THEN** 不再误触发二次空流合成，全流终端恰一

### Requirement: 跨缝掩码不因信封字符整段失效

系统 SHALL 对跨缝命中逐字符掩码并跳过信封位，IPv6 全字母组紧邻缝 SHALL 不被 `"key":` 过滤误删。

#### Scenario: 贴信封 PII 仍被掩码

- **WHEN** 跨缝命中区间含 `{ } " [ ]` 字符
- **THEN** 非信封位仍被 `*` 掩码且 JSON 结构完整可解析

### Requirement: usage 累计覆盖与透传语义锁定

系统 SHALL 对 `message_delta usage` 取历史 max 且乱序不回退，`thinking/signature` SHALL 不透明透传，`stream_options` SHALL 键级合并，`truncation disabled+400` SHALL 原样透出。

#### Scenario: 乱序 usage 不虚高不回退

- **WHEN** 流式 usage 递减或乱序到达
- **THEN** 记录值为历史最大值，不累加不回退

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
