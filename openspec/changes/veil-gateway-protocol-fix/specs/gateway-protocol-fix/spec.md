## Purpose

三协议阻断/截断/终端帧向官方规范收敛，状态机残留风险加固，不改变阻断文案与终端恰一约束。

## ADDED Requirements

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
