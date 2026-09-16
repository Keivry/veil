## MODIFIED Requirements

### Requirement: Anthropic 阻断为 text 块且 message_stop 为空对象

系统 SHALL 以 `text` 块合成 Anthropic 阻断，五件套顺序 SHALL 锁定为 `message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`。`message_start` SHALL 为阻断序列首帧且恰一，携带空 `content` 数组、null `stop_reason` 与全 0 usage；`id` SHALL 取会话标识（会话标识缺失时回退 `blocked-0`），`model` SHALL 为 `unknown_model`。`message_stop` SHALL 为空对象。新增首帧 SHALL NOT 改变既有四帧的内容与顺序。

#### Scenario: 文本期望方不误触发 tool 链

- **WHEN** 阻断帧进入下游
- **THEN** 首块 `type=="text"` 且无 `tool_use` 形态，`message_stop` 数据不含自造字段

#### Scenario: 阻断流首帧为 message_start

- **WHEN** Anthropic 流被审计阻断
- **THEN** 下游首个数据帧为 `message_start`（空 `content`、null `stop_reason`、usage 全 0），且恰一

#### Scenario: 五件套顺序稳定

- **WHEN** 顺序检查阻断序列
- **THEN** 依次为 `message_start`、`content_block_start`、`content_block_stop`、`message_delta`、`message_stop`，无缺失或重排
