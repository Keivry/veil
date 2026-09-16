## MODIFIED Requirements

### Requirement: FIX-2 三协议终止闭合

chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic 依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行。终止后到达的滞后分片 SHALL 被丢弃；重复终止标记 SHALL 去重，不得重复计费。

#### Scenario: AS-IS 修正前（终止未闭合）

- **WHEN** 上游流缺失终止标记且连接半开，或审计阻断注入后无统一收尾
- **THEN**（修正前）网关无限等待或收尾形态不定，下游 Hermes 把阻断流误判为截断而重试或挂起

#### Scenario: TO-BE 修正后（三协议闭合）

- **WHEN** 同样半开流超时或阻断注入
- **THEN**（修正后）chat 恒以 `data:[DONE]` 恰 1 个收尾，Anthropic 补五件套（`message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`），responses 阻断补 `response.completed`、截断补 `response.failed`，合成块带 `event:` 行，`stream_meta.terminal_injected=true`

#### Scenario: Anthropic 五件套终止

- **WHEN** Anthropic 流被阻断或正常结束
- **THEN** 网关依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta`（含 `stop_reason`）→ `message_stop`，首帧为 `message_start`（空 `content`、null `stop_reason`、usage 全 0），合成块带 `event:` 行
