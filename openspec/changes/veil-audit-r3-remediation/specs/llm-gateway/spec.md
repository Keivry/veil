## MODIFIED Requirements

### Requirement: 三协议终止闭合（引用 FIX-2）

本 Requirement 口径与 protocol-compliance-fix spec FIX-2 同字：chat 阻断/空流恒以 `data:[DONE]` 恰 1 个收尾；Anthropic 依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta` → `message_stop`；responses 阻断补 `response.completed`、截断补 `response.failed`；合成块必须带 `event:` 行。终止后到达的滞后分片 SHALL 被丢弃；重复终止标记 SHALL 去重，不得重复计费。

#### Scenario: chat 阻断补 DONE 恰 1 个

- **WHEN** chat 流被审计阻断或上游空流
- **THEN** 网关注入阻断块后恒以 `data:[DONE]` 恰 1 个收尾

#### Scenario: Anthropic 三件套终止

- **WHEN** 检查旧三件套口径
- **THEN** 该历史场景名仅用于 delta 场景对齐；口径已扩为五件套（见相邻场景「Anthropic 五件套终止」），原三帧内容与顺序不变

#### Scenario: Anthropic 五件套终止

- **WHEN** Anthropic 流被阻断或正常结束
- **THEN** 网关依五件套顺序补 `message_start` → `content_block_start` → `content_block_stop` → `message_delta`（含 `stop_reason`）→ `message_stop`，首帧为 `message_start`（空 `content`、null `stop_reason`、usage 全 0），合成块带 `event:` 行

#### Scenario: responses completed 与 failed 区分

- **WHEN** responses 流被阻断
- **THEN** 网关补 `response.completed`；截断场景补 `response.failed`，两者不得互换，合成块带 `event:` 行

### Requirement: 截断三态（唯一值）

流截断/终止状态 SHALL 仅为以下四态之一：`silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error`。其中 `synthesized_failed` 仅 responses 可用（协议适用范围口径不变）；`upstream_error` 用于「上游错误载荷帧即终端」的观测（带顶层 `error` 且无 `choices` 的帧）。网关 SHALL 在 `stream_meta.truncated_mode` 记录该值并落 metrics（截断计数按 mode 分标签）。四态之外的值 SHALL NOT 落该指标。本 spec 不得使用 `complete` / `truncated` / `aborted` 旧三态命名。

#### Scenario: silent_discard 静默丢弃

- **WHEN** 超限尾部命中静默丢弃策略
- **THEN** `stream_meta.truncated_mode=silent_discard` 并记 metrics

#### Scenario: open_ended 保持开放

- **WHEN** 流保持开放等待后续
- **THEN** `stream_meta.truncated_mode=open_ended` 并记 metrics

#### Scenario: synthesized_failed 仅 responses

- **WHEN** responses 流需合成失败终止
- **THEN** `stream_meta.truncated_mode=synthesized_failed` 并记 metrics；chat 与 Anthropic 不得取该值

#### Scenario: upstream_error 上游错误终端

- **WHEN** 带顶层 `error` 且无 `choices` 的 Chat 错误载荷帧被判定为终端
- **THEN** `stream_meta.truncated_mode=upstream_error` 并记 metrics，区别于 `open_ended`

#### Scenario: 四态白名单唯一

- **WHEN** 检查 `stream_meta.truncated_mode` 的合法取值集
- **THEN** 仅 `silent_discard` / `open_ended` / `synthesized_failed` / `upstream_error` 四态；四态之外的值 SHALL NOT 落该指标
