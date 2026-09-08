## Purpose

锁定网关 7 项 P0 合规修复的可验证行为：注入合并、阻断体形态、终止计数、组合路由、空格/大小写口径。

## ADDED Requirements

### Requirement: stream_options 键内合并注入

系统 SHALL 在协议为 Chat/Responses 且请求 `stream==true` 且 `stream_options.include_usage` 缺失时合并注入 `include_usage:true`，且 SHALL 保留用户自带其他键；Anthropic SHALL 永不注入。

#### Scenario: 用户自带 options 非空仍补 usage

- **WHEN** 请求为 Chat 流式且 `stream_options={"other":1}`
- **THEN** 转发体为 `{"other":1,"include_usage":true}` 且单测锁定

#### Scenario: Anthropic 永不注入

- **WHEN** 请求为 Anthropic 流式
- **THEN** 转发体无 `stream_options` 新增键

### Requirement: Anthropic 非流阻断体完整形态

系统 SHALL 对 Anthropic 非流阻断返回含 `id/type/role/content/stop_reason/usage/model` 的完整体，严格 SDK SHALL 可解析。

#### Scenario: 非流阻断可解析

- **WHEN** Anthropic 非流命中阻断
- **THEN** 响应含 `id/type/message/role/content[text]/stop_reason=end_turn/usage` 且状态码符合非流约定

### Requirement: Responses 阻断截断可读且终止恰一

系统 SHALL 在 Responses 阻断 `completed` 前输出 `output_text.delta` 明文，在截断 `failed` 前输出可读提示或文档声明空语义为有意；终止帧 SHALL 恰一（delta 帧不计入终止计数）。

#### Scenario: 阻断可见文本且恰一终止

- **WHEN** Responses 流命中阻断
- **THEN** 下游先见文本 delta 再见唯一 `response.completed`，无 `arguments` 泄漏

#### Scenario: 截断不伪造完成

- **WHEN** 流被截断
- **THEN** 下游见唯一 `response.failed`，无伪造 `completed`

### Requirement: 终止计数行级精确

系统 SHALL 以行级精确判定 `data: [DONE]`，`arguments` 内同串 SHALL 不计入终止。

#### Scenario: 工具参数内同串不误判

- **WHEN** 流中 `arguments` 含 `"data: [DONE]"` 字符串
- **THEN** 终止计数不变，流不提前闭合

### Requirement: stream加JSON 组合行为锁定

系统 SHALL 对 `stream:true + application/json` 组合按 design 选定路由（默认流泵）并文档化，加组合单测锁定。

#### Scenario: 组合路由可预期

- **WHEN** 请求 `stream:true` 且上游回 `application/json`
- **THEN** 系统按锁定路由处理且 conformance 通过

### Requirement: 空格大小写探测口径声明

系统 SHALL 以大小写不敏感 `tail`、严格 JSON `stream` 探测、`serde_json` 前导空白容忍为准，双空格 `data:` SHALL 可解析。

#### Scenario: 双空格 data 可解析

- **WHEN** 上游帧为 `data:  {"a":1}`
- **THEN** 解析成功且单测锁定

### Requirement: Chat 阻断帧形态与文案锁定

系统 SHALL 以 `message` 自闭合形态（非 `delta`）输出 Chat 流阻断帧并自带唯一 `data: [DONE]`，文案 SHALL 统一为中文 `BLOCK_MESSAGE` 或英文 `[blocked: reason]` 其一且单测锁定；下游 Hermes 展示 SHALL 与所选一致。

#### Scenario: 阻断自闭合且文案一致

- **WHEN** Chat 流命中阻断
- **THEN** 下游见 `message{role,content:所选文案}+finish:stop` 后紧跟唯一 `[DONE]`，无 `arguments` 泄漏

### Requirement: 占位名不触发二次调用

系统 SHALL 保证 Anthropic `blocked` 占位名不在任何 `allow` 名单且 `input:{}` 合法，下游 SHALL 不二次调用。

#### Scenario: 占位无害

- **WHEN** 流注入 `tool_use blocked` 占位
- **THEN** 下游不发起以 `blocked` 为名的工具调用
