# llm-proto-closeout Specification

## Purpose

收窄 Chat-only `stream_options` 注入（Responses 不再收到规范外字段），并为空流差异、Chat 无 `[DONE]`、错误事件统一与三项容忍口径提供测试锁定与文档声明。

## ADDED Requirements

### Requirement: stream_options 注入仅限 Chat

系统 SHALL 仅对 `Protocol::Chat` 且 `stream:true` 的请求注入 `stream_options.include_usage`；Responses SHALL NOT 被注入，用户自带键 SHALL 原样保留（Chat 按 key 合并，Responses 不动）。

#### Scenario: Chat 注入与键内合并

- **WHEN** Chat 请求 `stream:true` 且 `stream_options={"include_usage":false}`
- **THEN** 转发体保留 `false` 不被覆写；缺 `include_usage` 时注入 `true`

#### Scenario: Responses 不注入且字节保留

- **WHEN** Responses 请求 `stream:true` 无 `stream_options`
- **THEN** 转发体不含 `stream_options`，字节与改写前一致

#### Scenario: Responses 用户自带 stream_options 原样保留

- **WHEN** Responses 请求自带 `stream_options`（任意内容）
- **THEN** 非脱敏路径下该键逐字节保留，不被合并或替换

### Requirement: 空流三协议语义与差异声明

Chat/Anthropic 真空流 SHALL 保持 open-ended（零合成帧、仅记 `OpenEnded`）；Responses 真空流 SHALL 合成 `response.failed` 终端；README §8.6 SHALL 声明与原仓 `_ensure_nonempty_stream` 的差异、风险与下游依赖。

#### Scenario: Anthropic 真空流 open-ended

- **WHEN** Anthropic 上游返回 200 且零字节
- **THEN** 下游收零帧、无 `message_stop` 合成，`truncated_mode=open_ended`

#### Scenario: Responses 真空流合成 failed

- **WHEN** Responses 上游返回 200 且零字节
- **THEN** 下游收恰一 `response.failed` 终端

#### Scenario: 差异声明与证据登记存在

- **WHEN** 查阅 README §8.6
- **THEN** 含差异说明、风险、Hermes stub 证据或「待人工确认」open item 标注

### Requirement: Chat 缺 [DONE] 可观测

Chat 流末若已见 `finish_reason` 非 null 但未收到 `[DONE]`，系统 SHALL 置 `truncated_mode=open_ended` 并记录 warn 与指标，SHALL NOT 合成 `[DONE]` 或终止帧。

#### Scenario: finish_reason 后 EOF 无 DONE

- **WHEN** 上游发 `finish_reason:"stop"` 后断流，从未发 `[DONE]`
- **THEN** 下游零合成帧，`truncated_mode=open_ended`，warn 与指标各一

### Requirement: Responses 错误事件统一为 failed（锁定）

Responses `error` 事件 SHALL 合成恰一 `response.failed` 终端，SHALL NOT 出现 `response.completed` 或重复终端。

#### Scenario: error 事件恰一 failed

- **WHEN** 流中收到 `type:"error"` 事件
- **THEN** 下游收恰一 `response.failed`，无 completed，无重复终端

### Requirement: sequence_number 断序容忍

Responses 流中 `sequence_number` 非连续 SHALL 原样透传、不 panic、不丢帧，终端 SHALL 恰一。

#### Scenario: 断序帧透传

- **WHEN** 连续两帧 `sequence_number` 跳号
- **THEN** 两帧均转发，终端恰一，无错误日志升级

### Requirement: 占位符凭据门控口径声明

凭据占位符说明注入门控 `\d{6,}`（窄于 vault 还原 `\d{4,}`）SHALL 由既有单测锁定，且 README SHALL 含口径句（有意保守，注入宜漏不宜误）。

#### Scenario: 门控锁定与文档同字

- **WHEN** 运行占位符相关单测并查阅 README
- **THEN** 4-5 位形态不触发说明注入的断言存在；README 含该口径句
