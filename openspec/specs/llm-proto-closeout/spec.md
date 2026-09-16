# llm-proto-closeout Specification

## Purpose

收窄 Chat-only `stream_options` 注入（Responses 不再收到规范外字段），并为空流差异、Chat 无 `[DONE]`、错误事件统一与三项容忍口径提供测试锁定与文档声明。

## Requirements

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

Chat / Anthropic / Responses 三协议真空流（零字节零残余）SHALL 均走最小可解析终止：Chat 补恰一 `data: [DONE]`；Anthropic 补最小 `message_start` + `message_stop`（空 `content`、null `stop_reason`、usage 全 0，不含 `content_block_*`）；Responses 保持恰一 `response.failed` 全序列。系统 SHALL NOT 保持开放结尾、SHALL NOT 零合成帧。`truncated_mode` 观测口径 SHALL 保留（Chat/Anthropic `open_ended`、Responses `synthesized_failed`），`open_ended` 仅余观测语义、不再代表「不发终止帧」。README §8.6 SHALL 声明与原仓 `_ensure_nonempty_stream` 的差异、风险与下游依赖。

#### Scenario: Anthropic 真空流 open-ended

- **WHEN** 检查旧 open-ended 口径
- **THEN** 该历史场景名仅用于 delta 场景对齐；语义已废止——Anthropic 真空流不再保持开放结尾、不再零合成帧，改走最小终止（见相邻场景）

#### Scenario: Anthropic 真空流最小终止

- **WHEN** Anthropic 上游返回 200 且零字节
- **THEN** 下游收到 `message_start` 与 `message_stop` 各恰一（无 `content_block_*`），不再保持开放结尾、零合成帧；旧 open-ended 语义已废止

#### Scenario: Responses 真空流合成 failed

- **WHEN** Responses 上游返回 200 且零字节
- **THEN** 下游收恰一 `response.failed` 终端

#### Scenario: Chat 真空流补 DONE

- **WHEN** Chat 上游返回 200 且零字节
- **THEN** 下游收到恰一 `data: [DONE]`，无内容帧

#### Scenario: 差异声明与证据登记存在

- **WHEN** 查阅 README §8.6
- **THEN** 含差异说明、风险、Hermes stub 证据或「待人工确认」open item 标注

### Requirement: Chat 缺 [DONE] 可观测

Chat 流末的 `[DONE]` 补发与观测 SHALL 按以下口径：已出现非 null `finish_reason` 后**干净 EOF**（即使未收到 `[DONE]`）SHALL 仅补发恰一 `data: [DONE]`，且 `truncated_mode` SHALL NOT 记 `open_ended`；带顶层 `error` 且无 `choices` 的数据帧 SHALL 视为终端，SHALL NOT 补发 `[DONE]`，并记 `upstream_error`（区别于 `open_ended`）；无成功收尾信号的异常 EOF SHALL 补发恰一 `[DONE]` 并记 `open_ended`（含 warn 与指标）。系统 SHALL NOT 在 `finish_reason` 非 null 的正常收尾后记 `open_ended`。

#### Scenario: finish_reason 后 EOF 无 DONE

- **WHEN** 上游发 `finish_reason:"stop"` 后干净断流，从未发 `[DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，`truncated_mode` 不置 `open_ended`，不误记为截断

#### Scenario: 上游错误帧即终端

- **WHEN** Chat 流中出现带顶层 `error` 且无 `choices` 的数据帧
- **THEN** 该帧视为终端，不补发 `[DONE]`，观测记为 `upstream_error`

#### Scenario: 无收尾信号异常 EOF 记 open_ended

- **WHEN** Chat 流无成功收尾信号即异常 EOF
- **THEN** 补发恰一 `data: [DONE]` 并记 `open_ended`（含 warn 与指标）

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
