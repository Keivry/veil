## MODIFIED Requirements

### Requirement: 空流三协议语义与差异声明

Chat / Anthropic / Responses 三协议真空流（零字节零残余）SHALL 均走最小可解析终止：Chat 补恰一 `data: [DONE]`；Anthropic 补最小 `message_start` + `message_stop`（空 `content`、null `stop_reason`、usage 全 0，不含 `content_block_*`）；Responses 保持恰一 `response.failed` 全序列。系统 SHALL NOT 保持 open-ended、SHALL NOT 零合成帧。`truncated_mode` 观测口径 SHALL 保留（Chat/Anthropic `open_ended`、Responses `synthesized_failed`），`open_ended` 仅余观测语义、不再代表「不发终止帧」。README §8.6 SHALL 声明与原仓 `_ensure_nonempty_stream` 的差异、风险与下游依赖。

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
