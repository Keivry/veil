## ADDED Requirements

### Requirement: Chat 阻断合成帧必需字段完整

系统 SHALL 在合成 Chat 阻断流帧时补齐 OpenAI 流式对象必需字段 `id`、`object`、`created`、`model`，使官方 SDK 可解析该帧；字段值 SHALL 取会话上下文或合规默认值，SHALL NOT 因缺字段导致 SDK 解析失败。

#### Scenario: 合成帧字段完整

- **WHEN** Chat 阻断路径合成流帧
- **THEN** 每帧含 `id`/`object`/`created`/`model`，SDK 可正常解析

#### Scenario: 默认值合规

- **WHEN** 会话上下文缺字段来源
- **THEN** 使用合规默认值补齐，帧仍可被 SDK 解析

### Requirement: Responses 合成帧序号完整

系统 SHALL 使 Responses 合成帧（含真空流全序列与阻断序列）携带必需的 `sequence_number`，且为单调序列；SHALL NOT 省略该字段。

#### Scenario: 合成帧带序号

- **WHEN** 合成 Responses 帧（7 帧全序列或阻断序列）
- **THEN** 每帧含 `sequence_number` 且序列单调

#### Scenario: 不省略序号

- **WHEN** 以 SDK 或结构校验检查合成帧
- **THEN** 不存在缺失 `sequence_number` 的帧

### Requirement: Responses 合成响应对象字段完整与 conformance 不掩盖

合成/阻断的 Responses `response` 对象 SHALL 含 SDK `get_final_response().output_text` 解析所需字段（如 `output`、`status` 等），使该调用返回而不抛 `TypeError`；conformance 校验 SHALL NOT 以 try/except 掩盖解析失败，SHALL 对必需字段做显式断言。

#### Scenario: output_text 解析不抛错

- **WHEN** SDK 对阻断/合成 Responses 流调用 `get_final_response().output_text`
- **THEN** 返回文本或空值，不抛 `TypeError`

#### Scenario: conformance 不掩盖

- **WHEN** conformance 校验合成响应对象
- **THEN** 以显式断言校验必需字段，不以 try/except 吞掉解析错误
