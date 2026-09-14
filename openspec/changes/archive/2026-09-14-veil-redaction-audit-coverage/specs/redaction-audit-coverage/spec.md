## Purpose

锁定脱敏还原与流式审计覆盖契约：嵌套 stringified-JSON 工具参数的凭据还原保持内层 JSON 结构有效、跨缝掩码不破坏 JSON 结构符、掩码边缘规则与 README §7.10 一致、Responses 四类工具 delta 一律入审计且可阻断、Chat 审计到期与全局完成判定分离且晚到/截断未完成分片在终端收尾前仍被审计、Responses 审计字节不双计、Chat 审计按声明 `choices[].index` 分桶、截断时未完成 tool 调用落审计记录。

## ADDED Requirements

### Requirement: 嵌套 stringified-JSON 凭据还原正确性

系统 SHALL 对工具参数中嵌套的 stringified JSON（字符串值本身为 JSON 文档）执行 JSON-aware 凭据还原，还原写回 SHALL 与实际 JSON 深度匹配的转义层级；SHALL NOT 仅按外层单层转义导致内层出现非法裸 `"` 或结构破损。还原守卫 SHALL 校验内层结构有效性，内层破损时 SHALL 按既有 fail-closed 口径回退还原前占位符帧并记观测，SHALL NOT 静默透传破损帧。Python 对照语义为 `_token.py:698-738` 的 `_restore_json_aware` 递归 walk 字符串节点。

#### Scenario: 两层嵌套 JSON 参数还原后内层有效

- **WHEN** 帧内工具参数为两层嵌套 stringified JSON 且内层字符串含凭据占位符与引号
- **THEN** 下游收到还原后明文，内层 JSON 仍可 `jloads` 解析、无非法裸 `"` 结构破损

#### Scenario: 内层破损 fail-closed 回退

- **WHEN** 还原后外层 JSON 合法但内层 stringified JSON 结构破损
- **THEN** 守卫检出内层无效并按 fail-closed 回退还原前占位符帧，记回退观测，不静默透传破损帧

### Requirement: 跨缝掩码 JSON 结构保真

系统 SHALL 保证跨缝掩码（`mask_span_bytes`）不掩码 JSON 结构符，掩码豁免集 SHALL 覆盖 `{` `}` `"` `[` `]` 及 `,`/`:` 等结构字符（或改 JSON-aware 掩码达同效）；SHALL NOT 因跨缝掩码把结构符替换为 `*` 而导致帧 JSON 不可解析。

#### Scenario: 跨缝命中覆盖结构符仍可解析

- **WHEN** 跨缝待掩码区间覆盖 `,`/`:` 等 JSON 结构符
- **THEN** 掩码后帧仍可 `serde_json` 解析，结构符原样保留、仅非结构位掩码

#### Scenario: 常规跨缝掩码语义不变

- **WHEN** 跨缝命中为纯数据区间（不含结构符）
- **THEN** 两侧残片按既有口径掩码，输出与既有跨缝掩码行为一致

### Requirement: 掩码边缘规则与 README §7.10 一致

`mask_pii_value` 的数值/email 边缘分支 SHALL 与 README §7.10 声明及 Python 对照语义一致：6–7 字符及 ≥8 字符非 4 段 IPv4 形、无点 email、kind 别名（`bankcard`/`apikey`/`id_card` 等）行为 SHALL 被 README §7.10 准确登记；如实现与文档不一致，SHALL 经 design 决策选择「对齐实现规则」或「修正 README 声明」并同批落地，SHALL NOT 保留未登记的静默差异。

#### Scenario: §7.10 边缘样例行为一致

- **WHEN** 以 README §7.10 列举的边缘样例（6 字符与 7 字符非 4 段 IPv4、无点 email、别名 kind）调用掩码
- **THEN** 输出与 README §7.10 登记行为逐字一致，或 README 已按 design 决策修正为实际行为

#### Scenario: 别名超集可预期

- **WHEN** 以别名 kind（如 `bankcard`/`apikey`）与非别名主名调用掩码
- **THEN** 别名与主名行为一致，且该别名集在 README §7.10 完整登记

### Requirement: Responses 四类工具 delta 审计覆盖

系统 SHALL 为 `response.code_interpreter_call_code.delta`、`response.shell_call_command.delta`、`response.mcp_call_arguments.delta`、`response.custom_tool_call_input.delta` 建槽、累积分片并纳入审计判定；SHALL NOT 将其归为次要事件跳过审计或使其不可阻断。命中危险参数时 SHALL 走既有审计 verdict 通道，`block` 模式 SHALL 注入阻断终端且危险参数 SHALL NOT 透传。Python 对照语义为 `_llm.py:783-791` 将四者映射到 `function_call_arguments` 审计路径。

#### Scenario: 四类 delta 危险参数被审计/阻断

- **WHEN** 上述四类 delta 之一携带危险参数（如 shell 命令）且审计模式非 `off`
- **THEN** 该调用进入审计判定，`block` 模式下下游收到阻断终端且危险参数不透传

#### Scenario: 四类 delta 良性参数不误阻断

- **WHEN** 四类 delta 携带良性参数且审计模式为 `block`
- **THEN** 流正常透传，不注入阻断终端

### Requirement: Chat `tool_calls` 审计到期/全局完成分离与终端最终审计

系统 SHALL 将 Chat「审计到期」与「全局完成」判定分离：`finish_reason:"tool_calls"`（含顶层、`choices[].finish_reason`、`delta.finish_reason`、`message.finish_reason`）SHALL 仍触发对该轮 `hold.tool_triples()` 的审计评估与 `block` 阻断，SHALL NOT 因移除其全局完成语义而跳过审计或阻断；`tool_calls` SHALL NOT 置全局完成，使晚到 tool 分片继续累积入槽并受审计。系统 SHALL 在终端收尾（清除持仓）前对 `hold.tool_triples()` 执行恰一次幂等的最终审计评估，使截断/未完成或晚到分片仍被审计且 `block` 模式阻断，SHALL NOT 重复评估已判定参数。正常 Chat 流（无晚到分片）的透传与终端行为 SHALL 不变。

#### Scenario: 晚到危险分片仍被审计并阻断

- **WHEN** 上游在 `finish_reason:"tool_calls"` 之后继续发送携带危险参数的 tool 分片
- **THEN** 晚到分片仍被累积并审计，`block` 模式下危险参数被阻断、不透传

#### Scenario: tool_calls 仍触发审计到期

- **WHEN** Chat 该轮工具调用的参数在 `finish_reason:"tool_calls"` 帧到达时已可判定
- **THEN** 该帧触发审计评估，危险参数在 `block` 模式被阻断、不透传，良性参数照常重放透传

#### Scenario: 终端最终审计幂等

- **WHEN** 流截断或未发 `[DONE]` 收尾、持仓中仍有未判定的 tool 参数
- **THEN** 终端收尾前对其执行一次最终审计评估，`block` 模式阻断且不透出参数，已判定参数不重复评估

#### Scenario: 正常流语义不变

- **WHEN** 上游按正常序列在 `finish_reason:"tool_calls"` 后结束（无晚到分片）
- **THEN** 完成判定与终端行为与既有口径一致，无重复审计或重复终端

### Requirement: Responses 审计字节去重

系统 SHALL 按槽/调用维度对 Responses 审计持有字节去重，同一调用的 `.done` 参数 SHALL NOT 在 `total_bytes` 中重复计入；长流多工具 SHALL NOT 因重复计数提前触发溢出 fail-closed，真实超限 SHALL 仍拒绝并清仓。

#### Scenario: 双计场景 total_bytes 正确

- **WHEN** 同一 Responses 调用的分片与 `.done` 参数先后到达（`seq` 缺失场景）
- **THEN** `total_bytes` 只计该调用参数一次，不超过实际上限

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 去重后单调用活跃分片累计仍超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 审计拒绝并清仓，不透出参数

### Requirement: Chat 审计按声明 index 分桶

系统 SHALL 以 Chat `choices[].index` 声明值参与审计分桶（缺省回退枚举位置）；SHALL NOT 仅用位置序号导致乱序或跳号 `index` 时槽归属错位。分桶键 SHALL 保持既有 `chat_bucket` 语义（`ci*64+declared_index`）。

#### Scenario: 乱序/跳号 index 分桶正确

- **WHEN** Chat 响应 `choices[].index` 乱序或跳号（如 2、0、5）
- **THEN** 各 choice 的 tool 分片按声明 index 归入各自槽，审计对象与实际 choice 匹配

#### Scenario: 单 choice 快照不变

- **WHEN** 单 choice（`index=0`）常规流
- **THEN** 分桶键与既有行为等值，审计结果不回归

### Requirement: 截断未完成 tool 落审计

系统 SHALL 在流截断收尾时为未完成 tool 分片产生审计记录/告警，SHALL NOT 仅静默清空持仓；审计记录 SHALL NOT 泄漏参数明文（沿用既有脱敏口径）。截断场景 SHALL 可观测「存在未完成 tool 调用」。

#### Scenario: 截断场景审计记录存在

- **WHEN** 流在上游发完部分 tool 分片后截断（`chunk()` 报错或异常 EOF）
- **THEN** 产生未完成 tool 调用的审计/告警记录，记录不含参数明文，可观测截断丢弃

#### Scenario: 正常完成不产生截断审计

- **WHEN** tool 调用在流内正常完成且流正常结束
- **THEN** 不产生截断型审计告警，完成路径审计与既有口径一致
