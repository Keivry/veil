# redaction-audit-coverage Specification

## Purpose
锁定脱敏还原与流式审计覆盖契约：嵌套 stringified-JSON 工具参数的凭据还原保持内层 JSON 结构有效、跨缝掩码不破坏 JSON 结构符、掩码边缘规则与 README §7.10 一致、Responses 四类工具 delta 一律入审计且可阻断、Chat 审计到期与全局完成判定分离且晚到/截断未完成分片在终端收尾前仍被审计、Responses 审计字节不双计、Chat 审计按声明 `choices[].index` 分桶、截断时未完成 tool 调用落审计记录。

## Requirements

### Requirement: 嵌套 stringified-JSON 凭据还原正确性

系统 SHALL 对工具参数中嵌套的 stringified JSON（字符串值本身为 JSON 文档）执行 JSON-aware 凭据还原，还原写回 SHALL 与实际 JSON 深度匹配的转义层级；SHALL NOT 仅按外层单层转义导致内层出现非法裸 `"` 或结构破损。还原守卫 SHALL 校验内层结构有效性，内层破损时 SHALL 按既有 fail-closed 口径回退还原前占位符帧并记观测，SHALL NOT 静默透传破损帧。Python 对照语义为 `_token.py:698-738` 的 `_restore_json_aware` 递归 walk 字符串节点。

上述还原守卫 SHALL 同时覆盖流式与非流两条还原路径（RED-1 守卫延伸）：非流还原 SHALL NOT 仅做最外层 JSON 解析校验，SHALL 执行与流式一致的**内层 stringified-JSON 递归校验**；非流路径检出内层破损时 SHALL 同样按 fail-closed 回退还原前占位符并记观测，SHALL NOT 静默透传破损响应体。

还原所依赖的深度统计 SHALL 覆盖 JSON 对象键位（成员名）与字符串值两类位置：SHALL NOT 仅统计字符串值而漏算对象 key，否则键位凭据的深度被欠算、还原转义层级不匹配；键位与值位 SHALL 采用同一深度口径（与流式对照语义一致）。

#### Scenario: 两层嵌套 JSON 参数还原后内层有效

- **WHEN** 帧内工具参数为两层嵌套 stringified JSON 且内层字符串含凭据占位符与引号
- **THEN** 下游收到还原后明文，内层 JSON 仍可 `jloads` 解析、无非法裸 `"` 结构破损

#### Scenario: 内层破损 fail-closed 回退

- **WHEN** 还原后外层 JSON 合法但内层 stringified JSON 结构破损
- **THEN** 守卫检出内层无效并按 fail-closed 回退还原前占位符帧，记回退观测，不静默透传破损帧

#### Scenario: 非流内层破损 fail-closed 回退

- **WHEN** 非流对话响应体的外层 JSON 合法但内层 stringified JSON 结构破损
- **THEN** 非流还原守卫按与流式同口径检出内层无效，fail-closed 回退还原前占位符并记观测，不静默透传破损体

#### Scenario: 对象键位凭据深度正确

- **WHEN** 凭据占位符出现在嵌套 stringified JSON 的对象键位（成员名）
- **THEN** 深度统计计入对象 key，还原按该键位实际深度转义，内层 JSON 结构保持有效

### Requirement: 跨缝掩码 JSON 结构保真

系统 SHALL 保证跨缝掩码（`mask_span_bytes`）不掩码 JSON 结构符（`R7-09`），掩码豁免集 SHALL 覆盖 `{` `}` `"` `[` `]` 及 `,`/`:` 等结构字符（或改 JSON-aware 掩码达同效）；SHALL NOT 因跨缝掩码把结构符替换为 `*` 而导致帧 JSON 不可解析。README §7.9 SHALL 列出完整豁免集（`{` `}` `"` `[` `]` `,` `:`）或将其实质声明为有意保留的结构符超集，SHALL NOT 截断为 `{ } " [ ]` 而遗漏 `,`/`:`（实现指针为 `src/service/redaction/seam.rs::mask_span_bytes`；README 与实现 SHALL 同批修订，SHALL NOT 单侧漂移）。

#### Scenario: 跨缝命中覆盖结构符仍可解析

- **WHEN** 跨缝待掩码区间覆盖 `,`/`:` 等 JSON 结构符
- **THEN** 掩码后帧仍可 `serde_json` 解析，结构符原样保留、仅非结构位掩码

#### Scenario: 常规跨缝掩码语义不变

- **WHEN** 跨缝命中为纯数据区间（不含结构符）
- **THEN** 两侧残片按既有口径掩码，输出与既有跨缝掩码行为一致

#### Scenario: README §7.9 豁免集完整

- **WHEN** 核查 README §7.9 的逐字符豁免集与 `src/service/redaction/seam.rs` 的掩码豁免实现
- **THEN** 文档列出完整豁免集（`{ } " [ ] , :`）或声明为有意保留的结构符超集，零命中遗漏 `,`/`:` 的截断表述

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

系统 SHALL 按槽/调用维度对 Responses 审计持有字节去重，同一调用的 `.done` 参数 SHALL NOT 在 `total_bytes` 中重复计入；长流多工具 SHALL NOT 因重复计数提前触发溢出 fail-closed，真实超限 SHALL 仍拒绝并清仓。去重 SHALL 覆盖官方双投递形态（`R8-01`）：`response.function_call_arguments.done` 与 `response.output_item.done` 先后携带**同一完整参数**时，第二次 `.done` SHALL NOT 再次累加字节（记旧值 SHALL 取该槽 `held_bytes()`（分片与已存 `done_args` 之和），或对相同 `done_args` 幂等早退）；槽释放 SHALL 按同源口径恰好归还一次，使任意时刻「`total_bytes` == `args_by_index` 各值长度之和 + `responses_slots` 各 `held_bytes()` 之和」的守恒不变量成立（`pending_bytes` 为独立维度、不计入）。

#### Scenario: 双计场景 total_bytes 正确

- **WHEN** 同一 Responses 调用的分片与 `.done` 参数先后到达（`seq` 缺失场景）
- **THEN** `total_bytes` 只计该调用参数一次，不超过实际上限

#### Scenario: 重复 .done 不二次累加

- **WHEN** 官方流对同一调用先后投递 `response.function_call_arguments.done` 与 `response.output_item.done`（同一完整参数）
- **THEN** `total_bytes` 不重复累加，槽释放后字节归还恰一次，无残留

#### Scenario: 字节守恒

- **WHEN** 多工具长流中任意时刻检查 `total_bytes` 与「`args_by_index` 值长度之和 + `responses_slots` `held_bytes()` 之和」
- **THEN** 两者相等（饱和口径下不出现只增不归的泄漏）

#### Scenario: 真实超限仍 fail-closed

- **WHEN** 去重后单调用活跃分片累计仍超过 `AUDIT_HOLD_MAX_BYTES`
- **THEN** 审计拒绝并清仓，不透出参数

### Requirement: Chat 审计按声明 index 分桶

系统 SHALL 以 Chat `choices[].index` 声明值参与审计分桶（缺省回退枚举位置）；SHALL NOT 仅用位置序号导致乱序或跳号 `index` 时槽归属错位。分桶键 SHALL 采用位域公式 `(ci << 16) | (idx & 0xFFFF)`（`ci, idx < 2^16` 时单射无碰撞），SHALL NOT 使用历史 `ci*64+declared_index`（该式在 `idx >= 64` 时与下一 choice 的桶 0 碰撞）。`ci=0` 时位域公式与历史公式等值。

#### Scenario: 乱序/跳号 index 分桶正确

- **WHEN** Chat 响应 `choices[].index` 乱序或跳号（如 2、0、5）
- **THEN** 各 choice 的 tool 分片按声明 index 归入各自槽，审计对象与实际 choice 匹配

#### Scenario: 分桶无碰撞

- **WHEN** 两个不同 `(ci, idx)` 组合、其中 `idx >= 64`
- **THEN** 位域公式产出互异桶键，不映射到同一槽

#### Scenario: ci=0 等价锚点

- **WHEN** `ci=0` 且 `idx` 任意（`< 2^16`）
- **THEN** 位域公式结果与历史 `ci*64+idx` 等值，单 choice 快照不回归

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

### Requirement: Responses pending 工具槽终端最终审计（恰一次）

`R7-01`：系统 SHALL 在 Responses 流终端收尾（清除持仓）前，对仍缺 per-item `.done` 的 pending 工具槽（`responses_pending_triples()`，`!done_seen`）执行与 done 槽同 verdict 通道的最终审计评估，门控为 `protocol.is_responses()` 且持仓未置拒绝态；评估顺序 SHALL 为先 done 槽（`hold.tool_triples()` 的 Responses 部分）后 pending 槽。verdict 处置 SHALL 与 done 槽逐字一致：`Block` → 置拒绝态且 `blocked_index` 取**该 triple 自身 `output_index`**（与 done 槽同源）；`NeedApproval` → 建 pending 记录；`Allow` → 无动作。Chat/Anthropic 的 `args_by_index` 终端审计口径 SHALL NOT 改变。本 requirement 与既有「截断未完成 tool 落审计」条款分工互引：后者要求截断时对未完成 tool 产生不含明文的审计/告警记录，本 requirement 补齐 Responses pending 槽走**完整 verdict 通道**（可 `Block`/建单）与恰一次语义，二者 SHALL NOT 视为重复。

恰一次语义 SHALL 由两段协同保证：全局完成臂对 pending 槽审计且未 `Block` 后 SHALL 释放这些已判定槽（移除 `!done_seen` 槽并按其记账字节归还，饱和算术），使终端 pending 循环在**无截断的清理完成**流上自然为 no-op、同一槽 SHALL NOT 被二次审计；**中途截断**（未发全局完成）时 pending 槽保留至终端并恰被审计一次。释放 SHALL NOT 影响 done 槽与 `mark_rejected()`/`mark_completed()` 的既有清理语义。

#### Scenario: 清理完成不双审

- **WHEN** 危险 pending 槽经全局完成臂审计并释放后流正常收尾
- **THEN** 终端 pending 循环为 no-op，该槽恰审计一次（无重复阻断、无重复建单），阻断终端恰一

#### Scenario: 截断 pending 危险槽阻断

- **WHEN** 未发全局完成的截断流中 pending 槽携带危险参数且审计模式非 `Off`
- **THEN** 终端审计命中 `Block`，`blocked_index` 为该槽自身 `output_index`，危险明文不透出，阻断终端恰一

#### Scenario: 截断 pending 需审批建单一次

- **WHEN** 截断流中 pending 槽经终端审计命中 `NeedApproval`
- **THEN** 恰建一条 pending 记录，不重复建单

#### Scenario: 已拒绝不重复审计

- **WHEN** 持仓已置拒绝态
- **THEN** 终端 pending 循环不执行（门控未满足），既有拒绝清理语义不变

#### Scenario: Chat/Anthropic 终端审计不变

- **WHEN** 运行既有 Chat/Anthropic 终端最终审计回归
- **THEN** 口径与结果逐项不变，无新增/删除审计评估

### Requirement: 工具分桶单射与越界 index 归属

系统 SHALL 保证审计工具分桶对「同一事件内多外层块」与「越界索引」均为单射（`R8-05`/`R8-15`）：Anthropic `custom_tool_call`（及同型数组承载）的数组项 SHALL 以「块键 + 块内位置」复合桶键 `anthropic_item_bucket(block_bucket, item_index)` 编码（`block_bucket` 为既有 `anthropic_bucket_index(outer_index, block, fallback)` 已算出的块身份编码；`item_index == 0` 且块键在合法域（`< ANTHROPIC_BLOCK_MAX`）时退化为纯块键、与对象分支等价；合法域位域单射、越界（含块键 `>= ANTHROPIC_BLOCK_MAX`）经有界哈希溢出桶），SHALL NOT 使用裸数组下标致不同块或同块多项串扰。协议声明的 `index`/`output_index` 取值超出既有桶位域时，系统 SHALL 将其路由至保留带溢出桶或视为缺失（`None`），SHALL NOT 以 `u64 as u32` 静默截断后操作错误槽。

#### Scenario: Anthropic 数组项跨块不串扰

- **WHEN** 同一 Anthropic 事件的多个 `content_block` 各携带 `custom_tool_call` 数组项（`outer_index` 缺失，非流消息解析常态）
- **THEN** 各 (块键, 块内位置) 归入互异槽，审计参数不合并、不串扰

#### Scenario: 越界 index 不静默截断

- **WHEN** 上游 `index`/`output_index` ≥ 2^32
- **THEN** 系统不以截断值操作槽（路由至溢出桶或按缺失处理），不误清/误审其他槽

#### Scenario: 常规分桶不回归

- **WHEN** 既有 Chat/Anthropic/Responses 常规流（index 在带内）
- **THEN** 分桶键与既有行为等值，审计结果不回归
