## MODIFIED Requirements

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
