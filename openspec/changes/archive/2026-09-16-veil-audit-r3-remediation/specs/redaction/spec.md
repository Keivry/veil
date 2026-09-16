## ADDED Requirements

### Requirement: 残余帧 JSON 转义还原

系统 SHALL 对残余帧（流末未被正常路径处理、但载荷为完整 JSON 的半帧）使用 JSON-aware 的按深度转义还原（`restore_response_with_spans_json`），与正常帧同一口径；SHALL NOT 使用逐字插入变体（`restore_response_with_spans`）。当还原明文含 `"`、`\` 或控制字符时，输出 SHALL 仍为合法 JSON。

#### Scenario: 明文含引号仍为合法 JSON

- **WHEN** 残余帧为完整 JSON 且还原出的明文含双引号或反斜杠
- **THEN** 明文按 JSON 深度转义写入，残余帧解析后仍为合法 JSON

#### Scenario: 控制字符不破坏结构

- **WHEN** 还原明文含换行等控制字符
- **THEN** 按深度转义输出，JSON 结构保持完整可解析

### Requirement: 未闭合 JSON 片段深度计

系统 SHALL 在已知工具参数载体帧下，对**未闭合**的 JSON 片段按「外层字符串 + 内层容器」计 `depth+1`。载体判据 SHALL 限定为：帧 `type == "response.function_call_arguments.delta"`；或 `type == "content_block_delta"` 且 `delta.type == "input_json_delta"`；或子树键名为 `partial_json` / `arguments`。完整可解析容器的既有分支优先级 SHALL 不变；载体以外的普通字符串（如 `delta.text`）SHALL NOT 应用加一，SHALL NOT 无差别加一。

若实现中载体判定被证实不可靠，系统 SHALL 降级为「声明该限制 + 锁定回归用例」；SHALL NOT 采用无差别加一（会使纯文本被过度转义）。

#### Scenario: 未闭合片段按内层深度转义

- **WHEN** 工具参数载体帧携带以 `{`/`[` 开头但整体不可解析的 JSON 片段，其中含凭据 token
- **THEN** 该 token 按 `depth+1` 转义写入，片段拼接进内层 JSON 后结构有效

#### Scenario: delta.text 不受影响

- **WHEN** 普通字符串字段（如 `delta.text`）含 token 而非 JSON 容器
- **THEN** SHALL NOT 应用加一，还原转义与既有口径一致

#### Scenario: 完整容器行为不变

- **WHEN** 载体帧携带完整可解析的 JSON 容器
- **THEN** 走既有完整容器分支，深度与转义结果不变
