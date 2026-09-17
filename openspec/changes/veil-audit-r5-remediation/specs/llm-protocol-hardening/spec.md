# Spec Delta

## MODIFIED Requirements

### Requirement: Responses 恒恰一终端

系统 SHALL 保证 Responses 流下游恰一终端帧，终端集合为 `response.completed` / `response.failed` / `response.incomplete`。已发出任一终端后到达的 `error`/`incomplete`/数据帧 SHALL 被忽略。`response.incomplete` SHALL 原样透传（保留 `incomplete_details`）并作为唯一终端，SHALL NOT 转换为 `response.failed`。`type:"error"` SHALL 合成为单帧 `response.failed`（携带上游 error message），SHALL NOT 注入含 `output_index` 的合成序列；含 `output_index` 的 7 帧全序列 SHALL 仅用于零帧真空流。

上游 `data: [DONE]` SHALL 仅对 Chat 被识别为终止标记：Chat 命中且此前未发终端时置终端已发并透出恰一 `[DONE]`，重复 `[DONE]` SHALL 被终端守卫丢弃；非 Chat 协议（Responses/Anthropic）收到上游 `data: [DONE]` SHALL 视为**非事件**（不置终端位、不向下游透出），交由既有中途断流/真空流合成路径产出协议正确的恰一终端，SHALL NOT 令 Responses 下游收到零个 `response.*` 终端、SHALL NOT 令 Anthropic 下游收到协议外事件。合规上游在官方终端之后附带的 `[DONE]` 因终端守卫被丢弃，不受本条款影响。

#### Scenario: completed 后 error 忽略

- **WHEN** 上游先发 `response.completed` 再发 `type:"error"`
- **THEN** 下游恰一终端（`response.completed`），无 `response.failed`

#### Scenario: incomplete 原样透传

- **WHEN** 上游发出 `response.incomplete` 且带 `incomplete_details`
- **THEN** 下游原字节收到该帧，其后无数据帧，无合成 `response.failed`

#### Scenario: error 单帧 failed

- **WHEN** 上游流中发出 `type:"error"` 且此前未发终端
- **THEN** 下游收到恰一 `response.failed` 单帧，无 `output_index` 合成序列，无重复序号

#### Scenario: 真空流全序列恰一终端

- **WHEN** Responses 上游返回 200 且流式体零帧
- **THEN** 下游收到 7 帧全序列且终端恰一（`response.failed`）

#### Scenario: 非 Chat 的 DONE 不短路终端

- **WHEN** Responses 上游发送 `data: [DONE]` 而未发官方 `response.*` 终端（或 Anthropic 上游发送 `data: [DONE]`）
- **THEN** 该帧被视为非事件：不置终端、不向下游透出；Responses 由既有合成路径产出恰一协议正确终端，Anthropic 不收到协议外事件

#### Scenario: Chat 的 DONE 仍为终端并去重

- **WHEN** Chat 上游发送 `data: [DONE]` 且此前未发终端，或在其后重复发送 `[DONE]`
- **THEN** 下游恰一 `data: [DONE]`，重复者被终端守卫丢弃

### Requirement: Chat 错误载荷帧即终端

系统 SHALL 将带顶层 `error` 且无 `choices` 的 Chat 数据帧视为终止事件：命中即置终端已发，SHALL NOT 在流末补发 `data: [DONE]`；并以独立观测 `TruncatedMode::UpstreamError`（`upstream_error`）区别于中途截断的 `open_ended`。判据 SHALL 限定为「顶层 `error` 存在」与「`choices` 缺席」同时成立，SHALL NOT 误伤 `choice` 内含 `error` 字段或顶层 `error` 与 `choices` 共存的正常形态。

系统 SHALL 使 Anthropic `error` 终端同样记录 `upstream_error` 观测（该值对非 Responses 协议本就合法）：Anthropic 流中 `type:"error"` 作为终端透出且此前未发终端时，除既有终端语义外，`truncated_mode` SHALL 置 `upstream_error`，SHALL NOT 留空（`None`）使「上游错误即终端」的第四态在 Anthropic 面失明。Responses `error` 合成 `response.failed` 走其自有路径（记 `synthesized_failed`），不受本条款影响。

#### Scenario: error 帧后不补 DONE

- **WHEN** Chat 流中出现带顶层 `error` 且无 `choices` 的数据帧
- **THEN** 系统置终端已发、不再注入 `data: [DONE]`，观测记为 `upstream_error`（非 `open_ended`）

#### Scenario: choice 内含 error 不误伤

- **WHEN** Chat 帧的 `choices[].error` 字段非空或顶层 `error` 与 `choices` 共存
- **THEN** 该帧不被判为终端，既有透传与收尾语义不变

#### Scenario: Anthropic error 终端记 upstream_error

- **WHEN** Anthropic 流透传 `type:"error"` 事件且此前未发终端
- **THEN** 该帧仍作为终端透出，且 `truncated_mode` 记为 `upstream_error`（非 `None`、非 `open_ended`）

### Requirement: 工具桶流/非流一致

系统 SHALL 使 Responses `output[]` 的流式分片桶号与非流提取同键：取 `item.output_index`，缺失回退枚举下标。系统 SHALL 使流式 `extract_tool_fragments` 与非流 `extract_tool_calls` 对同一输入的字段值（id/name/args）与桶号一致，仅日志告警可因入口不同而有无。

系统 SHALL 使非流 Responses `output[]` 条目与流式 `response.output_item.done` 条目的工具判定**同结论**：非流 `output[]` 的 `is_tool` 判据 SHALL 包含 `responses_item_tool_name(item_type).is_some()`（不得仅凭 `item_type.contains("tool")`/`name`/`arguments`/`input`），使 `code_interpreter_call`（字段 `code`/`id`/`status`）与 `shell_call`（字段 `action`/`call_id`）等内置工具进入审计。

**内置条目的名与参派生机制（M-1，`veil-audit-r4-remediation`）**：仅放宽 `is_tool` **不足**——非流 `output[]` 既有分支经 `custom_obj_to_call`（`src/service/llm_gateway/tool.rs::custom_obj_to_call`）走 `custom_tool_parts`，而 `code_interpreter_call`/`shell_call` 无 `name`/`arguments`/`input` 字段，结果 `name=None` 且 args 空。故系统 SHALL 对非 function/non-custom 的内置条目经**派生名路径**建条目（与既有检索 early-return 同形，`src/service/llm_gateway/tool.rs::extract_tool_calls_with` 的 Responses `output[]` 臂）：① 名 SHALL 由 `responses_item_tool_name(item_type)` 派生（如 `code_interpreter`/`shell`），符号锚点 `src/service/llm_gateway/tool_responses.rs::responses_item_tool_name`；② 参 SHALL 按 item-done 路径同口径回退序列化，符号锚点 `src/service/llm_gateway/tool_responses.rs::derived_item_tool_call`：先取 `["arguments","code","command","input"]`，空则 `retrieval_args(obj)`（`src/service/llm_gateway/tool.rs::retrieval_args`），再空则 `item.action` 整体 `serde_json::to_string`。function/custom tool 条目 SHALL 维持既有 `custom_obj_to_call` 路径。

`local_shell_call` 覆盖现状（精确口径，MINOR 1）：`contains("shell")` 仅存在于 `responses_item_tool_name`（`src/service/llm_gateway/tool_responses.rs::responses_item_tool_name`），故**今日仅** `response.output_item.done` 路径（`src/service/llm_gateway/tool.rs::extract_tool_calls_with` 的 item-done 臂）覆盖之；非流 `output[]` 的 `is_tool`（`src/service/llm_gateway/tool.rs::extract_tool_calls_with` 的 `output[]` 臂）**在本要求落地前无 shell 分支**，随 A 落地才补齐；`responses_derived_tool_kind`（`src/service/llm_gateway/tool_responses.rs::responses_derived_tool_kind`）仅匹配 delta 事件子串 `shell_call_command`（即 `shell_call_command` 型 delta 事件），**不匹配 item 类型** `local_shell_call`。`image_generation_call` SHALL 为非目标（无可执行参数 + 图像大 payload），本要求 SHALL NOT 要求其进入审计。

本要求对 `src/service/llm_gateway/tool_responses.rs` 等文件的引用 SHALL 采用符号锚点（`文件::符号`）：`scripts/check_doc_paths.py` 仅校验**路径存在性**与**行号在界**，**不校验符号是否存在**，故符号锚点与实现的一致性 SHALL 由 code review 保证，行号锚点 SHALL NOT 作为符号存在性的证据（D14）。

**桶号索引越界与碰撞（R5-16）**：桶号提取 SHALL NOT 以 `as u32` 静默截断客户端/上游可控的索引（`choices[].index`、`tool_calls[].index`、Responses `output_index`/`index`、Anthropic 外层/内层 `index`）；越界值 SHALL 映射进**有界哈希溢出桶**——按原始索引派生 `hash(idx) % K`（`K` 为有界常量并计入桶容量与审计槽记账）并记一次告警，SHALL NOT 与其他合法索引碰撞、SHALL NOT panic；**单一固定溢出桶被显式拒绝**（其把全部越界值重新撞入同一槽，与本要求的不碰撞目标相悖）。Chat 桶键位域打包 SHALL NOT 使不同 `(choice, index)` 落在同一桶键（如 `index` 为 `0` 与 `65536` 在 16 位掩码下碰撞）。Chat 旧式 `function_call` 在同一 choice 内多条目时 SHALL 桶号无碰撞（按条目枚举下标或有界派生，与 `custom_tool_call` 同口径），SHALL NOT 多条目恒用固定桶 `0` 致审计槽互相覆盖；`function_call` 的边界枚举（多条目）SHALL 以**条目枚举下标**为派生输入。

**合法域收紧登记（D8）**：`src/service/llm_gateway/tool/bucket.rs::chat_bucket_raw` 的 choice 合法上界由 `ci < 2^16` 收紧为 `ci < 0xFF00`——合法桶域为 `(ci << 16) | idx` 且须 `< 0xFF00_0000`，与溢出桶保留带 `0xFF00_0000..0xFF00_00FF`（`K = 256`）不相交；越界 `ci` 与越界 `idx` 一并有界哈希溢出桶并记告警，使更紧的上界成为文档化契约而非隐式实现细节。

#### Scenario: output_index 存在同键

- **WHEN** Responses `output[]` 条目带 `output_index: 3`
- **THEN** 流式与非流提取桶号均为 3

#### Scenario: output_index 缺失回退下标

- **WHEN** `output[]` 条目缺失 `output_index`
- **THEN** 两路径均回退枚举下标，结论一致

#### Scenario: 缺参缺 id 结论一致

- **WHEN** tool 调用缺 `arguments`/`id`
- **THEN** 流式与非流 args 归一与合成 id 结果一致（非流可 warn，流式静默）

#### Scenario: 非流 output[] 内置工具不遗漏

- **WHEN** 非流 `/v1/responses` 响应体的 `output[]` 含 `code_interpreter_call`（字段 `code`）或 `shell_call`（字段 `action.command`）
- **THEN** 两者均被判为 tool 并经派生名路径产出**非空派生名**（`code_interpreter`/`shell`）与**非空 args**（args 来自 `code` / `action` 序列化，非空串），不再被 `continue` 跳过、不再因 `name=None` 而空名

#### Scenario: 流/非流同输入同结论

- **WHEN** 同一工具条目分别以 `response.output_item.done`（流式）与非流 `output[]` 形态投递
- **THEN** 两路径的 `(name, args, bucket)` 逐一致

#### Scenario: 桶号越界不静默截断

- **WHEN** 客户端/上游投递超出桶号位域或 u32 范围的索引
- **THEN** 该值映射进有界哈希溢出桶（`hash(idx) % K`，`K` 有界并计入容量）并记告警，不与合法索引碰撞、不 panic

#### Scenario: 越界索引哈希溢出桶不重撞

- **WHEN** 两个不同的越界索引（如 `u32::MAX` 与 `65536`）同时投递
- **THEN** 两者按 `hash(idx) % K` 落入各自溢出桶而非同一固定桶、审计槽互不覆盖，且 `K` 有界并计入桶容量

#### Scenario: 旧式 function_call 多条目桶无碰撞

- **WHEN** 同一 choice 内含多条 legacy `function_call` 条目
- **THEN** 各条目落在互不相同的桶，审计槽不互相覆盖
