# llm-protocol-hardening Specification

## Purpose
锁定 LLM 网关三协议（Chat / Anthropic / Responses）流式与非流式在修复后的线级行为契约：恒恰一终端、真空流最小终止、Responses `incomplete` 原样透传、非 JSON 错误体原样透传、SSE CRLF 跨块正确性、脱敏回退 fail-closed、工具桶流/非流一致。

## Requirements

### Requirement: Chat 终止帧补发

系统 SHALL 在 Chat 流出现非 null `finish_reason` 且流结束时仍未收到 `data: [DONE]` 的情况下，于流结束处补发恰一 `data: [DONE]`；零帧真空流同样 SHALL 补发恰一 `data: [DONE]`。系统 SHALL NOT 伪造 `finish_reason`、内容或 usage；`finish_reason` 之后到达的 usage 尾帧（`choices: []`）SHALL 照常透传，不得提前截断。上游已发 `[DONE]` 时 SHALL NOT 重复补发。

#### Scenario: finish_reason 后断流补 DONE

- **WHEN** 上游发出含非 null `finish_reason` 的分片后断流且从未发 `data: [DONE]`
- **THEN** 下游收到恰一 `data: [DONE]`，且此前内容帧与 usage 尾帧均已透传

#### Scenario: 真空流补 DONE

- **WHEN** Chat 上游返回 200 且流式体零帧
- **THEN** 下游收到恰一 `data: [DONE]`，无内容帧

#### Scenario: 自带 DONE 不重复

- **WHEN** 上游正常发送 `data: [DONE]` 收尾
- **THEN** 下游收到恰一 `data: [DONE]`，网关不再补充

### Requirement: Anthropic 真空流最小终止

系统 SHALL 在 Anthropic 真空流（零帧）时发出最小可解析终止序列 `message_start` + `message_stop`；`message_start` SHALL 携带空 `content` 数组与 null `stop_reason`，SHALL NOT 注入任何 `content_block_*` 事件、SHALL NOT 声称语义 stop_reason 或正 usage。系统 SHALL 将 `type:"error"` 事件视为终端：一旦透传 `error`，SHALL NOT 在其后注入 `message_stop` 或任何数据帧。

#### Scenario: 真空流最小终止

- **WHEN** Anthropic 上游返回 200 且流式体零帧
- **THEN** 下游收到 `message_start` 与 `message_stop` 各恰一，且无 `content_block_*` 事件

#### Scenario: error 即终端不补 stop

- **WHEN** 上游流中透传 `type:"error"` 事件
- **THEN** 下游不再收到任何帧（含 `message_stop`）

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

### Requirement: 非 JSON 错误体原样透传

系统 SHALL 对上游 `status>=400` 且响应体非 JSON 的响应原样透传状态码与正文字节；SHALL NOT 以合成 `502 E_EMPTY_BODY` 替换。`status<400` 的非 JSON 空体处理维持现状；502/401 的 JSON 完整后处理链维持不变。

#### Scenario: 429 文本错误体

- **WHEN** 上游返回 429 且 `content-type: text/plain` 非 JSON 体
- **THEN** 下游收到 429 与同字节正文

#### Scenario: 500 HTML 错误体

- **WHEN** 上游返回 500 且 HTML 非 JSON 体
- **THEN** 下游收到 500 与同字节正文，不被替换为 502

#### Scenario: 404 非 JSON 错误体

- **WHEN** 上游返回 404 且非 JSON 体
- **THEN** 下游收到 404 与同字节正文

### Requirement: SSE 跨块行解析正确

系统 SHALL 在 SSE 解析中把跨块的 `\r\n` 视为单一行终止：块末孤立 `\r` 的 CRLF 判定 SHALL 延后到下一块合并（下一块首字节为 `\n` 时按单一行终止消费，否则按孤立 `\r` 处理）。系统 SHALL 使 `event:` 与 `data:` 在同一块内归属同一事件，SHALL NOT 因 TCP 分片提前分发。无冒号的 `data` 行 SHALL 按空值 `data` 字段处理。

#### Scenario: CRLF 跨块不分裂

- **WHEN** 先推送 `event: x\r` 再推送 `\ndata: y\r\n\r\n`
- **THEN** 恰产生一个事件，`event_type=="x"` 且 `data=="y"`

#### Scenario: 块末 CR 后首字节非 LF

- **WHEN** 先推送 `data: z\r` 再推送非 `\n` 起始的下一块
- **THEN** 前一块按孤立 `\r` 终止解析，事件字段归属不变

#### Scenario: 无冒号 data 行

- **WHEN** 块内出现无冒号的 `data` 行
- **THEN** 该行按空值 data 字段参与合并（如 `data\ndata: x` 得 `\nx`）

### Requirement: 脱敏回退 fail-closed

系统 SHALL 在 `stream_options` 注入路径重解析脱敏文本失败时，回退转发已脱敏字节；SHALL NOT 回退转发未脱敏原文。`x-veil-normalized` 声明头 SHALL 仅在请求体成功重序列化时置位。

#### Scenario: 重解析失败不泄漏

- **WHEN** 脱敏文本无法重解析为 JSON 且原请求体可解析
- **THEN** 转发体含占位符、不含原文，且无 `x-veil-normalized` 头

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

泵内 SHALL 维护「已见上游序号上界」游标（`responses_seq_cursor: Option<u64>`）：仅当协议为 Responses 且帧为可解析 JSON 时更新，取既有游标与上游 `sequence_number` 的最大值；缺 `sequence_number` 的帧 SHALL NOT 更新游标，回退值 SHALL 被忽略，断序 SHALL NOT 升级为错误。合成注入（阻断 7 帧序列与截断单帧）的起始基准 SHALL 为 `cursor.map_or(0, |c| c.saturating_add(1))`，后续合成帧序号 SHALL 以饱和加法递增（`saturating_add`，`R8-04`）；上游 `sequence_number == u64::MAX` 时 SHALL NOT panic、SHALL NOT 回绕为非单调序列。真空流（零帧）游标为空、基准 `0`，既有 0..6 全序列 SHALL 保持不变；`type:"error"` 单帧 SHALL 沿用上游 error 自带 `sequence_number`，SHALL NOT 重新编号。

#### Scenario: 合成帧带序号

- **WHEN** 合成 Responses 帧（7 帧全序列或阻断序列）
- **THEN** 每帧含 `sequence_number` 且序列单调

#### Scenario: 不省略序号

- **WHEN** 以 SDK 或结构校验检查合成帧
- **THEN** 不存在缺失 `sequence_number` 的帧

#### Scenario: 阻断帧接续上游序号

- **WHEN** 审计阻断发生在已透传最大 `sequence_number=N` 之后
- **THEN** 合成序列起始序号为 N+1，全程单调、不倒退、不重复

#### Scenario: 真空流基准为 0

- **WHEN** Responses 上游返回 200 且零帧
- **THEN** 合成全序列 `sequence_number` 自 0 起（0..6），与既有口径一致

#### Scenario: 缺序号帧不推进游标

- **WHEN** 上游帧无 `sequence_number` 或其序号回退
- **THEN** 游标不更新（保持既有上界），后续合成基准不回退

#### Scenario: error 单帧沿用上游序号

- **WHEN** 上游 `type:"error"` 自带 `sequence_number=7`
- **THEN** 合成 `response.failed` 携带序号 7，不重新编号

#### Scenario: 极值序号饱和不溢出

- **WHEN** 上游 `sequence_number == u64::MAX` 后触发合成注入（阻断或截断）
- **THEN** 合成基准与后续序号按饱和加法处理，SHALL NOT panic、SHALL NOT 回绕为非单调序列

### Requirement: Responses 合成响应对象字段完整与 conformance 不掩盖

合成/阻断的 Responses `response` 对象 SHALL 含 SDK `get_final_response().output_text` 解析所需字段（如 `output`、`status` 等），使该调用返回而不抛 `TypeError`；conformance 校验 SHALL NOT 以 try/except 掩盖解析失败，SHALL 对必需字段做显式断言。

#### Scenario: output_text 解析不抛错

- **WHEN** SDK 对阻断/合成 Responses 流调用 `get_final_response().output_text`
- **THEN** 返回文本或空值，不抛 `TypeError`

#### Scenario: conformance 不掩盖

- **WHEN** conformance 校验合成响应对象
- **THEN** 以显式断言校验必需字段，不以 try/except 吞掉解析错误

### Requirement: Anthropic 真空流与中途断流分野

系统 SHALL 区分 Anthropic **真空流**与**中途断流**：真空流（零字节零残余）SHALL 走最小可解析终止（`message_start` + `message_stop`）；中途断流（已发内容帧后异常 EOF 或 `chunk()` 报错）SHALL 仅记 `truncated_mode=open_ended` 观测，SHALL NOT 合成 `message_stop` 或任何终端数据帧，SHALL NOT 伪造成功终止。

#### Scenario: 中途断流不补 stop

- **WHEN** Anthropic 上游已发送内容帧后异常 EOF
- **THEN** 下游不收到合成的 `message_stop`，`truncated_mode=open_ended` 被记录

#### Scenario: 真空流仍最小终止

- **WHEN** Anthropic 上游返回 200 且零帧
- **THEN** 下游收到 `message_start` 与 `message_stop` 各恰一，不因中途断流条款而放行开放结尾

### Requirement: Chat 错误载荷帧即终端

系统 SHALL 将带顶层 `error` 且无 `choices` 的 Chat 数据帧视为终止事件：命中即置终端已发，SHALL NOT 在流末补发 `data: [DONE]`；并以独立观测 `TruncatedMode::UpstreamError`（`upstream_error`）区别于中途截断的 `open_ended`。判据 SHALL 限定为「顶层 `error` 存在」与「`choices` 缺席」同时成立，SHALL NOT 误伤 `choice` 内含 `error` 字段或顶层 `error` 与 `choices` 共存的正常形态。

系统 SHALL 使 Anthropic `error` 终端同样记录 `upstream_error` 观测（该值对非 Responses 协议本就合法）：Anthropic 流中 `type:"error"` 作为终端透出且此前未发终端时，除既有终端语义外，`truncated_mode` SHALL 置 `upstream_error`，SHALL NOT 留空（`None`）使「上游错误即终端」的第四态在 Anthropic 面失明。

Responses `type:"error"` 合成 `response.failed` SHALL 走其自有路径并记录 `synthesized_failed`（`R7-03`）：终端计划（`plan_responses_error`）SHALL 携带 `truncated: Some(TruncatedMode::SynthesizedFailed)`；调用点 SHALL 解构该观测并在 `commit` 后**无条件**调用 `set_truncated`（与中途断流调用点同口径），SHALL NOT 以终端帧是否送达（`terminal_ok`）门控观测；`terminal_ok` 仍只决定 `commit` 的终端帧位与 `StreamMeta.terminal_injected`。`set_truncated` 自带的 Responses-only 守卫 SHALL 保持不变，调用点 SHALL NOT 重复协议门控。

#### Scenario: error 帧后不补 DONE

- **WHEN** Chat 流中出现带顶层 `error` 且无 `choices` 的数据帧
- **THEN** 系统置终端已发、不再注入 `data: [DONE]`，观测记为 `upstream_error`（非 `open_ended`）

#### Scenario: choice 内含 error 不误伤

- **WHEN** Chat 帧的 `choices[].error` 字段非空或顶层 `error` 与 `choices` 共存
- **THEN** 该帧不被判为终端，既有透传与收尾语义不变

#### Scenario: Anthropic error 终端记 upstream_error

- **WHEN** Anthropic 流透传 `type:"error"` 事件且此前未发终端
- **THEN** 该帧仍作为终端透出，且 `truncated_mode` 记为 `upstream_error`（非 `None`、非 `open_ended`）

#### Scenario: Responses error 终端记 synthesized_failed

- **WHEN** Responses 流透传 `type:"error"` 事件且此前未发终端
- **THEN** 合成恰一 `response.failed`，`truncated_mode` 记为 `synthesized_failed` 并落 metrics 分标签计数；下游早断（终端帧未送达）时观测仍落（不低于一次），`terminal_ok` 仅影响终端帧位

### Requirement: responses_failed_frame 手写信封保留声明

系统 SHALL 保留 `responses_failed_frame` 的手写信封构造：`responses_frame` **无条件**写入 `sequence_number`，而失败帧 SHALL 仅在上游 error 携带序号时写入 `sequence_number`；系统 SHALL NOT 为「序号不可得」情形新增字段，以维持 README §7.2 的 TRN-2 lossy 边界（可得时写入、缺失不填充）。本要求 SHALL NOT 被解读为要求信封去重；信封格式在 `frames.rs` 内至少 5 处重复，单点统一不构成收敛，SHALL NOT 在本批抽取（信封去重列为可选后续）。

#### Scenario: 序号不可得不新增字段

- **WHEN** 上游 error 未携带 `sequence_number` 而合成 `response.failed`
- **THEN** 合成帧不含 `sequence_number` 字段（不无条件写入），与 lossy 边界一致

#### Scenario: 序号可得时写入

- **WHEN** 上游 error 携带 `sequence_number`
- **THEN** 合成 `response.failed` 写入该序号

### Requirement: Responses 内置工具类型审计覆盖

系统 SHALL 对 Responses 内置工具的 item 类型与 delta 事件派生统一工具名：`responses_item_tool_name` 与 `responses_derived_tool_kind` SHALL 均含 computer 分支，以 `contains("computer")` 兼容 `computer_call`/`computer_call_output`/`computer_use_preview`，派生名 SHALL 为 `"computer"`，参数 SHALL 取 `action`（沿用 item-done/output[] 的 action 回退）。

**证据分级（MINOR 7，`veil-audit-r4-remediation`）**：全仓 `grep computer src/` 当前**零命中**，即无现行上游 computer 事件样本。故：`responses_item_tool_name(item_type)` 的 computer 分支覆盖流式 item-done 与非流 `output[]` 的 **item 类型**路径，为本要求**主路径**；`responses_derived_tool_kind(ev_type)` 的 computer 分支为**防御性（DEFENSIVE）覆盖**——上游若投递 computer 型 delta 事件则命中，但**无现行上游证据**，SHALL NOT 被当作已有证据的路径、SHALL NOT 因该分支无测试样本而判定要求失败。本要求仍 SHALL 以 `responses_item_tool_name` 的两路径（item-done + `output[]`）为行为验收主对象。

`local_shell_call` 覆盖现状（精确口径，MINOR 1）：今日仅 `response.output_item.done` 路径由 `responses_item_tool_name` 的 `contains("shell")`（`src/service/llm_gateway/tool.rs:222`）覆盖，非流 `output[]` 随主要求 A 落地后覆盖；`responses_derived_tool_kind` 仅匹配 `shell_call_command` delta 子串（`src/service/llm_gateway/tool.rs:205-206`）。`image_generation_call` SHALL 为非目标（无可执行参数 + 图像大 payload），本要求 SHALL NOT 要求其进入审计。

#### Scenario: computer_call item 两路径一致

- **WHEN** `computer_call`/`computer_use_preview` 经流式 item-done 或非流 `output[]`（item 类型路径）投递
- **THEN** 两路径均派生 `name="computer"` 且 args 来自 `action`，审计覆盖一致

#### Scenario: computer delta 分支为防御性覆盖

- **WHEN** 检查 `responses_derived_tool_kind` 的 computer 分支与上游证据
- **THEN** 该分支存在但标注为 DEFENSIVE（无现行上游 computer delta 样本）；不以其测试样本缺失判失败

#### Scenario: local_shell_call 覆盖现状精确声明

- **WHEN** `local_shell_call` 经 item-done 路径投递（今日即覆盖），或经非流 `output[]` 投递（A 落地后覆盖）
- **THEN** 由 `responses_item_tool_name` 的 `contains("shell")` 派生 `name="shell"`；spec 明确该覆盖的路径边界（item-done 今日覆盖、`output[]` 随 A 覆盖、delta 仅 `shell_call_command` 子串）

#### Scenario: image_generation_call 非目标

- **WHEN** `image_generation_call` 出现在 `output[]` 或流式事件中
- **THEN** 不要求其进入审计（非目标显式登记），不得因此产生漏审告警误判

### Requirement: Anthropic 扩展思考签名连续性限制声明

系统 SHALL 显式声明 Anthropic 扩展思考（extended thinking）的签名连续性限制：`thinking_delta` 文本被还原为明文，而 `signature`（opaque）不还原且系对**占位符文本**签名；请求级随机 token 使下一轮重脱敏字节不同，故跨轮次签名校验/思考连续性**不保证**成立。网关 **SHALL NOT** 校验上游签名，**SHALL NOT** 承诺无条件连续。条件性缓解的**必要条件**为 conversation 级稳定 token（同明文同 token），该能力已由 `veil-pii-conversation-cache`（2026-09-17 归档）交付，其 requirement「Anthropic thinking 签名连续性（条件性收益与残余限制）」现位于 canonical `openspec/specs/llm-gateway/spec.md`（该 requirement 明示会话级 token 稳定为**必要条件而非充分条件**，且 `MUST NOT` 声称签名连续性已实现或已验证）；即便启用会话级稳定 token，含 PII 的 thinking 文本连续性亦 SHALL NOT 被视为保证项。

#### Scenario: 限制被登记

- **WHEN** 核查 canonical `llm-protocol-hardening` spec
- **THEN** 明确记载思考签名连续性为已知限制、网关不校验签名、不承诺无条件连续，并**按 requirement 名**指向 `veil-pii-conversation-cache` 的「Anthropic thinking 签名连续性（条件性收益与残余限制）」为必要条件的后续依赖

#### Scenario: 不承诺签名校验

- **WHEN** 检查网关代码是否存在上游签名校验路径
- **THEN** 不存在该路径，spec 亦不承诺；opaque 帧按字节级还原透传（`is_anthropic_opaque_event`），维持 fail-closed
