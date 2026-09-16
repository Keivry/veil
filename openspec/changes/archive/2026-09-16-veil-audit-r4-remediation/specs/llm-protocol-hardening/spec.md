## MODIFIED Requirements

### Requirement: 工具桶流/非流一致

系统 SHALL 使 Responses `output[]` 的流式分片桶号与非流提取同键：取 `item.output_index`，缺失回退枚举下标。系统 SHALL 使流式 `extract_tool_fragments` 与非流 `extract_tool_calls` 对同一输入的字段值（id/name/args）与桶号一致，仅日志告警可因入口不同而有无。

系统 SHALL 使非流 Responses `output[]` 条目与流式 `response.output_item.done` 条目的工具判定**同结论**：非流 `output[]` 的 `is_tool` 判据 SHALL 包含 `responses_item_tool_name(item_type).is_some()`（不得仅凭 `item_type.contains("tool")`/`name`/`arguments`/`input`），使 `code_interpreter_call`（字段 `code`/`id`/`status`）与 `shell_call`（字段 `action`/`call_id`）等内置工具进入审计。

**内置条目的名与参派生机制（M-1，`veil-audit-r4-remediation`）**：仅放宽 `is_tool` **不足**——非流 `output[]` 既有分支经 `custom_obj_to_call`（`src/service/llm_gateway/tool.rs:176-198`）走 `custom_tool_parts`，而 `code_interpreter_call`/`shell_call` 无 `name`/`arguments`/`input` 字段，结果 `name=None` 且 args 空。故系统 SHALL 对非 function/non-custom 的内置条目经**派生名路径**建条目（与既有检索 early-return 同形，`src/service/llm_gateway/tool.rs:662-683`）：① 名 SHALL 由 `responses_item_tool_name(item_type)` 派生（如 `code_interpreter`/`shell`）；② 参 SHALL 按 item-done 路径同口径回退序列化（`src/service/llm_gateway/tool.rs:572-581`）：先取 `["arguments","code","command","input"]`，空则 `retrieval_args(obj)`（`src/service/llm_gateway/tool.rs:105-141`），再空则 `item.action` 整体 `serde_json::to_string`。function/custom tool 条目 SHALL 维持既有 `custom_obj_to_call` 路径。

`local_shell_call` 覆盖现状（精确口径，MINOR 1）：`contains("shell")` 仅存在于 `responses_item_tool_name`（`src/service/llm_gateway/tool.rs:222`），故**今日仅** `response.output_item.done` 路径（`src/service/llm_gateway/tool.rs:542-552`）覆盖之；非流 `output[]` 的 `is_tool`（`src/service/llm_gateway/tool.rs:650-656`）**在本要求落地前无 shell 分支**，随 A 落地才补齐；`responses_derived_tool_kind`（`src/service/llm_gateway/tool.rs:205-206`）仅匹配 delta 事件子串 `shell_call_command`（即 `shell_call_command` 型 delta 事件），**不匹配 item 类型** `local_shell_call`。`image_generation_call` SHALL 为非目标（无可执行参数 + 图像大 payload），本要求 SHALL NOT 要求其进入审计。

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

## ADDED Requirements

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

系统 SHALL 显式声明 Anthropic 扩展思考（extended thinking）的签名连续性限制：`thinking_delta` 文本被还原为明文，而 `signature`（opaque）不还原且系对**占位符文本**签名；请求级随机 token 使下一轮重脱敏字节不同，故跨轮次签名校验/思考连续性**不保证**成立。网关 **SHALL NOT** 校验上游签名，**SHALL NOT** 承诺无条件连续。条件性缓解的**必要条件**为 conversation 级稳定 token（同明文同 token），依赖后续 change `veil-pii-conversation-cache` 的 `openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md` requirement「Anthropic thinking 签名连续性（条件性收益与残余限制）」（该 requirement 明示会话级 token 稳定为**必要条件而非充分条件**，且 `MUST NOT` 声称签名连续性已实现或已验证）；在该依赖落地前，含 PII 的 thinking 文本连续性 SHALL NOT 被视为保证项。

#### Scenario: 限制被登记

- **WHEN** 核查 canonical `llm-protocol-hardening` spec
- **THEN** 明确记载思考签名连续性为已知限制、网关不校验签名、不承诺无条件连续，并**按 requirement 名**指向 `veil-pii-conversation-cache` 的「Anthropic thinking 签名连续性（条件性收益与残余限制）」为必要条件的后续依赖

#### Scenario: 不承诺签名校验

- **WHEN** 检查网关代码是否存在上游签名校验路径
- **THEN** 不存在该路径，spec 亦不承诺；opaque 帧按字节级还原透传（`is_anthropic_opaque_event`），维持 fail-closed
