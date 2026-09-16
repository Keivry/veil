# Design — veil-audit-r4-remediation

> 本设计承载第四轮独立七维只读审查（r4）的逐发现修复决策。审查基线为已归档变更 `veil-audit-r3-remediation`（r3 归档 commit `25a9f7d`）。所有「现状证据」均为只读核验后的 `file:line` 锚点（apply 期为现行真相源；归档 r3 锚点见 §D-J）。
>
> **裁断来源**：本 change 的结论来自 **Oracle 首轮 9 项裁断（F1–F9）** 与 **本轮 Q1–Q9 决策**的汇总（见 §2），以及 **Momus 独立复审**新增的 **N（B-1）** 与 M-1…M-5 / MINOR 1–9 修订单。经 Oracle 证伪或降级的项在 §3 显式登记，**不得静默省略**。

---

## 1. Goals

1. 消除审计不对称绕过：非流 Responses `output[]` 与流式 `output_item.done` 对内置工具（`code_interpreter_call`/`shell_call` 等）同结论（A）。
2. 闭合 `computer_call` 全路径缺口（B），显式声明 `image_generation_call` 非目标。
3. 消除 `count_tokens` 秘密明文上行（C），`batches` 显式例外。
4. 消除残余帧无守卫回退（D）与 CR 载荷出口/解析不对称（E）。
5. 使 `PENDING_EVENTS` 溢出 **fail-safe**（宁缺信封不错标）（M）。
6. 收敛死代码/冗余与过度声明注释（F/G/I/K），补齐文档正面档（J）。
7. 补齐四态截断指标白名单端到端覆盖（N），消除 canonical 四态 ↔ 代码三态的活矛盾。
8. 全部变更在 `gate.sh` 七步下可验证，不引入新 FAIL；**本 change 为 artifacts-only，apply 期落码**。

## 2. Oracle 裁断来源（首轮 F1–F9 裁断 + 本轮 Q1–Q9 决策 + Momus 复审）

### 2.1 首轮 F1–F9 裁断（并入本轮 Q 决策）

| 项 | 裁断 | 处置 |
|---|---|---|
| **F1** | 跨块 `event:` FIFO 严格配对为**有意保真偏离**，严重度**降级 P3**；仅其溢出语义存在错标风险 | 由 **Q4/M** 收敛（溢出清空整队），不重开 FIFO 配对（`src/service/sse/parser.rs:330-378` 语义不变） |
| F2 | 已并入 Q 决策（见覆盖表），无独立残留 | — |
| **F3** | **FALSE POSITIVE**：非流路径「未查 `inner_json`」不成立 | `src/service/redaction/restore_guard.rs:20-26` 在 `placeholder_parsed=None` 时**内部解析**占位符并执行 `inner_json_intact`；见 §3 |
| F4 | 已并入 Q 决策，无独立残留 | — |
| **F5** | **FALSE POSITIVE**：opaque（base64）密文不可能被 token 扫描命中并还原篡改 | **主依据**为 minted-set 请求级授权（`src/service/redaction/scope.rs:177`：`token.starts_with(TOKEN_PREFIX) && !self.minted.contains(token)` 时不还原、原样返回）；base64 字母表论证为**辅助形态预过滤**（见 §3） |
| **F6** | assistant 文本不进审计为**既定非目标**（审计对象为 tool 调用与危险命令，非对话正文） | 登记于 Non-goals，不修改 |
| F7 | 已并入 Q 决策，无独立残留 | — |
| F8 | 已并入 Q 决策，无独立残留 | — |
| F9 | 已并入 Q 决策，无独立残留 | — |

> 说明：F2/F4/F7/F8/F9 的裁断要点已并入对应 Q 决策与覆盖表条目，不另列；未在审查中提出独立新结论者，本 change 不做无谓变更。

### 2.2 本轮 Q1–Q9 决策

| Q | 发现 | 决策（Oracle） | 落点 |
|---|---|---|---|
| **Q1** | A：非流 `output[]` 漏审内置工具 | `is_tool` 增补 `responses_item_tool_name(item_type).is_some()`；内置条目经派生名路径建条目，参按 item-done 同口径回退（M-1 精确化） | §A |
| **Q2** | B：`computer_call` 未覆盖 | 覆盖 computer（`contains("computer")`，参数取 `action`）；`responses_derived_tool_kind` 分支为 DEFENSIVE；`local_shell_call` 覆盖现状精确声明；`image_generation_call` 非目标 | §B |
| **Q3** | C：`count_tokens` 秘密上行 | `count_tokens` 收窄为 redact-only 对话变体；`batches` 显式例外；观测计数**登记现状、不新增端点维度**（M-2） | §C |
| **Q4** | M：`PENDING_EVENTS` 溢出错标 | 溢出**清空整队** + 计数 + 每流首次 warn（fail-safe） | §M |
| **Q5** | D：残余帧缺守卫回退 | 抽 `emit_restored_json_frame`（恒守卫 + 失败回退），残余/正常帧共用；落点避开 `event_loop.rs`（B-2） | §D |
| **Q6** | E：`data_frame` CR 不对称 | `data_frame` 按行终止集合拆分；含裸 CR 载荷声明 **LF 归一**（B-3），修正注释 + 回归测试 | §E |
| **Q7** | H：Anthropic 思考签名连续性 | **仅登记已知限制**；条件性缓解按 requirement 名依赖 `veil-pii-conversation-cache`；不承诺网关校验签名 | §H |
| **Q8** | I：`x-veil-protocol` 字面量 + leaf helper 对 | 补 `PROTOCOL_HEADER_NAME` 常量并替换（重开 r3 内联保留条款）；leaf helper 以 `bool` 参合并 | §I |
| **Q9** | J/K：文档缺口与架构收敛边界 | 补 README `E_EMPTY_BODY` 正面档 + §4 措辞**可选**对齐（M-4）+ 归档锚点口径；`StreamTerminator` 重构延后 | §J/§K |

### 2.3 Momus 复审新增（B-1/B-2/B-3、M-1…M-5、MINOR 1–9）

| 项 | 要点 | 落点 |
|---|---|---|
| **B-1/N** | 四态截断白名单仅三态（≥6 处），canonical 已锁四态 → 活矛盾 | §N |
| **B-2** | `tool.rs` 788 行、`event_loop.rs` 753 行，A/B/D 增补会越 800 上限 | §A/§B/§D/§9 |
| **B-3** | E 的「逐字节一致（含 `\r\n`）」不可达（解析侧 LF 连接已锁） | §E |
| M-1 | A 的机制不完整（仅放宽 `is_tool` 不能产出非空名/参） | §A |
| M-2 | C 的「按端点观测计数」不可实现（单原子计数） | §C |
| M-3 | 3.3 复用既有测试名作新语义证据 | §C/§N（新命名测试） |
| M-4 | J 的 §4 措辞「纠错」前提无效（README 未称 `error.code`） | §J |
| M-5 | F/G 验收为 grep 字符串守护 | §F/§G |
| MINOR 1 | `local_shell_call` 覆盖声明不精确 | §B |
| MINOR 2 | `custom.rs:399-400` 锚点偏移（`Arc::clone` 在 `:401`） | §J |
| MINOR 3 | 计数口径不一致（proposal P3×9 vs design 8） | §8 |
| MINOR 4 | 旧场景名与新 THEN 矛盾 | §9 |
| MINOR 5 | F5 依据应绑定 B3（minted 授权为主、字母表为辅） | §3 |
| MINOR 6 | `tool/tests.rs:61-108` 实为 `:61-101` | §A |
| MINOR 7 | B 的 delta 分支无上游证据 → 标记 DEFENSIVE | §B |
| MINOR 8 | conformance 23/24 不影响 gate 第 6 步（仅退出码） | §5 |
| MINOR 9 | H 应按 requirement 名引用依赖 | §H |

---

## 3. 证伪与纠偏记录（避免误导，必读）

| 声称 | 裁决 | 依据锚点 |
|---|---|---|
| **F3** 非流路径未查 `inner_json` | **FALSE POSITIVE** | `src/service/redaction/restore_guard.rs:20-26`：`placeholder_parsed=None` 分支内部 `serde_json::from_str(placeholder)` 后执行 `inner_json_intact`；`src/handler/llm/nonstream.rs:272` 的 `restore_guard_ok(..., None)` 因此仍覆盖内层完整性检查。 |
| **F5** opaque 密文可被还原篡改 | **FALSE POSITIVE** | **主依据**：响应侧凭据还原为 minted-set 请求级授权（`src/service/redaction/scope.rs:177`）——非本请求脱敏产出者不还原、原样返回；调用方自带 token 字面量不可能借进程单例历史映射还原。**辅助依据**（形态预过滤，非充分保证）：token 形态由 `__VG_CRED_`/`__PII_` 前缀 + `_` 分隔构成（`src/service/redaction/leaf.rs:253-256`），base64 字母表不含 `_`，故密文扫描形态上亦难命中。字母表检查仅为**形态预过滤**，安全保证以 minted 授权为准。 |
| **F1** 跨块 event FIFO | **降级 P3** | `src/service/sse/parser.rs:330-378` 的跨块配对是 canonical `gateway-transport-fidelity` 锁定的**有意保真偏离**；仅溢出语义按 Q4 收敛。 |
| **F6** assistant 文本不审计 | **既定非目标** | 审计对象为 tool 调用/危险命令（`src/service/llm_gateway/tool.rs` 单一提取核心），非对话正文；不修改。 |
| 「流式错误体无界」 | **疑误** | `src/handler/llm/dispatch.rs:369-372` 的 `Body::from_stream(up.bytes_stream())` 为**惰性**流式转发，不整块缓冲，**非**内存无界；与非流有界读的区别为**有意策略差异**（见 §L）。 |
| **I** `data: [DONE]\n\n` 生产直写 | **澄清** | `src/service/block_inject.rs:35,48-49,152-153` 全在 `#[cfg(test)] mod tests`（:21 起）；生产调用点已统一 `chat_done_frame()`（`src/service/block_inject/frames.rs:303`；`src/handler/llm/pump/spawn/event_loop.rs:742`、`src/handler/llm/pump/synth_flush.rs:93`）。按 canonical `deadcode-positional-cleanup`「测试内断言文本 SHALL NOT 纳入抽取」登记。 |
| **E** 「出口/解析逐字节互逆（含 `\r\n`）」 | **不可达，已纠正** | 解析侧多 `data:` 行以单 `\n` 连接（`src/service/sse/parser.rs:327`）为 canonical 锁定行为；裸 CR 载荷经出口拆分后必归一为 LF。见 §E（B-3）。 |

---

## 4. 逐发现设计决策

### A（P2）· 非流 `/v1/responses` `output[]` 内置工具漏审

**现状证据**：
- 流式 item-done 覆盖：`src/service/llm_gateway/tool.rs:542-552`（`is_tool` 含 `responses_item_tool_name(type_str)`），`:572-581` 补 `retrieval_args → item.action` 参数回退。
- delta 覆盖：`src/service/llm_gateway/tool.rs:202-214`（`responses_derived_tool_kind`）。
- 非流 `output[]`：`src/service/llm_gateway/tool.rs:647-659` 的 `is_tool` **漏** `responses_item_tool_name(item_type).is_some()`；`code_interpreter_call`（字段 `code`）、`shell_call`（字段 `action.command`）不被 `item_type.contains("tool")`/`name`/`arguments`/`input` 命中 → `continue` 跳过。
- **机制缺口（M-1）**：即便放宽 `is_tool`，`output[]` 既有分支经 `custom_obj_to_call`（`src/service/llm_gateway/tool.rs:176-198`）走 `custom_tool_parts`；`code_interpreter_call`（`code`/`id`/`status`）与 `shell_call`（`action`/`call_id`）无 `name`/`arguments`/`input`，结果 `name=None` 且 args 空 → 仅放宽判定**不能**满足「name 派生且 args 非空」。
- 测试盲区：`src/service/llm_gateway/tool/tests.rs:61-101` 的 `item_done_type_coverage` 仅覆盖 `response.output_item.done`。

**决策（Q1 + M-1）**：修代码。
1. 非流 `output[]` 的 `is_tool` 增补 `responses_item_tool_name(item_type).is_some()`（复用 `:219-231`，勿复制字面量）。
2. 非 function/non-custom 的内置条目 SHALL 经**派生名路径**建条目（与既有检索 early-return `:662-683` 同形）：
   - 名 = `responses_item_tool_name(item_type)`（如 `code_interpreter`/`shell`/`mcp`/`custom_tool`/`computer`）；
   - 参按 item-done 路径同口径回退（`src/service/llm_gateway/tool.rs:572-581`）：先 `["arguments","code","command","input"]`，空则 `retrieval_args(obj)`（`src/service/llm_gateway/tool.rs:105-141`），再空则 `item.action` 整体 `serde_json::to_string`；
   - function/custom tool 条目维持既有 `custom_obj_to_call` 路径。
3. 补测试：① 非流 `output[]` 全量体用例 `responses_output_builtin_tools_audited`（覆盖 function/custom/code_interpreter/shell/mcp/file_search/web_search/computer），**断言各内置条目派生名非空且 args 非空**（真实条目，如 `code_interpreter_call` 携带 `code`、`shell_call` 携带 `action`）；② 流/非流 parity 测试 `responses_output_stream_nonstream_parity`（同输入 `(name, args, bucket)` 逐一致）。

**备选与否决**：改用「统一走 `extract_tool_calls_with` 单核心」已是既有架构（`src/service/llm_gateway/tool.rs:236-702` 同核心），无需新架构；直接复用 `responses_item_tool_name` 而非复制 `contains("code_interpreter")` 字面量，避免双份漂移。仅「就地补 `action` 回退」否决——不能解决 `name=None`（M-1）。

**接口/数据结构**：无新公开类型；复用 `ToolCall`、`responses_item_tool_name`、`retrieval_args`。

**失败模式**：若 `output[]` 条目既非 tool 又无参，维持 `continue`（不虚增审计量）。

**验收口径（行为性）**：`cargo test -p veil responses_output_builtin_tools_audited` 与 `responses_output_stream_nonstream_parity` 通过；断言真实 `code_interpreter_call`/`shell_call` 条目产出**非空派生名 + 非空 args**；流/非流 parity。**不以 grep 字符串为验收**。

**锚点**：`src/service/llm_gateway/tool.rs:105-141,176-198,202-214,216-218,219-231,542-552,572-581,647-659,660-696`；测试 `src/service/llm_gateway/tool/tests.rs:61-101`。

---

### B（P2）· `computer_call`（computer use）全路径缺口

**现状证据**：全仓 `grep computer`（`src/`）**零命中** → `responses_item_tool_name`（`src/service/llm_gateway/tool.rs:219-231`）与 `responses_derived_tool_kind`（`:202-214`）均无 computer 分支。

**`local_shell_call` 覆盖现状（精确口径，MINOR 1）**：`contains("shell")` **仅**存在于 `responses_item_tool_name`（`src/service/llm_gateway/tool.rs:222`），故**今日仅** `response.output_item.done` 路径（`:542-552`）覆盖 `local_shell_call`；非流 `output[]` 的 `is_tool`（`:650-656`）**在 A 落地前无 shell 分支**；`responses_derived_tool_kind`（`:205-206`）仅匹配 delta 事件子串 `shell_call_command`（对应 `shell_call_command` 型 delta 事件），**不匹配 item 类型** `local_shell_call`。

**决策（Q2）**：修代码。在两函数中新增 computer 分支，用 `contains("computer")` 以兼容 `computer_call`/`computer_call_output`/`computer_use_preview`；参数取 `action`（沿用 A 的 action 回退）。**证据分级（MINOR 7）**：`responses_item_tool_name` 的 computer 分支覆盖流式 item-done 与非流 `output[]` 的 item 类型路径，为主路径；`responses_derived_tool_kind` 的 computer 分支为**防御性（DEFENSIVE）覆盖**（无现行上游 computer delta 样本），不以其测试样本缺失判失败。`image_generation_call` 显式**非目标**（无可执行参数 + 图像大 payload）。

**备选与否决**：逐类型枚举（`computer_call`/`computer_call_output`/`computer_use_preview`）否决——上游类型演进频繁，`contains("computer")` 与既有 `contains("shell")`/`contains("mcp")` 风格一致；误报面由「工具名派生」限定，不引入执行语义。「因无上游证据而完全不做 delta 分支」可接受，但为抵御上游演进保留为 DEFENSIVE 更稳。

**接口/数据结构**：无新类型。

**失败模式**：非 tool 的普通 item 不命中；`computer_call_output` 若仅为结果回执也可能命中（与 `shell_call_output` 现状一致，误报优于漏审）。

**验收口径**：`cargo test -p veil responses_computer_call_audited` 通过；流式 item-done 与非流 `output[]` 两路径均产出 `name=computer` 且 args 来自 `action`；delta 分支以 DEFENSIVE 登记（无上游样本）。

**锚点**：`src/service/llm_gateway/tool.rs:202-214,219-231,542-552,647-659`。

---

### C（P2）· Anthropic `count_tokens` 秘密明文上行

**现状证据**：`src/service/llm_gateway/protocol.rs:81-94` 将 Anthropic `count_tokens`/`batches` 列为官方子资源；`:112-114` 命中即 `None` → `Protocol::NonDialog`；`Protocol::NonDialog` 唯一字节透传（`:151-153`）→ 请求/响应零脱敏。`count_tokens` 携带与 `/v1/messages` 相同的 `messages`/`system`/`tools` 负载。

**决策（Q3 + M-2）**：修代码 + 修订 canonical。将 `count_tokens` 从「官方子资源排除 → NonDialog」改为 **redact-only 对话变体**：`Protocol` 判定沿用 `Anthropic` 分支的 **redact-only 模式位**（或等价的 `Protocol::Anthropic` + `redact_only` 标记），执行：
1. **执行**请求侧脱敏（`scope.redact_request`）+ 占位符说明注入门控（`should_inject_placeholders`）；
2. **跳过**审计判定、响应侧还原与新 PII 扫描、阻断合成、用量记账；
3. **保留** hop 过滤与有界读（受 `NONSTREAM_MAX_BYTES` 约束）。

`batches` **保持 `NonDialog` 字节透传**（显式例外：异步批处理元数据端点，响应为分页对象、不含对话机密；理由与后续 change 指向写入 spec）。

**观测计数（M-2 决策：登记现状、不新增维度）**：既有 `nondialog_passthrough` 为**无参单原子**（`src/service/llm_gateway/metrics.rs:98`；API 见 `:149-157`），本 change **SHALL NOT** 改为按端点的键控计数器、**SHALL NOT** 新增导出指标族。`count_tokens` 收窄为 redact-only 后**不计**该计数；`batches` 与其他 NonDialog 端点继续计 1。要求「新增按端点的 NonDialog 透传观测计数」**撤销**（不可实现且无必要）。

**备选与否决**：
- 「`count_tokens` 整体转完整对话处理」否决——会触发审计判定与用量记账，语义错位（该端点不产生对话用量）。
- 「仅文档声明泄漏」否决——秘密上行属实质风险，非纯声明缺口。
- 「改 `nondialog_passthrough` 为端点键控计数」否决（M-2）——须改无参原子为 `KeyedCounters` 并新增导出维度，收益低且与 Non-goals 冲突。

**接口/数据结构（单一形态锁定，取代原「二选一」表述）**：采用 **`Protocol::Anthropic` + `RequestCtx` 新增 `redact_only: bool`** 单一形态，**SHALL NOT 新增 `Protocol` 变体**——故 `src/service/llm_gateway/protocol.rs:48-53` 的 8 模块穷举检查清单无需扩列、`wire_name`（`:25-32`）语义不分叉。

- **判定**：`count_tokens` 由 `is_official_subresource`（`src/service/llm_gateway/protocol.rs:89-94`）从「排除 → `None` → `NonDialog`」收窄为「`Protocol::Anthropic` + redact-only」，`batches` 保持返回 `None`（仍 `NonDialog` 字节透传）；`resolve_protocol`（`:139-149`）签名与 `Copy` 返回值不变，`redact_only` 由等价 sibling 判定产出，在 `RequestCtx` 装配点（`src/handler/llm/dispatch.rs:217-232`）写入。
- **(a) 短路点（须显式跳过；因 `Protocol::Anthropic` 会令 `is_passthrough` 为 `false`，这些路径会被**自动启用**）**：
  1. **用量记账**：`src/service/metrics/store.rs:106`（`record_chat_extended` 的 `is_passthrough` 早返）与 `:250`（`record_aux_counts`）；调用点 `src/handler/llm/nonstream.rs:172`、`src/handler/llm/pump/spawn/finish.rs:56,65`。
  2. **审计判定**：`src/handler/llm/nonstream.rs:184-204`（逐 tool `evaluate_and_record`）与 `:215-223`（`evaluate_nonstream`）；流式门 `src/handler/llm/pump/spawn/event_loop.rs:379`（`env.protocol.is_dialog()`）。
  3. **响应侧还原与新 PII 扫描**：`src/handler/llm/nonstream.rs:260-268`（`restore_response_with_spans_json` + `redact_response_new_pii_with_skip`）；流式 `src/handler/llm/pump/spawn/event_loop.rs:616-704`。
  4. **阻断合成**：`src/handler/llm/nonstream.rs:224-242`（`blocked` → `block_body` + `x-veil-protocol`）；流式 `src/service/block_inject.rs` 与 `src/handler/llm/pump/spawn.rs` 合成臂。
- **(b) `is_passthrough` 语义不变**：仍为 `protocol.is_nondialog()`（`src/service/llm_gateway/protocol.rs:151-153`），`is_dialog()`（`:45`）对 `Anthropic` 仍为 `true`。**SHALL NOT** 将 redact-only 并入 `is_passthrough`/`is_dialog`（否则请求侧脱敏亦被跳过，与本项「执行请求侧脱敏」目标相悖）；仅以 `redact_only` 标志在四个短路点分流。
- **(c) wire 级副作用（delta 同批登记）**：① 下游 `x-veil-protocol` 值由 `passthrough`（`NonDialog`，`wire_name` `:30`）变为 `anthropic`（`Anthropic`，`:28`）——`count_tokens` 头值**变化**，须声明；② `x-veil-normalized: json-whitespace` **可能新出现**——redact-only 经请求侧 `scope.redact_request` 的 loads→walk→dumps 紧凑重序列化即置位 `normalized_out`（原透传路径不置位），须在 delta 显式声明；`request_rewrite` 置位口径见 `src/handler/llm/rewrite.rs`。

**失败模式**：redact-only 路径若误入审计/用量，将产生虚假 usage 桶；以「跳过记账」的显式分支 + 测试锁定。

**验收口径**：**新增**测试 `count_tokens_redact_only`（请求体 `messages` 内 PII 被占位符替换、响应字节不含还原、无 usage 记录）；**新增**测试 `nondialog_passthrough_batches_only`（`batches` 计 NonDialog 透传递增、`count_tokens` 不计）；spec delta 与 canonical 同字。**不得复用既有测试名 `nondialog_passthrough_counter_accumulates`（`src/service/llm_gateway/mod.rs:472`）作新语义证据（M-3）**。

**锚点**：`src/service/llm_gateway/protocol.rs:81-94,96-123,139-153`；观测 `src/service/llm_gateway/metrics.rs:98,149-157`；脱敏入口 `src/service/redaction/scope.rs`（请求侧）。

---

### D（P3）· 残余帧还原缺守卫回退

**现状证据**：`src/handler/llm/pump/spawn/terminal.rs:207-228`：`residual_frame_payload` 放行完整 JSON 后仅 `restore_response_with_spans_json`（`:214`）+ `redact_response_new_pii_with_skip`（`:215-217`）→ 直接 `feed_output_frame`（`:219-228`），**未** `guard_restored_frame_parsed`。正常帧在 `src/handler/llm/pump/spawn/event_loop.rs:626` 与 `:643-648` 有守卫，失败回退占位符帧。

**决策（Q5）**：修代码。抽单一 `emit_restored_json_frame(prefix_hold, boundary, detector, vault, boundary_spans, agg, restored, placeholder, parsed) -> ()`（或等价签名），内部：
1. `json_aware_line` 重序列化（如需）；
2. `guard_restored_frame_parsed`（含 metrics + warn）；
3. 守卫失败**回退占位符帧**（不落非法 JSON）；
4. 成功才 `feed_output_frame`。

残余帧（`src/handler/llm/pump/spawn/terminal.rs`）与正常帧（`src/handler/llm/pump/spawn/event_loop.rs:616-648` 两臂）共用该 helper。

**落点约束（B-2）**：`src/handler/llm/pump/spawn/event_loop.rs` 当前 **753 行**（近 800 上限），`emit_restored_json_frame` **SHALL NOT** 落在 `event_loop.rs`——置 sibling/新模块（如 `src/handler/llm/pump/spawn/` 内新文件）或 `src/handler/llm/pump/spawn/terminal.rs`（当前 **343 行**，余量充足）。

**备选与否决**：仅在残余帧就地补一次 `guard_restored_frame_parsed` 否决——三处逻辑仍重复，无法保证后续站点不回退。

**接口/数据结构**：新 helper 置于 handler 层（含 metrics/warn），保持 `service::redaction::restore_guard` 零 axum 依赖的边界（`src/service/redaction/restore_guard.rs:1-5`）。

**失败模式**：守卫误拒（明文合法但判失败）会回退占位符帧（fail-closed，不破帧）；与既有正常帧语义一致。

**验收口径**：`cargo test -p veil residual_frame_guard_fallback` 通过（构造还原后非法 JSON 的残余帧 → 输出回退占位符帧、记 metrics）；三处调用点共用同一 helper。

**锚点**：`src/handler/llm/pump/spawn/terminal.rs:207-228`；`src/handler/llm/pump/spawn/event_loop.rs:616-648,626,643-648`；`src/service/redaction/restore_guard.rs:20-26`。

---

### E（P3）· `data_frame` 拆分口径 vs 解析侧裸 `\r` 终止

**现状证据**：`src/service/sse/emit.rs:14-24` 的 `data_frame` 对 `data.split('\n')`；注释 `:9-13` 声称与解析侧「严格互逆」。解析侧 `src/service/sse/parser.rs:207-226` 把裸 `\r` 与 `\r\n` 与 `\n` 一律当行终止；同一事件多 `data:` 行以**单 `\n`** 连接（`src/service/sse/parser.rs:327`）。→ 载荷含裸 `\r` 时出口不拆，解析侧会误判为新行；且 CR 载荷**不可能**逐字节还原。

**决策（Q6 + B-3 可达化）**：修代码。
1. `data_frame` 同时按 `\r\n` 与 `\r` 拆分（**SHALL NOT** 把裸 CR 留在单条 `data:` 行内），使解析侧不把裸 CR 误切为新行；`parse(emit(x))` 对 `\n` 载荷逐字节互逆。
2. **显式声明 LF 归一**：解析侧单 `\n` 连接为 canonical 锁定行为，含裸 CR/CRLF 载荷经 `emit → parse` 后为**已声明 LF 归一**（如 `a\rb` → `a\nb`），**SHALL NOT** 声称逐字节一致、**SHALL NOT** 声称含 `\r\n` 字节恒等。
3. 修正 `src/service/sse/emit.rs:9-13` 的「严格互逆」为「与解析侧行终止集合（`\n`/`\r\n`/`\r`）相关，含裸 CR 载荷按已声明 LF 归一」。
4. 补回归测试 `sse_data_frame_cr_roundtrip`（含裸 CR/CRLF：断言出口不产生裸 CR 行、解析得已声明 LF 归一值、恰一事件、无 `event:` 名错配），并纳入既有往返测试 `src/service/sse/cr_tests.rs:73`（`sse_multiline_data_roundtrip`）。

**备选与否决**：只改注释、不改拆分否决——裸 CR 载荷仍会被消费者/解析器错切（行为缺陷）。「按 CR 拆为多条 `data:` 行并断言逐字节还原 `\r`」否决——解析侧单 `\n` 连接不可还原 `\r`，断言必假（B-3）。

**接口/数据结构**：`data_frame(prefix, data) -> String` 签名不变（`src/service/sse/emit.rs:14`）。

**失败模式**：把 CR 归一为 LF 会改变原始字节（对 data 载荷内的 CR）——已按上述声明吸收；回归用例锁定声明的 LF 归一，不锁逐字节恒等。

**验收口径**：`cargo test -p veil sse_data_frame_cr_roundtrip` 通过；含裸 CR/CRLF 的 data 载荷经 `emit → parse` 得**已声明 LF 归一**值且恰一事件、`event:`/`id:`/`retry:` 不错配；**不以「逐字节一致（含 `\r\n`）」为断言**。

**锚点**：`src/service/sse/emit.rs:9-24`；`src/service/sse/parser.rs:207-226,327`；测试 `src/service/sse/cr_tests.rs:73`。

---

### F（P3）· `meta.rs`/`aggregate.rs` 注释「三态」vs 实际四态

**现状证据**：`src/service/sse/meta.rs:3` 注释「`TruncatedMode` 三态」；实际 4 变体（`src/service/sse/meta.rs:10-17`：`SilentDiscard`/`OpenEnded`/`SynthesizedFailed`/`UpstreamError`）。**同一陈旧「三态」注释亦见 `src/service/metrics/aggregate.rs:30`（F 扩域，B-1 同批）**。

**决策**：改两处注释为「四态」并登记（r3 已将截断态扩为四态；canonical `llm-gateway`/`observability-admin` 截断白名单同批四态）。**验收为行为性（M-5）**：以 §N 的「四态白名单落点」测试为本项验收（断言截断态白名单含四态，且四态在 metrics/store/aggregate/admin 各有落点）；注释文本准确性仅为 **code-review 项**，SHALL NOT 以 grep 命中「四态」为验收。

**备选与否决**：无（纯注释 + 行为验收绑定 N）。

**失败模式**：无行为影响。

**验收口径**：§N 行为测试通过（四态齐备、各态落点独立）；两处注释在 code review 中确认与 `src/service/sse/meta.rs:10-17` 四变体一致。

**锚点**：`src/service/sse/meta.rs:3,10-17`；`src/service/metrics/aggregate.rs:30`。

---

### G（P3）· `tool.rs` 注释「同结论」过度声明

**现状证据**：`src/service/llm_gateway/tool.rs:216-218` 注释声称 item-done 路径与「非流路径同结论」，而当前非流路径（`:647-659`）未用该函数（见 A）。

**决策**：随 A 修正——A 落地后该注释成立（非流 `output[]` 同用 `responses_item_tool_name`）；若 A 未落地则注释须改为「与 delta 路径同名，非流路径经 output[] 分支等价判定」的准确表述。**验收口径（M-5）**：**唯一行为判据**为 A 的 parity 测试 `responses_output_stream_nonstream_parity`（同输入 `(name,args,bucket)` 逐一致）；注释变更保留为 **code-review 项**，SHALL NOT 以 grep 命中「同结论/等价」为验收。

**备选与否决**：无（注释与 A 同批）。

**失败模式**：无。

**验收口径**：`cargo test -p veil responses_output_stream_nonstream_parity` 通过；注释在 code review 中确认与实际一致。

**锚点**：`src/service/llm_gateway/tool.rs:216-218,647-659`。

---

### H（P3）· Anthropic 扩展思考连续性

**现状证据**：`src/handler/llm/pump/event.rs:299-314`（`is_anthropic_opaque_event`）与 `:320-334`（`is_anthropic_thinking_event`）；`src/handler/llm/pump/spawn/event_loop.rs:616-648`：thinking 明文走 `carry` + 还原 + 新 PII 扫描，opaque（signature）走字节级还原。`thinking_delta` 文本被还原为明文，而 `signature` 未还原（对占位符文本签名）；请求级随机 token 使下一轮重脱敏字节不同。

**决策（Q7 + MINOR 9）**：**不改代码，仅登记为已知限制**。文字写清：
- 网关**不校验**上游签名，**不承诺**思考连续性在跨轮次下无条件成立；
- 条件性缓解的**必要条件是 conversation 级稳定 token**（同明文同 token），依赖后续 change `veil-pii-conversation-cache` 的 `openspec/changes/veil-pii-conversation-cache/specs/llm-gateway/spec.md` requirement「**Anthropic thinking 签名连续性（条件性收益与残余限制）**」——**按 requirement 名引用**（而非仅 change 名），防跨 change 漂移；该 requirement 明示会话级 token 稳定为**必要条件而非充分条件**，且 `MUST NOT` 声称签名连续性已实现或已验证；
- 在该依赖落地前，签名连续性在含 PII 的 thinking 文本上**不保证**。

**备选与否决**：在本 change 引入 conversation 级稳定 token 否决——与请求隔离隐私硬要求冲突，且属独立大改（另立 change）。

**接口/数据结构**：无。

**失败模式**：无（仅声明）。

**验收口径**：spec/README 登记语句存在且**按 requirement 名引用依赖**；无行为测试要求。

**锚点**：`src/handler/llm/pump/event.rs:299-334`；`src/handler/llm/pump/spawn/event_loop.rs:616-648`。

---

### I（P3）· 死代码/冗余残留

**现状证据**：
1. `x-veil-protocol` 字面量：`src/handler/llm/dispatch.rs:366`、`src/handler/llm/nonstream.rs:239,509,554`、`src/handler/llm/mod.rs:61`；对照 `x-veil-normalized` 已常量化（`src/service/redaction/leaf.rs:23,25`）。
2. `data: [DONE]\n\n` 字面量：`src/service/block_inject.rs:35,48-49,152-153` 均在 `#[cfg(test)] mod tests`（:21 起）；生产已统一（`src/service/block_inject/frames.rs:303`；`src/handler/llm/pump/spawn/event_loop.rs:742`、`src/handler/llm/pump/synth_flush.rs:93`）。
3. leaf 近同形 helper 对：`src/service/redaction/leaf.rs:59`（`prescan_custom`）vs `:79`（`prescan_custom_response`）；`:132`（`redact_leaf_inner`）vs `:193`（`redact_leaf_response`）。
4. **B-2 文件体量**：`src/service/llm_gateway/tool.rs` 788 行、`src/handler/llm/pump/spawn/event_loop.rs` 753 行，A/B/D 增补会越 800 上限。

**决策（Q8 + B-2）**：修代码。
1. 新增 `pub(crate) const PROTOCOL_HEADER_NAME: &str = "x-veil-protocol"`（置于 `src/service/redaction/leaf.rs` 邻近常量区或协议头常量区，与 `NORMALIZED_HEADER_NAME`（`:23`）同址），替换上述 5 处字面量。
2. `data: [DONE]` 字面量：**不改生产源码**；在 spec 登记「测试内断言文本不纳入抽取」（canonical `deadcode-positional-cleanup` 既有声明）；可选将测试字面量改用 `chat_done_frame()`（非必需）。
3. leaf helper 以 `bool` 参合并：`prescan_custom(..., is_response: bool)` 与 `redact_leaf_inner(..., register_response: bool)`（或等价），调用点同步；**行为保持**（请求表 vs 响应表、凭据还原授权的 `minted` 追踪不变）。
4. **B-2 抽取**：把 Responses 工具类型派生面（`responses_item_tool_name`、`responses_derived_tool_kind` 与 Responses `output[]`/delta 工具收集 helper）迁至 sibling 模块（如 `src/service/llm_gateway/tool_responses.rs`<!-- doc-paths-ignore -->），使 A/B 增补后 `tool.rs` 与各触及文件均 ≤800 行；`emit_restored_json_frame` 落点避开 `event_loop.rs`（见 §D）。

**备选与否决**：
- 「`x-veil-protocol` 继续内联保留」否决——canonical `deadcode-positional-cleanup` 的「r2 归档勾选更正与保留范围声明」曾声明其内联保留，但与本轮「常量收敛」冲突；本 change **显式重开**并在 spec 同批修订。
- leaf helper 合并如引入 `bool` 参导致可读性下降，可退回「保持双函数 + 共享私有实现」（等价收敛），由 apply 期定夺。

**接口/数据结构**：新常量 `PROTOCOL_HEADER_NAME`；helper 签名扩展 `bool` 参（内部实现单一）；新 sibling 模块（内部可见）。

**失败模式**：合并若漏区分请求/响应表，会破坏 PII 双向语义 → 由既有 `scope_tests`/`custom/tests` 全量回归兜底；抽取若遗漏 re-export 会编译失败 → 以 `cargo check`/门禁捕获。

**验收口径**：`cargo test -p veil` 全绿；leaf 合并后 `prescan_*`/`redact_leaf_*` 行为等价用例通过；`python3 scripts/check_file_sizes.py` exit 0（`tool.rs` 与新增 sibling 文件 ≤800）。生产面 `"x-veil-protocol"` 字面量收敛为常量（常量定义与测试除外）。

**锚点**：`src/service/redaction/leaf.rs:23,25,59,79,132,193,253-256`；`src/handler/llm/dispatch.rs:366`；`src/handler/llm/nonstream.rs:239,509,554`；`src/handler/llm/mod.rs:61`；`src/service/block_inject.rs:21,35,48-49,152-153`；`src/service/block_inject/frames.rs:303`；`src/service/llm_gateway/tool.rs`（788 行）；`src/handler/llm/pump/spawn/event_loop.rs`（753 行）。

---

### J（P3）· 文档缺口与归档锚点口径

**现状证据**：
- `E_EMPTY_BODY`：代码 `src/error.rs:86-97`（`code()`，`:88` 为 `E_EMPTY_BODY`）与 `:110`（`EmptyBody → 502`）；触发于非流 200 空体/非 JSON（`src/handler/llm/nonstream.rs`；`src/handler/llm/dispatch.rs:150`）；README 仅 `README.md:669` 否定式提及。
- README §4 表行 `README.md:253` 称「`502` + `response_too_large` JSON 体」，**并未**声称字段名为 `error.code`；代码字段为 `error.type`（`src/handler/llm/nonstream.rs:566`）。
- 归档 r3 `tasks.md` 锚点漂移（MINOR 2）：4.4 称 `src/service/pii/custom.rs:395-396`（`PiiDetector::custom` 容器），实际容器在 `src/service/pii/detector.rs:498`；`src/service/pii/custom.rs:395-396` 现为 `scan_custom` 参数/返回类型，`src/service/pii/custom.rs:401` 为 `Arc::clone` 站点（**锚点修正**）。
- `scripts/check_doc_paths.py:67,71-72`：`openspec/changes/archive/**` 整体豁免行号在界断言；`scripts/README.md` 已同字声明（含 `PENDING_LINE_REFS`）。

**决策（Q9 + M-4 + MINOR 2）**：修文档 + 登记口径。
1. README 补 `E_EMPTY_BODY` 正面档（触发条件、状态码 502、错误体字段形态、与 `response_too_large` 的先后关系）。
2. `README.md:253` 的字段名对齐为 **可选（SHOULD）**：README 现有措辞**无错误**，故补 `error.type` 仅为可选的措辞对齐（对齐 `src/handler/llm/nonstream.rs:566`），**移除「纠正错误表述」框架**，未对齐不判失败。
3. **归档锚点不回改口径**：r3 归档 `tasks.md` 的 `file:line` 为归档时刻**冻结快照**，行号随源码演进必然漂移；按 canonical `docs-test-parity`「指向冻结归档语料的引用 SHALL NOT 被回改」与 `scripts/check_doc_paths.py` 的 `ARCHIVED_PREFIX` 豁免处理——本 change **不修改**归档目录；锚点漂移仅在本 design 登记。
4. `scripts/README.md` 与脚本口径一致（已声明归档豁免与 `PENDING_LINE_REFS`），**无需改动**。

**备选与否决**：把归档 r3 锚点改为现行真值否决——归档目录禁改（历史快照）。

**接口/数据结构**：无。

**失败模式**：README 正面档若与代码字段不符会二次误导 → 以 `src/handler/llm/nonstream.rs:566` 与 `src/error.rs:110` 为准，逐字对齐。

**验收口径**：`grep -n "E_EMPTY_BODY" README.md` 命中正面档；§4 行对齐为 `error.type`（可选，若对齐）；`python3 scripts/check_doc_paths.py` exit 0。

**锚点**：`README.md:253,669`；`src/error.rs:86-97,110`；`src/handler/llm/nonstream.rs:566`；`src/handler/llm/dispatch.rs:150`；`src/service/pii/detector.rs:498`；`src/service/pii/custom.rs:401`；`scripts/check_doc_paths.py:67,71-72`。

---

### K（架构）· 最小正确性收敛与延后声明

**现状证据**：D 的 `emit_restored_json_frame` 为唯一收敛点；阻断/终止帧注入去重散布于 `src/service/block_inject/terminal.rs` 与泵（`src/handler/llm/pump/spawn/event_loop.rs`、`src/handler/llm/pump/synth_flush.rs`）。

**决策（Q9）**：本 change **仅**做：① `emit_restored_json_frame` 统一（D）；② 协议往返不变量测试（CR 载荷 E、纯 event 洪泛 M、redact↔restore 组合、opaque 帧字节恒等）。**完整 `StreamTerminator` 收敛（阻断/终止帧注入去重）登记为后续独立 change**，非本 change 范围。

**备选与否决**：本 change 内一并重构 `StreamTerminator` 否决——收敛面大、触及三协议终止语义（高风险），须独立 change + 独立评审。

**接口/数据结构**：无新公开类型（仅内部 helper）。

**失败模式**：范围蔓延；以 Non-goals 显式约束。

**验收口径**：新增不变量测试全绿；design/Non-goals 明确登记延后项。

**锚点**：`src/handler/llm/pump/spawn/event_loop.rs:616-648`；`src/handler/llm/pump/synth_flush.rs:87-113`。

---

### N（P2，B-1）· 四态截断指标白名单收口（`llm-gateway`/`observability-admin`）

**现状证据**：r3 已把第 4 态 `TruncatedMode::UpstreamError`（`src/service/sse/meta.rs:16`）落地，记录入口为 `src/service/sse/meta.rs:47` 的 `m.record_truncated(mode.as_str())`，但**至少六处**仍用三态白名单：
- (a) `src/service/llm_gateway/metrics.rs:54-55` `TRUNCATED_MODE_KEYS: [&str; 3]` = `silent_discard`/`open_ended`/`synthesized_failed`，KeyedCounters 容量 `:68` 与初始化 `:92` 同步为 3 → `upstream_error` 落 `other` 桶 + 每进程一次伪 warn（`src/service/llm_gateway/metrics.rs:26-41`）。
- (b) `src/service/metrics/store.rs:109-116`：`truncated_mode=upstream_error` 不匹配 `TRUNCATED_MODES` → 记「truncated_mode 非法值不落指标」warn 并丢弃。
- (c) `src/service/metrics/aggregate.rs:30`（注释「唯一三态」）与 `:31`（`TRUNCATED_MODES: [&str; 3]`）；`WindowAgg` 截断列 `:175-177`；`snapshot()` match 臂 `:337-342`；`MetricsSnapshot` 字段 `:271-273`；`SeriesPoint` 字段 `:296-298`；SQL 列 `src/service/metrics/store.rs:310-312`（三表）；UPSERT `:431-465`；读取/回填 `src/service/metrics/aggregate.rs:412-470,473-523`（`query_series_blocking`/`backfill_rows_blocking` 实际在 `aggregate.rs`，**非** `store.rs`）。
- (d) `src/handler/admin.rs:129-133` 的 `truncated` 对象仅导出三标签。

canonical `openspec/specs/llm-gateway/spec.md:118-143`（requirement「截断三态（唯一值）」，正文四态）与 `openspec/specs/observability-admin/spec.md:127-146`（requirement「truncated_mode 三态落 metrics 分标签计数」，四态）**已要求四态分标签计数** → 与代码的**活矛盾**。

**决策（B-1）**：修代码 + 修订 canonical（同批 delta）。
1. `TRUNCATED_MODE_KEYS` 扩为 `[&str; 4]`（含 `upstream_error`），`GatewayMetrics::truncated` 的 `KeyedCounters` 容量同步 4；`upstream_error` 命中具名键，不落 `other`、不触发未知键 warn。
2. `TRUNCATED_MODES` 扩为 4 项；`record_chat_extended`（`src/service/metrics/store.rs:109-116`）对 `upstream_error` 走合法分支，不记 warn、不丢弃。
3. `WindowAgg` 增 `t_upstream_error` 独立列/槽；聚合落标签（`src/service/metrics/store.rs:168-173`）、快照 match、`MetricsSnapshot`/`SeriesPoint` 增 `upstream_error` 独立字段。
4. `handler/admin.rs` 的 `truncated` 对象增 `upstream_error`。
5. 扩展 F 任务（6.1）覆盖 `src/service/metrics/aggregate.rs:30` 陈旧注释。

**Schema / 迁移决策（必读）**：持久化第 4 态**需要新增列** `t_upstream_error`（无既有列可复用承载，且 `upstream_error` 与 `open_ended`/`silent_discard` 语义不同、不得借列）。**采用加列式（additive）方案**：
- 三张表 `metrics_daily`/`metrics_hourly`/`metrics_five_min` 的 `CREATE TABLE` 增 `t_upstream_error INTEGER NOT NULL DEFAULT 0`；
- 存量库兼容：在 `src/service/metrics/store.rs:350-365` 的**既有补列循环**中加入 `t_upstream_error`（`ALTER TABLE ... ADD COLUMN ... DEFAULT 0`，`let _ =` 吞已存在错误）——旧库启动即补列，旧行读回 0。
- **兼容影响**：新列为**只加不改**——不删/不重命名既有 `t_silent`/`t_open`/`t_synth` 列；旧读者（`/`_admin/metrics` 旧字段、旧 `/_admin/series` 消费方）读取既有列不受影响；新字段为增量序列化字段，旧大盘忽略即可。无破坏性迁移、无数据回填需要（`DEFAULT 0` 语义正确）。
- 若**不**采用加列，则需把 `upstream_error` 挤入 `open_ended` 列——**否决**（标签语义错误、违反 canonical「与 `open_ended` 区分」）。

**备选与否决**：把 `upstream_error` 归入 `other`/`unknown` 桶或复用 `open_ended` 列——否决（违反「四态之外不落该指标」与「`upstream_error` 区别于 `open_ended`」，且属静默丢观测）。仅改 canonical 回退三态——否决（r3 已落四态变体与 `record_truncated` 调用，回退即与已归档事实冲突）。

**接口/数据结构**：`KeyedCounters<4>`；`TRUNCATED_MODES: [&str; 4]`；`WindowAgg::t_upstream_error: u64`；`MetricsSnapshot::truncated_upstream_error: u64`；`SeriesPoint::truncated_upstream_error: u64`；SQL 列 `t_upstream_error`；`/_admin/metrics` 的 `truncated.upstream_error`。

**失败模式**：漏改某落点（如 SQL SELECT 列序）会致错列/编译失败 → 以 `cargo test` + 新增四态落点测试兜底；旧库补列失败仅 warn（沿用既有循环 `let _ =`）不阻断。

**验收口径（行为性，M-5 取代 grep 守护）**：
- 进程内：`record_truncated("upstream_error")` 后 `upstream_error` 具名键 = 1、`other` = 0、无未知键 warn（可用 `#[cfg(test)]` 访问器断言）。
- 落盘/快照/导出：一次 `upstream_error` 记录经 `record_chat_extended` + 快照 + series 后，`upstream_error` 独立列/字段各为 1，三枚旧标签不受影响，无「非法值」warn。
- 四态齐备：依次记录四态，四枚标签各自为 1、互不串计。
- 测试命名（M-3）：新增 `truncated_mode_four_state_labels`（或等价新名），**不复用既有测试名**。

**锚点**：`src/service/sse/meta.rs:16,47`；`src/service/llm_gateway/metrics.rs:26-41,54-55,68,92,112`；`src/service/metrics/store.rs:109-116,168-173,310-312,350-365,431-465`（UPSERT；`:482-517` 实为 `purge_retention_blocking`/`persist_sample_batch`，**非**本项读取路径）；`src/service/metrics/aggregate.rs:30-31,175-177,271-273,296-298,337-342,412-470,473-523`（`query_series_blocking` 定义 `:412-470`、SELECT `:425-429`、`row.get(12..14)` `:460-462`；`backfill_rows_blocking` `:473-523`）；`src/handler/admin.rs:129-133`；canonical `openspec/specs/llm-gateway/spec.md:118-143`、`openspec/specs/observability-admin/spec.md:127-146`。

**锚点准确性注记（M-6）**：`scripts/check_doc_paths.py` 仅校验 `file:line` 的**存在性与界内**，**无法**发现「行号在界但内容错属（misattribution）」。本轮即由此漏检：`query_series_blocking`/`backfill_rows_blocking` 的 SQL 锚长期挂在 `store.rs:425-463/482-517`，而该区间实为 UPSERT 区与 `purge_retention_blocking`/`persist_sample_batch`。故凡新增 SQL/派生锚点，apply 期 SHALL 以「符号名 + 行号」双锚核对内容归属，不得仅依赖脚本通过。

---

### L（定性）· 既有设计差异逐项结论

| 项 | 现状锚点 | 结论 |
|---|---|---|
| 非流 `String::from_utf8_lossy` | `src/handler/llm/nonstream.rs:257` | **仅文档化**：非字节保真，但 `restore_guard_ok`（`:272`）+ 回退（`:278-283`）已兜底；不改。 |
| 流式错误体透传不设上限 vs 非流有界 | `src/handler/llm/dispatch.rs:369-372` | **文档化为有意策略差异**：`Body::from_stream` 惰性转发、非内存无界；非流走 `read_bounded_body`（`:375`）。 |
| Chat `stream_options` 畸形态整体替换 + warn | `src/service/llm_gateway/protocol.rs:194-197` | **维持现状**：`README.md:605-608` 已声明；核对一致性即可，不做行为变更。 |
| 非流 `restore_guard_ok(..., None)` 二次解析 | `src/handler/llm/nonstream.rs:272`；`src/service/redaction/restore_guard.rs:20-26` | **仅性能、不改**：正确性无缺口（`None` 时内部解析并执行 `inner_json_intact`）。 |

---

### M（P3，Oracle Q4）· `PENDING_EVENTS_MAX` 溢出语义

**现状证据**：`src/service/sse/parser.rs:341-369`：`event` 入 `pending_events`（`:343-357`），`ev.data.is_empty()` 分支；溢出（`:345-355`）当前 `pop_front()` **丢最旧**。后续含 `data` 块按 FIFO 取 `pending_events.pop_front()` → 队列被部分保留时，后续 data 帧的 `event:` 名**错配**。

**决策（Q4）**：修代码。溢出时**清空整队**（`self.pending_events.clear()`）+ 递增 `pending_events_dropped`（按被清项数或按事件计数，口径以测试锁定）+ 每流首次 warn（复用 `pending_events_drop_warned`）。语义：**宁缺信封不错标**（fail-safe）。安全影响 P3（终端/opaque/审计判定读 JSON 内 `type`，不读 `event` 行）。

**备选与否决**：继续「丢最旧」否决——会产生**错误**的 `event:` 标签（比缺失更有害）；「只留最后 1 个」否决——与 TRN-1 跨块 FIFO 保真偏离冲突（`src/service/sse/parser.rs:330-378`）。

**接口/数据结构**：`SseParser` 内部；`pending_events_dropped` 观测访问器（`take_*`）不变。**不新增导出指标**。

**失败模式**：清空后同块后续 data 帧无 `event:` 标签（缺信封，fail-safe）。

**验收口径**：`cargo test -p veil pending_events_overflow_clears_queue` 通过（9 个纯 `event:` 块后 data 帧无 event 标签 + 计数递增）；`sse_event_count`/出口帧计数语义对正常流不变。

**锚点**：`src/service/sse/parser.rs:330-378`；canonical `gateway-transport-fidelity`「SSE 出口信封字段保真」（`openspec/specs/gateway-transport-fidelity/spec.md:8-42`）。

---

## 5. conformance 口径（实测登记）

`scripts/api_conformance.py:794` 打印 `len(RESULTS)`；canonical `docs-contract-sync`「README 测试口径标签与脚本一致」（`openspec/specs/docs-contract-sync/spec.md:97-109`）与 `README.md:900-902` §8.5 声明脚本口径项数。

**live 实测口径（任务 9.2，已确认）**：`bash scripts/gate.sh` 第 6 步（`scripts/api_conformance.py`）实测输出 `共 24 项，失败 0 项`（全 gate 七步 exit 0）；四个阻断相条目为 `chat 阻断` / `anthropic 阻断` / `responses 截断` / `responses 非流阻断`。故 live 计数为 **24**（非 23）：`run_normal_phase` 14 项（脚本 `:689-700`）+ `run_credential_phase` 5 项（`:454-457`）+ 无库 503 1 项（`:471`）+ `run_block_phase` **4** 项（`:761-764`，含 `responses 非流阻断`），即 **24 = 14 常规 + 4 阻断 + 5 取用 + 1 无库 503**；README §8.5 旧文案「23 项 = 14 常规 + 3 阻断 + 5 取用 + 1 无库 503」中的「3 阻断」已陈旧（live 为 4 阻断）。

**同批修订（已完成）**：`README.md:900-902` §8.5、canonical `openspec/specs/docs-contract-sync/spec.md:97-109` 与本 change delta `specs/docs-contract-sync/spec.md` 已按 live 实测 **24 项**对齐（23→24、3 阻断→4 阻断）；原「待 gate 实测复核」余量已撤销。canonical `openspec/specs/test-coverage-fill/spec.md`（:53,:58,:68）此前遗漏于 task 9.2 的命名范围，现已同批对齐 23→24 / 3 阻断→4 阻断；归档变更目录中仍含旧 23 项措辞的按 `ARCHIVED_PREFIX` 豁免政策不追溯编辑。

**MINOR 8 澄清**：该计数差异**不影响 gate 第 6 步**——`gate.sh` 第 6 步仅看 `api_conformance.py` 的**退出码**（全项通过即 0），**不比较项数**；故计数文案差异只影响 README §8.5 与 canonical `docs-contract-sync` 的**文案口径**，不改变门禁判定。

---

## 6. 接口 / 数据结构汇总

| 变更 | 位置 | 形态 |
|---|---|---|
| `output[]` is_tool 增补 + 内置条目派生名路径 | `src/service/llm_gateway/tool.rs:647-659` | 复用 `responses_item_tool_name`（`:219-231`）+ `retrieval_args`/`item.action` 回退 |
| computer 分支 | `src/service/llm_gateway/tool.rs:202-214,219-231` | `contains("computer")` → `"computer"`（delta 分支 DEFENSIVE） |
| redact-only 协议变体 | `src/service/llm_gateway/protocol.rs:81-153` | `Protocol` 判定产物携带 redact-only 语义 |
| NonDialog 观测计数（登记现状） | `src/service/llm_gateway/metrics.rs:98,149-157` | 无参单原子，不新增端点维度 |
| `emit_restored_json_frame` | `src/handler/llm/pump/spawn/`（sibling/`terminal.rs`，避开 `event_loop.rs`） | 统一守卫 + 失败回退 |
| `PROTOCOL_HEADER_NAME` | 与 `NORMALIZED_HEADER_NAME`（`src/service/redaction/leaf.rs:23`）同址 | `pub(crate) const &str` |
| leaf helper 合并 | `src/service/redaction/leaf.rs:59,79,132,193` | `bool` 参（或共享私有实现） |
| Responses 派生面抽取 | `src/service/llm_gateway/tool.rs` → sibling 模块<!-- doc-paths-ignore --> | 文件体量 ≤800 |
| `PENDING_EVENTS` 溢出清队 | `src/service/sse/parser.rs:330-378` | 内部 `clear()` + 计数 |
| 四态截断白名单 | `metrics.rs`/`store.rs`/`aggregate.rs`/`admin.rs` | `KeyedCounters<4>`、`t_upstream_error` 加列、四态导出 |
| `metrics_daily/hourly/five_min` 加列 | `src/service/metrics/store.rs:298-348,350-365` | `t_upstream_error INTEGER NOT NULL DEFAULT 0`（加列式迁移） |

---

## 7. Risks / Trade-offs

| 风险 | 缓解 |
|---|---|
| A/B 增补后误纳非工具项致审计量上升 | 判据限定 `responses_item_tool_name`/`contains("computer")`；parity 测试锁定 |
| A 仅放宽 `is_tool` 仍产空名/空参 | 内置条目经派生名路径 + action 回退（M-1）；真实条目断言非空名/参 |
| B 的 computer delta 分支无上游样本 | 标记 DEFENSIVE，主路径以 item-done/`output[]` 验收（MINOR 7） |
| C redact-only 误入审计/用量 | 显式跳过分支 + `count_tokens_redact_only` 测试；`batches` 显式例外 |
| D 守卫误拒合法明文 | 回退占位符帧（fail-closed，不破帧），与正常帧同语义 |
| D/抽取落点越 800 行 | helper 避开 `event_loop.rs`；Responses 派生面外迁（B-2）；`check_file_sizes.py` 门禁 |
| E CR 往返不能字节恒等 | 声明 LF 归一（B-3）+ 回归用例锁定声明口径，不锁逐字节 |
| M 清空整队导致缺信封 | fail-safe（宁缺不错）；正常流计数语义不变测试锁定 |
| N 加列迁移破坏旧库/旧大盘 | 只加不改 + `DEFAULT 0` + 既有补列循环；旧字段读取不变；行为测试锁定四态独立 |
| N 四态落点漏改 | 行为测试覆盖 metrics/store/aggregate/admin 四落点；`cargo test` 兜底 |
| I 重开 `x-veil-protocol` 内联保留条款 | 同批修订 canonical `deadcode-positional-cleanup`，避免真相源自相矛盾 |
| leaf helper 合并破坏请求/响应语义 | 既有 `scope_tests`/`custom/tests` 全量回归兜底 |
| 文档锚点在同批改动后漂移 | 每步跑 `python3 scripts/check_doc_paths.py`；归档锚点按冻结快照豁免 |

---

## 8. 覆盖表（发现 → 决策 → 任务簇 → 证据）

| 发现 | 级别 | 决策 | 任务 | 关键锚点 |
|---|---|---|---|---|
| A 非流 `output[]` 漏审内置工具 | P2 | §A / Q1 / M-1 | 1.1–1.4 | `src/service/llm_gateway/tool.rs:647-659,572-581` |
| B `computer_call` 缺口 | P2 | §B / Q2 / MINOR 1/7 | 2.1–2.2 | `src/service/llm_gateway/tool.rs:202-214,219-231` |
| C `count_tokens` 秘密上行 | P2 | §C / Q3 / M-2/M-3 | 3.1–3.3 | `src/service/llm_gateway/protocol.rs:81-94,112-114` |
| D 残余帧缺守卫 | P3 | §D / Q5 / B-2 | 4.1–4.3 | `src/handler/llm/pump/spawn/terminal.rs:207-228` |
| E `data_frame` CR 不对称 | P3 | §E / Q6 / B-3 | 5.1–5.2 | `src/service/sse/emit.rs:9-24` |
| F `meta.rs`/`aggregate.rs` 三态注释 | P3 | §F / M-5 / B-1 | 6.1 | `src/service/sse/meta.rs:3,10-17`、`src/service/metrics/aggregate.rs:30` |
| G `tool.rs` 同结论注释 | P3 | §G / M-5 | 6.2 | `src/service/llm_gateway/tool.rs:216-218` |
| H 思考签名连续性 | P3 | §H / Q7 / MINOR 9 | 6.3 | `src/handler/llm/pump/event.rs:299-334` |
| I 死代码/冗余 | P3 | §I / Q8 / B-2 | 7.1–7.4 | `src/service/redaction/leaf.rs:23,59,79,132,193` |
| J 文档缺口 + 归档锚点 | P3 | §J / Q9 / M-4 / MINOR 2 | 8.1–8.3 | `README.md:253,669`、`src/service/pii/detector.rs:498` |
| K 最小收敛边界 | 架构 | §K / Q9 | 4.4, 9.1 | `src/handler/llm/pump/spawn/event_loop.rs:616-648` |
| L 定性差异 4 项 | 定性 | §L | 6.4 | 见 §L |
| M `PENDING_EVENTS` 溢出错标 | P3 | §M / Q4 | 5.3–5.4 | `src/service/sse/parser.rs:330-378` |
| **N 四态截断白名单三态化** | **P2** | **§N / B-1** | **10.1–10.4** | `src/service/llm_gateway/metrics.rs:54-55`、`src/service/metrics/store.rs:109-116`、`src/service/metrics/aggregate.rs:30-31`、`src/handler/admin.rs:129-133` |
| 证伪 F3/F5 + 澄清 I + 疑误流式错误体 | 登记 | §3 | 6.5 | 见 §3 |
| conformance 23/24 | 待核对 | §5 / MINOR 8 | 9.2 | `scripts/api_conformance.py:794` |

> 计数口径（MINOR 3 统一）：**P2×4**（A/B/C/N）、**P3×8**（D/E/F/G/H/I/J/M）、**架构×1**（K）、定性×1（L）。proposal 与 design 同字。

---

## 9. 门禁与验证策略

1. 每任务完成即跑 `bash scripts/gate.sh`（七步：fmt / clippy `-D warnings` / test / `check_doc_paths.py` / `check_file_sizes.py` / `api_conformance.py` / go vet+test）。
2. **spec 修订工作流**：spec 修订以本 change 的 `specs/<capability>/spec.md` delta 为归档晋升载体，**并在 apply 期同步直改 canonical `openspec/specs/**`**（沿用 r2/r3 先例）；归档时 OpenSpec 对同内容为 early-sync no-op。
3. 新增测试优先「锚点测试」（断言行为等价的判别性用例），**避免新增源码字符串守护**（M-5）。
4. **本 change artifacts-only**：规划期不改 `src/**`、`tests/**`、`scripts/**`、`README.md`、`openspec/specs/**` 与任何其他 change 目录；不归档、不 `git add/commit`、不运行 `cargo`。
5. **文件体量（B-2）**：`src/service/llm_gateway/tool.rs`（788 行）、`src/handler/llm/pump/spawn/event_loop.rs`（753 行）已近 `check_file_sizes.py` 的 800 上限；A/B/D 增补须先抽取（Responses 派生面外迁、`emit_restored_json_frame` 避开 `event_loop.rs`），改动后各文件 ≤800 行并跑 `check_file_sizes.py`。
6. **场景改名约束（MINOR 4）**：OpenSpec 的 MODIFIED 要求**场景保全**——上游参数化里 preserved 场景名被改名即报 `omits scenario(s)` 并使 `openspec validate --strict` 失败。故「（已取代）」**不能**直接改写既有场景名：本 change 保留 canonical 场景名（名称保全锚点）并**新增**同义「…（已取代）」场景，实际 THEN 指向新语义场景。这样既消除名称与新 THEN 的矛盾，又保持门禁绿。
7. 锚点自检：所有 `src/...rs:NNN` 引用须存在且在界（可由 `python3 scripts/check_doc_paths.py` 近似校验）；归档 r3 锚点按冻结快照豁免；规划期新模块路径（如 `tool_responses.rs`）以 `<!-- doc-paths-ignore -->` 标注，避免路径存在性断言误伤。

---

## 10. Non-goals（非目标，显式登记；apply 期不得顺手扩范围）

本节与 `proposal.md` 的「Non-goals」同字，将本 change 的**非目标**集中显式登记，作为范围约束的单一引用点（`K`，任务 9.1）：

1. **`batches` 脱敏**：Anthropic `v1/messages/batches` 为异步批处理元数据端点，响应为分页对象、不含对话机密，保持 `Protocol::NonDialog` 字节透传；脱敏评估另立 change。
2. **`image_generation_call` 审计**：无可执行参数且 payload 为图像大对象，纳入审计 hold 会放大体量；显式非目标（见 §B）。
3. **完整 `StreamTerminator` 重构**：阻断/终止帧注入去重收敛面大、触及三协议终止语义（高风险），登记为后续独立 change，非本 change 范围（见 §K）。
4. **全局跨会话确定性 token**：与请求隔离隐私硬要求冲突，非目标（`H` 的缓解依赖 conversation 级缓存，另立 change）。
5. **上游缓存命中率测量**：命中率为 provider 侧计费指标，网关侧不可见真值（既有 wont-measure 声明）。
6. **Anthropic 签名校验**：网关不校验上游签名，`H` 仅登记已知限制（见 §H）。
7. **NonDialog 端点维度观测计数**（M-2）：既有无参单原子计数形态维持，不新增键控维度、不新增导出指标族（`C` 的观测登记现状，见 §C）。

补充约束：本 change 不新增导出指标（`M` 仅内部计数 + warn；`N` 为既有四态标签补齐，非新增指标族）；不引入新 crate 依赖；不改 `NONSTREAM_MAX_BYTES` / 审计上限 / token 形态等既有阈值；不重开 r2/r3 已声明的有意偏离。
