## Context

独立六维审查（2026-09-14）在脱敏还原与流式审计覆盖面确认 8 项偏差（见 proposal Why 与覆盖表）。现状真相源：

- 还原仅外层转义：`src/service/redaction/scope.rs:194-215` `restore_response_with_spans_json` 在 `restore_response_with_spans` 结果上对 span 做一次 `json_escape_plain`（`:377-383`），内层 stringified JSON 的转义层级不匹配；`src/service/redaction/scope.rs:340-357` `restore_cred_tokens` 只对完整 token 直查重建；守卫 `src/handler/llm/pump/spawn/frame_feed.rs:17-28` `guard_restored_frame` 仅 `serde_json::from_str(strip_bom(&restored))` 校验外层（`RED-1`）。Python 对照 `_token.py:698-738` `_restore_json_aware`，经 `_cred_json_walk`（`:733`）递归处理字符串节点并在异常时回退纯文本。
- 掩码结构符豁免不足：`src/service/redaction/seam.rs:226-244` `mask_span_bytes` 的 `matches!(c, '{' | '}' | '"' | '[' | ']')`（`:236`）不含 `,`/`:`；`filter_window`（`:101-149`）在窗口空间过滤 `,`（`:140`）但掩码回写在原始帧字节上（`RED-2`）。
- 掩码边缘对照：`src/service/pii/detector.rs:189-...` `mask_pii_value` `ipv4` 非 4 段分支（`:242-258`）为 `(6..=7) → 前4****后4`、其余落 `short`（`>=6 → 前3****后3`）；Python `_pii.py:961-1045` 为 `<8 → 首1****尾1`、`>=8 → 前4****后4`；`email` 无点域名 Python 归 `***@***`，本仓落 `short`；别名 `bankcard`/`apikey`/`id_card` 为本仓超集（`RED-3`）。README §7.10 声称 6–7 字符「对齐原仓」。
- Responses 审计覆盖缺口：`src/service/llm_gateway/tool.rs:419-482` Responses 分支仅处理 `function_call_arguments`/检索/`output_item`；`src/handler/llm/pump/event.rs:258-266` `is_minor_event` 将 `["reasoning","mcp","code_interpreter","image_gen"]` 全按次要透传；Python `_llm.py:783-791` `kind_map` 将四类 delta 全部映射 `function_call_arguments`（`RED-4`）。
- Chat 完成语义：`src/service/audit/hold.rs:200-243` `is_complete_event` 以**单一判定**同时充当「审计到期」与「全局完成」——`finish_reason=="tool_calls"`（`:208-231`）既触发 tool 参数审计评估（`spawn.rs:410-442`）又置全局完成（`spawn.rs:530-531` `mark_completed`），`hold.rs:72-78` `push_fragment` 在 `completed` 后短路返回 `Approved`。Chat 无槽级完成事件（`content_block_stop`/`item_done` 为 Anthropic 类型，`hold.rs:259-264`）、`[DONE]` 在 `spawn.rs:308` 被跳过、`terminal.rs::finalize`（`:52-190`）收尾不评估审计，故 `finish_reason:"tool_calls"` 是 Chat 该轮 tool 参数**唯一**审计触发点；若仅移除该判定而不拆分谓词并补终端触发，Chat tool 参数将零审计、零阻断（`RED-5`，比原缺陷更严重）。
- Responses 字节计数：`src/service/audit/hold.rs:143-150` `push_responses_fragment` 用 `slot.frags.entry(seq_no)`，`seq` 缺失时 `next_seq` 自增生成新键，重复计入 `total_bytes`（`RED-6`）。
- Chat 分桶：`src/service/llm_gateway/tool.rs:143-147` 以 `choices.iter().enumerate()` 的位置 `ci` 参与 `chat_bucket(ci, idx)`（`src/service/llm_gateway/tool.rs:167`）（`RED-7`）。
- 截断审计盲区：`src/handler/llm/pump/spawn/terminal.rs:82-87` 截断时 `pending_tool_frames.clear()` 并 `record_truncated_tool_dropped`，不产生审计记录（`RED-8`）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、`README.md`、`scripts/`；不碰审计 verdict 与脱敏 recognizer 集合；不新增依赖。

## Goals / Non-Goals

**Goals：**

- 给出 `RED-1`–`RED-8` 的可实施方案与可验证场景，使 apply 阶段逐项落地并独立验证。
- 把「嵌套 JSON-aware 还原」「跨缝掩码结构保真」「掩码边缘与文档一致」「四类 Responses delta 审计覆盖」「Chat `tool_calls` 晚到分片审计」「审计字节去重」「声明 index 分桶」「截断未完成 tool 审计」收敛为 spec 契约，README §7.10 与行为同批同步。
- 固化三项待裁决策：`RED-2` 结构符豁免集策略、`RED-3` 规则对齐 vs 文档修正、`RED-5` 审计到期/全局完成分离与终端最终审计实现路线。

**Non-Goals：**

- 不修改审计 verdict 判定口径、脱敏 recognizer 集合与采样策略、usage `max` 口径、`stream_options` 注入合并语义。
- 不为 `RED-4` 新增审计策略规则；仅补齐「建槽—累积—审计—阻断」链路。
- 不改 `src/` 实现、`tests/`、`README.md` 与 `scripts/`（本 change 只交付规划）；不提交 commit；不改其它 change 目录。
- 不修改 Python 原仓；Python 文件仅作对照真相源。

## Decisions

### D1：内层 stringified JSON 递归还原 + 守卫内层校验（`RED-1`）

**决策**：在响应还原入口（`scope.rs:194-215`）之外新增 JSON-aware 递归还原路径：识别字符串节点（含被字符串化的内层 JSON），对内层 `loads→walk→dumps` 逐字符串节点执行凭据/PII 还原，写回时按节点实际所在 JSON 深度转义（内层再嵌入时二次转义），使「还原前可解析」的嵌套帧「还原后仍可解析」。`guard_restored_frame`（`frame_feed.rs:17-28`）守卫扩展：除外层 `jloads` 外，对字符串值尝试内层 JSON 解析，内层可解析且还原发生时校验结构有效；内层破损则回退还原前占位符帧并 `record_restore_fallback`。复用既有 `json_walk::process_text`（`scope.rs:258`）的递归 walk 能力与 `json_escape_plain`（`:377-383`）。

**理由**：工具 `arguments` 常以字符串承载 JSON，内层是独立的 JSON 文档；单层转义会以内层视角产生非法裸 `"`。Python 原仓 `_restore_json_aware` 递归 walk（`_token.py:733`）即此语义，对齐可保证跨实现一致。守卫只校验外层是缺陷根因（外层合法掩盖内层破损），扩展内层校验才能触发既有 fail-closed 回退。

**备选**：只修 `json_escape_plain` 增加一次转义——无法区分「外层字符串」与「内层字符串」深度，双层以上仍错，且会破坏单层帧，不采用；依赖 `guard_restored_frame` 回退——当前守卫看不到内层，不采用。

### D2：跨缝掩码结构符豁免集策略（`RED-2`）

**决策**：采用「扩充 `mask_span_bytes` 豁免集」路线：豁免集由 `{ } " [ ]` 扩充至 `{ } " [ ] , :`（并保留 `filter_window` 既有 `,`/`:`/`"key":` 键过滤语义），非结构位仍逐字符掩码。不引入完整 JSON-aware 掩码解析器。

**理由**：掩码发生在原始帧字节空间，作用对象是已定位的跨缝数据区间；JSON 结构符是有限闭集（RFC 8259 六种结构符 + `,`/`:`），扩充豁免集即可保证「掩码后仍可解析」，改动面小、无解析重排副作用（键序/数字表示不变，符合 README §7.7 字节保真声明）。完整 JSON-aware 掩码需 `loads→walk→dumps`，会引入键序/数字表示重排副作用，成本收益不成比例。

**备选**：JSON-aware 掩码——重序列化副作用与 README §7.7 保真声明冲突，不采用；仅豁免 `{ } " [ ]`（现状）——`,`/`:` 被掩导致结构破坏，不采用。

### D3：掩码边缘——规则对齐 vs 文档修正（`RED-3`）

**决策**：**双轨落地**。数值与 email 分支按 Python 原仓语义对齐（`ipv4` 非 4 段：`<8` → 首 1/尾 1、`>=8` → 前 4/后 4；`email` 含 `@` 域名无 `.` → `***@***`）；kind 别名 `bankcard`/`apikey`/`id_card` 保留为本仓**已声明兼容超集**，并在 README §7.10 完整登记真实别名集；同时修正 README §7.10 中「6–7 字符 IPv4 对齐原仓」的错误表述为实际规则。即：能对齐原仓的对齐（数值/email），属有意超集的登记而非删除（别名），文档错述的按事实修正。

**理由**：Python 对照是本仓 parity 契约基线（README §6.3 等以 baseline commit 锁定），数值/email 分支无「有意差异」声明，属实现漂移，应对齐；别名超集已在 `mask_pii_value` 实现且 `pii-parity-closeout` spec 声明为兼容超集，删除会破坏既有下游，保留并完整登记。README §7.10 的「对齐原仓」表述与 Python 不符，属文档事实错误，必须修正而非把实现迁就错述。

**备选**：全部对齐 Python（含删除别名超集）——破坏已声明兼容超集、引入回归，不采用；仅修文档不修代码——数值/email 漂移保留，违反 parity 基线，不采用；仅修代码不修文档——README §7.10 仍错述，不采用。

### D4：四类 Responses delta 建槽累积审计（`RED-4`）

**决策**：`extract_tool_fragments`（`fragments.rs`）的 Responses 分支新增对 `code_interpreter_call_code.delta`/`shell_call_command.delta`/`mcp_call_arguments.delta`/`custom_tool_call_input.delta` 的识别：按 `output_index`/`item_id` 建槽，delta 文本作为参数分片产出（工具名按事件类型派生，对齐 Python `_llm.py:783-791` 统一归 `function_call_arguments` 审计路径）；`is_minor_event`（`event.rs:258-266`）从次要集移除对应事件（`mcp`/`code_interpreter`），使审计判定可达。命中危险参数沿用既有 `evaluate_and_record` 通道，`block` 模式经既有阻断臂注入终端。

**理由**：Python 原仓明确将四类 delta 全部映射审计；现状四类既不建槽也不审计，属覆盖漏洞（危险参数零审计）。复用既有 `output_index`/`item_id` 键与审计通道，不新增策略规则、不改 verdict 口径。

**备选**：新增独立审计分类——违反 Non-Goal（不新增策略规则），不采用；仅在 `.done` 审计——delta 已流经且 `.done` 未必到达（截断场景），覆盖不全，不采用。

### D5：Chat 审计到期与全局完成判定分离 + 终端最终审计（`RED-5`）

**决策**：把 `AuditHold::is_complete_event`（`hold.rs:200-243`）承担的单一判定拆为两个正交谓词：**审计到期** `is_audit_due_event`——Chat **任意非空 `finish_reason`**（含顶层、`choices[].finish_reason`、`delta.finish_reason`、`message.finish_reason`，`tool_calls` 在内）仍触发对该轮 `hold.tool_triples()` 的审计评估与 `block` 阻断；**全局完成** `is_complete_event`（语义收窄）——移除四处 `tool_calls`，仅 `message_stop`/`response.completed`/`response.failed`/`response.incomplete` 触发 `mark_completed`，Chat 全局完成仅由真正终端（`[DONE]`/流结束）收口。`spawn.rs` 的槽重放（`decide::tool_replay_slot` `:339-360`）、评估门（`:410-442`）、释放（`release_audited` `:484-489`）与缓冲判定（`decide::should_buffer_tool_frame` `:364`）改用审计到期谓词；`mark_completed`（`:530-531`）改用全局完成谓词。新增**终端最终审计**：`spawn/terminal.rs::finalize`（`:52-190`）在清除 `pending_tool_frames`/收尾前，对 `hold.tool_triples()` 执行**恰一次幂等**最终 `evaluate_and_record`（`TerminalCtx` 扩展携带 `audit_sink`/`audit_mode`/`audit_policy`/`approval_whitelist`/协议等审计上下文），使截断/未完成或晚到分片仍被审计且 `block` 模式阻断；`Block` 走既有阻断臂注入终端并丢弃持仓，`Allow`/`NeedApproval` 释放持仓。幂等由「已判定参数已由 `release_audited` 移出持仓」加上显式 final-flush 标志共同保证，`tool_triples()` 为空时天然 no-op，不重复评估。

**理由**：`is_complete_event` 的单一判定把「本轮 tool 参数已可审计」（`tool_calls` 即到期）与「流内容已终结」两个不同语义耦合。审计必须在 `tool_calls` 帧进行（Chat 该轮唯一可用触发点），否则危险参数零审计；而全局完成若也在 `tool_calls` 置位，`push_fragment` 短路使晚到分片既不累积也不审计却仍可能透传。拆分后：审计到期保留 `tool_calls`（评估/阻断可达、正常工具参数照常重放透传），全局完成移除 `tool_calls`（晚到分片继续累积、继续审计）；终端最终审计补齐 `terminal.rs` 的审计真空与「无 `[DONE]`/截断未完成」分片，与 `RED-8` 的截断告警互补——本项负责「参数必审/必阻断」，`RED-8` 负责「丢弃可观测」。

**备选**：保留 `tool_calls` 为全局完成、仅在 `push_fragment` 去掉 `completed` 短路——`completed` 语义被污染、`mark_completed` 后 `tool_triples` 仍含旧槽导致重复审计，不采用；仅新增终端审计、不动 `is_complete_event`——晚到分片仍被 `push_fragment` 短路，终端 flush 前参数从未进槽，审计不到，不采用；仅移除 `tool_calls` 全局完成而不保留审计到期——即本缺陷，Chat tool 参数零审计、零阻断，不采用。

### D6：Responses 审计字节按槽/调用去重（`RED-6`）

**决策**：`push_responses_fragment`（`hold.rs:111-161`）增加按槽/调用维度的「已计字节」判定：若该 `args_delta` 对应同一调用的 `.done` 参数已计入（或同一 `seq` 已被占用），则 `added_bytes = 0`；`mark_responses_done`（`:163-170`）记录 `done_args` 时不同时重复累加 `total_bytes`。溢出判定仍基于 `total_bytes`。

**理由**：`.done` 携带完整参数，若 `seq` 缺失被赋予新键则与既有分片重复计数，长流提前误判溢出（fail-closed 误伤）。按槽/调用去重使计数反映唯一参数体量，真实超限仍受 `AUDIT_HOLD_MAX_BYTES` 约束。

**备选**：只在 `.done` 时不累加——分片与 `.done` 可能仅到其一，需双向去重，不采用；提高上限——掩盖根因，不采用。

### D7：Chat 分桶用声明 `choices[].index`（`RED-7`）

**决策**：`extract_tool_fragments` Chat 分支（`fragments.rs:31-92`）把 `chat_bucket(ci, idx)` 的 `ci` 改为该 choice 的声明 `index`（`ch.get("index").as_u64()`，缺省回退枚举位置 `ci`）；`chat_bucket`（`tool.rs:167`）语义保持 `declared*64+idx`，单 choice `index=0` 与旧键等值。

**理由**：`choices[].index` 是协议声明槽位，位置枚举在乱序/跳号时错位；用声明值分桶使审计对象与实际 choice 匹配。缺省回退位置保持对未声明 index 的兼容。

**备选**：仅位置——乱序漂移，不采用；按 `id` 分桶——Chat tool_call `id` 可能缺失且非 choice 维度，不采用。

### D8：截断未完成 tool 落审计（`RED-8`）

**决策**：`terminal.rs` 截断收尾（`:82-87`）在清空 `pending_tool_frames` 前，对其中未完成 tool 调用产生审计记录/告警：记 warn（含槽号/已缓冲分片数，**不含参数明文**）并经审计 sink 记录「截断未完成」事件（复用既有审计记录口径与脱敏）；`truncated_tool_dropped` 指标保留。正常完成路径不产生该记录。

**理由**：截断时未完成 tool 调用被静默丢弃，审计面不可见（审计盲区）；落审计记录使「截断丢弃」可观测且可告警，与「危险参数必审」契约一致。记录不带参数明文，不新增泄漏面。

**备选**：仅保留指标——指标粒度不足以告警具体调用，不采用；记录参数明文——违反零明文口径，不采用。

## Risks / Trade-offs

- [`RED-1` 递归还原引入 `loads→dumps` 重排] → 仅对含凭据占位符的字符串节点触发还原写回；无替换时保持字节透传（对齐 README §7.7 零替换透传声明）。回归覆盖单层与双层帧。
- [`RED-1` 内层守卫回退面扩大] → 内层破损本应 fail-closed；回退为还原前占位符帧（token 形态保留、不破帧），既有外层守卫语义不回退。回归锁定回退计数。
- [`RED-2` 豁免 `:` 影响 IPv6 跨缝检测] → `filter_window` 注释（`seam.rs:96`）已说明 `:` 本身保留（IPv6 跨缝需要）；`mask_span_bytes` 豁免 `:` 与窗口过滤一致，逐字符掩码下非结构位仍被掩，检测面不变。
- [`RED-3` 对齐数值/email 分支改变既有掩码输出] → 属修正实现漂移；受影响的掩码样本单测需随口径更新（apply 阶段），README §7.10 同批修正。别名保留无回归。
- [`RED-4` 审计量上升] → 四类 delta 计入审计可能提高审计量（误报优于漏审，与既有检索调用口径一致）；监控审计量突变属预期。
- [`RED-5` 审计到期/全局完成分离 + 终端最终审计] → Chat 完成改由终端事件收口；审计到期保留 `tool_calls`，该轮 tool 参数照常评估/阻断且正常流重放透传，晚到分片在全局完成移除后继续进槽、并在终端 flush 中被审计；若上游仅发 `finish_reason:"tool_calls"` 而无 `[DONE]`，终端补发走既有 D6 断流收尾路径（`veil-stream-fidelity-fix` 已落地），不悬挂。终端 flush 幂等（已判定参数移出持仓 + final-flush 标志），不重复审计；回归覆盖正常序列、对抗性晚到分片、截断未完成三臂。
- [`RED-6` 去重] → 需保证 `.done` 参数仍进入审计判定（去重只影响字节计数，不影响参数文本累积）；回归锁定审计结论不变、字节数正确。
- [`RED-7` 声明 index 分桶] → 未声明 index 回退位置，兼容既有单 choice 流；多 choice 乱序场景由回归锁定。
- [`RED-8` 截断审计记录] → 记录不含参数明文，不新增泄漏面；告警频率与截断频率同阶，不引入噪声放大（仅截断触发）。

## Migration Plan

1. 按 tasks 顺序落地：先还原与掩码正确性（`RED-1`/`RED-2`/`RED-3`），再 Responses 审计覆盖与计数（`RED-4`/`RED-6`），再 Chat 审计到期/全局完成分离与终端最终审计、分桶（`RED-5`/`RED-7`），最后截断审计（`RED-8`），收口门禁。
2. 每组独立 `cargo test`；README §7.10 与 `RED-3` 改动同批更新；spec 与 README 对应段落互引；测试名与 tasks 验证命令对齐。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。
4. 发布口径：无 BREAKING 配置项；下游可感知的行为变化（掩码数值/email 边缘输出、四类 delta 审计、Chat 晚到分片审计、截断审计记录）由 README §7.10 与 spec 声明。

## Open Questions

- 无。`RED-1`–`RED-8` 均已裁定；三项待裁决策（`RED-2` 豁免集、`RED-3` 规则/文档、`RED-5` 路线）已在 D2/D3/D5 收敛。若 apply 阶段实测某分支有额外 parity 细节，以 spec 对应 Scenario 为准并在本节记录差异。
