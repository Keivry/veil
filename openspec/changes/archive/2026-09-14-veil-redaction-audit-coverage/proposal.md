## Why

独立六维审查（2026-09-14，Rust 基线 `/home/keivry/项目/Rust/veil` @ `a4fc46a`，Python 对照 `/home/keivry/项目/Python/credential-proxy` @ `df1b523`）在脱敏还原与流式审计覆盖面确认 8 项偏差（RED-1–RED-8），其中 5 项 P1、3 项 P2，违反既有 README 声明、Python 原仓对照语义或审计「危险参数必审」契约：

- **RED-1（P1）嵌套 stringified-JSON 工具参数凭据还原破内层 JSON**：`src/service/redaction/scope.rs:194-215` 的 `restore_response_with_spans_json` 仅按外层 JSON 字符串上下文转义一次，内层被字符串化的 JSON 参数（工具 `arguments` 常见形态）内明文写入时转义层级不匹配；`src/handler/llm/pump/spawn/frame_feed.rs:17-28` 的 `guard_restored_frame` 只对外层 `jloads` 校验（外层仍合法 → 不回退），内层破损静默透传。Python 对照 `_token.py:698-738` 的 `_restore_json_aware` 经 `_cred_json_walk`（`:733`）递归 walk 字符串节点。
- **RED-2（P1）跨缝掩码损坏 JSON 结构符**：`src/service/redaction/seam.rs:226-244` 的 `mask_span_bytes` 仅逐字符豁免 `{ } " [ ]`（`:236`），`,` 与 `:` 被掩为 `*`；跨缝命中区间若覆盖结构符，掩码后帧 JSON 结构被破坏。`filter_window`（`:140`）虽在窗口空间过滤 `,`，但掩码回写发生在原始帧字节上，结构符仍在豁免集之外。
- **RED-3（P2）掩码边缘与 README §7.10 不一致**：`src/service/pii/detector.rs:242-258` 的 `mask_pii_value` `ipv4` 非 4 段分支在 6–7 字符取前 4/后 4，≥8 字符落入 `short`（前 3/后 3），与 Python `_pii.py:961-1045`（<8 → 首 1/尾 1；≥8 → 前 4/后 4）不一致；README §7.10 声称 6–7 字符行为「对齐原仓」与实际不符。`email` 无点域名（含 `@`、域名无 `.`）在 Python 归 `***@***`，本仓落入 `short`；kind 别名（`bankcard`/`apikey`/`id_card`）为已声明兼容超集，README §7.10 未完整登记。
- **RED-4（P1）Responses 流式工具审计绕过（四类 delta 零审计）**：`src/handler/llm/pump/fragments.rs:181-372` 的 Responses 分支只为 `function_call_arguments`/检索/`output_item` 产分片，对 `response.code_interpreter_call_code.delta`、`response.shell_call_command.delta`、`response.mcp_call_arguments.delta`、`response.custom_tool_call_input.delta` 不产分片（不建槽、不累积、不审计、不可阻断）；`src/handler/llm/pump/event.rs:258-266` 的 `is_minor_event` 进一步把 `mcp`/`code_interpreter` 归为次要事件透传。Python 对照 `_llm.py:783-791` 的 `kind_map` 将四者全部映射 `function_call_arguments` 入审计。
- **RED-5（P1）Chat `finish_reason:"tool_calls"` 后审计旁路**：`src/service/audit/hold.rs:200-243` 的 `is_complete_event` 把 `finish_reason == "tool_calls"` 判为全局完成（`:208-231`），`src/handler/llm/pump/spawn.rs:530-531` 随之 `mark_completed`；`hold.rs:72-78` 的 `push_fragment` 在 `completed` 后短路返回 `Approved`，晚到分片既不累积也不审计却仍透传（对抗性上游可借此夹带危险参数）。同一 `is_complete_event` 也是 Chat 该轮 tool 参数**唯一**审计触发点（`spawn.rs:410-442`；Chat 无槽级完成事件、`[DONE]` 于 `spawn.rs:308` 被跳过、`terminal.rs:52-190` 收尾不评估审计），故修复须分离「审计到期」与「全局完成」并补终端最终审计，不得只移除 `tool_calls` 判定（否则 Chat tool 参数零审计、零阻断，比原缺陷更严重）。
- **RED-6（P2）Responses `.done` 参数双计 `total_bytes`**：`src/service/audit/hold.rs:143-150` 的 `push_responses_fragment` 在 `seq` 缺失时自增生成新 `seq` 键，`slot.frags.entry(seq_no)` 因此对同一调用重复计入字节，长流可提前触发溢出 fail-closed。
- **RED-7（P2）Chat 审计分桶用位置 `ci` 而非声明 `choices[].index`**：`src/handler/llm/pump/fragments.rs:32,45` 以 `choices.iter().enumerate()` 的位置 `ci` 参与 `chat_bucket(ci, idx)`（`src/service/llm_gateway/tool.rs:167`），乱序/跳号 `choices[].index` 时槽归属错位，审计对象与实际 choice 不匹配。
- **RED-8（P2）截断时未完成 tool 不落审计**：`src/handler/llm/pump/spawn/terminal.rs:82-87` 在截断收尾时清空 `pending_tool_frames` 并记 `truncated_tool_dropped`，但不为其中未完成 tool 分片产生审计记录/告警，未完成调用成为审计盲区。

真相源为上述 `src/` 文件、`README.md` §7.10 与 Python 对照仓文件。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/`、`README.md`、`scripts/`，不提交 commit；实现与文档同步留待 apply 阶段。

引用规范：Python 原仓凭据 JSON-aware 还原语义（`_token.py:698-738`）、原仓掩码语义（`_pii.py:961-1045`）、原仓 Responses 工具审计 kind 映射（`_llm.py:783-791`）、README §7.10 掩码边缘与别名声明、审计 hold-until-complete 与「危险参数必审」契约。

## What Changes

- **RED-1 递归 JSON-aware 还原**：还原层对内层 stringified JSON 参数递归执行凭据还原（内层字符串节点独立 `loads→walk→dumps`），写回转义层级与实际 JSON 深度匹配；`guard_restored_frame` 守卫扩展为内层结构有效性校验，内层破损时按既有 fail-closed 口径回退还原前占位符帧；补两层嵌套 JSON 参数还原后内层结构有效回归。
- **RED-2 跨缝掩码结构保真**：`mask_span_bytes` 豁免集扩充至全 JSON 结构符（含 `,`/`:` 等）或改 JSON-aware 掩码，保证跨缝掩码后帧仍可解析；补跨缝命中覆盖结构符的解析回归。
- **RED-3 掩码边缘与 §7.10 对齐**：对照 Python `_pii.py:961-1045` 逐分支核定 `mask_pii_value` 行为——数值/email 分支按原仓语义对齐（或经 design 决策修正 README §7.10 声明），kind 别名超集在 README §7.10 完整登记；回归使用 §7.10 列举的边缘样例（6–7 字符 IPv4、无点 email、别名）。
- **RED-4 四类 delta 审计覆盖**：`extract_tool_fragments` 为 `code_interpreter_call_code.delta`/`shell_call_command.delta`/`mcp_call_arguments.delta`/`custom_tool_call_input.delta` 建槽并累积，`is_minor_event` 不再把对应事件列为次要，命中危险参数时审计并可阻断；补四类 delta 各一带危险参数的阻断/审计回归。
- **RED-5 Chat 审计到期/全局完成分离 + 终端最终审计**：拆分 `is_complete_event` 的单一判定——审计到期谓词保留 `finish_reason:"tool_calls"`（任意非空 `finish_reason`）使该轮 tool 参数照常评估/阻断，全局完成谓词移除 `tool_calls` 使晚到分片继续累积并审计；`terminal::finalize` 清除持仓前对 `hold.tool_triples()` 执行恰一次幂等最终审计，覆盖截断/未完成与晚到分片；正常流语义不变；补晚到分片、终端 flush、正常流三臂回归。
- **RED-6 total_bytes 去重**：`push_responses_fragment` 按槽/调用维度去重计数，同一 `.done` 参数不重复加入 `total_bytes`；补双计场景 `total_bytes` 正确回归。
- **RED-7 declared index 分桶**：Chat 分桶改用 `choices[].index`（缺省回退位置），乱序/跳号 index 分桶正确；补乱序/跳号回归。
- **RED-8 截断未完成 tool 落审计**：截断收尾对未完成分片产生审计记录/告警（不泄漏参数原文）；补截断场景审计记录存在回归。
- **文档同步**：README §7.10（掩码边缘规则与别名）与修复后行为同批更新；spec 与 README 对应段落互引。

## Capabilities

### New Capabilities

- `redaction-audit-coverage`：脱敏还原与流式审计覆盖契约——嵌套 stringified-JSON 凭据还原正确性、跨缝掩码 JSON 结构保真、掩码边缘规则与 README §7.10 一致、Responses 四类工具 delta 审计覆盖、Chat 审计到期/全局完成分离与终端最终审计、Responses 审计字节去重、Chat 审计按声明 index 分桶、截断未完成 tool 落审计。

### Modified Capabilities

- 无。本 change 新增 capability；既有 `openspec/specs/redaction/spec.md`、`openspec/specs/audit-parity/spec.md`、`openspec/specs/pii-parity-closeout/spec.md` 等契约中与本 spec 冲突或需补强的旧口径，在 apply 阶段按 `openspec/changes/veil-redaction-audit-coverage/specs/redaction-audit-coverage/spec.md` 为准同步并在归档时随 canonical 修订，不作为本 change 的 MODIFIED delta。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `RED-1` | P1 | 内层 stringified JSON 递归还原 + 守卫校验内层结构有效性；两层嵌套 JSON 还原后内层有效回归 | 1.1、1.2、1.3 |
| `RED-2` | P1 | `mask_span_bytes` 豁免集扩充（含 `,`/`:`）或 JSON-aware 掩码，跨缝掩码后可解析；解析回归 | 2.1、2.2 |
| `RED-3` | P2 | 对照 Python 核定 `mask_pii_value` 边缘分支；规则对齐或修正 README §7.10（design 决策）；§7.10 样例回归 | 3.1、3.2、3.3 |
| `RED-4` | P1 | 四类 Responses delta 建槽累积、审计、可阻断；`is_minor_event` 去次要归类；四类各一回归 | 4.1、4.2、4.3 |
| `RED-5` | P1 | 拆分审计到期（保留 `tool_calls` 触发评估/阻断）与全局完成（移除 `tool_calls`）；终端收尾前幂等最终审计未完成/晚到分片；晚到/终端/正常流三臂回归 | 5.1、5.2、5.3、5.4 |
| `RED-6` | P2 | `push_responses_fragment` 按槽/调用去重计数；双计场景 `total_bytes` 回归 | 6.1、6.2 |
| `RED-7` | P2 | Chat 分桶用声明 `choices[].index`（缺省回退位置）；乱序/跳号回归 | 7.1、7.2 |
| `RED-8` | P2 | 截断收尾对未完成分片落审计/告警且不泄漏原文；截断审计回归 | 8.1、8.2 |

## Non-Goals（显式）

- **本 change 仅规划**：只交付 proposal/design/spec/tasks 规划 artifacts；不改 `src/`、`tests/`、`README.md`、`scripts/`，不改其它 change 目录，不提交 commit。
- **不改审计 verdict 判定口径、脱敏 recognizer 集合与采样策略、usage `max` 口径、`stream_options` 注入合并语义。**
- **不修改 Python 原仓**：Python 文件仅作对照真相源，不在本仓改写。
- **不扩张 RED-1–RED-8 之外的无声明差异**：审查清单外的行为差异不纳入本 change（另立 change 交付）。
- **不为 RED-4 四类 delta 发明阻断语义**：沿用既有审计 verdict 与阻断帧通道，仅补齐「建槽—累积—审计—阻断」链路，不新增策略规则。

## Impact

- **新增文件**：`openspec/changes/veil-redaction-audit-coverage/proposal.md`、`design.md`、`specs/redaction-audit-coverage/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/service/redaction/scope.rs`、`src/service/redaction/seam.rs`、`src/service/pii/detector.rs`、`src/handler/llm/pump/spawn/frame_feed.rs`、`src/handler/llm/pump/fragments.rs`、`src/handler/llm/pump/event.rs`、`src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump/spawn/terminal.rs`、`src/service/audit/hold.rs`、`src/service/llm_gateway/tool.rs`、对应单测与 e2e、`README.md` §7.10。
- **影响系统**：凭据/PII 响应还原正确性、跨缝掩码 JSON 保真、掩码边缘可预期性、Responses 工具审计覆盖面、Chat 审计到期/全局完成分离与分桶、审计 hold 容量记账、截断审计可观测。
- **依赖**：无新依赖；仅既有 `serde_json`、`axum`、`tokio` 与测试设施。
