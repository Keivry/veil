## Why

六维深度审查（2026-09-11，LLM 网关三协议流式/非流式面）确认 11 项待收敛偏差，均违反既有契约或 README 声明：

- **合规类**：`N1` Responses 双终止帧（`spawn.rs:218-244` 的 `incomplete/error` 合成分支在任何 `terminal_sent` 检查之前执行，`response.completed` 后仍可能合成 `response.failed`）；`N3` SSE CRLF 跨块错位（`sse/parser.rs:117-160` 块末孤立 `\r` 立即当行终止，`event:`/`data:` 分属两个事件）；`P2` 真空流无终止帧（Chat/Anthropic 零帧流保持 open-ended）。
- **正确性类**：`N2`（同 `P6`）非 JSON 且非 502/401 的错误体被替换为合成 `502 E_EMPTY_BODY`（429/500/404 丢失状态码与正文）；`P1` Chat 见 `finish_reason` 却无 `[DONE]` 时不补终止帧；`P4` Responses `incomplete` 被误映射为 7 帧 `response.failed`（丢 `incomplete_details`，且已流出 `output_index:0` 时重复序号）；`P7` 脱敏文本重解析失败回退未脱敏原文（理论外泄）；`P9`/`X2` 工具分桶与提取在流/非流双实现漂移；`P11` 无冒号 `data` 行被整行忽略。
- **记录类**：`P5`（终端去重常规路径正确，缺口由 `N1` 收口）、`P3`（`stream_options` 注入口径正确）、`P10`（usage 五列 `max` 与三级回退正确）审计为 COMPLIANT，无改动；`P8`（= `X5`，`placeholder.rs:175-189` 死分支）由 change `veil-code-hygiene-closeout` 负责删除，本 change 不重复。

真相源为 `src/handler/llm/pump/spawn.rs`、`src/service/sse/parser.rs`、`src/handler/llm/nonstream.rs`、`src/service/llm_gateway/{mod,tool,usage,protocol}.rs`、`src/handler/llm/rewrite.rs`。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`。

引用规范：WHATWG HTML §9.2.4 Server-Sent Events（行终止与字段解析）；OpenAI Chat Completions 流式事件（`finish_reason`、usage 尾帧、`data: [DONE]`）；Anthropic Messages 流式事件（`message_start`/`message_stop`/`error` 语义）；OpenAI Responses 流式事件（`response.completed/failed/incomplete`、`sequence_number` 单调）。

## What Changes

- **`N1` Responses 双终止帧收口**：`spawn.rs:218` 分支首行加 `if terminal_sent { continue; }` 守卫（先于 `responses_failed_sent` 判定）；补 `completed → error`、`completed → incomplete` 回归测试，保证恒恰一终端。
- **`N2`（同 `P6`）非 JSON 错误体原样透传**：`classify_empty`（`service/llm_gateway/mod.rs:159-175`）与 `nonstream.rs:124-145/254-262` 收敛为「`status>=400` 且非 JSON（含空体）原样透传状态码与正文字节」，不再合成 `502 E_EMPTY_BODY`；补 429/500/404 用例；README §7.2 同步豁免范围。
- **`N3` SSE CRLF 跨块正确性**：`push_text` 块末孤立 `\r` 的 CRLF 判定延后到下一块（跨块状态暂存，下一块首字节为 `\n` 时合并为单一行终止，否则按孤立 `\r` 处理）；补 `push_bytes(b"event: x\r")` + `push_bytes(b"\ndata: y\r\n\r\n")` 跨块单测。
- **`P1` Chat `[DONE]` 补发**：保留 `finish_reason` 软终止信号（`spawn.rs:177`），流结束时若从未见 `[DONE]` 则补发恰一 `data: [DONE]`；`finish_reason` 后的 usage 尾帧（`choices: []`）照常透传，不提前截断；README §7.2 同步。
- **`P2` 真空流终止**：Chat 真空流补 `data: [DONE]`；Anthropic 真空流补最小 `message_start`+`message_stop`（空 content、null stop_reason、usage 全 0）；Responses 保持 `response.failed`；三协议各加测试；README §8.6 同步。
- **`P4` Responses `incomplete`/`error` 语义**：`incomplete` 原样透传（本身即官方合法终止，保留 `incomplete_details`）；`type:"error"` 仅合成单帧 `response.failed`（携带上游 error message）；含 `output_index` 的 7 帧全序列仅真空流使用；截断丢弃路径同步改单帧 failed。
- **`P7` 脱敏回退 fail-closed**：注入分支重解析失败时回退转发脱敏字节（不得回落未脱敏原文）；`x-veil-normalized` 仅成功重序列化时置位；补构造性测试。
- **`P9` 工具分桶对齐**：流式 Responses `output[]` 桶号由数组下标 `i` 对齐为 `item.output_index.unwrap_or(i)`，与非流 `tool.rs:462-466` 同键；补流/非流交叉一致性测试。
- **`X2` 工具提取共享实现**：`extract_tool_calls`（`tool.rs:140`）与 `extract_tool_fragments`（`fragments.rs:14`）的字段归一/合成 id/桶号逻辑抽共享内部 helper（`emit_warn` 参数保持非流 warn、流式静默现值），两公有入口保留；补一致性锁定测试。
- **`P11` 无冒号 `data` 行**：`dispatch_block` 对无冒号的 `data` 行按空值字段处理（WHATWG），其他无冒号行维持忽略；补边界测试。
- **记录项落 design.md**：`P5`/`P3`/`P10` 记「audited COMPLIANT, no change」及行号证据；`P8`（= `X5`）仅交叉引用（Non-Goals）。
- **文档同步**：README §7.2（Chat 收尾、非 JSON 错误体）、§8.6（空流三协议语义）与修复后行为同批更新。

## Capabilities

### New Capabilities

- `llm-protocol-hardening`：修复后三协议线级行为的规范契约——恒恰一终端、真空流最小终止、Responses `incomplete` 原样透传、非 JSON 错误体透传、SSE CRLF 跨块正确性、脱敏回退 fail-closed、工具桶流/非流一致。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约（`stream-protocol-parity`、`nonstream-compliance` 等）的行为不动；本 change 新增 capability，README §7.2/§8.6 随行为同步更新。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `N1` | MED（合规） | `spawn.rs:221` 分支首行 `if terminal_sent { continue; }`；`completed → error/incomplete` 回归恰一终端 | 1.1、1.2 |
| `N2`（同 `P6`） | MED（正确性） | 非 JSON 且 `status>=400` 原样透传（保留状态+正文）；429/500/404 测试；README §7.2 | 2.1、2.2、2.3 |
| `N3` | MED（合规） | 块末孤立 `\r` 跨块状态暂存、下一块合并判定；跨块单测 | 3.1、3.2 |
| `P1` | RISK | 见非 null `finish_reason` 软终止，流结束补发恰一 `[DONE]`（usage 尾帧不丢）；README §7.2 | 4.1、4.2、4.3 |
| `P2` | RISK | Chat 真空补 `[DONE]`；Anthropic 真空补最小 `message_start`+`message_stop`；Responses 保持 failed；README §8.6 | 5.1、5.2、5.3 |
| `P4` | RISK | `incomplete` 原样透传；`error` 单帧 `response.failed`；含 `output_index` 全序列仅真空流 | 6.1、6.2、6.3 |
| `P5` | 记录（COMPLIANT） | 终端去重常规路径正确（`terminal.rs:23-57`、`spawn.rs:256/458/510`），缺口由 `N1` 收口；design.md 记录并指向 `N1` | 11.1（收口于 1.1、1.2） |
| `P7` | RISK（低） | 回退改投脱敏字节（不回落原文）；构造性测试 | 7.1、7.2 |
| `P9` | RISK | 流式 `output[]` 桶号对齐 `item.output_index.unwrap_or(i)`；交叉一致性测试 | 8.1、8.2 |
| `X2` | MED | 字段/桶号提取抽共享 helper（`emit_warn` 保持现值）；流/非流一致测试 | 9.1、9.2 |
| `P11` | LOW | 无冒号 `data` 行按空值字段处理；边界测试 | 10.1、10.2 |
| `P3` | 记录（COMPLIANT） | `stream_options` 仅 Chat 注入、保留用户 `false`、不注入 Responses/Anthropic；design.md 记录 | 11.2 |
| `P10` | 记录（COMPLIANT） | usage 五列 `max` + 三级回退正确；design.md 记录 | 11.2 |
| `P8`（= `X5`） | 记录（转出） | 死分支删除由 `veil-code-hygiene-closeout` 承接；仅 Non-Goals 交叉引用 | 12.1 |

## Non-Goals（显式）

- **`P8`（= `X5`）不处理**：`placeholder.rs:175-189` 死分支删除由 change `veil-code-hygiene-closeout` 负责，本 change 不触碰 `placeholder.rs`，仅在覆盖表与 design D11 交叉引用。
- **不伪造成功**：截断/断流仍出 failed 或 open-ended 观测，不得把截断当完成；不得为 Chat/Anthropic 合成虚假内容或 usage；Anthropic `error` 之后不得注入 `message_stop`（error 本身终端）。
- **不碰审计 verdict 判定口径、不碰脱敏 recognizer 集合与采样策略、不改 `stream_options` 注入合并语义（`P3` 维持现状）、不改 usage `max` 口径（`P10` 维持现状）。**
- **不新增 `TruncatedMode` 枚举**：`P1`/`P2` 的 metrics 口径维持 `open_ended`（如实描述上游截断形态），避免旧大盘枚举漂移；枚举名与新增终止帧的行为差异在 design D2/D3 记录。
- **不改 `src/` 实现与 README**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内任何既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-llm-protocol-hardening/` 下 `proposal.md`、`design.md`、`specs/llm-protocol-hardening/spec.md`、`tasks.md`、`.openspec.yaml`。
- **apply 阶段改动面**：`src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump/event.rs`、`src/handler/llm/pump/fragments.rs`、`src/service/sse/parser.rs`、`src/handler/llm/nonstream.rs`、`src/service/llm_gateway/mod.rs`、`src/service/llm_gateway/tool.rs`、`src/handler/llm/rewrite.rs`、`src/service/block_inject/frames.rs`、`src/service/block_inject/terminal.rs`（如去重口径随 `P4` 调整）、对应单测与 `README.md` §7.2/§8.6。
- **影响系统**：三协议流式终止与真空流行为、非流错误透传语义、SSE 解析正确性、脱敏安全回退、工具审计流/非流一致性。
- **依赖**：无新依赖；仅 `serde_json`、`axum`、既有测试设施。
