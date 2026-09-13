## Why

独立六维审查（2026-09-13，LLM 网关三协议流式面）确认 11 项流式保真偏差（S1–S11），其中 2 项 critical、4 项 major，违反既有 spec/README 声明或官方流式规范：

- **`S1`（critical）默认配置全流缓冲、非增量**：`src/service/audit/hold.rs:283` 的 `held()=!completed&&!rejected` 在流开始即真；`src/handler/llm/pump/decide.rs:108-114` 的抑制判定不含审计模式与 pending 判据；`src/handler/llm/pump/spawn.rs:532-538` 命中即 `continue` 跳过 `select_emit`；Chat `finish_reason:"stop"` 不触发 `mark_completed`（`hold.rs:188-235` 仅认 `tool_calls`/`message_stop`/`response.*`）。实测默认 `AUDIT_MODE=off` 的 Chat 流下游仅收到 1 帧（整段拼接），Anthropic/Responses 到 `message_stop`/`completed` 才放行。
- **`S2`（critical）Responses 多工具调用逃逸审计**：`hold.rs:116-122` 在 `completed` 时提前返回且不建槽；`hold.rs:222-233` 把 `response.output_item.done`/`response.function_call_arguments.done` 当全局完成（`spawn.rs:483-485` 随之 `mark_completed`）。实测 item0 良性完成后 item1 `exec {"command":"rm -rf /"}`（block 模式）无阻断帧、危险参数透传。
- **`S3`（major）Responses 合成终端乱序**：`spawn.rs:258-284` 的 `SynthesizeFailed` 直接发送 `response.failed`，未 `boundary.flush()/clear()`，滞留帧在 EOF（`spawn.rs:642`）才落，实测帧序 `response.failed` 先于末段 delta。
- **`S4`（major）跨帧切分占位符不还原**：`src/service/credential_vault.rs:40-51`、`src/service/pii/chunk.rs:124`、`src/service/redaction/leaf.rs:200-231`、`spawn.rs:486-510` 皆为逐帧还原无跨帧缝合；`src/service/redaction/seam.rs:177-197` 只掩码跨缝残片。实测 `__VG_CRE`+`D_000001__` 两帧前半被剥离、未还原明文。
- **`S5`（major）中途传输错误静默当正常 EOF**：`spawn.rs:162` `while let Ok(chunk)` 遇 `Err` 直接退出，无日志、无 truncated 观测；Chat/Anthropic 无 `finish_reason` 时既不补终端也不记截断，Responses 已发帧时不合成 failed。
- **`S6`（major）流式请求上游 4xx/5xx 被改写为 200 SSE**：`src/handler/llm/dispatch.rs:252-268` 的 `rw.stream_flag` 分支不看状态码一律转泵；`src/handler/llm/pump/event.rs:18-40` 的 `build_sse_response` 恒 200。
- **`S7`（minor）`AuditHold.total_bytes` 不回收**：`hold.rs:88-96` 累加，`clear_index`（`hold.rs:248-252`）与 `mark_completed` 不递减，长流多工具可误判溢出 fail-closed。
- **`S8`（minor）keepalive gate 语义错位**：`spawn.rs:213-216` 以 `hold.held()` 为门（与 `S1` 同根因）。
- **`S9`（minor）截断合成强制置位**：`spawn.rs:603-630` 合成帧 `send` 失败（下游已断）仍置 `terminal_sent=true`，掩盖空流合成守门。
- **`S10`（record/decision）Python 审批挂起期独立保活（`_llm.py:1948-1969`）未迁移**：Rust 流式审批不挂起（README §6.4 已声明），本 change 在 design 落 Non-Goal 并在 spec 引用。
- **`S11`（record/decision）mid-stream 断流终端策略未固化**：各协议补/不补终止帧与 `truncated_mode` 口径需在 design 决策并写入 spec 与 README §7.2/§8.6。

真相源为上述 `src/` 文件与 `README.md` §6.4/§7.2/§8.6。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`、`tests/` 与 README；实现与文档同步留待 apply 阶段。

引用规范：OpenAI Chat Completions 流式（增量分片、`finish_reason`、`data: [DONE]`）；Anthropic Messages 流式（`message_start`/`message_stop`/`error`）；OpenAI Responses 流式（`response.completed/failed/incomplete`、per-item `done`）；WHATWG SSE（`data:` 字段逐帧语义）。

## What Changes

- **`S1` 默认逐帧增量**：抑制判据由流级 `hold.held()` 改为「审计模式非 off 且确有未完成 tool 分片」；完成事件审计后（含 approve 建单，不阻塞流）释放抑制集；`decide::should_suppress_held_output` 与 `spawn.rs:532-538` 调用点接线；补 mock 上游慢速分片 + 下游按帧读取的逐帧到达回归测试。
- **`S2` Responses 槽级/全局完成隔离**：`AuditHold::is_complete_event` 移除 `response.output_item.done`/`response.function_call_arguments.done`、加入 `response.incomplete`；per-item done 走槽级审计与槽清理；补多 item 阻断回归测试。
- **`S3` 合成终端保序**：`error`→`response.failed` 与截断→`response.failed` 合成前先 flush 边界滞留帧并按序下行；补 delta A 后 `type:error` 的保序回归测试。
- **`S4` 跨帧占位符缝合**：还原层新增跨帧 carry：帧尾占位符合法前缀持有至下一帧拼接还原；流末残余前缀按既有残缺剥离口径清理；凭证与 PII 均覆盖，补两种切分位置回归测试。
- **`S5` 传输错误可观测**：`chunk()` `Err` 分支记录 warn 与截断观测（`truncated_mode`/指标），不再静默退出；补 mock 中途断连测试。
- **`S6` 流式错误透传**：上游 `status>=400` 或 `content-type` 非 `text/event-stream` 时透传状态码与正文字节（与非流路径一致），不再一律 200 SSE；补 500 JSON 与 500 HTML 测试；README §7.2 同步。
- **`S7` hold 字节回收**：按槽记账，槽清理/per-item done/`mark_completed`/`mark_rejected` 归还字节，长流多工具不再误判溢出；真实超限仍 fail-closed；补长流多工具测试。
- **`S8` keepalive gate 统一判据**：与 `S1` 同源改为「仅未完成分片存在时门控」；补 keepalive 触发条件测试。
- **`S9` 截断合成置位守门**：仅在合成帧实际发送成功后置位 `terminal_sent`/帧计数；补截断+下游早断测试。
- **`S10` 审批挂起 Non-Goal 记录**：design 显式记录 Python 审批挂起期独立保活不迁移，spec 声明流式审批不挂起；恢复需新 change。
- **`S11` 断流终端策略固化**：design 决策——Chat 补恰一 `[DONE]` 且记 `open_ended`；Anthropic 不合成终止帧、记 `open_ended`；Responses 已发帧合成恰一 `failed`、记 `synthesized_failed`；写入 spec 并同步 README §7.2/§8.6。
- **文档同步**：README §6.4（审批不挂起引用）、§7.2（流式错误透传、断流收尾）、§8.6（截断终端与 `truncated_mode` 口径）与修复后行为同批更新。

## Capabilities

### New Capabilities

- `stream-fidelity-fix`：流式面保真契约——默认逐帧增量、审计持有最小化（仅未完成分片）、Responses 槽级完成与全局完成隔离、合成终端保序、跨帧占位符缝合还原、传输错误可观测与断流终端策略、流式上游错误状态透传、hold 字节按槽回收、截断合成发送成功才置位、流式审批不挂起声明。

### Modified Capabilities

- 无。本 change 新增 capability；既有 `openspec/specs/stream-protocol-parity/spec.md`、`openspec/specs/llm-streaming-parity/spec.md` 等契约中与本 spec 冲突的旧口径（空流/截断终止、残缺剥离）在 apply 阶段按 `openspec/changes/veil-stream-fidelity-fix/specs/stream-fidelity-fix/spec.md` 为准同步并在归档时随 canonical 修订，不作为本 change 的 MODIFIED delta。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `S1` | critical | 抑制判据改「审计非 off + 确有未完成分片」；完成审计后释放；mock 慢速分片逐帧到达回归 | 1.1、1.2 |
| `S2` | critical | 全局完成仅认 `completed/failed/incomplete`；per-item done 走槽级审计与清理；多 item 阻断回归 | 2.1、2.2 |
| `S3` | major | 合成终端前 flush 边界滞留帧并先于终端下行；delta A 后 error 保序回归 | 3.1、3.2 |
| `S4` | major | 还原层跨帧 carry 缝合凭证/PII token；流末残片按既有口径剥离；两切分位置回归 | 4.1、4.2、4.3 |
| `S5` | major | `chunk()` `Err` 记 warn + 截断观测；mock 中途断连测试 | 5.1、5.3 |
| `S6` | major | 上游 `status>=400` 或非 `text/event-stream` 透传状态与字节；500 JSON/HTML 测试；README §7.2 | 6.1、6.2、6.3 |
| `S7` | minor | 按槽记账并回收字节；长流多工具不误判；真超限仍 fail-closed | 7.1、7.2 |
| `S8` | minor | keepalive 门控与抑制同判据（仅未完成分片）；keepalive 触发条件测试 | 1.3 |
| `S9` | minor | 截断合成仅发送成功后置位；截断+下游早断测试 | 8.1、8.2 |
| `S10` | record/decision | design Non-Goal 记录 Python 挂起保活未迁移；spec 声明不挂起；apply e2e 不回退 | 9.1、9.2 |
| `S11` | record/decision | design 固化断流终端策略与 `truncated_mode` 口径；断流矩阵回归；README §7.2/§8.6 | 5.2、5.3、5.4 |

## Non-Goals（显式）

- **`S10` 不迁移**：Python 原仓审批挂起期独立保活（`_llm.py:1948-1969`）不迁入 Rust；流式审批维持不挂起（README §6.4），恢复需新 change 交付。
- **不伪造成功**：断流/截断不得合成伪造内容、usage 或成功语义；Anthropic 不合成 `message_stop`；Responses 只出 `response.failed`。
- **不碰审计 verdict 判定口径、脱敏 recognizer 集合与采样策略、usage `max` 口径、`stream_options` 注入合并语义。**
- **不改 `src/`、`tests/` 与 README**：本 change 只交付规划 artifacts，实现与文档改动留待 apply 阶段；不改 `openspec/changes/` 内既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-stream-fidelity-fix/proposal.md`、`design.md`、`specs/stream-fidelity-fix/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/service/audit/hold.rs`、`src/handler/llm/pump/decide.rs`、`src/handler/llm/pump/spawn.rs`、`src/handler/llm/pump/event.rs`、`src/handler/llm/dispatch.rs`、`src/service/credential_vault.rs`、`src/service/pii/chunk.rs`、`src/service/redaction/leaf.rs`、`src/service/redaction/seam.rs`、对应单测与 e2e、`README.md` §6.4/§7.2/§8.6。
- **影响系统**：三协议流式增量与终止语义、审计持有与阻断时序、占位符还原正确性、上游错误透传、hold 容量记账。
- **依赖**：无新依赖；仅既有 `serde_json`、`axum`、`tokio`、`reqwest` 与测试设施。
