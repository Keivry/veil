# Proposal

## Why

第七轮审计（7 维度代码级复核 + 逐项证据核实）确认基线整体健康，但发现 2 项 Major 安全/审计缺陷与 6 项 Minor 缺陷：

- **R7-01（Major，审计 fail-open）**：Responses 流中途截断（无 `response.completed`）时，仍缺 per-item `.done` 的 pending 工具槽只在全局完成臂被审计（`src/handler/llm/pump/spawn/event_loop.rs`），而终端最终审计只遍历 `hold.tool_triples()`（done 槽 ∪ Chat/Anthropic 分片），pending 槽被静默跳过且 `release_audited()` 不清理它们——危险参数在 `block` 模式下仅剩 warn，无 verdict/阻断/建单，与 Chat/Anthropic 的终端必审语义不对称。
- **R7-02（Major，脱敏旁路）**：`src/service/json_walk.rs` 的 Object 分支只递归值、键名从不经过 leaf 回调，PII/凭据以 JSON 键形态出现时明文转发上游；响应侧新 PII 键位不被掩码；响应侧全文还原反而会还原键位 token（请求/响应不对称）。
- **R7-03（Minor）**：Responses `type:"error"` 合成 `response.failed` 的终端计划 `truncated: None`，调用点用 `..` 丢弃截断观测且从不 `set_truncated`，README §7.2 声称的 `synthesized_failed` 实际未落 metrics。
- **R7-04（Minor）**：Chat 稳定前缀提取无条件读取非标准顶层 `system`，与 canonical「Anthropic MAY 另取顶层 `system`」的口径漂移，同一请求多写一个字段即换会话键。
- **R7-05（Minor）**：非流请求（`stream` 未为 `true`）而上游仍回 `text/event-stream` 时，复用带 30s 总超时的非流 client 转发；长流被总超时截断且未声明。
- **R7-07（Minor）**：`src/service/block_inject/terminal.rs` 的 `dedupe_terminal_frames`/`count_done` 仅测试引用却无 `#[cfg(test)]`，与既有 `terminal_count` 的收编口径不一致。
- **R7-08（Minor，可观测性）**：`src/handler/llm/dispatch.rs` 在键推导前无条件读取 `prompt_cache_key`/`previous_response_id`；协议外原生键经后续白名单静默丢弃（无告警/无计数），行为未文档化。
- **R7-09（Minor，文档漂移）**：README §7.2 以截断简写 `cache_read/cache_creation_input_tokens` 指代实现的精确字段名；§7.9 的逐字符豁免集遗漏 `,`/`:`。

本 change 以 Oracle 已裁决的修复方向收敛上述 8 项发现，使 README/canonical 与实现重新一致，并为最危险的 R7-01/R7-02 补齐回归覆盖。

## What Changes

- **R7-01（运行时行为变更，安全修复）**：新增 `AuditHold::release_pending_audited()`（移除 `!done_seen` 槽并按饱和算术归还记账字节）；`event_loop.rs` 全局完成臂对 pending 槽审计且未 `Block` 后调用该释放；`terminal.rs` 终端最终审计追加 pending 槽循环（门控 `protocol.is_responses() && !hold.is_rejected()`，done 槽在前、pending 槽在后，verdict 处置与 done 槽一致，`blocked_index` 取该槽自身 `output_index`）。清理完成流经释放后终端循环自然 no-op；截断流在终端恰审一次。
- **R7-02（运行时行为变更，安全修复）**：`json_walk_nested` 的 Object 分支对键位应用 leaf（键按纯字符串 leaf 处理，不做 stringified-JSON 递归）；以原始键集合做碰撞回退（替换后键与原始键/已选键同名时保留原键）；命中键位替换同置 `x-veil-normalized`；响应侧掩码与还原沿用同一入口（还原全文扫描已覆盖键位）。新增键位脱敏、碰撞回退、键串内嵌子串、token 形态键、往返有效性单测。
- **R7-03**：`plan_responses_error` 返回 `truncated: Some(TruncatedMode::SynthesizedFailed)`；Responses error 调用点解构 `truncated` 并在 `commit` 后**无条件** `set_truncated`（不新增 helper，不以 `terminal_ok` 门控；`terminal_ok` 仍只决定 commit 的终端位）。
- **R7-04**：`extract_system` 的顶层 `system` 读取门控为 `protocol.is_anthropic()`（Chat 仅 `messages` 首条 `system`/`developer`；Responses 不变）；修正代码注释与 README §7.3 措辞为「Anthropic 取原生顶层 `system` 或 `messages` 首条；Chat 仅 `messages`；Responses 取 `instructions`」。
- **R7-05（声明，不重发请求）**：README §7.2 增加声明——非流请求遇上游 `text/event-stream`（`status<400`）时经非流 client 总超时转发（不重发上游非幂等请求），超时按中途断流终端路径收尾；长流须显式 `stream:true`。
- **R7-07**：`dedupe_terminal_frames` 与 `count_done` 加 `#[cfg(test)]`（`terminal_count` 已收编）；核查 `src/service/block_inject.rs` 重导出（glob 随收编自动收窄，显式重导出则同加 gating），零生产行为变更。
- **R7-08（文档声明，选项 b）**：README §7.3 明确协议外原生键被**静默忽略**（不命中、不告警、不计数）；本 change 不引入提取门控与计数器（见 design D7 登记）。
- **R7-09（文档修正）**：README §7.2 缓存字段名改为精确的 `cache_read_input_tokens`/`cache_creation_input_tokens`；README §7.9 豁免集补齐为 `{ } " [ ] , :`（或声明为有意保留的结构符超集）。

### Non-goals

- 不重发上游请求处理非流遇 SSE 场景（R7-05 选择声明而非重发；重发会造成第二次非幂等模型调用）。
- 不扩展已声明有意差异（README §6/§7/§8）——仅执行 R7-04/§7.3、R7-05/§7.2、R7-08/§7.3、R7-09/§7.2+§7.9 的文档修正。
- 不扩展 `scripts/check_doc_paths.py` 语义。
- 不引入 R7-08 的提取门控/告警/计数（design D7 的选项 b；选项 a 登记为后续候选）。
- 不重开 R7-06 等未纳入本轮决策清单的审计项（design D10 登记）。

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `redaction`: R7-02 键位脱敏与碰撞回退（MODIFIED「json-aware 语义等价改写（FIX-5 权威定义）」）；R7-04/R7-08 稳定前缀 `system` 与协议原生键门控（ADDED「稳定前缀 `system` 提取与协议原生键的协议门控」）。
- `redaction-audit-coverage`: R7-01 Responses pending 槽终端最终审计恰一次（ADDED）；R7-09 §7.9 豁免集完整登记（MODIFIED「跨缝掩码 JSON 结构保真」）。
- `llm-protocol-hardening`: R7-03 Responses error 终端落 `synthesized_failed` 观测（MODIFIED「Chat 错误载荷帧即终端」）。
- `transport-fidelity-fix`: R7-05 非流请求遇上游 SSE 的总超时口径声明（MODIFIED「流式转发独立超时策略」）。
- `deadcode-positional-cleanup`: R7-07 测试专用终端 helper 收编（MODIFIED「零生产引用符号清零」）。
- `stream-protocol-parity`: R7-09 §7.2 Anthropic 缓存字段名精确登记（MODIFIED「Model and cache columns restored」）。

## Impact

- **代码**：`src/service/audit/hold.rs`、`src/handler/llm/pump/spawn/event_loop.rs`、`src/handler/llm/pump/spawn/terminal.rs`、`src/handler/llm/pump/spawn/terminator.rs`、`src/service/json_walk.rs`、`src/service/redaction/conversation_key.rs`、`src/service/block_inject/terminal.rs`、`src/service/block_inject.rs`（重导出核查）、`src/service/redaction/seam.rs`（`:224` doc comment 豁免集同步）、`src/service/llm_gateway/usage.rs`（`:26` doc comment 字段名同步）；新增/扩展单测（`hold/tests.rs`、`responses_audit_tests.rs`、`json_walk.rs` tests、`conversation_key_tests.rs`）。
- **文档**：`README.md`（§7.2×2、§7.3×2、§7.9）。
- **规范**：上述 6 个 canonical capability 的 change-local delta（归档时合并；本 change SHALL NOT 手改 `openspec/specs/**`）。
- **无 API 路径/环境变量/依赖变更**；R7-02 为安全修复型可观测变更（键位 PII 不再明文上游），R7-01 为审计 fail-closed 修正，均不构成配置迁移 BREAKING。
