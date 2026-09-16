## Why

本 change 是 `veil-audit-r4-remediation`（2026-09-16 归档）中**显式延后的架构收敛项**：该轮 Oracle 架构审查识别出「阻断/终止帧注入逻辑跨模块重复、且『恰一终端』不变量由跨模块 flag 协调维持」的结构性风险，当时以「收敛面大、触及三协议终止语义（高风险），须独立 change + 独立评审」为由登记为**后续独立 change**（见归档 `design.md` §K 与 §10 Non-goals 第 3 条、`tasks.md` 9.1）。本 change 即该延后项。

现状风险（只读核验，逐条 `file:line` 见 `design.md` §1）：流式阻断帧在**两处**独立构造并注入——流内阻断臂 `src/handler/llm/pump/spawn/event_loop.rs:160-173`（`apply_reject_block`）与收尾终审臂 `src/handler/llm/pump/spawn/terminal.rs:158-171`；终止帧合成另在 `src/handler/llm/pump/synth_flush.rs:71-160`（中途断流）与 `src/handler/llm/pump/spawn/terminal.rs:283-312`（真空流）各成一路。同时「恰一终端」由 `PumpLoopState`（`src/handler/llm/pump/spawn/setup.rs:64-70`）中 6 枚 bool（`any_frame_sent`/`terminated`/`rejected_sticky`/`block_injected`/`audit_blocked`/`terminal_sent`/`responses_failed_sent`）跨 `event_loop.rs`、`terminal.rs`、`synth_flush.rs`、`finish.rs` 四处读写协调，另叠 `StreamMeta.terminal_injected`（`src/service/sse/meta.rs:30-34`）与 `truncated_mode` 两个随流标记。**不变量因此不是结构性的，而是约定性的**：任一处漏置/错置 flag 即可产生重复或缺失终端，且没有单一类型可承载「注入恰一次」的保证。

## What Changes

**一个纯重构（behavior-preserving）**：把流式阻断帧/终止帧的注入与「恰一终端」状态机收敛为单一所有者 `StreamTerminator`（落点 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->，命名为实现期可依仓库惯例微调）。

- **单一所有者**：`StreamTerminator` 独占终端状态写入（`terminal_sent`/`block_injected`/`rejected_sticky`/`terminated`/`audit_blocked`/`responses_failed_sent` 与 `StreamMeta.terminal_injected` 的终端写点）。`PumpLoopState` 与各泵模块 SHALL NOT 再直写这些位，读取方经访问器（如 `is_open()`/`block_injected()`）。
- **单一注入入口**：`plan_block`/`plan_midstream`/`plan_empty_stream`/`plan_responses_error` 各自返回 `TerminalPlan`（本次应发送的协议帧集 + `TerminalKind`），消灭两处重复的 `protocol_block_frames` 构造与散落的 `match protocol` 终端帧选择。
- **幂等**：已终端/已阻断（`!is_open()`）时再次请求注入返回空计划（`TerminalPlan::None`），结构性保证不产生第二终端。
- **计数留在调用点**：实际 `pump_tx.send` 与帧级/截断计数（`metrics.add_sse_event()`、`record_emitted_events`、`set_truncated`）仍在调用点执行（不迁入 `StreamTerminator` 吞掉计数），发送结果经 `commit` 回填由 `StreamTerminator` 更新终端位。
- **删除重复实现**：`event_loop.rs:160-173` 与 `terminal.rs:158-171` 的重复阻断帧构造收敛为一处调用；`synth_flush.rs` 的 Chat/Responses 终端帧选择迁入 `plan_midstream`。
- **回归锁定**：新增 `stream_terminator_exact_one_terminal_matrix`（三协议 × 阻断/中途断流/真空流/上游 error 的恰一终端矩阵）与 `stream_terminator_injection_idempotent`（重复注入被拒）。

## Capabilities

### New Capabilities

无（本 change 只修改既有 capability）。

### Modified Capabilities

- `architecture-cleanup`: 新增 requirement「流式阻断/终止帧注入单一所有者」——把 `StreamTerminator` 单一所有者、单一注入入口、注入幂等与「恰一终端」结构性保证、计数留在调用点、纯重构行为保持全部锁定为契约。该 capability 的 Purpose 即「结构性/可维护性契约，所有 REQUIREMENT 以纯重构为前提，不改变对外运行时行为」，与本 change 同域。

## Non-goals

- **无协议/行为变更**：线级帧序、帧内容、`truncated_mode` 观测、审计时序、`PumpOutcome` 字段逐项不变；不重开 r2/r3/r4 已声明的有意偏离。
- **不新增导出指标**：帧级计数与截断观测口径不变，不新增指标族/端点维度。
- **不改脱敏/还原**：不触及请求/响应侧脱敏、占位符还原、`minted-set` 授权。
- **不改四态截断语义**：`TruncatedMode` 四态（`src/service/sse/meta.rs:10-17`）语义与白名单落点不动。
- **不新增端点**；不引入新 crate 依赖；不改 `NONSTREAM_MAX_BYTES`/审计上限/阈值。
- **不重开** `veil-audit-r4-remediation` 已修复的 `emit_restored_json_frame` 统一（该收敛已在位，见 `src/handler/llm/pump/spawn/restore_emit.rs:55-88`），本 change 不重复。
- **非流阻断体**（`nonstream_block_body`）与 `block_inject` 的帧**构造**（`frames.rs`）不在收敛范围——只收敛**泵内注入点**与**终端状态机**；`block_inject` 保持「只合成帧/体、不累积字节」的既有职责声明（`src/service/block_inject/frames.rs:440-444`）。

## 兼容性

**非 BREAKING**：纯重构 + 行为不变。对外可见的 HTTP 响应、SSE 帧、状态码、`truncated_mode` 观测与 `PumpOutcome` 全部逐项等价；无配置项变化，无需迁移步骤（迁移仅指内部模块/类型搬迁，见 `design.md` §6）。

## 验证门禁影响

- 每任务实施后跑 `bash scripts/gate.sh` 七步（fmt / clippy `-D warnings` / test / doc-paths / file-sizes / conformance / go vet+test），任一步非零即未完成。
- `python3 scripts/check_doc_paths.py`：本 change 内所有 `src/...rs:NNN` 锚点须存在且在界；规划期新建路径（`terminator.rs`、`terminator_tests.rs`）以 `<!-- doc-paths-ignore -->` 标注。
- `python3 scripts/check_file_sizes.py`：`src/handler/llm/pump/spawn/event_loop.rs`（782 行）与 `spawn_tests.rs`（784 行）逼近 800 上限——本 change **须降低** `event_loop.rs`/`terminal.rs` 行数（迁出注入逻辑），新测试**不得**追加进 `spawn_tests.rs`，应落新 sibling `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（在 `src/handler/llm/pump.rs:33-46` 注册）。
- `openspec validate veil-stream-terminator-convergence --strict` 通过（`openspec/specs/architecture-cleanup/spec.md` 既有 requirement header/场景名不受影响——本 change 仅 `## ADDED Requirements`，无 MODIFIED）。
- **本 change 为 artifacts-only（规划）**：规划期不改 `src/**`、`tests/**`、`scripts/**`、`README.md`、`openspec/specs/**` 与任何其他 change 目录；不归档、不 `git add/commit`、不运行 `cargo`。
