# Design — veil-stream-terminator-convergence

> 本设计承载 `veil-audit-r4-remediation`（2026-09-16 归档）中**显式延后的架构收敛项**（归档 `design.md` §K、§10 Non-goals 第 3 条、`tasks.md` 9.1）。所有「现状证据」均为只读核验后的 `file:line` 锚点（apply 期以现行源码为真相源）。本 change 为 **artifacts-only（规划）**，apply 期才落源码。
>
> **裁断来源**：延后决策来自 r4 的 Oracle 架构审查（Q9/§K）；本 design 的目标结构与边界为该延后项独立评审的前置输入。

---

## 1. 现状证据（只读核验）

### 1.1 阻断/终止帧注入点（重复实现）

| # | 注入点 | 锚点 | 产出 | 终端位写入 |
|---|---|---|---|---|
| I-1 | 流内阻断臂 `apply_reject_block` | `src/handler/llm/pump/spawn/event_loop.rs:137-176` | `block_inject::protocol_block_frames(...)`（`:163-170`） | `rejected_sticky=true`(`:144`)、`audit_blocked=true`(`:145`)、`terminal_sent=true`(`:146`)、`block_injected=true`(`:161`) |
| I-2 | 收尾终审臂（RED-5 terminal audit） | `src/handler/llm/pump/spawn/terminal.rs:152-176` | `block_inject::protocol_block_frames(...)`（`:161-168`）| `terminal_sent=true`(`:153`)、`block_injected=true`(`:159`) |
| I-3 | 中途断流终端 | `src/handler/llm/pump/synth_flush.rs:71-160` | Chat `chat_done_frame()`(`:93`)、Responses `synthesize_truncation(...)`(`:130-132`)、Anthropic 仅观测(`:113-118`) | `mark_terminal`(`:101`/`:142`) |
| I-4 | 真空流最小终止 | `src/handler/llm/pump/spawn/terminal.rs:283-312` | `block_inject::empty_stream_frames(...)`(`:291-292`) | `block_injected=true`(`:296`)、`mark_terminal`(`:310`) |
| I-5 | Responses `type:"error"` 单帧 | `src/handler/llm/pump/spawn/event_loop.rs:290-343` | `block_inject::responses_failed_frame(...)`(`:323-327`) | `responses_failed_sent=true`(`:295`)、`terminal_sent=true`(`:338`)、`mark_terminal`(`:339`)、`terminated=true`(`:341`) |

I-1 与 I-2 是**同一协议帧构造逻辑的两处独立副本**（均调 `protocol_block_frames`，唯 `metrics` 参数不同：I-1 传 `Some(&env.metrics)`、I-2 传 `None`，见 `src/service/block_inject/frames.rs:141-160` 签名）。I-3/I-4 各承载一套 `match protocol` 的终端帧选择。

### 1.2 「恰一终端」依赖的跨模块 flag（精确集合）

`PumpLoopState` 声明见 `src/handler/llm/pump/spawn/setup.rs:49-76`，初始化见 `:115-138`。

| flag | 声明 | 写点（file:line） | 读点（file:line） |
|---|---|---|---|
| `any_frame_sent` | `setup.rs:64` | `event_loop.rs:318`、`:334`、`:776`；`terminal.rs:206`、`:248` | 经参数入 `decide::should_apply_midstream_terminal`（`decide.rs:81,84`）；经参数入 `event::should_synthesize_empty_stream`（`event.rs:79`） |
| `terminated` | `setup.rs:65` | `event_loop.rs:341`、`:346` | `event_loop.rs:119`（`run_pump` 循环跳出） |
| `rejected_sticky` | `setup.rs:66` | `event_loop.rs:144` | `event_loop.rs:251`、`:263`（经 `decide::sticky_suppress_action`）、`:366` |
| `block_injected` | `setup.rs:67` | `event_loop.rs:161`；`terminal.rs:159`、`:296` | 经参数入 `decide.rs:78`；`finish.rs:74`（`PumpOutcome`） |
| `audit_blocked` | `setup.rs:68` | `event_loop.rs:145` | `finish.rs:70`（`record_aux_counts`） |
| `terminal_sent` | `setup.rs:69` | `event_loop.rs:146`、`:338`、`:623`、`:759`；`terminal.rs:153`、`:279` | `event_loop.rs:230`、`:277`、`:283`、`:358`、`:756`；`terminal.rs:77`/`:103`（经 `TerminalCtx`） |
| `responses_failed_sent` | `setup.rs:70` | `event_loop.rs:295`、`:350` | `event_loop.rs:285`（经 `decide::responses_control_action`，`decide.rs:25-41`） |
| `StreamMeta.terminal_injected` | `src/service/sse/meta.rs:33` | 经 `block_inject::mark_terminal`（`src/service/block_inject/terminal.rs:14`）：`event_loop.rs:173`、`:339`；`terminal.rs:171`、`:310`；`synth_flush.rs:101`、`:142` | `finish.rs:75`（`PumpOutcome.terminal_injected`，`src/handler/llm/pump.rs:94`）；多测试断言 |
| `StreamMeta.truncated_mode` | `src/service/sse/meta.rs:32` | 经 `set_truncated`（`meta.rs:36-50`）：`event_loop.rs:231`；`terminal.rs:294`、`:300`；`synth_flush.rs:108`、`:115`、`:144` | `finish.rs:61`（`record_chat`）；`aggregate`/`admin` 指标读取 |

> 关键观察：**9 枚状态位中 7 枚在 ≥2 个模块被写**；`terminal_sent` 在 2 个模块、6 处被写，`block_injected` 在 2 个模块、3 处被写，`any_frame_sent` 在 2 个模块、5 处被写。「恰一终端」由这些写点与 `decide.rs`/`event.rs` 的纯谓词协同维持，**无单一类型可承载该不变量**。

### 1.3 既有已锁定行为（本 change MUST NOT 改变）

- 三协议终端集合与真空流/中途断流分野：canonical `llm-protocol-hardening`（`Responses 恒恰一终端`）、`stream-fidelity-fix`（`终端帧 SHALL 恒恰一`）、`llm-proto-closeout`（真空流最小终止）。
- 流内阻断「先清缓冲、非截断不记截断计数」（`event_loop.rs:150-159`）、`rejected_sticky` 粘滞抑制（`event_loop.rs:251-273`）。
- 合成终端前先 flush 边界滞留帧（`synth_flush.rs:23-43` 的 `flush_pre_terminal`，D3/S3 保序）。
- 终端 `send` 失败不置位（D9/S9，`terminal.rs:278-279`、`synth_flush.rs:95-111`）。
- Responses 阻断序列接续上游序号游标 `base = cursor.map_or(0, |c| c + 1)`（`frames.rs:156,163`）。
- `mark_terminal` / `dedupe_terminal_frames` 帧级去重口径（`block_inject/terminal.rs:14,23-57`）。

---

## 2. 目标结构

### 2.1 `StreamTerminator`（新模块 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->）

**职责**：成为流式「恰一终端」状态机的**唯一所有者**与阻断/终止帧注入的**唯一入口**。

**持有状态**（取代 `PumpLoopState` 的 7 枚终端相关 bool + `meta.terminal_injected`）：

```rust
pub(super) struct StreamTerminator {
    // 单一状态：替代 terminal_sent / block_injected / rejected_sticky / terminated / audit_blocked
    state: TerminalState,          // Open | Blocked | Synthesized | UpstreamTerminal
    responses_failed_seen: bool,   // 取代 responses_failed_sent（上游 failed 分类，非终端位）
    any_frame_sent: bool,          // 帧发送事实（note_frame_sent 唯一写点）
}
```

> `StreamMeta.terminal_injected` 保留为**可观测汇**（`finish.rs` 据此组装 `PumpOutcome`，多测试断言），但其写点收敛为 `StreamTerminator` 单一调用；`meta.truncated_mode` 保持 `set_truncated` 既有写入口，由调用点触发（计数留在调用点）。

**接口**（命名 apply 期可依仓库惯例微调；`TerminalPlan` 为纯数据）：

```rust
pub(super) enum TerminalKind { Block, Midstream, EmptyStream, ResponsesError }
pub(super) enum TerminalPlan { None, Frames { kind: TerminalKind, frames: Vec<String> } }

impl StreamTerminator {
    fn new() -> Self;
    fn is_open(&self) -> bool;                 // 供 decide/event 纯谓词读取
    fn block_injected(&self) -> bool;          // 供 PumpOutcome
    fn terminated(&self) -> bool;              // 供 run_pump 循环跳出

    fn note_frame_sent(&mut self);             // any_frame_sent 唯一写点
    fn mark_upstream_terminal(&mut self);      // event_terminal / [DONE]：上游终端
    fn note_sticky_rejected(&mut self);        // rejected_sticky 语义
    fn mark_audit_blocked(&mut self);          // audit_blocked 语义

    fn plan_block(&self, protocol, reason, conv_id, blocked_index, seq_cursor, metrics) -> TerminalPlan;
    fn plan_midstream(&self, protocol, conv_id, clean_close, seq_cursor) -> TerminalPlan;
    fn plan_empty_stream(&self, protocol_name, conv_id) -> TerminalPlan;
    fn plan_responses_error(&self, fid, err_obj, seq) -> TerminalPlan;

    fn commit(&mut self, kind: TerminalKind, all_frames_sent: bool); // 唯一终端位写点
}
```

**调用点契约（计数留在调用点）**：调用点循环 `env.pump_tx.send(frame)`、逐帧 `env.metrics.add_sse_event()` / `record_emitted_events(...)`、按需 `set_truncated(...)`，随后以「是否全部 send 成功」调 `commit(kind, all_frames_sent)` 更新终端位——计数与发送**不迁入** `StreamTerminator`。`plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None`（幂等）。

### 2.2 与现有模块的边界

| 模块 | 现状角色 | 收敛后角色 |
|---|---|---|
| `src/handler/llm/pump/spawn/event_loop.rs`（782 行） | I-1 阻断注入 + I-5 Responses error + 上游终端置位 | 调用 `terminator.plan_block`/`plan_responses_error` + 调用点 send/计数 + `commit`；`mark_upstream_terminal` 替代直写 `terminal_sent`；**不再**构造 `protocol_block_frames`/`responses_failed_frame` |
| `src/handler/llm/pump/spawn/terminal.rs`（356 行） | I-2 阻断注入 + I-4 真空流 + 中途断流调度 | `finalize` 仅保留审计终审、截断/残余处置与调度；I-2/I-4 改调 `terminator.plan_block`/`plan_empty_stream`；**不再**直写终端位；`TerminalCtx`（`:32-67`）删去已被 `StreamTerminator` 接管的 `terminal_sent`/`block_injected`/`any_frame_sent` 借用字段 |
| `src/handler/llm/pump/synth_flush.rs`（161 行） | I-3 中途断流终端帧选择 | `flush_pre_terminal`（`:23-43`）保留；`midstream_terminal`（`:71-160`）的**帧选择**迁入 `terminator.plan_midstream`，保留 `MidstreamTerminalOutcome`（`:48-51`）与 send/计数调用点；`synth_flush` 保留「flush 保序 + 观测（`set_truncated`/warn）」职责 |
| `src/service/block_inject/frames.rs`（530 行） | 帧/体**合成**（含 `protocol_block_frames`/`synthesize_truncation`/`empty_stream_frames`） | **不变**：`StreamTerminator` 是这些纯帧工厂的调用者，不是替代者；`block_inject` 保持「只合成帧/体、不累积字节」声明（`frames.rs:440-444`） |
| `src/service/block_inject/terminal.rs`（74 行） | 帧级去重/计数 + `mark_terminal` | **不变**（帧级工具）；`StreamTerminator` 的 `commit` 调用 `mark_terminal` 写 `StreamMeta.terminal_injected` |
| `src/service/sse/meta.rs`（50 行） | `StreamMeta` + `set_truncated` | **不变**；`truncated_mode` 写入口与四态语义不动 |
| `src/handler/llm/pump/decide.rs`（126 行） | 纯决策谓词 | `should_apply_midstream_terminal`（`:71-85`）与 `sticky_suppress_action`（`:54-66`）保持纯函数，入参改取 `terminator.is_open()`/`block_injected()` 等访问器值 |
| `src/handler/llm/pump/spawn/finish.rs`（77 行） | 组装 `PumpOutcome` | `state.block_injected`/`state.terminal_sent` 改经 `terminator.block_injected()`；`PumpOutcome`（`pump.rs:88-95`）字段不变 |
| `src/handler/llm/pump/spawn/setup.rs`（173 行） | `PumpLoopState` 持有 flag | 持有 `StreamTerminator`（单字段）替代 7 枚 bool；`setup.rs:115-138` 初始化同步 |

---

## 3. 「恰一终端」如何被结构化保证

1. **单写者**：终端位（`is_open`/`block_injected`/`terminated`）只能经 `StreamTerminator` 的 `commit`/`mark_upstream_terminal`/`note_sticky_rejected` 变更；`PumpLoopState` 不再暴露可直写的同名字段（删除公开字段，改私有于 `StreamTerminator`）。
2. **单入口 + 幂等**：所有终端帧注入必须先 `plan_*`；`plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None`，调用点收到空计划即不发送、不计数——**重复注入在类型层被拒**，不依赖「调用点记得判 flag」。
3. **状态迁移封闭**：`state` 迁移为 `Open → {Blocked | Synthesized | UpstreamTerminal}`，皆为终态（无反向迁移）；`commit` 在终态后为 no-op。`responses_failed_seen` 独立于 `state`（它表达上游分类，不表达终端位），避免两概念混用同一 bool。
4. **`debug_assert` 守护**：`commit` 入口断言「本次为首次迁移」，并在 debug 构建暴露违反调用约定的路径（与 canonical `architecture-cleanup`「服务层不变量守护补齐」同法）。
5. **行为锁定测试**：新增 `stream_terminator_exact_one_terminal_matrix`（三协议 × {阻断, 中途断流, 真空流, 上游 error}）断言每路径恰一终端帧；新增 `stream_terminator_injection_idempotent` 断言已终端后 `plan_*` 返回 `None`。

---

## 4. 备选方案与否决理由

| 备选 | 描述 | 否决理由 |
|---|---|---|
| A. 仅在 `block_inject` 加去重包装 | 保留泵内两处注入，仅在帧工厂层去重 | 治标不治本：终端**状态**仍跨模块协调，`!is_open()` 判定仍散落；且 `block_inject` 会越权持有泵状态，违反其「纯帧工厂」边界（`frames.rs:440-444`） |
| B. 仅合并 I-1/I-2 重复阻断帧构造 | 抽一个 `inject_block_frames(...)` helper | 不触碰终止帧（I-3/I-4）与 7 枚 flag，跨模块耦合仍在；r4 §K 已把「完整 `StreamTerminator` 收敛」作为整体延后项，半程收敛不消除风险 |
| C. 用 `enum` 替换 bool 但保留多模块写点 | 只把 flag 换成状态枚举，写点仍分散 | 枚举不解决「谁能写」问题；幂等与单入口仍靠约定，未结构化 |
| D. **本方案：单一所有者类型 + 单一注入入口 + 幂等 plan** | `StreamTerminator` 独占状态与注入 | 采纳。收敛面可控（仅泵内 4 个模块 + 1 新模块），不动 `block_inject` 帧工厂与 `StreamMeta` 语义，行为保持由既有回归 + 新矩阵测试双锁 |

---

## 5. 失败模式

| 失败模式 | 触发 | 缓解 |
|---|---|---|
| 漏置终端位（重复终端） | `commit` 未在发送成功后调用 | `debug_assert` 单次迁移 + 新增幂等/矩阵测试；`PumpOutcome.terminal_injected` 既有断言兜底 |
| 计数漂移 | 发送/计数迁入 `StreamTerminator` 或调用点漏记 | 设计显式要求「计数留在调用点」；`PumpOutcome.forwarded` 与 `sse_event_count` 既有测试锁定 |
| 文件体量越线 | `event_loop.rs`（782）/`spawn_tests.rs`（784）已逼近 800 | 注入逻辑**迁出** `event_loop.rs` 降低行数；新测试落 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（不追加 `spawn_tests.rs`）；`check_file_sizes.py` 门禁 |
| 借用冲突 | `StreamTerminator` 与 `PumpLoopState` 同时可变借用 | 以 `TerminalCtx`/`FrameSink`（`restore_emit.rs:20-30`）同法：终态由 `StreamTerminator` 持有，其余状态仍归 `PumpLoopState`，调用点按需短借用 |
| 文案/注释过度声明 | 新的「单一所有者」措辞与实现不符 | 验收以行为测试为准（矩阵/幂等），注释准确性为 code-review 项（沿用 r4 M-5 口径） |

---

## 6. 迁移步骤（apply 期）

1. **骨架先行**：新建 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->（`StreamTerminator`/`TerminalPlan`/`TerminalKind`）+ 在 `spawn.rs:5-10` 注册 `mod terminator;`；此步纯新增、零调用点改动（可编译、全测试绿）。
2. **状态搬迁**：`PumpLoopState`（`setup.rs:49-76`）删去 7 枚终端 bool，改持 `terminator: StreamTerminator`；`setup.rs:115-138` 初始化同步；各读点改访问器（`decide.rs`/`event.rs` 纯谓词仅换入参来源）。
3. **注入点收敛**：按 I-1 → I-2 → I-3 → I-4 → I-5 顺序逐点改造为 `plan_*` + 调用点 send/计数 + `commit`；每改动一点跑 `cargo test` 保绿（原子提交）。
4. **上游终端收敛**：`event_loop.rs:622-624` 与 `:753-772` 改 `mark_upstream_terminal()`。
5. **测试补齐**：新建 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（在 `pump.rs:33-46` 注册 `#[cfg(test)] mod terminator_tests;`），新增矩阵与幂等测试。
6. **门禁**：`bash scripts/gate.sh` 七步全绿；`openspec validate --strict` 通过。
7. **canonical 晋升（归档期）**：按 r2/r3/r4 先例，归档时把本 change 的 `specs/architecture-cleanup/spec.md` delta 晋升 canonical `openspec/specs/architecture-cleanup/spec.md`。

---

## 7. 覆盖表（注入点 → 收敛任务 → 证据）

| 现状注入点 | 锚点 | 收敛任务 | 关键回归 |
|---|---|---|---|
| I-1 流内阻断 | `event_loop.rs:137-176` | 2.1 | `direct_rejected_sticky_suppresses_tool_frames`（`spawn_tests.rs:501`） |
| I-2 收尾阻断 | `terminal.rs:152-176` | 2.2 | `synth_terminal_flush_order`（`spawn_tests.rs:645`）、`synth_terminal_single`（`:683`） |
| I-3 中途断流 | `synth_flush.rs:71-160` | 3.1 | `truncation_terminal_flush_order`（`spawn_tests.rs:720`）、`truncation_send_failure_guard`（`:761`） |
| I-4 真空流 | `terminal.rs:283-312` | 3.2 | `spawn_decision_empty_stream_gate_call_order`（`spawn_tests.rs:360`） |
| I-5 Responses error | `event_loop.rs:290-343` | 3.2 | `direct_n1_completed_then_error_single_terminal`（`spawn_tests.rs:378`） |
| flag 集合 | `setup.rs:64-70` | 1.2/2.1 | 新增 `stream_terminator_exact_one_terminal_matrix` |
