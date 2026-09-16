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

`StreamTerminator` 私有字段声明见 `src/handler/llm/pump/spawn/terminator.rs:65-80`；`PumpLoopState` 以单字段持有见 `setup.rs:68`（初始化 `setup.rs:127`）。下表为 **3.3 收敛后**（apply 真相源）的实际写点/读点——原 7 枚 `PumpLoopState` bool 已删，`responses_failed_sent` 已更名为 `responses_failed_seen`：

| 位（语义） | `StreamTerminator` 私有字段 | 写点（唯一变更器，file:line） | 读点（访问器，file:line） |
|---|---|---|---|
| `any_frame_sent` | `any_frame_sent` | `note_frame_sent()`（`event_loop.rs:318`、`:337`、`:781`；`terminal.rs:200`、`:242`、`:274`） | `any_frame_sent()`（`terminal.rs:253`、`:289`，经参数入 `decide::should_apply_midstream_terminal`/`event::should_synthesize_empty_stream`） |
| `terminated` | `loop_terminated` | `mark_loop_terminated()`（`event_loop.rs:346`、`:350`） | `terminated()`（`event_loop.rs:120`，`run_pump` 循环跳出） |
| `rejected_sticky` | `rejected_sticky` | `note_sticky_rejected()`（`event_loop.rs:145`） | `rejected_sticky()`（`event_loop.rs:251`、`:264`、`:371`） |
| `block_injected` | `state`（`Blocked`/`EmptyStream`） | `commit()`（`event_loop.rs:173`；`terminal.rs:165`、`:314`） | `block_injected()`（`terminal.rs:252`、`:290`；`finish.rs:72` 组装 `PumpOutcome`） |
| `audit_blocked` | `audit_blocked` | `note_sticky_rejected()`（`event_loop.rs:145`） | `audit_blocked()`（`finish.rs:68`，`record_aux_counts`） |
| `terminal_sent` | `state`（`Blocked`/`Synthesized`/`UpstreamTerminal`/`ResponsesError`） | `commit()`（`event_loop.rs:173`、`:342`；`terminal.rs:165`、`:282`、`:314`）、`mark_upstream_terminal()`（`event_loop.rs:628`、`:764`） | `terminal_sent()`（`event_loop.rs:230`、`:277`、`:284`、`:363`、`:727`、`:761`；`terminal.rs:251`、`:288`） |
| `responses_failed_seen`（原 `responses_failed_sent`） | `responses_failed_seen` | `note_responses_failed()`（`event_loop.rs:295`、`:355`） | `responses_failed_seen()`（`event_loop.rs:285`，经 `decide::responses_control_action`，`decide.rs:25-41`） |
| `StreamMeta.terminal_injected` | `commit` 唯一回填 | `commit()`（经 `block_inject::mark_terminal`，`src/service/block_inject/terminal.rs:14`）：`event_loop.rs:173`、`:342`；`terminal.rs:165`、`:314` | `finish.rs:73`（`PumpOutcome.terminal_injected`，`src/handler/llm/pump.rs:94`）；多测试断言 |
| `StreamMeta.truncated_mode` | 调用点按 plan 落 | `set_truncated`（`src/service/sse/meta.rs:36-50`）：`event_loop.rs:231`；`terminal.rs:279`、`:311`（midstream/空流按 `plan.truncated`） | `finish.rs:59`（`record_chat`）；`aggregate`/`admin` 指标读取 |

> 收敛后观察：**全部终端位写入收敛至 `StreamTerminator` 单一所有者**（`commit`/`mark_upstream_terminal`/`mark_loop_terminated`/`note_sticky_rejected`/`note_responses_failed`/`note_frame_sent`），读点全部经访问器，泵内模块（`event_loop`/`terminal`/`finish`）无直写/直读；「恰一终端」由 `plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None` 结构性拒绝重复注入，不再依赖跨模块 flag 约定。

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

**持有状态**（取代 `PumpLoopState` 的 7 枚终端相关 bool + `meta.terminal_injected`；字段**全私有**，仅经访问器/变更器读写）：

```rust
// MAJOR-4 选项 (a)：测试模块 `pump::terminator_tests` 是 `pump::spawn` 的**兄弟**，
// `pub(super)` 只到 `spawn`、无法命名；故三种类型与 impl 统一声明
// `pub(in crate::handler::llm::pump)`，测试保持在 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->。
pub(in crate::handler::llm::pump) struct StreamTerminator {
    // 终端推进（terminal_sent / block_injected 的**位保留**语义）：Open 为唯一可注入态，
    // 迁移到任一终态后无反向迁移
    state: TerminalState,          // Open | Blocked | Synthesized | EmptyStream | UpstreamTerminal | ResponsesError
    loop_terminated: bool,         // 取代 terminated（run_pump 循环跳出；仅 Responses error/DuplicateFailed 置位）
    rejected_sticky: bool,         // 取代 rejected_sticky（I-1 粘滞拒绝；I-2 不置）
    audit_blocked: bool,           // 取代 audit_blocked（I-1 阻断命中，finish 的 record_aux_counts 读取）
    responses_failed_seen: bool,   // 取代 responses_failed_sent（上游 failed 分类，非终端位）
    any_frame_sent: bool,          // 帧发送事实（note_frame_sent 唯一写点）
}
```

> 说明：`terminal_sent` 与 `block_injected` 是**两条独立语义位**（I-1/I-2/I-4 置 `block_injected` 而不置 `terminal_sent`；I-3/I-5 置 `terminal_sent` 而不置 `block_injected`），故 `state` 必须保留该区分，不得压成单一「已终止」布尔；`rejected_sticky`/`audit_blocked` 与 `loop_terminated` 亦各有独立写点，一并保留为私有位，仅经访问器暴露。

> `StreamMeta.terminal_injected` 保留为**可观测汇**（`finish.rs` 据此组装 `PumpOutcome`，多测试断言），但其写点收敛为 `StreamTerminator` 单一调用；`meta.truncated_mode` 保持 `set_truncated` 既有写入口，由调用点按 plan 触发（计数留在调用点）。

**接口**（命名 apply 期可依仓库惯例微调；`TerminalPlan` 为纯数据）：

```rust
pub(in crate::handler::llm::pump) enum TerminalKind { Block, Midstream, EmptyStream, ResponsesError }

// MAJOR-6：`None` 严格保留给「未开放 / 已终端」（幂等拒绝，调用点零动作）；
// 「按设计零合成帧」不得用 `None` 表达——Anthropic 中途断流即 `Frames` + `frames` 为空。
// `truncated` 由 plan 携带、调用点落 `set_truncated`（观测口径不变）。
pub(in crate::handler::llm::pump) enum TerminalPlan {
    None,
    Frames {
        kind: TerminalKind,
        frames: Vec<String>,
        truncated: Option<TruncatedMode>,
    },
}

#[cfg_attr(not(test), allow(dead_code))] // MAJOR-8：迁移窗口登记，见 §2.3
impl StreamTerminator {
    fn new() -> Self;

    // 读取访问器（覆盖 §1.2 全部读点）
    fn is_open(&self) -> bool;                 // state == Open（供 decide/event 纯谓词）
    fn terminal_sent(&self) -> bool;           // terminal_sent 语义（event_loop.rs:230/358/756 等）
    fn block_injected(&self) -> bool;          // block_injected 语义（decide + PumpOutcome）
    fn terminated(&self) -> bool;              // loop_terminated（run_pump 循环跳出）
    fn any_frame_sent(&self) -> bool;          // MAJOR-7（decide.rs:81,84；event.rs:79）
    fn rejected_sticky(&self) -> bool;         // MAJOR-7（decide.rs:54-66；event_loop.rs:251/263/366）
    fn audit_blocked(&self) -> bool;           // MAJOR-7（finish.rs:70）
    fn responses_failed_seen(&self) -> bool;   // MAJOR-7（decide.rs:25-41；event_loop.rs:283-288）

    // 变更器（终端位唯一写点族）
    fn note_frame_sent(&mut self);             // any_frame_sent 唯一写点
    fn mark_upstream_terminal(&mut self);      // event_terminal（:622-624）/ [DONE]（:753-772）：置 terminal_sent
    fn note_sticky_rejected(&mut self);        // I-1 rejected_sticky + audit_blocked
    fn note_responses_failed(&mut self);       // responses_failed_sent 写点（:295/:350）
    fn mark_loop_terminated(&mut self);        // 仅置 loop_terminated（BLOCKER-3：无帧也可终止循环）

    // 注入计划（`!is_open()` 时一律返回 TerminalPlan::None）
    fn plan_block(&self, protocol, reason, conv_id, blocked_index, seq_cursor, metrics) -> TerminalPlan;
    // MAJOR-5：镜像 plan_block 增 `metrics`——Responses 臂需
    // `resolve_conv_id(None, &Value::Null, Some(metrics), "truncated")`（`synth_flush.rs:71-160`
    // 的帧选择迁入 `terminator.rs:212-268` → `tool.rs:740-742`）以记 `record_conv_missing` 并取归档回退 id。
    fn plan_midstream(&self, protocol, conv_id, clean_close, seq_cursor, metrics: Option<&GatewayMetrics>) -> TerminalPlan;
    fn plan_empty_stream(&self, protocol_name, conv_id) -> TerminalPlan;
    fn plan_responses_error(&self, fid, err_obj, seq) -> TerminalPlan;

    // BLOCKER-3：`commit(meta, kind, frames_sent, terminal_frame_delivered)` 为终端帧位与
    // `meta.terminal_injected` 的唯一回填点，逐 kind 镜像现状（见下表）；`frames_sent` = 收尾是否成立、
    // `terminal_frame_delivered` = 终端帧是否实际下行（决定 `terminal_injected`），二者 SHALL NOT 合并；
    // 调用点按站点传参（I-5 传实际 `terminal_ok` 两次，I-3 传 `mid.terminal_sent` 与
    // `!frames.is_empty() && mid.terminal_sent`）。
    // `loop_terminated` **不由 commit 置位**：Responses error 臂在 commit 后另调
    // `mark_loop_terminated()`（对齐 `event_loop.rs:341` 无条件置 `terminated`），
    // `DuplicateFailed` 仅调 `mark_loop_terminated()`（对齐 `:345`，无帧发送）；
    // I-1/I-2/I-3/I-4 均不置 loop_terminated。
    fn commit(&mut self, meta: &mut StreamMeta, kind: TerminalKind, frames_sent: bool, terminal_frame_delivered: bool);
}

// commit 逐 kind 回填语义（= 现状逐点，行为保持）：
//   Block        → terminal_sent=true、block_injected=true、mark_terminal（现状 I-1/I-2 无条件，两参仅记录）
//   Midstream    → terminal_sent=frames_sent；mark_terminal 仅当 frames_sent && !frames.is_empty()
//                  （Chat/Responses 终端帧实际下行才标；Anthropic 零合成帧但收尾成立 →
//                   frames_sent=true、terminal_frame_delivered=false，置收尾位、不置注入标记，
//                   故不追加任何合成帧）
//   EmptyStream  → block_injected=true、mark_terminal（仅非空帧集；空帧集时仅由调用点落 set_truncated）
//   ResponsesError → terminal_sent=frames_sent、mark_terminal 仅当 terminal_frame_delivered（下游早断不撒谎）
```

**调用点契约（计数留在调用点）**：调用点循环 `env.pump_tx.send(frame)`、`record_emitted_events(...)`、按 plan 的 `truncated` 字段 `set_truncated(...)`，随后以「收尾是否成立 + 终端帧是否实际下行」两事实调 `commit(meta, kind, frames_sent, terminal_frame_delivered)` 更新终端位——计数与发送**不迁入** `StreamTerminator`。

**计数口径按站点逐点保持，不得新增或删除**（BLOCKER-1，按现行为真相源）：

| 站点 | 现状帧级计数 | 收敛后 |
|---|---|---|
| I-1 `apply_reject_block`（`event_loop.rs:163-172`） | **无** `add_sse_event` | 保持无（不得新增） |
| I-2 收尾阻断（`terminal.rs:161-170`） | **无** `add_sse_event` | 保持无（不得新增） |
| I-3 中途断流（`synth_flush.rs:39` / `:98` / `:137`；`:39` 为 `flush_pre_terminal`，I-5 亦复用） | 既有 `add_sse_event` | 保持既有（不得删除） |
| I-4 真空流（`terminal.rs:291-299`） | **无** `add_sse_event` | 保持无（不得新增） |
| I-5 Responses error（`event_loop.rs:332`） | 既有 `add_sse_event` | 保持既有（不得删除） |

`plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None`（幂等）；Anthropic 中途断流返回 `TerminalPlan::Frames { frames: vec![], truncated: Some(TruncatedMode::OpenEnded), .. }`（**零合成帧但仍是合法终止**，调用点据 `truncated` 记 `open_ended`）。

### 2.2 与现有模块的边界

| 模块 | 现状角色 | 收敛后角色 |
|---|---|---|
| `src/handler/llm/pump/spawn/event_loop.rs`（782 行） | I-1 阻断注入 + I-5 Responses error + 上游终端置位 | 调用 `terminator.plan_block`/`plan_responses_error` + 调用点 send/计数 + `commit`；`mark_upstream_terminal` 替代直写 `terminal_sent`；**不再**构造 `protocol_block_frames`/`responses_failed_frame` |
| `src/handler/llm/pump/spawn/terminal.rs`（356 行） | I-2 阻断注入 + I-4 真空流 + 中途断流调度 | `finalize` 仅保留审计终审、截断/残余处置与调度；I-2/I-4 改调 `terminator.plan_block`/`plan_empty_stream`；**不再**直写终端位；`TerminalCtx`（`:32-67`）删去已被 `StreamTerminator` 接管的 `terminal_sent`/`block_injected`/`any_frame_sent` 借用字段 |
| `src/handler/llm/pump/synth_flush.rs`（161 行） | I-3 中途断流终端帧选择 | `flush_pre_terminal`（`:23-43`）保留；`midstream_terminal`（`:71-160`）的**帧选择**迁入 `terminator.plan_midstream`，保留 `MidstreamTerminalOutcome`（`:48-51`）与 send/计数调用点；`synth_flush` 保留「flush 保序 + 观测（`set_truncated`/warn）」职责 |
| `src/service/block_inject/frames.rs`（530 行） | 帧/体**合成**（含 `protocol_block_frames`/`synthesize_truncation`/`empty_stream_frames`） | **不变**：`StreamTerminator` 是这些纯帧工厂的调用者，不是替代者；`block_inject` 保持「只合成帧/体、不累积字节」声明（`frames.rs:440-444`） |
| `src/service/block_inject/terminal.rs`（74 行） | 帧级去重/计数 + `mark_terminal` | **不变**（帧级工具）；`StreamTerminator` 的 `commit` 调用 `mark_terminal` 写 `StreamMeta.terminal_injected` |
| `src/service/sse/meta.rs`（50 行） | `StreamMeta` + `set_truncated` | **不变**；`truncated_mode` 写入口与四态语义不动 |
| `src/handler/llm/pump/decide.rs`（126 行） | 纯决策谓词 | `should_apply_midstream_terminal`（`:71-85`）、`sticky_suppress_action`（`:54-66`）与 `responses_control_action`（`:25-41`）保持纯函数，入参改取 `terminator.is_open()`/`block_injected()`/`any_frame_sent()`/`rejected_sticky()`/`responses_failed_seen()` 访问器值（MAJOR-7） |
| `src/handler/llm/pump/spawn/finish.rs`（77 行） | 组装 `PumpOutcome` | `state.audit_blocked`/`state.block_injected` 改经 `terminator.audit_blocked()`/`terminator.block_injected()`；`PumpOutcome`（`pump.rs:88-95`）字段不变 |
| `src/handler/llm/pump/spawn/setup.rs`（173 行） | `PumpLoopState` 持有 flag | 持有 `StreamTerminator`（单字段）替代 7 枚 bool；`setup.rs:115-138` 初始化同步 |

### 2.3 中间态 `dead_code` 登记（MAJOR-8）

迁移窗口内，新 `terminator.rs` 的骨架 API 在 3.1/3.2 消费者落位前于**非测试 lib target** 无生产调用；`#[cfg(test)]` 内联测试**不能**为该 target 消除 `dead_code`，而每步 `clippy --all-targets -- -D warnings` 门禁照跑。故采纳 critic 备选方案（**非**静默掩盖）：

- `terminator.rs` 中在迁移窗口内尚无生产消费者的类型/impl/item（如 `TerminalKind`/`TerminalPlan` 变体、`plan_*` 方法，及尚未接线的访问器/变更器）声明 `#[cfg_attr(not(test), allow(dead_code))]`，并在同处注释登记原因与到期条件（「消费者全部落位后须移除」）。
- 登记的原因与移除义务：`design.md` §2.3（本段）+ `tasks.md` 3.3（移除任务，验证 `grep -rn "allow(dead_code)" src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore --> 命中为 0）。
- 该 `allow` **仅覆盖迁移窗口**；1.1 不再声称「同批内联测试即可避免 `dead_code`」，也不得使用无登记、无移除任务的 `#[allow(dead_code)]`。

---

## 3. 「恰一终端」如何被结构化保证

1. **单写者**：终端位（`is_open`/`block_injected`/`terminated`）只能经 `StreamTerminator` 的 `commit`/`mark_upstream_terminal`/`mark_loop_terminated`/`note_sticky_rejected`/`note_responses_failed`/`note_frame_sent` 变更；`PumpLoopState` 不再暴露可直写的同名字段（删除公开字段，改私有于 `StreamTerminator`）。
2. **单入口 + 幂等**：所有终端帧注入必须先 `plan_*`；`plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None`，调用点收到 `None` 即不发送、不计数——**重复注入在类型层被拒**，不依赖「调用点记得判 flag」。`TerminalPlan::None` 只表达「未开放/已终端」；「按设计零合成帧」（Anthropic 中途断流）以 `Frames { frames: [], .. }` 表达，二者不可混用（MAJOR-6）。
3. **状态迁移封闭**：`state` 迁移为 `Open → {Blocked | Synthesized | EmptyStream | UpstreamTerminal | ResponsesError}`，皆为终态（无反向迁移）；`commit` 在终态后为 no-op。`terminal_sent`/`block_injected` 两条帧位由 `state` 保留区分；`loop_terminated`、`rejected_sticky`、`audit_blocked`、`responses_failed_seen` 为独立私有位（各自表达循环跳出/粘滞/审计/上游分类，不与帧位混用同一布尔）。
4. **幂等守护**：重复注入在类型层被拒（`plan_*` 于 `!is_open()` 返回 `TerminalPlan::None`），`commit` 于非 `Open` 态早退为 no-op（不施加入口 `debug_assert`——须允许重复 `commit` 静默无第二次迁移，见 `stream_terminator_injection_idempotent`）；调用约定的违反由矩阵/幂等测试在 CI 暴露。
5. **行为锁定测试**：新增 `stream_terminator_exact_one_terminal_matrix`（三协议 × {阻断, 中途断流, 真空流, 上游 error}）断言**每路径终端闭合恰一次**——含「零合成帧也是合法终止」（Anthropic 中途断流），测试**不得**通过伪造终端帧来满足「恰一」；新增 `stream_terminator_injection_idempotent` 断言已终端后 `plan_*` 返回 `TerminalPlan::None`。

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
| 漏置终端位（重复终端） | `commit` 未在发送成功后调用 | `plan_*` 的 `!is_open()` → `None` 门 + 新增幂等/矩阵测试；`PumpOutcome.terminal_injected` 既有断言兜底 |
| 计数漂移 | 发送/计数迁入 `StreamTerminator` 或调用点误增/误删 | 设计 §2.1 按站点列出各点既有计数（I-1/I-2/I-4 无、I-3/I-5 有）；`PumpOutcome.forwarded` 与 `sse_event_count` 既有测试锁定 |
| 文件体量越线 | `event.rs`（787，余量 13）/`event_loop.rs`（782）/`spawn_tests.rs`（784）已逼近 800 | 注入逻辑**迁出** `event_loop.rs` 降低行数；`event.rs:79` 仅就地换参（**不得新增行**）；新测试落 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（不追加 `spawn_tests.rs`）；`check_file_sizes.py` 门禁 |
| 中间态 `dead_code` | 骨架 API 在 3.x 消费者落位前无非测试 lib 调用 | §2.3 登记 `#[cfg_attr(not(test), allow(dead_code))]` + 3.3 移除任务（验证 grep 命中为 0） |
| 借用冲突 | `StreamTerminator` 与 `PumpLoopState` 同时可变借用 | 以 `TerminalCtx`/`FrameSink`（`restore_emit.rs:20-30`）同法：终态由 `StreamTerminator` 持有，其余状态仍归 `PumpLoopState`，调用点按需短借用 |
| 文案/注释过度声明 | 新的「单一所有者」措辞与实现不符 | 验收以行为测试为准（矩阵/幂等），注释准确性为 code-review 项（沿用 r4 M-5 口径） |

---

## 6. 迁移步骤（apply 期）

1. **骨架先行**：新建 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->（`StreamTerminator`/`TerminalPlan`/`TerminalKind`；类型与 impl 声明 `pub(in crate::handler::llm::pump)`，MAJOR-4 选项 (a)；迁移窗口内无生产消费者的项按 §2.3 加 `#[cfg_attr(not(test), allow(dead_code))]`）+ 在 `spawn.rs:5-10` 注册 `mod terminator;`；此步纯新增、零调用点改动（可编译、全测试绿；`clippy -D warnings` 因 §2.3 登记而 pass）。
2. **状态搬迁**：`PumpLoopState`（`setup.rs:49-76`）删去 7 枚终端 bool，改持 `terminator: StreamTerminator`；`setup.rs:115-138` 初始化同步；各读点改访问器（`decide.rs`/`event.rs` 纯谓词仅换入参来源；`finish.rs` 取 `audit_blocked()`/`block_injected()`）。
3. **注入点收敛**：按 I-1 → I-2 → I-3 → I-4 → I-5 顺序逐点改造为 `plan_*` + 调用点 send + **按站点既有口径**计数/`set_truncated` + `commit`；每改动一点跑 `cargo test` 保绿（原子提交）。
4. **上游终端收敛**：`event_loop.rs:622-624` 与 `:753-772` 改 `mark_upstream_terminal()`；Responses error 臂 `commit(ResponsesError, terminal_ok)` 后另调 `mark_loop_terminated()`，`DuplicateFailed` 仅调 `mark_loop_terminated()`（BLOCKER-3）。
5. **测试补齐**：新建 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（在 `pump.rs:33-46` 注册 `#[cfg(test)] mod terminator_tests;`），新增矩阵与幂等测试。
6. **移除中间态 `allow`（3.3）**：全部 `plan_*` 消费者落位后删除 `#[cfg_attr(not(test), allow(dead_code))]`，跑 `clippy --all-targets -- -D warnings` 复验（`grep -rn "allow(dead_code)" src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore --> 命中为 0）。
7. **门禁**：`bash scripts/gate.sh` 七步全绿；`openspec validate --strict` 通过。
8. **canonical 晋升（归档期）**：按 r2/r3/r4 先例，归档时把本 change 的 `specs/architecture-cleanup/spec.md` delta 晋升 canonical `openspec/specs/architecture-cleanup/spec.md`。

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
