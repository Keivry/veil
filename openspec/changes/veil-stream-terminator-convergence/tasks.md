## 1. 骨架与状态搬迁（前置）

- [ ] 1.1 新建 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->：定义 `StreamTerminator`（私有 `TerminalState`）+ `TerminalKind`/`TerminalPlan`；实现 `new`/`is_open`/`block_injected`/`terminated`/`note_frame_sent`/`mark_upstream_terminal`/`note_sticky_rejected`/`mark_audit_blocked`/`plan_block`/`plan_midstream`/`plan_empty_stream`/`plan_responses_error`/`commit`。`plan_*` 在 `!is_open()` 时返回 `TerminalPlan::None`；`commit` 为唯一终端位写点，内 `debug_assert!` 首次迁移并调 `block_inject::mark_terminal`（`src/service/block_inject/terminal.rs:14`）落 `meta.terminal_injected`。**同批**在本文件内写最小单测覆盖 `plan_*`/`commit` 幂等路径（避免中间态 dead_code 告警，**不得**用 `#[allow(dead_code)]` 掩盖）；在 `src/handler/llm/pump/spawn.rs:5-10` 注册 `mod terminator;`
  - 验证：`cargo build` 与 `cargo clippy --tests --all-targets -- -D warnings` 通过（新增模块无用例告警）；`python3 scripts/check_file_sizes.py` exit 0（`terminator.rs` ≤800 行）

- [ ] 1.2 `src/handler/llm/pump/spawn/setup.rs:49-76` 的 `PumpLoopState` 删去 7 枚终端相关 bool（`any_frame_sent`/`terminated`/`rejected_sticky`/`block_injected`/`audit_blocked`/`terminal_sent`/`responses_failed_sent`），改持 `terminator: StreamTerminator`；`:115-138` 初始化同步；读点改访问器——`event_loop.rs:119`（`terminator.terminated()`）、`:230/:277/:283/:358/:756`（`terminator.is_open()` 取反）等；写点由 2.1/2.2/3.1/3.2 接管
  - 验证：`cargo test -p veil` 全绿（行为不变）；`cargo clippy --tests --all-targets -- -D warnings` exit 0（无 `dead_code`/未用字段）

## 2. 阻断注入收敛（I-1/I-2，见 design §1.1）

- [ ] 2.1 收敛流内阻断臂：`src/handler/llm/pump/spawn/event_loop.rs:137-176` 的 `apply_reject_block` 改为置 `note_sticky_rejected`/`mark_audit_blocked` 后调 `terminator.plan_block(protocol, reason, conv_id, blocked_index, seq_cursor, Some(&env.metrics))`；调用点循环 `send` + 逐帧 `metrics.add_sse_event()`，全部成功后 `terminator.commit(TerminalKind::Block, true)`；**保持** `:150-159` 的 pending 缓冲归还/清空顺序与返回值 `is_tool_or_complete` 语义不变；删除 `:160-173` 的 `protocol_block_frames` 直构
  - 验证：`cargo test -p veil direct_rejected_sticky_suppresses_tool_frames`（`spawn_tests.rs:501`）与 `cargo test -p veil spawn_decision_sticky_suppress_truth_table`（`:300`）通过；`grep -c "protocol_block_frames" src/handler/llm/pump/spawn/event_loop.rs` 生产段为 0

- [ ] 2.2 收敛收尾阻断臂：`src/handler/llm/pump/spawn/terminal.rs:152-176` 改为调 `terminator.plan_block(...)`（`metrics` 参数保持现状 `None`）+ 调用点 send + `commit`；删除 `:161-168` 直构；`TerminalCtx`（`:32-67`）删去 `terminal_sent`/`block_injected`/`any_frame_sent` 借用字段，改经 `StreamTerminator` 访问器；`terminal.rs:153-157` 的清缓冲顺序与 `:171` 的 `mark_terminal` 经 `commit` 完成
  - 验证：`cargo test -p veil synth_terminal_single`（`spawn_tests.rs:683`）与 `cargo test -p veil synth_terminal_flush_order`（`:645`）通过；`grep -c "protocol_block_frames" src/handler/llm/pump/spawn/terminal.rs` 为 0

## 3. 终止帧收敛（I-3/I-4/I-5 + 上游终端，见 design §1.1）

- [ ] 3.1 收敛中途断流终端帧选择：`src/handler/llm/pump/synth_flush.rs:71-160` 的 `midstream_terminal` 帧选择迁入 `terminator.plan_midstream`（Chat 用 `chat_done_frame` `src/service/block_inject/frames.rs:303`、Responses 用 `synthesize_truncation` `frames.rs:485-498`、Anthropic 返回空计划仅保留观测）；`flush_pre_terminal`（`synth_flush.rs:23-43`）与 `MidstreamTerminalOutcome`（`:48-51`）保留；`terminal.rs:255-280` 调用点以 `terminator.commit(TerminalKind::Midstream, terminal_sent)` 回填（`send` 失败不置位语义不变）
  - 验证：`cargo test -p veil truncation_terminal_flush_order`（`spawn_tests.rs:720`）、`cargo test -p veil truncation_send_failure_guard`（`:761`）通过；`PumpOutcome.forwarded` 与既有断言逐项一致

- [ ] 3.2 收敛真空流与 Responses error 与上游终端：`terminal.rs:283-312` 真空流改 `terminator.plan_empty_stream`（`empty_stream_frames` `frames.rs:505-512`）+ `commit(TerminalKind::EmptyStream, ...)`；`event_loop.rs:290-343` 的 `type:"error"` 单帧改 `terminator.plan_responses_error`（`responses_failed_frame` `frames.rs:180-199`）+ `commit(TerminalKind::ResponsesError, true)`；`event_loop.rs:622-624`（`event_terminal`）与 `:753-772`（`[DONE]`）改 `terminator.mark_upstream_terminal()`
  - 验证：`cargo test -p veil direct_n1_completed_then_error_single_terminal`（`spawn_tests.rs:378`）与 `cargo test -p veil spawn_decision_empty_stream_gate_call_order`（`:360`）通过；`grep -c "responses_failed_frame" src/handler/llm/pump/spawn/event_loop.rs` 生产段为 0

## 4. 纯谓词接线与不变量守护

- [ ] 4.1 纯谓词保持纯函数、仅换入参来源：`src/handler/llm/pump/decide.rs:71-85`（`should_apply_midstream_terminal`）、`:54-66`（`sticky_suppress_action`）、`src/handler/llm/pump/event.rs:79`（`should_synthesize_empty_stream`）改取 `terminator.is_open()`/`block_injected()`/`terminated()`；`src/handler/llm/pump/spawn/finish.rs:70,74,75` 改经访问器组装 `PumpOutcome`（`src/handler/llm/pump.rs:88-95` 字段名与语义不变）
  - 验证：`cargo test -p veil spawn_decision_midstream_terminal_gate_truth_table`（`spawn_tests.rs:87`）、`cargo test -p veil spawn_decision_empty_stream_gate_call_order` 通过；`PumpOutcome.terminal_injected`/`block_injected` 断言（`stream_tests.rs:424,476` 等）全绿

- [ ] 4.2 新增测试文件 `src/handler/llm/pump/terminator_tests.rs`<!-- doc-paths-ignore -->（在 `src/handler/llm/pump.rs:33-46` 注册 `#[cfg(test)] mod terminator_tests;`）：`stream_terminator_exact_one_terminal_matrix`（三协议 × {阻断, 中途断流, 真空流, 上游 error} 经 `collect_pump` 断言每路径**恰一**终端帧）+ `stream_terminator_injection_idempotent`（已终端后 `plan_*` 返回 `TerminalPlan::None`，不产生第二终端）；复用 `stream_tests` 的 `collect_pump`/`fresh_arcs`/`loopback_server`/`pump_ctx`
  - 验证：`cargo test -p veil stream_terminator_exact_one_terminal_matrix` 与 `cargo test -p veil stream_terminator_injection_idempotent` 通过；`python3 scripts/check_file_sizes.py` exit 0（`terminator_tests.rs` ≤800、`spawn_tests.rs` 行数不增长）

## 5. 文档与 spec 同步

- [ ] 5.1 本 change delta `specs/architecture-cleanup/spec.md` 的 requirement 正文与 design §2/§3 一致（单所有者/单入口/幂等/计数留在调用点/纯重构行为保持）；canonical `openspec/specs/architecture-cleanup/spec.md` 于归档期晋升（本 change 仅 `## ADDED Requirements`，不改既有 requirement header/场景名）
  - 验证：`openspec validate veil-stream-terminator-convergence --strict` 通过

- [ ] 5.2 design §1.2 的 flag 集合与 apply 后实际写点一致：若实现期发生改名/合并/删除，须同批修订 `design.md` 与 delta spec，**不静默漂移**
  - 验证：code review 逐项核对 `design.md` §1.2 表与现行 `src/handler/llm/pump/spawn/*.rs` 写点；`grep -n "terminal_sent\|block_injected\|responses_failed" openspec/changes/veil-stream-terminator-convergence/design.md` 命中

## 验证门禁（Verification Gate）

- [ ] G-1 `bash scripts/gate.sh` 七步全绿（fmt / clippy `-D warnings` / test / doc-paths / file-sizes / conformance / go vet+test），任一步非零退出即本 change 未完成
- [ ] G-2 `openspec validate veil-stream-terminator-convergence --strict` 通过；`openspec validate --all --strict` 亦通过
- [ ] G-3 `python3 scripts/check_doc_paths.py` exit 0；本 change 内所有 `src/...rs:NNN` 锚点存在且在界；规划期新模块路径以 `<!-- doc-paths-ignore -->` 标注
- [ ] G-4 `python3 scripts/check_file_sizes.py` exit 0；`event_loop.rs`/`terminal.rs`/`synth_flush.rs` 与新增 `terminator.rs`/`terminator_tests.rs` 均 ≤800 行，`spawn_tests.rs` 不增长
- [ ] G-5 归档晋升：apply 完成后按 r2/r3/r4 先例将本 change 的 `specs/architecture-cleanup/spec.md` delta 晋升 canonical `openspec/specs/architecture-cleanup/spec.md`（同批直改 + 归档 early-sync no-op）
- [ ] G-6 本 change 规划期（artifacts-only）不改 `src/**`、`tests/**`、`scripts/**`、`README.md`、`openspec/specs/**` 与任何其他 change 目录；不归档、不 `git add/commit`、不运行 `cargo`
