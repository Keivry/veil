## ADDED Requirements

### Requirement: 流式阻断/终止帧注入单一所有者

系统 SHALL 将流式阻断帧与终止帧的注入、以及「恰一终端」状态机收敛为单一所有者类型 `StreamTerminator`（新模块 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->）；SHALL NOT 由 `src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/pump/spawn/terminal.rs` 各自独立构造并注入协议阻断帧（现状两处重复构造见 `event_loop.rs:160-173` 与 `terminal.rs:158-171`，均调 `protocol_block_frames`）。

`StreamTerminator` SHALL 独占终端状态写入：`terminal_sent`/`block_injected`/`rejected_sticky`/`terminated`/`audit_blocked`/`responses_failed_seen`（原 `responses_failed_sent`，收敛期更名）与 `StreamMeta.terminal_injected`（声明见 `src/handler/llm/pump/spawn/terminator.rs:65-80` 与 `src/service/sse/meta.rs:30-34`）的终端相关写点 SHALL 仅经 `StreamTerminator` 的 API；`PumpLoopState` SHALL NOT 再暴露可被多个模块直写的同名字段，读取方 SHALL 经访问器（如 `is_open()`/`block_injected()`/`terminated()`）取状态。

注入决策 SHALL 为单一入口：`plan_block`/`plan_midstream`/`plan_empty_stream`/`plan_responses_error` 各自返回终端计划（本次应发送的协议帧集、终端种类与可选的截断观测），SHALL NOT 在泵内散落 `match protocol` 的终端帧构造。终端计划 SHALL 区分「未开放/已终端」（`TerminalPlan::None`，调用点零动作）与「按设计零合成帧」（`Frames` 且帧集为空，如 Anthropic 中途断流），SHALL NOT 以后者冒充前者。

实际发送与计数 SHALL 留在调用点——帧发送（`pump_tx.send`）与帧级/截断计数（`metrics.add_sse_event()`、`record_emitted_events`、`set_truncated`）SHALL NOT 迁入 `StreamTerminator`。帧级计数 SHALL 按各站点既有语义逐点保持，SHALL NOT 新增或删除任何计数：I-1（`event_loop.rs:163-172`）、I-2（`terminal.rs:161-170`）、I-4（`terminal.rs:291-299`）现状无 `add_sse_event`，收敛后 SHALL 保持无；I-3（`synth_flush.rs:39`/`:98`/`:137`）与 I-5（`event_loop.rs:332`）现状有 `add_sse_event`，收敛后 SHALL 保持。发送结果 SHALL 经 `commit(meta, kind, frames_sent, terminal_frame_delivered)` 回填，其为终端帧位与 `StreamMeta.terminal_injected` 的唯一回填点；终端帧位由 `frames_sent` 决定（收尾是否成立），`StreamMeta.terminal_injected` 另由 `terminal_frame_delivered` 决定（终端帧是否实际下行），二者 SHALL NOT 合并，逐 kind 镜像现状：Responses error（I-5）与 Chat/Responses 中途断流（I-3）SHALL 仅在 `terminal_frame_delivered == true` 时落 `terminal_injected`，`terminal_frame_delivered == false`（下游早断）时 SHALL NOT 置位（「下游早断不撒谎」），终端帧位仍按 `frames_sent` 回填；I-1/I-2 阻断与 I-4 真空流 SHALL 保持现状的无条件置位语义；I-3 Anthropic 零合成帧 SHALL 以 `frames_sent=true`（收尾成立）回填终端位，`terminal_frame_delivered=false`，SHALL NOT 置 `StreamMeta.terminal_injected`（对齐 `veil-stream-fidelity-fix` D9/S9 的「不撒谎」口径），SHALL NOT 追加任何合成终端帧。`loop_terminated`（`run_pump` 循环跳出）SHALL 独立于 `commit`：Responses error 臂在 `commit` 后另调显式终止方法置位（对齐 `event_loop.rs:341` 无条件置位），`DuplicateFailed` SHALL 仅调该显式终止方法（对齐 `:345`，无帧发送），其余站点 SHALL NOT 置 `loop_terminated`。

注入 SHALL 幂等：当已终端或已阻断（`is_open()` 为假）时再次请求注入 SHALL 返回 `TerminalPlan::None`，SHALL NOT 产生第二个终端帧；终端恰一 SHALL 由该单一所有者结构性保证，SHALL NOT 依赖跨模块 flag 约定。

该收敛 SHALL 为纯重构（behavior-preserving）：线级帧序、帧内容、`truncated_mode` 观测、审计时序与 `PumpOutcome`（`src/handler/llm/pump.rs:88-95`）字段 SHALL 逐项与重构前一致；三协议终端语义（Chat `data: [DONE]`、Anthropic 真空 `message_start`+`message_stop`、Responses 恰一 `response.completed`/`response.failed`/`response.incomplete`）SHALL NOT 改变。

#### Scenario: 阻断帧单点注入

- **WHEN** 审计阻断命中并触发阻断帧注入（无论流内 `apply_reject_block` 路径还是收尾终审路径）
- **THEN** 阻断帧仅由 `StreamTerminator` 的单一入口产出并恰一注入，泵内不存在第二处独立的协议阻断帧构造点

#### Scenario: 重复注入被幂等拒绝

- **WHEN** 终端已置位或已阻断后再次请求终端帧注入
- **THEN** 注入入口返回 `TerminalPlan::None`，不发送帧、不产生第二个终端帧

#### Scenario: 终端状态单一写入者

- **WHEN** 检查终端位与 `StreamMeta.terminal_injected` 的写点
- **THEN** 仅 `StreamTerminator` 写入终端状态，各泵模块经访问器读取，无跨模块直写

#### Scenario: 终端闭合按路径恰一次（含零合成帧）

- **WHEN** 对 Chat/Anthropic/Responses 分别走阻断、中途断流、真空流与上游错误路径
- **THEN** 满足「终态闭合恰一次 / terminal closure exactly once per path」，按协议与路径分别为：
  - Chat：阻断/中途断流/真空流各恰一台成 `data: [DONE]`；上游 error 时上游 error 帧自身即终端，**零合成终端帧**、不补 `[DONE]`，记 `truncated_mode=upstream_error`；
  - Anthropic：阻断恰一 `message_stop`（阻断全序列尾帧）；真空流 `message_start` 与 `message_stop` 各恰一；**中途断流合成终端帧数为零**且记 `truncated_mode=open_ended`（SHALL NOT 伪造 `message_stop`）；
  - Responses：阻断恰一 `response.completed`（阻断 7 帧序列尾帧）；中途断流恰一 `response.failed`；真空流恰一 `response.failed`（真空流全序列尾帧）；上游 error 恰一 `response.failed`（单帧）。
- **AND** 「零合成帧」（Anthropic 中途断流）亦计为合法终止一次，无重复终端、无缺失终端；测试 SHALL NOT 通过伪造终端帧来满足「恰一」

#### Scenario: 计数仍在调用点

- **WHEN** 终端帧经发送成功下行
- **THEN** 帧级计数按各站点既有口径在调用点记录（I-1/I-2/I-4 不新增、I-3/I-5 不删除），`truncated_mode` 观测在调用点按计划落 `set_truncated`，`PumpOutcome` 的 `forwarded`/`block_injected`/`terminal_injected` 与重构前逐项一致

#### Scenario: 行为零回退

- **WHEN** 运行既有流式回归（含 `synth_terminal_single`、`synth_terminal_flush_order`、`truncation_terminal_flush_order`、`truncation_send_failure_guard`、`direct_n1_completed_then_error_single_terminal`、`direct_rejected_sticky_suppresses_tool_frames`）
- **THEN** 全部通过，且断言帧序/终端/`truncated_mode`/`PumpOutcome` 的既有用例无一回退
