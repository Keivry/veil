## ADDED Requirements

### Requirement: 流式阻断/终止帧注入单一所有者

系统 SHALL 将流式阻断帧与终止帧的注入、以及「恰一终端」状态机收敛为单一所有者类型 `StreamTerminator`（新模块 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->）；SHALL NOT 由 `src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/pump/spawn/terminal.rs` 各自独立构造并注入协议阻断帧（现状两处重复构造见 `event_loop.rs:160-173` 与 `terminal.rs:158-171`，均调 `protocol_block_frames`）。

`StreamTerminator` SHALL 独占终端状态写入：`terminal_sent`/`block_injected`/`rejected_sticky`/`terminated`/`audit_blocked`/`responses_failed_sent` 与 `StreamMeta.terminal_injected`（声明见 `src/handler/llm/pump/spawn/setup.rs:64-70` 与 `src/service/sse/meta.rs:30-34`）的终端相关写点 SHALL 仅经 `StreamTerminator` 的 API；`PumpLoopState` SHALL NOT 再暴露可被多个模块直写的同名字段，读取方 SHALL 经访问器（如 `is_open()`/`block_injected()`/`terminated()`）取状态。

注入决策 SHALL 为单一入口：`plan_block`/`plan_midstream`/`plan_empty_stream`/`plan_responses_error` 各自返回终端计划（本次应发送的协议帧集与终端种类），SHALL NOT 在泵内散落 `match protocol` 的终端帧构造。实际发送与计数 SHALL 留在调用点——帧发送（`pump_tx.send`）与帧级/截断计数（`metrics.add_sse_event()`、`record_emitted_events`、`set_truncated`）SHALL NOT 迁入 `StreamTerminator`；发送结果 SHALL 经 `commit` 回填，由 `StreamTerminator` 更新终端位。

注入 SHALL 幂等：当已终端或已阻断（`is_open()` 为假）时再次请求注入 SHALL 返回空计划，SHALL NOT 产生第二个终端帧；终端恰一 SHALL 由该单一所有者结构性保证，SHALL NOT 依赖跨模块 flag 约定。

该收敛 SHALL 为纯重构（behavior-preserving）：线级帧序、帧内容、`truncated_mode` 观测、审计时序与 `PumpOutcome`（`src/handler/llm/pump.rs:88-95`）字段 SHALL 逐项与重构前一致；三协议终端语义（Chat `data: [DONE]`、Anthropic 真空 `message_start`+`message_stop`、Responses 恰一 `response.completed`/`response.failed`/`response.incomplete`）SHALL NOT 改变。

#### Scenario: 阻断帧单点注入

- **WHEN** 审计阻断命中并触发阻断帧注入（无论流内 `apply_reject_block` 路径还是收尾终审路径）
- **THEN** 阻断帧仅由 `StreamTerminator` 的单一入口产出并恰一注入，泵内不存在第二处独立的协议阻断帧构造点

#### Scenario: 重复注入被幂等拒绝

- **WHEN** 终端已置位或已阻断后再次请求终端帧注入
- **THEN** 注入入口返回空计划，不发送帧、不产生第二个终端帧

#### Scenario: 终端状态单一写入者

- **WHEN** 检查终端位与 `StreamMeta.terminal_injected` 的写点
- **THEN** 仅 `StreamTerminator` 写入终端状态，各泵模块经访问器读取，无跨模块直写

#### Scenario: 三协议终端矩阵恰一

- **WHEN** 对 Chat/Anthropic/Responses 分别走阻断、中途断流、真空流与上游错误路径
- **THEN** 每协议每路径下游恰一终端帧，无重复终端、无缺失终端

#### Scenario: 计数仍在调用点

- **WHEN** 终端帧经发送成功下行
- **THEN** 帧级计数与 `truncated_mode` 观测在调用点记录，`PumpOutcome` 的 `forwarded`/`block_injected`/`terminal_injected` 与重构前逐项一致

#### Scenario: 行为零回退

- **WHEN** 运行既有流式回归（含 `synth_terminal_single`、`synth_terminal_flush_order`、`truncation_terminal_flush_order`、`truncation_send_failure_guard`、`direct_n1_completed_then_error_single_terminal`、`direct_rejected_sticky_suppresses_tool_frames`）
- **THEN** 全部通过，且断言帧序/终端/`truncated_mode`/`PumpOutcome` 的既有用例无一回退
