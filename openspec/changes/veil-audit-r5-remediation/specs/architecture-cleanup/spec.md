# Spec Delta

## MODIFIED Requirements

### Requirement: 流式阻断/终止帧注入单一所有者

系统 SHALL 将流式阻断帧与终止帧的注入、以及「恰一终端」状态机收敛为单一所有者类型 `StreamTerminator`（新模块 `src/handler/llm/pump/spawn/terminator.rs`<!-- doc-paths-ignore -->）；SHALL NOT 由 `src/handler/llm/pump/spawn/event_loop.rs` 与 `src/handler/llm/pump/spawn/terminal.rs` 各自独立构造并注入协议阻断帧（现状两处重复构造见 `src/handler/llm/pump/spawn/event_loop.rs::apply_reject_block` 与 `src/handler/llm/pump/spawn/terminal.rs::finalize`，均经 `src/service/block_inject.rs::protocol_block_frames_modeled` 的生产入口合成阻断帧）。

`StreamTerminator` SHALL 独占终端状态写入：`terminal_sent`/`block_injected`/`rejected_sticky`/`terminated`/`audit_blocked`/`responses_failed_seen`（原 `responses_failed_sent`，收敛期更名）与 `StreamMeta.terminal_injected`（声明见 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator` 与 `src/service/sse/meta.rs::StreamMeta`）的终端相关写点 SHALL 仅经 `StreamTerminator` 的 API；`PumpLoopState` SHALL NOT 再暴露可被多个模块直写的同名字段，读取方 SHALL 经访问器（如 `is_open()`/`block_injected()`/`terminated()`）取状态。

注入决策 SHALL 为单一入口：`plan_block`/`plan_midstream`/`plan_empty_stream`/`plan_responses_error` 各自返回终端计划（本次应发送的协议帧集、终端种类与可选的截断观测），SHALL NOT 在泵内散落 `match protocol` 的终端帧构造。终端计划 SHALL 区分「未开放/已终端」（`TerminalPlan::None`，调用点零动作）与「按设计零合成帧」（`Frames` 且帧集为空，如 Anthropic 中途断流），SHALL NOT 以后者冒充前者。

实际发送与计数 SHALL 留在调用点——帧发送（`pump_tx.send`）与帧级/截断计数（`metrics.add_sse_event()`、`record_emitted_events`、`set_truncated`）SHALL NOT 迁入 `StreamTerminator`。帧级计数 SHALL 按各站点既有语义逐点保持，SHALL NOT 新增或删除任何计数：I-1（`src/handler/llm/pump/spawn/event_loop.rs::apply_reject_block`）、I-2（`src/handler/llm/pump/spawn/terminal.rs::finalize` 的收尾终审阻断臂）、I-4（`src/handler/llm/pump/spawn/terminal.rs::finalize` 的真空流臂）现状无 `add_sse_event`，收敛后 SHALL 保持无；I-3（`src/handler/llm/pump/synth_flush.rs::flush_pre_terminal` 与 `src/handler/llm/pump/synth_flush.rs::midstream_terminal`）与 I-5（`src/handler/llm/pump/spawn/event_loop.rs::handle_event` 的 Responses error 臂）现状有 `add_sse_event`，收敛后 SHALL 保持。发送结果 SHALL 经 `commit(meta, kind, frames_sent, terminal_frame_delivered)` 回填，其为终端帧位与 `StreamMeta.terminal_injected` 的唯一回填点；终端帧位由 `frames_sent` 决定（收尾是否成立），`StreamMeta.terminal_injected` 另由 `terminal_frame_delivered` 决定（终端帧是否实际下行），二者 SHALL NOT 合并，逐 kind 镜像现状：Responses error（I-5）与 Chat/Responses 中途断流（I-3）SHALL 仅在 `terminal_frame_delivered == true` 时落 `terminal_injected`，`terminal_frame_delivered == false`（下游早断）时 SHALL NOT 置位（「下游早断不撒谎」），终端帧位仍按 `frames_sent` 回填；I-1/I-2 阻断与 I-4 真空流 SHALL 保持现状的无条件置位语义；I-3 Anthropic 零合成帧 SHALL 以 `frames_sent=true`（收尾成立）回填终端位，`terminal_frame_delivered=false`，SHALL NOT 置 `StreamMeta.terminal_injected`（对齐 `veil-stream-fidelity-fix` D9/S9 的「不撒谎」口径），SHALL NOT 追加任何合成终端帧。`loop_terminated`（`run_pump` 循环跳出）SHALL 独立于 `commit`：Responses error 臂在 `commit` 后另调显式终止方法置位（对齐 `src/handler/llm/pump/spawn/event_loop.rs::handle_event` 的 Responses error 臂无条件置位），`DuplicateFailed` SHALL 仅调该显式终止方法（对齐同处 `DuplicateFailed` 臂，无帧发送），其余站点 SHALL NOT 置 `loop_terminated`。

注入 SHALL 幂等：当已终端或已阻断（`is_open()` 为假）时再次请求注入 SHALL 返回 `TerminalPlan::None`，SHALL NOT 产生第二个终端帧；终端恰一 SHALL 由该单一所有者结构性保证，SHALL NOT 依赖跨模块 flag 约定。

收尾终审在流**已终端**（`is_open()` 为假，如上游已发 `message_stop`/`response.completed`/`[DONE]`/错误帧）时命中 `Block`：`plan_block` SHALL 返回 `TerminalPlan::None`（SHALL NOT 注入第二终端帧，方向正确），但系统 SHALL 保留本次阻断的**可观测语义**——`PumpOutcome.block_injected` SHALL 为 `true`，`StreamMeta.terminal_injected` SHALL NOT 置位（未下行第二终端），并 SHALL 记 `warn!`（不含明文/键值）与一次审计阻断计数；SHALL NOT 让该阻断不可观测（无 warn、无计数）或令 `block_injected` 由 `true` 回退为 `false`。该场景 SHALL 由单测锁定。

**结构性约束（D3）**：现有 `StreamTerminator` 状态机**无法**表达「`block_injected=true` 且 `terminal_sent=true` 且 `StreamMeta.terminal_injected=false`」三态并存——`src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::block_injected` 仅对 `TerminalState::{Blocked,EmptyStream}` 为真，`src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_block` 在 `!is_open()` 时返回 `TerminalPlan::None`，且 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::commit` 处理 `Block` 时会一并置位 `terminal_injected`。故满足本条款 SHALL 引入**独立于终端帧位的状态/位**（其置位 SHALL NOT 触发 `terminal_injected`），SHALL NOT 复用 `commit(Block)` 路径；`audit_blocks` 计数 SHALL 经 `audit_blocked` 位承载——该位由 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::note_sticky_rejected` 置位（`block_injected` 与 `audit_blocked` 非同位），并由 `src/handler/llm/pump/spawn/finish.rs::finish` 经 `terminator.audit_blocked()` 读取。

阻断臂 SHALL 结构性地消费触发帧：「拒绝即消费」不变量 SHALL 由阻断入口（`apply_reject_block`/等价统一入口）的返回契约或调用点无条件早返回保证——阻断判定成立时，触发该阻断的帧 SHALL 恒被消费，SHALL NOT 落至正常帧还原/放行路径并在阻断终端**之后**下行；该不变量 SHALL NOT 仅依赖各 `reject_reason` 设置点恰好位于 `is_audit_due_event`/`is_index_complete_event` 门内这一无编译期保护的隐式约定。

该收敛 SHALL 为**行为保持**（behavior-preserving），其判据以本要求的已登记场景为准：线级帧序、帧内容、`truncated_mode` 观测、审计时序与 `PumpOutcome`（`src/handler/llm/pump.rs::PumpOutcome`）字段 SHALL 与重构前逐项一致，**除下方「已终端后收尾审计命中 `Block`」这一已登记例外之外**；三协议终端语义（Chat `data: [DONE]`、Anthropic 真空 `message_start`+`message_stop`、Responses 恰一 `response.completed`/`response.failed`/`response.incomplete`）SHALL NOT 改变。

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
- **THEN** 帧级计数按各站点既有口径在调用点记录（I-1/I-2/I-4 不新增、I-3/I-5 不删除），`truncated_mode` 观测在调用点按计划落 `set_truncated`，`PumpOutcome` 的 `forwarded`/`block_injected`/`terminal_injected` 除「已终端后收尾审计命中 `Block`」已登记场景外与重构前逐项一致

#### Scenario: 已终端后收尾审计命中 Block 不注入第二终端

- **WHEN** 流已终端（上游已发终端帧）后收尾终审命中 `Block`
- **THEN** 不注入第二终端帧（`plan_block` 返回 `TerminalPlan::None`、`StreamMeta.terminal_injected` 不置位），但 `PumpOutcome.block_injected` 保持 `true`（经独立于终端帧位的状态/位承载，其置位不触发 `terminal_injected`），并记 `warn!`（不含明文）与一次审计阻断计数（经 `audit_blocked` 位，由 `note_sticky_rejected` 置位）；该场景由单测锁定

#### Scenario: 拒绝即消费结构化

- **WHEN** 阻断判定成立时触发本次阻断的帧恰好不属 tool/完成事件（历史实现会落至正常还原/放行路径的形态）
- **THEN** 该帧仍被阻断入口结构化消费（不落至正常还原/放行路径、不在阻断终端之后下行）；行为由测试锁定，SHALL NOT 依赖 `reject_reason` 设置点的隐式门控

#### Scenario: 行为零回退

- **WHEN** 运行既有流式回归（含 `synth_terminal_single`、`synth_terminal_flush_order`、`truncation_terminal_flush_order`、`truncation_send_failure_guard`、`direct_n1_completed_then_error_single_terminal`、`direct_rejected_sticky_suppresses_tool_frames`）
- **THEN** 全部通过，且断言帧序/终端/`truncated_mode`/`PumpOutcome` 的既有用例无一回退（「已终端后收尾审计命中 `Block`」已登记场景除外）

### Requirement: 单帧单次 JSON 解析

系统对每个 SSE 帧 SHALL 至多执行一次完整 JSON 解析，并复用该解析产物承载审计判定、内层 stringified-JSON 递归校验与转发决策；SHALL NOT 对同一帧重复解析。解析 SHALL 收敛为 `event.rs::parse_event_data` 单点；`sticky_terminal_event`、`responses_failed_incomplete`、`responses_error_object` SHALL 接收该解析产物（`Option<&Value>`），其原字符串签名 SHALL 降为 `#[cfg(test)]` 包装。解析复用 SHALL NOT 改变帧序、帧内容、审计判定、还原结果与终端恰一语义。

守护 SHALL 为双守卫：① `parse_event_data` 的 `#[cfg(test)]` 解析计数与 `take_parse_count`，在泵 e2e 断言每帧恰 1 次；② 源码守护断言 `event.rs` **生产段**（首个 `#[cfg(test)]` 之前）的 `from_str` 计数为 0。

生产请求体与帧载荷的 JSON 解析 SHALL 统一经中央 helper `src/service/json_walk.rs::{strip_bom, jloads}`（或其等价单一入口），SHALL NOT 在生产路径旁路直调 `serde_json::from_slice`/`serde_json::from_str`；解析 SHALL 先剥离前导 BOM 再判形，使 BOM 前缀体与非 BOM 体解析结果一致。该统一 SHALL NOT 改变帧序、审计判定、还原结果与终端恰一语义；其唯一语义后果为：BOM 前缀请求体由「解析失败走回退分支」变为「正常解析」。

**适用范围（D1，显式界定）**：本条款 SHALL 仅适用于 **LLM 网关负载**——LLM 请求体、上游响应体与 SSE 帧载荷；**非网关负载**的 JSON 解析 SHALL 不在本条款范围内：配置文件、审计策略文件、注册表存储、管理面可观测 SSE 流等站点的既有 `serde_json` 直调为**合法例外**，SHALL NOT 被要求迁移。该范围与实现现实一致（上述非网关站点保留既有直调）。

#### Scenario: 单帧仅解析一次

- **WHEN** 上游投递单帧 SSE 数据（含需内层递归校验的嵌套 JSON）
- **THEN** 该帧仅解析一次，审计/还原/转发决策复用同一解析结果（解析计数证据可见该帧解析次数为 1）

#### Scenario: 生产段零 from_str

- **WHEN** 检查 `event.rs` 首个 `#[cfg(test)]` 之前的生产前缀
- **THEN** `from_str` 计数为 0，解析仅经 `parse_event_data` 单点

#### Scenario: 解析复用行为逐字节不变

- **WHEN** 对复用解析的实现运行全部流式相关回归
- **THEN** 帧序、帧内容、审计时序与终端恰一语义与复用前逐项一致

#### Scenario: BOM 前缀体经中央 helper 正常解析

- **WHEN** 生产路径接收带前导 BOM（`\ufeff`）的 JSON 请求体
- **THEN** 该体经中央 `strip_bom`/`jloads` 入口正常解析（不再落入解析失败回退分支），解析结果与剥 BOM 后同字节体一致

### Requirement: 协议分派单一入口

协议**判定/分派谓词** SHALL 收敛为单一分派点（或类型化方法）供全仓复用；谓词集合 SHALL 限定为 `Protocol` 类型化方法（`is_chat`/`is_responses`/`is_dialog`/终态判定/审计到期/次要事件/`wire_name`），SHALL NOT 保留同一谓词语义的重复扩散实现。逐协议**差异产物构造**（帧序列、usage 累计、placeholder 处理、tool 提取分支等）SHALL NOT 视为重复分派，其 `match protocol` 分支 SHALL 允许保留。收敛 SHALL 保持分派结果等价。

协议差异的**类型化单一声明** SHALL 落为 `Protocol` 的单一 spec 访问器（如 `Protocol::spec()`，返回 `ProtocolSpec`），其**第一步** SHALL 至少承载 `done_terminator: Option<&str>` 与 `terminal_event_types` 两类字段，并成为**本要求所列已迁移消费者**的**唯一来源**；已迁移消费者 SHALL 限定为：① `[DONE]` 判定的协议门控点——`src/handler/llm/pump/spawn/event_loop.rs::handle_event` 中消费 `src/service/sse/parser.rs::is_done_payload` 结果并决定其是否作为 Chat 终端的站点（经 `done_terminator`）；② 流式终端事件集合判定 `src/handler/llm/pump/event.rs::is_terminal_event`（经 `terminal_event_types`）。SHALL NOT 在这两处消费者内散落与协议绑定的 `[DONE]`/终端集合字面量分支。

系统 SHALL NOT 以一个 `terminal_event_types` 字段强制替换仓内全部协议相关事件集合：仓内至少存在四组**语义不同**的集合——真终端集合（`src/handler/llm/pump/event.rs::is_terminal_event`）、粘滞抑制集合（`src/handler/llm/pump/event.rs::sticky_terminal_precise`，含 `content_block_stop`/`message_delta`）、Responses 失败/未完成分类集合（`src/handler/llm/pump/event.rs::responses_failed_incomplete`）与 Chat 错误终端集合（`src/handler/llm/pump/event.rs::is_chat_error_terminal`）。本要求 SHALL 仅覆盖已迁移消费者（`is_terminal_event` 与 `[DONE]` 协议门控点），其余三组集合 SHALL 保持现状或改由**按语义分组的独立字段**（每语义集合一个字段）承载，SHALL NOT 以单一字段冒充全部集合。**本要求仅覆盖第一步**：`ProtocolSpec` 的**全量字段迁移**（usage/tool/placeholder/header/rewrite/block-body 等）SHALL 登记为后续独立 change 的**非目标**，本要求 SHALL NOT 承诺其完成。

#### Scenario: 分派点收敛

- **WHEN** 检查全仓协议判定/分派谓词
- **THEN** 谓词经单一入口或 `Protocol` 类型化方法承载，无同一谓词语义的重复扩散

#### Scenario: 差异产物构造不被误判

- **WHEN** 检查逐协议差异产物构造的 `match protocol` 分支
- **THEN** 其保留被本 spec 认可，不视为重复分派缺陷

#### Scenario: 分派结果不变

- **WHEN** 运行三协议分派回归
- **THEN** 分派结果与收敛前一致

#### Scenario: [DONE] 与终端集合单一来源

- **WHEN** 检查已迁移消费者（`[DONE]` 协议门控点与 `src/handler/llm/pump/event.rs::is_terminal_event`）
- **THEN** 两类判定均取自 `Protocol::spec()` 的 typed 声明（`done_terminator`/`terminal_event_types`），这两处无散落的协议字面量分支；其余语义不同的终端集合（粘滞抑制/失败分类/Chat 错误）不被本条款覆盖

#### Scenario: 第一步范围被显式限定

- **WHEN** 检查 `ProtocolSpec` 的字段迁移范围
- **THEN** 仅要求 `done_terminator`/`terminal_event_types` 两类字段且仅覆盖已迁移消费者；语义不同的终端集合（粘滞抑制/失败分类/Chat 错误）SHALL NOT 被单一字段强制替换；全量字段迁移被显式登记为非目标/后续独立 change

### Requirement: 上游响应头克隆与逐跳过滤单一 helper

`src/handler/llm/nonstream.rs` 中上游响应头克隆与逐跳（hop）过滤的两处逐字重复逻辑 SHALL 抽取为单一 helper，供 `passthrough_upstream_response` 与 `snapshot_downstream_headers` 复用；SHALL NOT 保留两份并行的头克隆 + 解码配对 + hop 过滤实现。helper SHALL 保持 decoded/undecoded 配对语义（`downstream_decode_enabled` + `filter_hop_headers_counted`）与既有计数副作用不变。

上游/下游头处理的三步 preamble（剥内部头 + 选 `DECODE_ENABLED` 解码配对 + 计 hop 过滤数）SHALL 收敛为**每方向单一 helper**：上游方向为 `src/handler/llm/mod.rs::forward_headers`，下游方向为 `src/handler/llm/nonstream.rs::clone_upstream_headers`（由同文件 `snapshot_downstream_headers` 复用）。调用点 SHALL NOT 各自重复「剥 hop/剥内部头/计数」三步 preamble，SHALL NOT 出现第三份并行实现。逐跳过滤底层 SHALL 保持既有 `filter_hop_headers_counted` 为唯一实现，SHALL NOT 新增第二份 hop 过滤。

#### Scenario: 两调用点共用 helper

- **WHEN** 检查 `nonstream.rs` 的非对话透传与快照路径
- **THEN** 两处均调用同一 helper，头克隆/hop 过滤无重复实现

#### Scenario: 头过滤行为不变

- **WHEN** 运行非流/非对话透传相关测试（含编码配对与 `x-veil-*` 剔除）
- **THEN** 全部通过，下游响应头集合与重构前一致

#### Scenario: 转发头 preamble 单一方向参数化实现

- **WHEN** 检查上游方向（`src/handler/llm/mod.rs::forward_headers`）与下游方向（`src/handler/llm/nonstream.rs::clone_upstream_headers`，含 `snapshot_downstream_headers` 复用）的转发头处理路径
- **THEN** **每方向各有单一 helper** 承担「剥内部头 + 选解码配对 + 计数」，调用点不重复三步 preamble、无第三份并行实现；hop 过滤仍仅经 `filter_hop_headers_counted`
