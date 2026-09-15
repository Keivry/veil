## Context

见 `proposal.md` — Why 与覆盖表。本 change 为行为保持的纯重构，须先固化现状结构再决策拆分与统一边界；以下行号均经起草时打开源码复核。

- **ARC-1 巨型函数**：`src/handler/llm/pump/spawn.rs` 共 699 行，`spawn_stream_pump`（`:49-699`）**651 行**。内部阶段：函数签名 + `tokio::spawn` 闭包（`:49-56`）；`StreamPumpCtx` 解构与循环状态初始化（`:56-148`）；主循环 `loop { upstream.chunk() … for ev in events { … } }`（`:149-658`，其中 chunk 读取 `:150-163`、parser 喂入 `:169`、单事件处理 `:174-654`）；`terminal::finalize(...)` 调用（`:659-681`）；指标记录与 `PumpOutcome`（`:681-698`）。终止收尾**已**拆入 `spawn/terminal.rs`（`finalize`，190 行）与 `spawn/frame_feed.rs`；剩余不内聚处在 setup 与主循环/单事件处理。
- **ARC-2 决策表**：`src/service/credential/approval.rs:233` `static DECISIONS: OnceLock<Mutex<DecisionTable>>`，`:235-237` 访问器 `decisions()`。`DecisionTable`（`:157-159`）持 `HashMap<String, DecisionEntry>`，`DecisionEntry`（`:143-153`）有 `InFlight`/`Decided` 两态；`DECISION_TABLE_MAX_ENTRIES=4096`（`:160`）；`sweep`（`:163-171`）仅清过期 `Decided`；`resolve`（`:200-218`）写入终态后，若超上限则 `self.entries.keys().find(|k| k != key)` **取任意非当前键驱逐**（`HashMap` 迭代序，可为 `InFlight`）。调用点：`approval_decision_closure`（`:272-` 内 `:311/:338`）、waiter 任务的 `record_credential_decision`（`:240-243`，经 `:333` 调用，调用处持有 `owned` state）、`consume_decision`（`:253-255`）。唯一 `AppStateParts` 实现为 `src/state.rs:137` `impl … for AppState`。
- **ARC-3 tool 提取器**：`src/service/llm_gateway/tool.rs:196-578` `extract_tool_calls`（383 行，返回 `Vec<ToolCall>`，含 `id_synth`）与 `src/handler/llm/pump/fragments.rs:11-19` `extract_tool_fragments`（357 行，返回 `Vec<(u32, Option<String>, Option<String>, String)>`）各自实现三臂 walk；均复用 `chat_bucket`/`anthropic_bucket_index`/`responses_output_bucket`/`custom_tool_parts`/`synth_tool_id_with`。碎片路径的 `id` 在所有 push 点恒为 `Some`。既有 `src/handler/llm/pump/fragments/tests.rs` 多处以同一输入同时调用 `extract_tool_fragments` 与 `extract_tool_calls` 做等价对照（如 `:350-351`、`:374-375`、`:388-389`）。
- **ARC-4 头克隆/hop**：`src/handler/llm/nonstream.rs` 的 `passthrough_upstream_response`（`:321`）在 `:325-333` 克隆上游响应头、`:337-343` 解码配对 + `filter_hop_headers_counted`；`snapshot_downstream_headers`（`:388`）在 `:389-397` 克隆、`:398-404` 解码配对 + hop 过滤。两段头克隆**逐字重复**，hop 块同形。
- **ARC-5 死代码**：`src/service/llm_gateway/hop.rs:31-33` `pub fn filter_hop_headers`，重导出 `src/service/llm_gateway/mod.rs:286`；`grep -rn "filter_hop_headers" src/ tests/` 仅命中定义/重导出与 `_counted` 变体，无裸 `filter_hop_headers` 外部调用点。**起草复核修正**：审查清单误记为 `src/service/http/` 下 `hop.rs:31` 与 `mod.rs:286`（该目录不存在），实际为 `src/service/llm_gateway/hop.rs:31` 与 `src/service/llm_gateway/mod.rs:286`（见 proposal 覆盖表）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/`、README、`scripts/` 与其它 change 目录；无新依赖；不提交 commit。

## Goals / Non-Goals

**Goals：**

- 为 ARC-1–ARC-5 给出可实施的拆分/统一/删除方案与行为保持验证口径，使 apply 阶段逐项落地且独立可验证。
- 固化结构性契约（模块内聚、状态所有权、单实现、零死代码）为 spec REQUIREMENT，并明确「行为保持」为全部任务前提。
- 明确 ARC-2 的驱逐策略（仅终态、`InFlight` 永不驱逐）与软上限（仅剩 `InFlight` 超限时不驱逐 + warn/计数指标）可测语义。

**Non-Goals：**

- 不重设计流泵整体或 `AppState` 既有字段契约；不改决策表键语义（`pending_key`）与三态对外语义。
- 不引入新依赖、新配置项、新端点或新特性。
- 不做清单外架构重写；不处理 C1–C5、C7 的发现。
- 不改 `src/`/`tests/`/README/`scripts/`（本 change 只交付规划）。

## Decisions

### D1：流泵按 setup / 主循环 / 单事件处理拆分（ARC-1）

**决策**：将 `spawn_stream_pump`（`spawn.rs:49-699`）拆为：

1. **setup**：`StreamPumpCtx` 解构 + 循环状态初始化（现 `:56-148`）收敛为构造器，返回聚合可变状态的 `PumpLoopState` 结构体（含 `forwarded`/`agg`/`terminal_sent`/`pending_tool_frames`/`hold`/`meta`/`carry` 等）。
2. **main loop**：现 `:149-658` 拆出 `run_pump(...)` 驱动：chunk 读取（`:150-163`）与 parser 喂入（`:169-173`）留薄层，单事件处理体（`:174-654`）提取为 `handle_event(&mut state, ev, &deps) -> ControlFlow`。
3. **单事件处理内部再按职责提取**：Responses 控制动作（`:237-307`）、分片入 hold 与审计判定（`:370-489`）、还原/PII 扫描/发送（`:533-654`）各成内聚函数。
4. **收尾**：现 `:659-698` 提取为 `finish(...)`（调用既有 `terminal::finalize` + 指标 + `PumpOutcome`）；`spawn_stream_pump` 收敛为薄壳（建 setup → `run_pump` → `finish`）。

拆分子模块沿用既有布局：`spawn/setup.rs`（setup + 状态结构）、`spawn/event_loop.rs`（主循环与单事件处理）、`spawn/finish.rs`（收尾），与既有 `spawn/terminal.rs`、`spawn/frame_feed.rs` 并列。

**理由**：现状终止收尾已拆出，瓶颈在 setup 与巨型单事件体；把可变循环状态聚合为 `PumpLoopState` 可消除大量局部变量跨阶段借用 churn，使单事件处理成为可独立测试/评审的纯驱动函数。拆分保持所有分支与顺序原样搬移，帧序/终端/审计时序不变。

**备选**：①仅把 setup 抽为函数、主循环留原处——单事件体仍 480+ 行，未解决不内聚，不采用；②按协议拆三个独立泵——会复制公共骨架、扩大回归面且偏离「纯重构」，不采用；③不引入状态结构体、以大量 `&mut` 参数传递——借用冲突与参数爆炸，可读性更差，不采用。

### D2：审批决策表移入受管状态 + 仅驱逐终态（ARC-2）

**决策**：

- **所有权**：`DecisionTable` 由 `Arc<Mutex<DecisionTable>>` 承载，作为 `AppState` 字段构造并注入；`AppStateParts` 新增只读访问器（`fn decisions(&self) -> &Arc<Mutex<DecisionTable>>`），在唯一实现 `src/state.rs:137` 落地。`approval.rs` 的 `decisions()` 自由函数移除，所有调用点改经 `state.decisions()`；`record_credential_decision`（`:240`）改为接收 `state`（其 waiter 调用点已持有 `owned`），测试辅助 `credential_decision_slot` 改为经测试构建的 state 读取。
- **驱逐策略（软上限）**：容量超限时仅驱逐**终态**条目——按 `Decided.created` 升序（同刻以 key 字典序 tie-break）驱逐最早者，循环至不超软上限；**`InFlight` 永不驱逐**。若驱逐尽全部可驱逐 `Decided` 后仍超软上限（仅余 `InFlight`），则不驱逐任何条目、记 warn 并递增超软上限计数指标（`approval_decision_overflow_total`），允许暂时超出，直到 `InFlight` 自然落定；`InFlight` 数量受 Matrix 审批票并发约束、有界可观测，是软上限不被突破的最终 backstop。
- **容量边界（软上限）**：`DECISION_TABLE_MAX_ENTRIES`（`:160`）语义改为「**软**上限——仅约束可回收的终态条目数」；`sweep`（`:163-171`）维持 TTL 清理；容量与策略确定性、可单测（注入小上限）。
- **可观测**：软上限溢出累计与当前条目数经 `DecisionTable` 只读访问器暴露于 `GET /_admin/metrics`（`approval_decision_overflow_total`/`decision_table_size`，锁中毒降级 `0`）；软上限取值与驱逐策略不变。

**理由**：审批去重依赖 `InFlight` 存在（`begin` 遇 `InFlight` 返回 `Busy`，避免重复建单）；现行「任意非当前键」驱逐可能把尚在等待的 `InFlight` 删掉，导致同一 `pending_key` 被重复建单——这是正确性风险而非仅内存问题。表增长实际由一次性消费的 `Decided` 主导，仅驱逐终态即可保持有界；`InFlight` 由并发度天然约束。

**备选**：①保留 `static`，仅把驱逐改为过滤 `InFlight`——规避正确性风险但仍留进程级全局可变状态、不可注入、测试隔离差，不满足「移入受管状态」，不采用；②超限时拒绝新 `begin`（饱和 fail-closed）——会改变 `begin`/`202` 对外语义（可能把正常审批打成 `Busy`/错误），与「行为保持」冲突，不采用；③LRU 全表驱逐——仍会逐出 `InFlight`，不采用。

### D3：tool 提取器统一为单实现 + 薄适配（ARC-3）

**决策**：在 `src/service/llm_gateway/tool.rs` 建立单一三臂提取核心（以 `extract_tool_calls` 的 `Vec<ToolCall>` 为规范输出，覆盖两实现分支的**并集**：Chat 的 `delta`/`message`/`function_call`/`custom_tool_call`、Anthropic 的 `content_block`/`delta`/`content`/`message.content`/`function_call`/`custom_tool_call`、Responses 的 `function_call_arguments.delta/done`、检索事件、`output_item.added/done`、`output` 数组）。`extract_tool_fragments` 改为薄适配层：调用核心后映射为既有元组 `(index, Some(id), name, args)`（碎片路径 `id` 恒 `Some`，`id_synth` 在碎片路径不消费）；或由调用点直接消费 `ToolCall`。两入口签名与调用点保持不变，对外可观测结果不变。

**理由**：两实现已复用全部原语 helper，剩余重复即三臂 walk；统一后消除漂移面。既有 `fragments/tests.rs` 的 frag↔calls 等价对照用例是天然的等价锁定——统一实现须使这些用例全绿，且非流单测（`tool/tests.rs`）与 e2e 无回退。

**备选**：①把碎片路径改为调用 `extract_tool_calls` 并直接删除碎片函数——会改动 `spawn.rs` 调用点（`:223/:315`）与返回类型消费，扩大回归面，不采用；②反向以碎片元组为规范——`id_synth` 信息丢失且非流路径需改，不采用；③保留双实现仅加注释互引——不消除重复与漂移风险，不采用。

### D4：上游响应头克隆 + hop 过滤抽单一 helper（ARC-4）

**决策**：在 `src/handler/llm/nonstream.rs` 新增单一 helper（如 `clone_upstream_headers(up: &reqwest::Response, metrics: &GatewayMetrics) -> HeaderMap`），封装：上游头克隆进 `HeaderMap` + `downstream_decode_enabled` 解码配对判定 + `filter_hop_headers_counted(..., "downstream", decode_enabled, Some(metrics))`。`passthrough_upstream_response` 与 `snapshot_downstream_headers` 改调该 helper；后者额外的 `x-veil-*` 剔除与前者额外的 `builder.header`/`Body::from_stream` 不并入 helper（保持各自职责）。

**理由**：两段克隆逐字相同、hop 块同形，抽 helper 后编码配对语义与计数副作用单点维护，消除分叉。helper 返回过滤后的 `HeaderMap`，两路径消费方式不同（一为发响应、一为再剔除 `x-veil-*`），故只统一「克隆 + 过滤」公共段。

**备选**：①把 `x-veil-*` 剔除与 `builder` 装配一并抽入——两路径职责差异被硬合并，降低内聚，不采用；②不抽、仅去重注释——不消除重复，不采用。

### D5：删除死代码 `filter_hop_headers`（ARC-5）

**决策**：删除 `src/service/llm_gateway/hop.rs:31-33` 的 `pub fn filter_hop_headers` 定义与 `src/service/llm_gateway/mod.rs:286` 的重导出；保留 `filter_hop_headers_counted` 为唯一入口（生产调用点：`src/handler/llm/mod.rs:44`、`nonstream.rs:338/399`、`dispatch.rs:332` 均用 `_counted`）。删除后确认 `hop.rs` 内单测不依赖该裸函数。

**理由**：零生产引用死代码污染符号面；删除无行为影响。删除前须确认 `src/service/llm_gateway/hop.rs` 的 `#[cfg(test)]` 单测未调用裸 `filter_hop_headers`（现状单测均用 `_counted`）。

**备选**：①标 `#[allow(dead_code)]` 保留——掩盖真实调用关系、不满足「生产零引用死代码清除」，不采用；②保留为 deprecated 并注释——零调用者下无迁移价值，不采用。

**起草复核修正**：审查清单 ARC-5 误记路径为 `src/service/http/` 下 `hop.rs` + `mod.rs:286`（该目录不存在），实际为 `src/service/llm_gateway/hop.rs` 与 `src/service/llm_gateway/mod.rs:286`；本 change 以复核后的真实路径为准，未静默改发现语义。

### D6：行为保持验证策略（横切）

**决策**：apply 阶段按「先锁等价、后重构」执行——①对每项先运行相关既有测试确认基线绿；②重构/统一/删除后运行同一测试集 + `cargo fmt`/`cargo clippy --tests --all-targets -- -D warnings`/`cargo test`；③ARC-1/ARC-3/ARC-4 额外运行对应 e2e 与 frag↔calls 对照用例；④ARC-5 以 `grep` 零引用 + clippy 无 `dead_code` 锁定；⑤全局以 `scripts/check_file_sizes.py`（800 行上限）与 `scripts/check_doc_paths.py` 收口。任何一项回退即停止并报告差距，不跳过。

**理由**：纯重构的唯一验收是「行为不变 + 长期约束改善」；以既有测试为等价判据、以门禁为结构判据，避免新增口径。

## Risks / Trade-offs

- [ARC-1 拆分改变借用/生命周期致编译期大改] → 以 `PumpLoopState` 聚合可变状态、按原顺序搬移分支；不改变分支条件与 await 点顺序；逐阶段编译验证，测试绿为准。
- [ARC-1 拆分引入行为漂移（帧序/等待点）] → 纯搬移不重排；保留 `terminal::finalize` 与 `frame_feed` 不动；以截断矩阵/审计阻断/增量到达 e2e 锁定。
- [ARC-2 状态注入触及调用链] → 唯一 `AppStateParts` 实现（`state.rs:137`）加字段访问器；`record_credential_decision` 调用点已持有 state；测试辅助改为经 state 读取；若个别测试无 state，允许测试内自建 state 实例。
- [ARC-2 仅驱逐终态致 InFlight 过多时短暂超软上限] → 软上限显式允许暂时超出：仅剩 `InFlight` 时不驱逐、记 warn + 计数指标 `approval_decision_overflow_total`；`InFlight` 受 Matrix 审批票并发约束且有界，作为 backstop；不驱逐 `InFlight` 是正确性优先的显式取舍。
- [ARC-3 统一后某协议分支漏并集] → 以两实现分支并集为目标，逐分支对照迁移；frag↔calls 对照用例 + 三协议单测 + e2e 锁定。
- [ARC-4 helper 抽取改变头集合/顺序] → helper 内保持原克隆顺序与过滤调用顺序；`x-veil-*` 剔除留在调用点；非流/非对话透传测试锁定。
- [ARC-5 删除后仍有隐藏引用（如宏/文档）] → 删除前全仓 `grep` + clippy `-D warnings` 双门禁；文档指针（如 README §7.1 引用 `filter_hop_headers_counted`）不受影响。
- [范围蔓延] → 严格限定 ARC-1–ARC-5；不碰 C1–C5/C7；Non-Goals 显式排除清单外重写。

## Migration Plan

1. 按 tasks 顺序落地：先 ARC-5（删除死代码，最小面）与 ARC-4（抽取 helper），再 ARC-3（统一提取器），再 ARC-2（状态注入 + 驱逐策略），最后 ARC-1（流泵拆分，回归面最大）。
2. 每项独立运行对应测试集与门禁；测试名/验证命令与 tasks「验证：」行对齐。
3. 回滚策略：按项 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化、无对外行为变化。
4. 发布口径：无 BREAKING、无配置项变化、无下游可感知行为变化；纯内部结构重构。

## Open Questions

- 无。五项决策均可直接落地；ARC-1 的子模块命名（`spawn/setup.rs`/`event_loop.rs`/`finish.rs`）为可调实现细节，不改变 spec、方案或任务拆分，apply 时可随实际依赖就近调整。
