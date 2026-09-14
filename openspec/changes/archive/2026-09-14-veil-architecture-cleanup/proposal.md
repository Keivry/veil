## Why

独立六维审查（2026-09-14，架构清理面）确认 5 项架构风险（ARC-1–ARC-5），均为可维护性/正确性问题而非流式保真缺陷：一处 **651 行**巨型函数（逻辑不内聚）、一处进程级 `static` 审批决策表且驱逐可能误删 `InFlight` 票、一处三协议 tool 提取器双实现（约 300 行重复）、一处响应头克隆 + hop 过滤逐字重复、一处零调用死代码。若不收敛：巨型函数难评审与定位回归；驱逐误删 `InFlight` 会破坏审批去重（重复建单）；双实现与重复代码随演进漂移分叉；死代码污染符号面并掩盖真实调用关系。

真相源为 `src/` 现行实现；本 change 起草时已逐一打开源码复核行号与重复范围（见覆盖表「起草复核」列），修正了审查清单中 ARC-5 的目录笔误（审查记为 `src/service/http/*`，实为 `src/service/llm_gateway/*`；`src/service/http/` 不存在）。本 change 只交付规划 artifacts（proposal/design/spec/tasks），为**纯重构计划**：不改 `src/`、`tests/`、`README.md`、`scripts/` 任何实现或其它 change 目录；实现留待 apply 阶段，且全部任务以**行为保持（behavior-preserving）**为前提。

## What Changes

- **`ARC-1` 巨型函数按职责拆分**：`src/handler/llm/pump/spawn.rs:49-699` 的 `spawn_stream_pump`（651 行）按职责拆分——参数/设置（setup）、主循环（main loop，与单帧/单事件处理）、收尾合成与 finalize 三段。纯重构，帧序/帧内容/终端语义零变化。注：终止收尾已由 `spawn/terminal.rs::finalize` 承载（`spawn.rs:659` 调用），本项补齐 setup 与主循环的职责内聚拆分。
- **`ARC-2` 审批决策表受管化 + 仅驱逐终态（软上限）**：`src/service/credential/approval.rs:233` 的进程级 `static DECISIONS: OnceLock<Mutex<DecisionTable>>` 移入受管状态（`AppState`/`Arc` 注入）；`resolve`（`:213-217`）驱逐由「任意非当前键」改为**仅驱逐终态 `Decided` 条目**（按 `Decided.created` 升序，同刻 key 字典序 tie-break），`InFlight` 永不驱逐；容量为**软上限**（`DECISION_TABLE_MAX_ENTRIES=4096`）——仅剩 `InFlight` 超限时不驱逐、记 warn 并递增计数指标（`approval_decision_overflow_total`），以 Matrix 审批票并发度为 backstop；驱逐策略确定性、可测。该溢出累计与当前条目数经 `DecisionTable` 只读访问器在 `GET /_admin/metrics` 暴露为 `approval_decision_overflow_total`/`decision_table_size`，使软上限占用状态可观测（软上限取值与驱逐语义不变）。
- **`ARC-3` C6 tool 三臂提取器统一**：`src/service/llm_gateway/tool.rs:196-578` `extract_tool_calls`（383 行）与 `src/handler/llm/pump/fragments.rs:20-376` `extract_tool_fragments`（357 行）合并为**单一共享实现**，两路径共用同一三臂 walk；`extract_tool_fragments` 保留为薄适配层（输出元组）或由调用点直接消费统一返回类型。行为（分桶/合成 id/字段优先级/检索事件/`.done` 语义）逐项等价。
- **`ARC-4` 响应头克隆 + hop 过滤抽公共 helper**：`src/handler/llm/nonstream.rs:325-333`（`passthrough_upstream_response`）与 `:389-397`（`snapshot_downstream_headers`）逐字重复的头克隆循环，以及相邻 hop 过滤块（`:337-343` vs `:398-404`）抽为单一 helper，两调用点复用。
- **`ARC-5` 删除死代码 `filter_hop_headers`**：删除 `src/service/llm_gateway/hop.rs:31-33` 的 `pub fn filter_hop_headers` 定义与 `src/service/llm_gateway/mod.rs:286` 的重导出；生产路径均用 `filter_hop_headers_counted`，删除后无引用、无 `dead_code` 警告。
- **门禁与行为保持**：全部改动后 `cargo fmt`/`cargo clippy --tests --all-targets -- -D warnings`/`cargo test` 全绿，`python3 scripts/check_file_sizes.py` 与 `python3 scripts/check_doc_paths.py` 通过；新增/拆分函数均远低于 800 行文件上限。

## Capabilities

### New Capabilities

- `architecture-cleanup`：架构清洁度契约——巨型函数按职责拆分且行为保持、审批决策表受管状态且驱逐仅限终态（`InFlight` 永不误逐）、三协议 tool 提取器单一实现、响应头克隆/hop 过滤单一 helper、无生产零引用死代码。

### Modified Capabilities

- 无。本 change 为行为保持的纯重构，不改变任何既有 canonical spec 的运行时 REQUIREMENT；新增 `architecture-cleanup` capability 承载结构性契约与验证口径。

## 发现覆盖表（ID → 严重度 → 起草复核证据 → 修复要点 → task）

| ID | 严重度 | 起草复核证据（已打开源码） | 修复要点 | task |
|:---|:-------|:---------------------------|:---------|:-----|
| `ARC-1` | P2 | `src/handler/llm/pump/spawn.rs:49-699` `spawn_stream_pump` = **651 行**（文件共 699 行）；主循环 `loop {` 起于 `:149`；`terminal::finalize` 调用 `:659`。审查记「~645 行」 | 按 setup / main loop / 单事件处理三段拆出内聚函数，`spawn_stream_pump` 收敛为薄壳；帧序与终端语义零变化 | 5.1-5.4 |
| `ARC-2` | P2 | `src/service/credential/approval.rs:233` `static DECISIONS: OnceLock<Mutex<DecisionTable>>`；`DECISION_TABLE_MAX_ENTRIES=4096`（`:160`）；`resolve` 驱逐 `:213-217` 取任意非当前键（`HashMap` 序，可为 `InFlight`）；`sweep` `:163-171` 仅清过期 `Decided`。审查记 `:213-237` | 决策表移入 `AppState`/`Arc` 受管状态；驱逐仅针对终态（`Decided`，按 `created` 升序），`InFlight` 永不驱逐；容量为软上限——仅剩 `InFlight` 超限时不驱逐 + warn/计数指标（`approval_decision_overflow_total`，经 `/_admin/metrics` 只读暴露为 `approval_decision_overflow_total`/`decision_table_size`）；容量策略可测确定 | 4.1-4.4 |
| `ARC-3` | P2 | `src/service/llm_gateway/tool.rs:196-578` `extract_tool_calls`（383 行）vs `src/handler/llm/pump/fragments.rs:20-376` `extract_tool_fragments`（357 行）；两者三臂 walk 重复，共用 `chat_bucket`/`anthropic_bucket_index`/`responses_output_bucket`/`custom_tool_parts`/`synth_tool_id_with`。审查记 `tool.rs:196-577`、`fragments.rs:20-376` | 统一为单一实现，碎片路径改薄适配；分叉对齐由既有 `fragments/tests.rs` 的 frag↔calls 对照用例锁定 | 3.1-3.3 |
| `ARC-4` | P2 | `src/handler/llm/nonstream.rs:325-333`（`passthrough_upstream_response` 头克隆）与 `:389-397`（`snapshot_downstream_headers` 头克隆）逐字重复；hop 过滤块 `:337-343` vs `:398-404` 同形。审查记 `:325-333` vs `:389-397` | 抽「上游响应头克隆 + 剥 hop + 解码配对」单一 helper，两调用点复用 | 2.1-2.2 |
| `ARC-5` | P3 | `src/service/llm_gateway/hop.rs:31-33` `pub fn filter_hop_headers`；重导出 `src/service/llm_gateway/mod.rs:286`；`grep -rn "filter_hop_headers"` 无外部调用点（生产路径均用 `filter_hop_headers_counted`）。**起草复核修正：审查误记为 `src/service/http/` 下 `hop.rs`+`mod.rs`（该目录不存在），实际为 `src/service/llm_gateway/hop.rs` 与 `src/service/llm_gateway/mod.rs`** | 删除定义 + 重导出；`clippy` 无 `dead_code` 警告、全仓零引用 | 1.1-1.2 |

## Non-Goals（显式）

- **规划-only**：本 change 只交付 proposal/design/spec/tasks 规划 artifacts；**SHALL NOT 改 `src/`、`tests/`、`README.md`、`scripts/`、其它 `openspec/changes/` 目录**；不提交 commit。
- **行为保持**：所有任务 SHALL 为纯重构——不改运行时行为、协议语义、审计 verdict 口径、脱敏口径、指标/日志口径、对外 API 形态（含 `202 + E_PENDING`、审批 TTL、审批消息内容）。
- **不扩范围**：仅处理 ARC-1–ARC-5；不做清单外的架构重写（如不重设计流泵整体、不改 `AppState` 既有字段契约、不改决策表键语义 `pending_key`）。
- **无新依赖**：仅用现有 `std`/`tokio`/`axum`/`serde` 生态，不新增 crate。
- **不新增功能**：不借重构引入新特性、新配置项或新端点。
- **不静默合并/删除发现**：ARC-1–ARC-5 逐项独立映射 task，不合并、不遗漏（见覆盖表）。

## Impact

- **新增文件**：`openspec/changes/veil-architecture-cleanup/proposal.md`、`design.md`、`specs/architecture-cleanup/spec.md`、`tasks.md`（`.openspec.yaml` 已脚手架在位）。
- **apply 阶段改动面**：`src/handler/llm/pump/spawn.rs`（+ 新增子模块如 `spawn/setup.rs`、`spawn/event_loop.rs` 或等价拆分）、`src/service/credential/approval.rs`（+ 决策表状态注入接线，涉 `src/state.rs` / `src/handler/credential.rs` 调用点）、`src/service/llm_gateway/tool.rs`、`src/handler/llm/pump/fragments.rs`、`src/handler/llm/nonstream.rs`、`src/service/llm_gateway/hop.rs`、`src/service/llm_gateway/mod.rs` 及对应单测。
- **影响系统**：模块内聚性与可评审性、审批去重正确性（`InFlight` 不被误逐）、tool 提取路径一致性、响应头过滤单实现、符号面清洁度。运行时对外行为不变。
- **依赖**：无新依赖；仅既有 `std`/`tokio`/`axum`/`reqwest`/`serde_json` 与测试设施。
