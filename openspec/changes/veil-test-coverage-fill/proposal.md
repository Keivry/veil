## Why

覆盖审查（2026-09-11，只读 `src/` 与 `tests/`）确认：`cargo test` 当前 **784 passed / 0 failed / 21 suites**（`cargo test -- --list` 计 **640 项**），相对原仓 Python 约 **727 用例（41 个 `*_test.py`，需 `pytest -o python_files=*_test.py` 收集）**总量已反超，但**覆盖粒度与门禁闭环**存在 4+1+2 项待收敛缺口：

- **T1（High，最高风险缺口）`spawn.rs` 无直接单测**：`src/handler/llm/pump/spawn.rs`（**717 行**，三协议流式主循环）无任何 `#[cfg(test)]`；终止判定/N1 守卫/P1 补 DONE/空流守门/边界 hold 释放/tool hold-until-complete/rejected_sticky 抑制等决策点仅经 `src/handler/llm/stream_tests.rs`（14 项）、`src/handler/llm/proto_closeout_tests.rs`（11 项）、`tests/http_e2e_truncation_matrix.rs`（7 项）间接覆盖。原仓 `tests/llm_test.py` 的 **90 个细粒度算法用例**正对应此层；分支级回归目前无法直接定位，等价重构（抽纯函数）也无直接断言面。`src/handler/llm/pump/event.rs` 已有 `empty_stream_synthesis_gate_truth_table` 等谓词直测，但主循环内联判定（N1 `if terminal_sent { continue; }`、P1 四条件与、sticky 三分支、buffer/replay/hold 抑制）仍埋在 async 闭包内。
- **T2（Medium，薄弱用例）**：三个 e2e 断言密度偏低——`tests/http_e2e_pii_concurrency.rs::t3_1_pii_100_concurrent_restore_isolated_no_crosstalk`（**3 条 `assert!`**，第 3 条为嵌套循环）、`tests/http_e2e_metrics_snapshot.rs::b5_snapshot_shape_matches_series_and_empty_window_ok`（**7 条**，仅字段存在性）、`tests/http_e2e_nondialog_passthrough.rs::t2_1_nondialog_models_passthrough_with_count_and_no_side_effects`（**9 条**）。
- **T3（Medium，口径）真 SDK 一致性未进 `cargo test`**：原仓 `api_spec_conformance_test.py`（**12 项真 SDK e2e**）在本仓移入 `scripts/api_conformance.py`（**20 项 = 11 常规 + 3 阻断 + 5 取用 + 1 无库 503**，覆盖更广，SDK pin `openai==3.5.0`/`anthropic==1.1.0`），但默认不在 `cargo test`，也无显式 gate/CI 步骤（仓库无 `.github/workflows`）；README §8.5 仅声明「口径不同非回归缺失」。
- **T4（Medium，粒度）可观测性测试粒度下降**：原仓独立 `observability_model_filter_test.py(4)` / `observability_upstream_filter_test.py(3)` / `observability_series_test.py(5)` / `observability_sse_metrics_test.py(1)`；本仓合并为 `tests/http_e2e_metrics_filter.rs(2)` + `src/service/metrics/aggregate/tests.rs(13)` + `tests/http_e2e_metrics_snapshot.rs(1)`。现存 e2e 仅覆盖 `range=24h` 一档旧映射（`http_e2e_metrics_filter.rs:181`）、model/upstream 仅「弃用忽略」断言（同文件 `:168-178`）、快照仅字段存在性；缺 model/upstream 实际筛选（SSE 建连过滤，`src/service/admin/sse.rs:82-116` 仅单测 `sse_filter_dimensions`）、`1h/7d/30d` 映射、SSE 快照形状与取值。
- **GO（Medium，闭环）Go 端到端 5.1–5.3 未闭环**（`veil-hardening` 承接，README §5/§8.3）：存量 Go 直连全链路、三因子齐全/缺失两场景、阻断流终止验证。Go 侧判定为「不可直接轮询 202/E_PENDING、取用路径不发三因子头、无 SSE 消费代码」，真机闭环依赖 Go 侧改动；网关侧行为目前仅存于 `veil-hardening/tasks.md` 的人工验证记录，无 Rust 契约测试锁定。
- **记录项**：`#[ignore]`/禁用测试为 **0**（全仓仅 `tests/http_e2e_pii_concurrency.rs:6` 的 `//!` 注释提及 flaky 隔离策略，无实际属性）；`spawn.rs` 之外的零直接测试文件（gateway 面 facade、`sse/emit.rs`/`meta.rs`/`parser.rs`、`block_inject/frames.rs`/`terminal.rs`）由上层 `sse.rs`（**30 项**，apply 实测；审计基线 29）`/`block_inject.rs`（**24 项**）覆盖，属可接受，design.md 记录。

真相源为 `src/handler/llm/pump/{spawn,pump,event}.rs`、`src/handler/llm/stream_tests.rs`、`src/handler/llm/proto_closeout_tests.rs`、`tests/http_e2e_{pii_concurrency,metrics_snapshot,nondialog_passthrough,metrics_filter,truncation_matrix}.rs`、`scripts/api_conformance.py`、README §5/§8.3/§8.5。本 change 只规划测试补齐与门禁（proposal/design/spec/tasks），不改 `src/`、`tests/` 与既有 change。

## What Changes

- **T1 泵关键决策点直接单测**：把 `spawn.rs` 主循环的内联判定抽为纯函数（新 `src/handler/llm/pump/decide.rs`，`pub(super)`，无 async/无 IO），新增 `#[cfg(test)] mod spawn_tests`（`src/handler/llm/pump/spawn_tests.rs`）承载真值表与泵直测，覆盖 7 决策点：终止判定、N1 守卫、P1 补 DONE、空流守门、边界 hold 释放、tool hold-until-complete、rejected_sticky 抑制；等价重构由既有 `stream_tests`/`proto_closeout_tests`/truncation e2e 全绿锁定。
- **T2 薄弱断言增强**：三个 e2e 提升断言厚度——PII 100 并发逐请求校验 + 全对串扰矩阵 + 计数断言；快照字段类型/取值/与 series 一致；NonDialog 计数递增/无副作用/hop 过滤。
- **T3 真 SDK 脚本纳入门禁**：定义显式 gate 步骤（`scripts/gate.sh`，含前置条件、失败非零退出、Mock TPM 回退），把 `scripts/api_conformance.py` 接入 gate，并更新 README §8.5/`scripts/README.md` 口径声明；不要求改写为 cargo 测试。
- **T4 可观测性粒度恢复**：补 model/upstream 筛选 e2e（SSE 建连过滤 + metrics/events 弃用忽略）、series 旧 `range=1h/24h/7d/30d` 四档映射 e2e、SSE 快照形状/取值显式断言。
- **GO 网关侧契约锁定**：新增镜像 Go `get` 请求形状的 Rust 集成/契约测试（纯 body POST 无头 → 403 `E_AUTH` 对象体；三因子齐全/缺失矩阵；三协议阻断流终止 0s 闭合），与 `veil-hardening` 5.1–5.3 交叉引用（不改该 change 文件）；真机 Go 闭环仍由 `veil-hardening` 承接。
- **记录项落 design.md**：零直接覆盖文件清单与可接受理由；`#[ignore]` 为 0 及验证命令。

## Capabilities

### New Capabilities

- `test-coverage-fill`：测试补齐的输入输出与可验证场景——泵决策点直接单测、薄弱断言厚度、真 SDK 脚本门禁、可观测性粒度、Go 网关侧契约锁定、覆盖登记。

### Modified Capabilities

- 无。既有 `openspec/specs/`（`coverage-closure`、`test-gap-closure`、`review-coverage-fill`、`test-closure-round2` 等）的行为契约不动；本 change 只新增测试资产与门禁声明，不改变任何生产语义。

## 发现覆盖表（ID → 严重度 → 发现要点 → 覆盖方式 → task）

| ID | 严重度 | 发现要点 | 覆盖方式 | task |
|:---|:-------|:---------|:---------|:-----|
| `T1` | HIGH | `spawn.rs`（717 行）无 `#[cfg(test)]`；7 决策点仅间接覆盖（原仓 `llm_test.py` 90 例对应层） | 抽纯函数 `decide.rs` + `spawn_tests` 真值表（每点 ≥2 正例+≥1 负例）+ 泵直测 4 例 | 1.1、1.2、1.3 |
| `T2-1` | MED | `t3_1_pii_100_concurrent...` 仅 3 条 assert | 并发逐请求断言 + 全对串扰矩阵 + `requests==100` | 2.1 |
| `T2-2` | MED | `b5_snapshot_shape...` 仅 7 条 assert（存在性） | 字段类型/取值断言 + series 与快照一致 | 2.2 |
| `T2-3` | MED | `t2_1_nondialog_models...` 仅 9 条 assert | 计数递增 1→2→3 + hop 过滤 + 无用量/审计/还原 | 2.3 |
| `T3` | MED | `api_conformance.py` 20 项未进 cargo/CI 门禁，无 gate 步骤 | `scripts/gate.sh` 串联 + README §8.5/`scripts/README.md` 同步 | 3.1、3.2 |
| `T4-1` | MED | model/upstream 筛选仅「弃用忽略」，无实际过滤 e2e | 补 SSE 建连筛选 + 弃用忽略双口径 e2e | 4.2 |
| `T4-2` | MED | series 旧 `range` 仅 `24h` 一档 e2e | `1h/24h/7d/30d` 四档映射与等价性 e2e | 4.1 |
| `T4-3` | MED | SSE 快照仅字段存在性 | `sse_events`/`per_protocol`/`truncated` 形状与取值断言 | 4.3 |
| `GO` | MED | Go 5.1–5.3 未闭环（`veil-hardening` 承接） | 网关侧 Rust 契约测试（Go 形状直连/三因子矩阵/阻断终止）+ 交叉引用；真机 Go 闭环仍由 `veil-hardening` 承接（本 change 不冒充） | 5.1、5.2、5.3 |
| `R1` | 记录 | `#[ignore]`/禁用测试为 0 | design.md 记录 + grep 验证 | 6.1 |
| `R2` | 记录 | 零直接覆盖文件可接受（上层 `sse.rs` 29/`block_inject.rs` 24 覆盖） | design.md D6 记录清单与理由 | 6.2 |

## Non-Goals（显式）

- **不改任何 `src/`/`tests/` 代码**：本 change 只交付规划 artifacts；测试与等价重构落 apply 阶段。
- **不改生产语义与对外行为**：T1 的纯函数抽取为等价重构，若 apply 阶段暴露实现 bug，转对应修复 change 处理，不在本 change 修实现。
- **不要求 Go 真机闭环**：Go 侧改动另立 change；`veil-hardening` 5.1–5.3 的承接关系只读引用，不修改该 change 任何文件。
- **不把 `scripts/api_conformance.py` 改写为 `cargo test`**：SDK pin 与 Python venv 前置条件不同，保留脚本口径（原仓 12 项 vs 本仓 20 项差异为有意）。
- **不新增运行时依赖**：测试仅用既有 `tokio`/`reqwest`/`serde_json`/`axum` 设施；不引入测试框架。
- **不改既有 change 文件；不提交 commit。**

## Impact

- **新增文件（本 change）**：`openspec/changes/veil-test-coverage-fill/` 下 `.openspec.yaml`、`proposal.md`、`design.md`、`specs/test-coverage-fill/spec.md`、`tasks.md`。
- **apply 阶段改动面**：`src/handler/llm/pump/decide.rs`（新增纯函数）、`src/handler/llm/pump/spawn_tests.rs`（新增）、`src/handler/llm/pump.rs`（声明 `mod decide`/`mod spawn_tests`）、`src/handler/llm/pump/spawn.rs`（调用纯函数、替换内联判定）、`tests/http_e2e_pii_concurrency.rs`、`tests/http_e2e_metrics_snapshot.rs`、`tests/http_e2e_nondialog_passthrough.rs`、`tests/http_e2e_metrics_filter.rs`、`tests/go_interop_contract.rs`（新增）、`scripts/gate.sh`（新增）、`scripts/README.md`、`README.md` §8.5。
- **影响系统**：测试覆盖粒度、CI/发布门禁可执行性、Go 互操作契约的可追踪性；生产行为零变更。
- **依赖**：既有真回环 harness（`test_app()`+`serve()`+`mock_upstream()` 形态）、`scripts/api_conformance.py` 的 Python venv 与 SDK pin（`openai==3.5.0`/`anthropic==1.1.0`）、Mock TPM 回退 `VEIL_ALLOW_MOCK_TPM=1`。
