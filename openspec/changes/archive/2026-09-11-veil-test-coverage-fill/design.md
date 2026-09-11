## Context

覆盖审查（2026-09-11，只读）基线（全部实测/计数确认）：

- `cargo test` = **784 passed / 0 failed / 21 suites**；`cargo test -- --list | grep -c ": test$"` = **640**。
- 原仓 Python = **41 个 `*_test.py`**（`/home/keivry/项目/Python/credential-proxy/tests/`），合计约 727 用例；`llm_test.py` 实测 `def test_` = **90**；`observability_model_filter_test.py`=4、`observability_upstream_filter_test.py`=3、`observability_series_test.py`=5、`observability_sse_metrics_test.py`=1、`api_spec_conformance_test.py`=12。
- 流泵真相源：`src/handler/llm/pump/spawn.rs`（717 行，无 `#[cfg(test)]`）；主循环决策点行号——N1 守卫 `spawn.rs:222`、Responses error/failed 分支 `:225-259`、sticky 抑制 `:199-217`、tool 重放槽 `:280-286`、hold-until-complete 缓冲 `:299-304`、边界 hold 抑制 `:482`、`[DONE]` 终端去重 `:518`、P1 补发四条件 `:625-628`、空流守门 `:655`、截断丢弃 `:549-587`。
- 既有间接覆盖：`stream_tests.rs`（585 行，14 项泵级测试，harness `pump_ctx`/`loopback_server`/`collect_pump` 在 `:35/:64/:106`）、`proto_closeout_tests.rs`（469 行，11 项，含 `n1_single_terminal_completed_then_error_or_incomplete`、`p1_chat_done_three_scenarios`、`vacuum_stream_three_protocol_e2e_comparison`）、`tests/http_e2e_truncation_matrix.rs`（7 项）。
- 既有谓词直测：`src/handler/llm/pump/event.rs`（`empty_stream_synthesis_gate_truth_table`、`dedupe_terminal_single_truncated_frame` 等）；`src/service/admin/sse.rs::sse_filter_dimensions` 单测；`src/service/admin/events.rs` 旧 range 映射单测。
- 薄弱 e2e 实测断言：`tests/http_e2e_pii_concurrency.rs:92`（3 条 `assert!`，`CONCURRENCY=100`）、`tests/http_e2e_metrics_snapshot.rs:53`（7 条）、`tests/http_e2e_nondialog_passthrough.rs:86`（9 条）。
- `scripts/api_conformance.py` 项数结构：`run_normal_phase` 11 项（三协议流式/非流式/tool）、`run_block_phase` 3 项、`run_credential_phase` 5 项 + `no_db` 1 项 = **20**；退出码非零即失败（`main()` 末 `SystemExit(1 if failed else 0)`）。
- 仓库无 `.github/workflows` 等 CI 配置；门禁现状为 README/`scripts/README.md` 记述的手工命令。
- `#[ignore]` 实测 0 个属性（仅 `tests/http_e2e_pii_concurrency.rs:6` 注释文本）。
- 零直接测试文件（`cfg(test)` 仅测试用访问器/无测试模块）：`src/service/sse/emit.rs`、`meta.rs`、`parser.rs`、`src/service/block_inject/frames.rs`、`terminal.rs` 及 gateway 面 facade；由上层 `src/service/sse.rs`（30 项）、`src/service/block_inject.rs`（24 项）覆盖（apply 实测；审计基线 `sse.rs` 29 项，前序 change 新增 1 项）。

约束：本 change 只写规划 artifacts，不改 `src/`、`tests/` 与既有 change；不改生产语义；测试库文件受 `scripts/check_file_sizes.py` 800 行上限约束（`spawn.rs` 已 717 行，测试必须外置）。

## Goals / Non-Goals

**Goals：**

- **T1**：为流泵 7 个关键决策点建立**直接**单测（真值表 + 泵直测），并把内联判定抽为纯函数以便断言；等价重构由既有 `stream_tests`/`proto_closeout_tests`/truncation e2e 全绿锁定。
- **T2**：三个薄弱 e2e 断言厚度提升到请求级/字段级/取值级，保持耗时预算与并发规模不变。
- **T3**：`scripts/api_conformance.py`（20 项真 SDK）纳入显式 gate 步骤，前置条件与失败语义文档化，README §8.5 口径同步。
- **T4**：恢复可观测性粒度——model/upstream 筛选、series `1h/24h/7d/30d` 四档、SSE 快照形状与取值。
- **GO**：以 Rust 契约测试锁定 Go `get` 请求形状下的网关侧行为，与 `veil-hardening` 5.1–5.3 交叉引用。
- **记录**：零直接覆盖文件清单与可接受理由、`#[ignore]` 为 0 落 design.md。

**Non-Goals：**

- 不改任何生产语义/对外行为；不改 `stream_options`/usage/审计 verdict/脱敏口径。
- 不把 `api_conformance.py` 改写为 cargo 测试，不新增 Python 依赖。
- 不要求 Go 真机闭环（`veil-hardening` 5.x 承接，Go 侧改动另立 change）。
- 不改既有 `openspec/changes/` 文件；不提交 commit。

## Decisions

### D1：T1 抽纯函数 + 外置 `spawn_tests`，测试不经 inline `#[cfg(test)]`

**决策**：新增 `src/handler/llm/pump/decide.rs`（crate-internal `pub(super)`，全纯函数、无 async/无 IO），把 `spawn.rs` 内联布尔判定替换为函数调用；新增 `#[cfg(test)] mod spawn_tests`（声明于 `pump.rs`，文件 `src/handler/llm/pump/spawn_tests.rs`）承载真值表与泵直测。抽取清单（7 决策点 → 函数）：

| 决策点 | 纯函数（拟定签名，布尔入参） | spawn.rs 现位置 |
|:-------|:------------------------------|:----------------|
| N1 守卫/Responses 控制帧 | `responses_control_action(terminal_sent, responses_failed_sent, is_error, is_failed) -> ResponsesAction`（`Ignore`/`SynthesizeFailed`/`FailIfFirst`/`Passthrough`） | `:222-259` |
| P1 补 DONE | `should_backfill_chat_done(protocol, terminal_sent, saw_finish_reason, truncated_mode_set) -> bool` | `:625-628` |
| 空流守门（既有） | `should_synthesize_empty_stream(terminal_sent, any_frame_sent, block_injected)`（已在 `event.rs:50`，补 pump 调用序不变量测试） | `:655` |
| tool hold-until-complete 缓冲 | `should_buffer_tool_frame(audit_hold_on, is_tool_event, is_complete, is_index_complete) -> bool` | `:299-304` |
| 完成帧重放槽 | `tool_replay_slot(protocol, v, is_complete, is_index_complete) -> Option<Option<u32>>`（包装既有 `outer_event_index`） | `:280-286` |
| 边界 hold 抑制 | `should_suppress_held_output(minor, hold_held, out_data_nonempty) -> bool` | `:482` |
| rejected_sticky 抑制 | `sticky_suppress_action(rejected_sticky, data_empty, is_done, is_terminal, is_tool_or_complete) -> StickyAction`（`Pass`/`Drop`） | `:199-217` |

**理由**：`spawn.rs` 717 行逼近 800 行上限，inline 测试不可行且违反 `check_file_sizes.py`；`event.rs` 已有「纯谓词 + 真值表测试」先例（`empty_stream_synthesis_gate_truth_table`），沿用以保持一致风格。纯函数只承载布尔决策，`metrics` 计数与副作用留在调用点（保持可观测计数不漂移）。等价重构以既有 14+11+7 项间接测试全绿为锁定条件；未覆盖组合由新真值表补足。

**备选**：把测试追加到 `stream_tests.rs`（585/800 行，余量不足且职责混杂，不采用）；`#[cfg(test)]` inline 于 `spawn.rs`（触上限，不采用）；仅依赖间接 e2e（本次要消除的缺陷，不采用）。

### D2：T2 断言增强只加不减，保持预算与规模

**决策**：三个 e2e 仅增加断言/校验维度，不改 `CONCURRENCY=100`、120s 超时预算、mock 拓扑与 seed 形态；不做时序性断言（只断言计数、内容与结构等确定量）。

- `t3_1`：每路请求级断言（状态码、本路 `phone(i)` 还原、本路占位符形态经还原、他路号码缺席）+ 全对（100×99）串扰计数归零 + `/_admin/metrics` 的 `requests==100`。
- `b5`：字段类型断言（`is_precise` 布尔、`sse_events`/`ring_len`/`dropped` 数值、`p95_ms` 数值）、嵌套结构断言（`tokens` 六列、`truncated` 三 mode、`per_protocol`/`per_model` 行）、seed 后 series 与快照取值一致、空窗零值。
- `t2_1`：连续三次透传计数 1→2→3、`hop_filtered` 方向计数、上游收到路径/方法/头断言、无用量（`requests==0` 不变）、无审计事件、无凭据/PII 占位符注入、状态码/`content-type` 不改写。

**理由**：原仓对应测试（`pii_concurrency_test.py`、`observability_sse_metrics_test.py::test_metrics_snapshot_payload_shape`、`observability_non_dialog_test.py`）的断言厚度即基线；现 3/7/9 条的密度不足以定位串扰/形状回归。保持 120s 预算是为了不引入 flaky（100 并发已实测通过）。

### D3：T3 门禁形态 = `scripts/gate.sh` + 文档，保留脚本口径

**决策**：新增 `scripts/gate.sh` 串联六步：`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、`python3 scripts/check_doc_paths.py`、`python3 scripts/check_file_sizes.py`、`python3 scripts/api_conformance.py`（最后一步需 Python venv 与 SDK pin；TPM 门禁失败由脚本内建 Mock TPM 回退处理）。任一非零即 gate 失败。缺 venv/SDK 时 gate 以显式前置条件错误退出，或经显式 `GATE_SKIP_CONFORMANCE=1` 跳过并在输出打印「跳过理由」，**不得静默跳过**。README §8.5 由「口径不同非回归缺失」升级为「已纳入 gate 步骤 + 前置条件与跳过语义」；`scripts/README.md` 登记用法。

**理由**：仓库无 CI 系统，直接新建 CI provider 配置超出测试补漏范围；`gate.sh` 是 provider 无关的可执行契约，未来接入任一 CI 只需调用一行。保留 `api_conformance.py` 脚本口径（原仓 12 项 cargo + SDK 版本；本仓 20 项脚本），不强行 cargo 化——SDK pin 与 venv 前置是 Python 侧事实。

**备选**：仅 README 写命令（不可执行、易漂移，不采用）；新增 `.github/workflows`（无现有 CI 约定，且违背「provider 中立」最小改动，不采用）；把 SDK 用例 cargo 化（大改且口径漂移，不采用）。

### D4：T4 口径按新 API 语义分双轨

**决策**：

- **model/upstream 实际筛选**走 SSE 建连参数（`/_admin/events/stream?model=&upstream=`，`src/service/admin/sse.rs:82-116`）——e2e 建两条流，断言命中流收到事件、未命中流零事件、双条件交集、空值不过滤；与既有单测 `sse_filter_dimensions` 形成单测+e2e 双层。
- **metrics/events 旧 `?model=&upstream=`** 维持 README §3 声明的「忽略过滤 + deprecated 标注」口径——e2e 断言 `deprecated` 标注与结果与全局一致（不改变兼容语义）。
- **series 旧 range 四档**：`1h→five_min`、`24h→hourly`、`7d/30d→daily`（映射函数 `src/service/admin/events.rs::compat_granularity_for_range`，已有单测）；e2e 四档逐项断言 `granularity` + `deprecated` + 同窗新口径 points 逐点等价。
- **SSE 快照形状**：消费 mock 流后断言 `/_admin/metrics` 中 `sse_events` 相对基线精确增加（= 下游收到帧数）、`per_protocol` 行、`truncated`/`chat_tail_lenient`/`is_precise` 类型与取值。

**理由**：粒度下降的本质是「合并到通用文件后丢掉了原仓按维度拆分的显式断言」，而非口径变更；按新 API 语义恢复各维度断言即可，不恢复旧 API 行为。

### D5：GO 契约测试只锁网关侧，真机闭环不冒充

**决策**：新增 `tests/go_interop_contract.rs`（真回环 harness）三组用例：

1. **Go 形状直连**：模拟 Go `FetchCredential` 的纯 body POST（无三因子头、仅 `body.auth.caller_hash/caller_path`）→ 断言 403 且错误体为 `{"error":{"code":...,"message":...}}` **对象**（锁定「Go 不可直接轮询/解析」根因）；`body.secret` 兼容路径与 `body.auth.get_binary_secret`/`get_binary_hash` **被采纳**（等价头，`auth.rs:22-45`，`credential/mod.rs:84-90` 标注 Go 别名）的行为锁定。
2. **三因子矩阵**：齐全（头体一致）→ 放行或转审；缺 `X-Get-Binary-Hash`/`X-Get-Binary-Secret`/`body.auth.*` 各 → 403 明确（无空响应/挂起）；`caller_hash==GET_BINARY_HASH` → 403。
3. **阻断流终止**：三协议阻断相各一，chat 恰一 `data: [DONE]` 且含 `[blocked:`、anthropic `message_stop`+`content_block_stop`、responses `response.failed`，即时闭合（0s 级，无重试/挂起断言）。

测试文件头注释标注对应 `veil-hardening` 5.1/5.2/5.3；design/proposal 显式声明「Go 真机闭环仍由 `veil-hardening` 承接」，防止把网关侧契约误读为 5.x 已完成。

**理由**：Go 客户端无 SSE 消费代码、取用不发头，真机场景不可执行（`veil-hardening/tasks.md` 5.x 验证记录）；网关侧行为可确定性锁定且未来 Go 兼容改造有契约锚点。

### D6：记录项——零直接覆盖清单与禁用测试为零

**决策**：design 本节记录（apply 阶段 `openspec/specs/test-coverage-fill/spec.md` 归档时保留）：

- **零直接测试文件 + 覆盖来源**：`src/service/sse/emit.rs`、`meta.rs`、`parser.rs`、`src/service/block_inject/frames.rs`、`terminal.rs`、gateway 面 facade——无独立测试模块（`cfg(test)` 仅为测试访问器），行为由上层 `src/service/sse.rs`（30 项，apply 实测）与 `src/service/block_inject.rs`（24 项）覆盖；`parser.rs` 的 CRLF/裸 data 等边界由 `sse.rs` 测试锁定。**判定：可接受，不补独立测试模块**（薄封装/纯数据，重复测试无新增判据）。
- **`#[ignore]`/禁用测试 = 0**：验证命令 `grep -rn "#\[ignore" src/ tests/` 仅命中 `tests/http_e2e_pii_concurrency.rs:6` 的 `//!` 注释；`cargo test -- --list` 无 ignored 统计。保持该状态。

## Risks / Trade-offs

- [T1 抽取引入行为漂移] → 纯函数仅布尔决策、metrics/副作用留调用点；既有 `stream_tests`(14)/`proto_closeout_tests`(11)/`http_e2e_truncation_matrix`(7) 全绿为锁定条件；apply 阶段逐函数比对原条件。
- [T2 增强后并发测试变慢/flaky] → 只加确定性断言、不加 sleep、不动 120s 预算与 100 并发；失败隔离策略维持（注释所述）。
- [T3 gate 增加单次运行时长（conformance 构建+起服务）] → gate 明确为发布/CI 门禁而非每次保存运行；`GATE_SKIP_CONFORMANCE=1` 显式跳过并打印理由，不静默。
- [T4 SSE 筛选 e2e 时序 flaky] → 用已 seed 的事件环 + 有界读取（超时即失败），只断言命中/未命中计数；不依赖墙钟。
- [GO 测试被误读为 5.x 闭环] → 测试注释 + proposal/spec/design 三处显式声明「网关侧锁定；真机 Go 闭环仍在 `veil-hardening`」。
- [T1 外置测试文件本身触 800 行上限] → `spawn_tests.rs` 按决策点拆分命名、控制在 800 行内；若超出按 N1/P1/hold/sticky 拆两个测试文件（apply 决策，plan 不预设）。

## Migration Plan

1. 按 tasks 顺序落地：T1 抽取+直测 → T2 断言增强 → T4 粒度恢复 → GO 契约 → T3 gate 与文档 → 记录与门禁。
2. 每组独立 `cargo test -p veil <前缀>`；T1 完成时先跑 `stream_tests`/`proto_closeout_tests`/`http_e2e_truncation_matrix` 验证等价，再跑新增 `spawn_tests`。
3. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无生产代码语义变更（T1 为等价重构）。
4. 发布口径：无 BREAKING；`scripts/gate.sh` 与文档为新增门禁，不影响运行时。

## Open Questions

- 无。若 apply 阶段发现某决策点的纯函数抽取会显著扭曲调用形状（例如 `tool_replay_slot` 与 `outer_event_index` 耦合），允许改为「直接对既有 `event.rs` 谓词补真值表 + pump 直测」并在 design 记录差异，不改变「直接单测」验收。
