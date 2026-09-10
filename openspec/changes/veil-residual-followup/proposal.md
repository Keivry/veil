## Why

Oracle 终审（2026-09-10，基线 `0a51675`）确认四变更发现项全部修复且无阻断，同时登记 3 项低危遗留：① `t8_100kb_scan_under_800ms` 在并行测试负载下偶发超 800ms 门禁（单跑 0.30s 通过，非本批回归，但 `cargo test` 非确定性绿有 CI 风险）；② `resolve_upstream` 缺省回退 warn 在热路径逐请求触发（`src/service/llm_gateway/mod.rs`），未配置缺省上游时日志噪音；③ `openspec/specs/stream-protocol-parity/spec.md` 将 "Hermes stub protection still applies" 写为事实，而 README §8.6 已列为「待人工确认」，存在文档张力。本 change 只收敛这三项加一项信息登记，不碰网关语义与门禁阈值。

## What Changes

- **F1 性能用例确定性（t8）**：`src/service/pii/chunk.rs` `perf_budget_tests::t8_100kb_scan_under_800ms` 改为连续 3 次测量取**最小值**断言；800ms 上界与 `hits.len() > 100` 命中断言不动（不放松门禁语义——最小值滤除调度抖动，真实回归仍会使三次全部超界）。
- **F2 热路径 warn 去重**：`resolve_upstream` 缺省回退 warn 改**每进程至多一次**（模块级 `AtomicBool::swap`）；「端口升序取首」确定性与既有单测保持。
- **F3 spec 口径对齐**：以 delta 修改 canon `stream-protocol-parity`「Empty streams stay open-ended for chat/anthropic」需求——不再把 Hermes stub 保护写为仓库保证，改为条件化表述并互引 README §8.6；补 Anthropic 空流场景（B2.1 已实现测试的回写）。
- **F4 信息登记（无需动作）**：非流「仅 2xx 合成阻断体」的精确规则当前仅在未归档 delta 中，待 `veil-nonstream-audit-align` 归档后并入 canon；本 change 仅在 design 附录登记，不改 spec。

## Capabilities

### New Capabilities

- `residual-followup`：F1/F2 的可验证场景。

### Modified Capabilities

- `stream-protocol-parity`：空流需求口径条件化 + Anthropic 场景补充（delta 见 `specs/stream-protocol-parity/spec.md`）。

## Non-Goals（显式）

- 不改 800ms 上界、不改其它 t8 用例（1KB/1MB/CJK/字典/增量均 ≥8x 余量）、不改扫描实现。
- 不改回退选路语义（端口升序取首不变，仅告警频次变化）。
- 不实现 ENV dev 回环（`veil-deadcode-positional-cleanup` 已声明 BREAKING）、不碰协议/审计/PII 行为。
- 不提交 commit（由 orchestrator 决定）。

## Impact

- **新增文件**：本目录下 proposal/design/specs/tasks/.openspec.yaml。
- **影响文件**：`src/service/pii/chunk.rs`（t8 用例）、`src/service/llm_gateway/mod.rs`（warn）、`openspec/specs/stream-protocol-parity/spec.md`（经 archive 合并，本 change 仅提供 delta）。
- **影响系统**：测试确定性与日志噪音，无业务行为变更。
- **依赖**：无新依赖。
