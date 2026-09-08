## Why

Rust `cargo test --list` 约 320 项 vs Python 727 用例（~44%），核心域覆盖率高但 6 类缺口未立项：SSE 断线重试无真 E2E（仅退避单测）；`choices_n2` 广播隔离、`restore_fidelity_fields` 字段级保真缺失；审批 e2e 未断言载荷精确释放；FIFO→LRU 淘汰漂移无迁移测试；性能墙钟门限（Python `<500/<100/<2ms`）被锚点代替，退化漏检；`admin.html` Non-Goal 未在 conformance 显式豁免；另有 4 处可疑断言待核（`ipv6_time` 第 17 项 `trailing_double_colon`、TSS04 计费去重、`metrics_snapshot vs series 15s` 快照 shape、`stream:true+JSON` 组合）。本 change 一次补齐，不碰实现语义，只加测试与豁免声明。

## What Changes

- **补 1，SSE/流式保真 4 项**：上游断线重试真 E2E；`choices_n2_no_broadcast` 广播隔离；`restore_fidelity_fields`（`id/object/created/model/index/finish_reason` 原样透传）；`token_split_across_deltas/hold_eventually_flushed/double_underscore/p@ss"quote` 嵌套还原单测。
- **补 2，审批载荷精确 2 项**：批准释放危险 args 原样断言；拒绝注入载荷断言（替代现 `!blocked` 弱断言）。
- **补 3，淘汰与缓存 3 项**：FIFO→LRU 迁移显式测试（热点驻留/冷淘汰行为）；容量分表锁（凭据 5000 / PII 单表 1000）；`redact_cache_hit/rebuild/depth_bomb/roundtrip` 回退单测。
- **补 4，性能与豁免 2 项**：perf 墙钟门限二选一（恢复门限或文档声明锚点代替并经 maintainers 签字）；`admin.html` 在 `scripts/api_conformance.py` 显式豁免 + conformance 注释。
- **核 4，可疑断言**：`ipv6 trailing_double_colon` 第 17 项语义；TSS04 计费去重口径；`15s` 快照 shape（`metrics_snapshot` vs `series`）；`stream:true+JSON` 组合（与 `veil-gateway-p0-fix` 共用，测试落本 change）。

## Capabilities

### New Capabilities

- `test-closure-round2`：上述补齐与核查的用例清单、断言强度与豁免声明。

### Modified Capabilities

- 无。既有 spec 需求不动；只新增测试覆盖与豁免。

## Non-Goals（显式）

- 不改任何 `src/` 实现语义；失败用例若暴露实现 bug，转对应修复 change，不在本 change 修实现。
- 不恢复 `admin.html` 交付；只做豁免声明。
- 不改既有 change 文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-test-closure-round2/` 下 proposal/design/specs/tasks；apply 阶段加 `tests/` 与 `src/**/tests` 用例，改 `scripts/api_conformance.py` 豁免注释。
- **影响系统**：测试时长与 CI 门限；无运行时影响。
- **依赖**：真回环网络、 sentinel fixtures、7 字节 TCP 切片 harness（既有）。
