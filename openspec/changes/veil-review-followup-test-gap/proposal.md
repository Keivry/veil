## Why

深度审查 §2 结论：总数持平（Python 727 vs Rust 702），但 4 类 e2e 偏薄 + 2 项已知未闭环 + 2 项口径待注明。若不补齐，metrics 筛选/滚动回归无网、NonDialog 透传计数无验证、PII 并发冲突无保障、vault 语义漂移无感知、Matrix 真链路与 Go 互操作长期开环。本 change 只补测试与文档注明，不改生产语义（B1.2/B7 诚实声明保持）。

## What Changes

- **补 T-M1（metrics 筛选/滚动 e2e）**：`series?granularity/model/upstream`、`daily/hourly` 跨窗、`QueueFull` 丢最老、`ENOSPC` 降级内存-only、四回归文件映射登记。
- **补 T-M2（NonDialog 透传 e2e）**：字节透传 + `nondialog_passthrough` 计数 + hop 过滤不断言还原/审计/用量。
- **补 T-M3（PII 并发 e2e）**：对标原仓 `pii_concurrency 3` + `stream_restore_lock 5`，100 并发下标不冲突。
- **补 T-M4（vault 稳定 e2e）**：LRU 逐出与容量分表 5000/1000 回归。
- **补 T-M5（Matrix 真链路说明+e2e 占位）**：当前仅 mock 单测，补真链路缺件说明或最小 e2e 占位，owner 归 `veil-hardening` 可联动。
- **注明 T-M6（Go F3 5.1-5.3 未闭环）**：存量 Go 直连/三因子两场景/阻断终止三项在 tasks 登记承接关系，不在本 change 闭环但须可追踪。
- **注明 T-M7（sentinel_record.py 无对应）**：Rust 靠 `sentinel_*` e2e 回放覆盖，补一行文档说明替代关系。
- **补 T-M8（hook/env 薄 e2e）**：audit hook 与 env 细节当前仅单测，补最小 e2e 或书面豁免。
- **注明 T-M9（conformance 口径差异）**：原仓 `api_spec_conformance 12`（cargo）vs Rust `scripts/api_conformance.py 20`（脚本），在 README/对照表注明口径不同。

## Capabilities

### New Capabilities

- `test-gap-closure`：上述补测与注明的输入输出与可验证场景。

### Modified Capabilities

- 无。不改生产语义；B1.2（token 文件仅 cfg(test)）、B7（隔离桶）诚实声明保持不动。

## Non-Goals（显式）

- 不改 metrics 口径（max/缓存列/分桶）、不限流语义、不改 vault LRU 为 FIFO。
- 不闭环 Go 真机联调（只登记承接）。
- 不改既有 change 文件；不提交 commit。

## Impact

- **新增文件**：本目录 proposal/design/specs/tasks；apply 新增 `tests/http_e2e_*` 与 `src` 内单测，改 README 对照表述。
- **影响系统**：测试覆盖率与可追踪性，无生产行为变更。
- **依赖**：现有 `cargo test` 与 `scripts/api_conformance.py`。
