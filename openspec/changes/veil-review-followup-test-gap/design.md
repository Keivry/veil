## Context

现状：metrics/NonDialog/并发/vault/Matrix/Go 六类覆盖薄弱或开环，但生产语义正确。约束：只加测试与文档注明，不改生产语义；B1.2/B7 诚实声明不动；真相源为 `admin-ratelimit-contract` 与各 parity spec。

## Goals / Non-Goals

Goals：每缺项都有 e2e/单测或书面承接，覆盖矩阵无第三状态。
Non-Goals：不改口径语义、不闭环 Go 真机、不回滚 BREAKING。

## Decisions

### D1：metrics 按三层补（T-M1 单测+e2e）

决策：单测锁 `QueueFull` 丢最老、`flush` 2s 去抖、`hourly/daily` 跨窗、`model :@` 白名单；e2e 锁 `series?granularity/model/upstream` 与空窗快照形状。`ENOSPC` 降级内存-only 用单测模拟，不做真实满盘。
理由：原仓 33 用例指标矩阵在 Rust 只有 1 快照 e2e，回归网最大。
备选：只补单测不补 e2e，不采用（筛选是网关出口行为）。

### D2：NonDialog 字节透传 e2e（T-M2）

决策：e2e 断言未知尾缀原文转发 + `nondialog_passthrough` 计数 + 无用量/审计/还原。hop 过滤保留。
理由：与 Python 直通语义一致须有网验证，否则对话体误入该臂无感知。
备选：仅单测，不采用（透传是端到端行为）。

### D3：并发与稳定 e2e（T-M3/T-M4）

决策：PII 100 并发下标不冲突 e2e（对标 `pii_concurrency/stream_restore_lock`）；vault LRU + 5000/1000 容量 e2e。失败即 mark flaky 隔离，不阻塞全绿。
理由：请求隔离 + LRU 是重构核心权衡，无 e2e 则漂移无感知。
备选：仅单测，不采用。

### D4：Matrix 与 Go 只登记不闭环（T-M5/T-M6）

决策：Matrix 真链路补缺件说明 + 最小占位 e2e（mock 标记）；Go 5.1-5.3 在 tasks 登记 owner `veil-hardening 5.x` 与追踪链接，不在本 change 闭环。
理由：需真机/真网，不宜在本 change 强行闭环，但须可追踪防遗忘。
备选：强行闭环，不采用（环境不可控）。

### D5：口径与替代注明（T-M7/T-M9）与 hook 薄项（T-M8）

决策：README 追加 `sentinel_record.py → sentinel_* e2e` 替代句与 conformance 12 vs 20 口径差异句；hook/env 补最小 e2e 或书面豁免，二选一锁定。
理由：消除“缺脚本/缺用例即 bug”误判，保留可验证性。

## Risks / Trade-offs

- [并发 e2e flaky] → 隔离标记 + 重试 → 不阻塞门禁。
- [ENOSPC 真实满盘危险] → 单测模拟 → 不做真实 fault injection。

## Migration Plan

按 tasks T1→T9 顺序补，每项独立 Verify，全绿后跑 `cargo test` + conformance。

## Open Questions

- 无。Go 真机闭环以 `veil-hardening` 实测为准。
