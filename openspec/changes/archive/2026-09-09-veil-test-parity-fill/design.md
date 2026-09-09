## Context

See proposal.md Why. Current counts: 单元 config 35/admin 25/metrics 22/audit 19/hold 18/sse 17/pii 31/redaction 28/block 21/matrix 19/llm-mod 19/tool 7/pump 7/protocol 6/usage 6/vault 9/placeholder 4/credential 1/rewrite 0/nonstream 0；E2E truncation_matrix 7/truncation 2/audit_approve 4/sse_loop 2/sentinel 21。

## Goals / Non-Goals

**Goals:**

- 零覆盖文件清零；高风险主题（占位符/流式核心/审计/凭据）回补到与原仓同等强度。
- 性能退化有门禁拦；并发语义有大并发锁定。

**Non-Goals:**

- pii_value 32 项（`veil-metrics-sampler-fix`）。
- 生产代码修复（本 change 只加测试，bug 转交对应 change）。

## Decisions

- 原样移植优先：占位符/审计/凭据/vault 用例按原 Python 断言语义移植（仅语言改写），不重新设计。
- 性能阈值沿用原仓：1MB<500ms、100KB<100ms、1KB<2ms；CI 不稳定则标记 `#[ignore]` 但保留本地运行指引。备选“放宽阈值”掩盖退化不采用。
- 并发：vault 100 并发 gather 用 `tokio::join_set`；hold 隔离用多任务 Scope 互不可见断言。
- series 桶：1h/24h/7d/30d 桶数 + 空桶零 + 缓存聚合逐项断言，不合并为单用例。
- ipv6：17 项逐项展开，不压缩为单用例。

## Risks / Trade-offs

- [Risk] 大并发/性能测试 CI 抖动 → Mitigation：重试 1 次 + 超时放宽系数文档化，仍失败则按 bug 处理。
- [Risk] 回补量大（约 150+ 用例）→ Mitigation：按 tasks 9 组分批落地，每组独立可合。

## Migration Plan

- 按 tasks 1-9 落地，每组 `cargo test <组>`；零生产代码变更，回滚直接删除新增测试文件/模块。
