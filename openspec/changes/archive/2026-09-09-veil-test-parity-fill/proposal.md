## Why

覆盖对比（原 727 vs Rust 452）发现高/中风险缺口：`rewrite.rs`/`nonstream.rs` 零单测（原 `llm_empty` 7 项无人锁）；占位符 38+7→4；`llm_test` 90→26（dual_hold/token 后缀 hold 大面积缺失）；审计 null 防御/缺 index/dotdot 不全；凭据 24→14 且无 E2E；vault 24→9（缺空洞跳过/大并发）；`audit_perf` 6 项时限零覆盖；observability 77 项 model/upstream 联动与 series 桶口径分散；ipv6 17→1；并发 3 项部分覆盖。若不回补，回归无人拦，性能退化无感知。

## What Changes

- `rewrite.rs`/`nonstream.rs` 补空体转502/strip 后空体/正常文本非502/502-401 语义单测（原 `llm_empty` 7 项）。
- 占位符回补 34+ 项：多 system 串/数组/image 块/截断 JSON 透传/非对象透传/三协议真注入集成。
- 流式核心回补：dual_hold/token 前后缀 hold/PII 数字同尾/single_hold 等价性/fast 慢径 delta 切分。
- 审计回补：null 防御/缺 index 跳过/dotdot O(n)/管道优先级/混淆命令/内网放行。
- 凭据 E2E：三因子/health/加解锁/限流/终端直调 403。
- vault：空洞跳过/rand8 不可枚举/100 并发 gather。
- 性能门禁：1MB<500ms / 100KB<100ms / 1KB<2ms / CJK/dict 时限断言（CI 失败即拦）。
- observability：model/upstream 联动、series 1h/24h/7d/30d 桶数、24h/7d 近似口径、sse 按块计一一映射。
- ipv6：毫秒/单位数/日期 T 分隔等 16 项展开；并发：100 并发 gather + ContextVar hold 隔离语义。

## Capabilities

### New Capabilities

- `coverage-closure`: 上述 9 组回补测试（只加测试，不改业务；若测试暴露业务 bug 则另立修复任务）。

### Modified Capabilities

- 无（本 change 纯加测试；性能时限为新增门禁，属 New）。

## Impact

- 只加 `#[cfg(test)]` 与 `tests/` E2E，不改生产代码（测试暴露的 bug 回写到对应 P0/P1/sampler/arch change）。
- CI 时间增加（perf 门禁 + 100 并发），阈值按原仓口径（1MB<500ms 等）。
- 与 `veil-metrics-sampler-fix` 联动：pii_value 32 项归 sampler change，本 change 不重复。
