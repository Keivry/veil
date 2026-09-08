## Context

现状：Rust 真网络回放强于 Python（loopback + reqwest + 字节级回放），但粒度粗导致 6 类静默漂移（默认值 BREAKING、淘汰策略、usage 口径、开环语义）无测试感知。约束：只加测试与豁免，不修语义；用例失败转对应修复 change；`admin.html` 永不交付。

## Goals / Non-Goals

**Goals：**

- 给出每类缺口的用例形状、fixture 与断言强度，使 apply 可逐项加测。
- 对 perf 门限与 admin 豁免给出二选一决策。

**Non-Goals：**

- 不定实现修复方案（见 gateway/approval/arch changes）。
- 不引入外部压测依赖。

## Decisions

### D1：SSE/流式保真用真 E2E + 字节回放

**决策**：重试 E2E 用“mock 上游首连 RST/次连成功” harness（复用 7 字节切片），断言客户端终见完整流且重试次数符合 `[500,1000,2000]ms` 退避；n2 广播隔离用双 `index` 交织流断言各路独立累积；保真用全字段对比（`id/object/created/model/index/finish_reason/usage`）；嵌套还原用 `p@ss"quote/\u0031` 回归语料。

### D2：审批载荷精确断言替代弱断言

**决策**：批准 e2e 改为“危险 `rm -rf` args 在批准后原样见于下游”，拒绝 e2e 改为“下游见阻断帧且无原始参数子串”；保留现 `!blocked` 作为前置，新增载荷子串断言为门禁。

### D3：淘汰迁移显式测试锁定新语义

**决策**：FIFO→LRU 用“热点循环访问后逐出顺序”单测锁定 LRU（热点驻留、冷者先逐）；容量分表用常量断言（`MAX_TOKEN_ENTRIES=5000`、`PII_MAX_ENTRIES=1000`）；`redact_cache/rebuild/depth_bomb/roundtrip` 用 `json_walk` 既有 harness 补齐。

### D4：perf 门限二选一 + admin 豁免显式化

**决策**：perf 默认推荐“文档声明锚点代替”（维持现状不卡墙钟，CI 不引入 flaky），但须经 maintainers 签字并在 spec 记录；若签字不通过则恢复 Python 墙钟门限（`<500/<100/<2ms` 按 Rust harness 等价折算）。`admin.html` 在 `scripts/api_conformance.py` 头部加 `NON_GOAL` 豁免注释 + conformance 跳过该项。

### D5：四可疑断言逐项核对

**决策**：`ipv6` 第 17 项以 Python 语料为准重放，不一致则修实现或文档；TSS04 计费以“开环不重复计费 + `dedupe` 不重复”双断言锁定；`15s` 快照以 `series` 语义为准核 `metrics_snapshot` 字段；`stream+JSON` 组合测试与 `veil-gateway-p0-fix` 设计决策同字。

## Risks / Trade-offs

- [真 E2E flaky] → CI 抖动 → 重试 E2E 限单次 + 超时熔断，不卡门限只告警。
- [载荷精确断言引入危险语料] → 误触发审计 → 用例走 `AUDIT_MODE=off` 隔离 + 语料脱敏注释。
- [perf 门限恢复导致 CI 红] → 以锚代门为默认，签字制衡。

## Migration Plan

1. 按 tasks T1→T5 顺序加测，每类独立 PR 可合入，失败用例标 `#[ignore]` 并转修复 change，不阻塞他类。
2. 豁免与签字先行（D4），再补用例，最后核可疑断言。
3. 回滚：新增用例全可独立删除，不影响运行时。

## Open Questions

- 无。perf 二选一由 maintainers 在 apply 前签字。
