## Context

现状：流式“增量不审/完成才审/按槽清/超限 fail-closed”双边一致，但 `approve` 是否挂起、PII 半截是否等待两处语义分叉无决策；usage/审计源/隔离三口径 Rust 更优但缺显式锁定与迁移注释。约束：每项必须二选一（补实现或文档接受），不留“测试全绿但语义变”；与 `veil-gateway-p0-fix` 零重叠。

## Goals / Non-Goals

**Goals：**

- 对 approve 与跨片 hold 给出可实施的二选一方案（含 e2e 断言改法），apply 可直接执行。
- 对 usage/审计源/隔离/采样默认给出锁定口径与文档位置。

**Non-Goals：**

- 不重定网关阻断帧形态。
- 不引入新外部依赖。

## Decisions

### D1：approve 二选一（默认推荐 B 案文档化，A 案备选）

**决策（推荐 B）**：保留挂起声明，理由：流式挂起等真人 ✅ 会引入分钟级长连接与上游超时竞态（`AUDIT_TIMEOUT` 禁 110-130s 即为此），Rust 转 pending + 凭据链承载是合理架构演进；代价是 e2e 断言必须改写为“pending 建单 + 事件环可查 + 无原文泄漏”，且 README §6 新增 BREAKING 条目显式声明与 Python 差异。若 maintainers 坚持 Python 同形，则切 A 案：泵内 `is_complete_event` 命中后 `await_audit_approval` 挂起（`audit_timeout` 口径），`Some(true)` 放行、`Some(false)/None` 注入阻断帧并 `rejected_sticky`，超限仍 fail-closed。

**理由**：B 案不断链、不挂起，对 Hermes 更友好；A 案最贴原仓但运维成本高。关键是显式而非静默。

**备选**：维持现状无声明——静默降级，不采用。

### D2：跨片 hold 二选一（默认推荐 A 案补实现）

**决策（推荐 A）**：移植 Python D5 最小实现：响应侧 `SseParser` 输出前加尾窗扫描（尾 64 窗 + `partial_prefix_hints`），命中候选则 `safe/pending` 分割、pending 滞留至下一帧或完成/超时 flush；`strip_partials` 保留用于残缺占位符清理。B 案（接受风险）仅当性能 profiling 证明 hold 拖尾不可接受时采用，且必须进 README 威胁模型。

**理由**：分片切断是 SSE 常态（7 字节 TCP 切片单测即证），半截 PII 透出是明文泄漏，不宜接受。实现成本为一小缓冲 + 一次扫描，远低于泄漏代价。

### D3：usage max、审计读原文、请求隔离三锁定

**决策**：`usage` 以 `accumulate_usage=max` 为准，dashboard 迁移注释进 README 7.2（已部分有，加“旧 sum 对比换算”一句）；审计以“读上游原文 JSON”为准，Python 非流读还原后视为注释与实现矛盾，统一为原文并在 `audit.rs` 头注释声明对抗理由（防占位符混淆审计）；PII 以“请求隔离 + 全局 vault”为准（`Scope::pii` 请求级、`vault/detector` 进程单例只读），prompt-cache 命中率影响进 README 一句声明。

### D4：采样默认锁与 HMAC 告警

**决策**：`PII_VALUE_SAMPLE_ENABLED` 默认关保持，`PERSIST` 默认开保持但加启动 warn（采样开启 + HMAC 缺失即 warn“无盐 sha256 可枚举，生产必须配 HMAC_KEY”），并加旧关闭语料回归单测（显式 `ENABLED=0` 全链路无落盘）。

## Risks / Trade-offs

- [A 案 approve 挂起引入长连接] → 上游超时/客户端重连 → 挂起期 `keepalive :ping` + `AUDIT_TIMEOUT` 熔断 + 超时注入阻断帧。
- [A 案跨片 hold 拖尾] → 尾延迟 +1 帧 → hold 上限 `PII_HOLD_MAX 64` + 超时 flush，性能单测锚点不卡墙钟。
- [B 案文档化被误读为漏拦] → Hermes 误判 → e2e 断言显式查 `pending` 建单 + 无泄漏，文档给“如何区分 pending 与放行”指引。

## Migration Plan

1. 先定 D1（approve），再定 D2（hold），最后落 D3/D4 文档锁；D1 决策翻转只影响 e2e 断言，不影响网关 P0。
2. 每步独立验证：approve 用 e2e 批准/拒绝双场景；hold 用跨帧切片回放；usage 用双段单调 max 单测。
3. 回滚：hold 实现可 feature-gate 关闭回“接受风险”；approve A/B 切回只需改泵内一分支 + e2e 断言。

## Open Questions

- 无。D1/D2 二选一由 apply 前 maintainers 拍板，默认按推荐执行。
