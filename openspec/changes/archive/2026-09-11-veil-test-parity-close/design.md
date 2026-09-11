## Context

现状：骨干对齐（PII 六类/IPv6 时间/硬化/ReDoS/字典 CJK、`sentinel 9` 解析回放、conformance 20/20），缺角集中在截断矩阵、SDK 还原断言、流边界、凭据分支、可观测语义、性能锚六组。约束：只加测试与标注，不改生产语义；BREAKING 项要么迁移测试要么接受风险二选一，不留第三状态。

## Goals / Non-Goals

**Goals：**

- 给出每组缺口的补测形状与断言点，使 apply 可机械执行。
- 给出 BREAKING/收敛项的验收二选一清单。
- 给出显式豁免项（`admin.html`、`DEBUG_DIR` 落盘）。

**Non-Goals：**

- 不规定生产实现改法（见另两个 change）。
- 不新增 mock 上游协议。

## Decisions

### D1：截断矩阵按 TSS01–04 + 真实数据补齐

**决策**：新增 `tests/http_e2e_truncation_matrix.rs`：TSS01 完整残余静默丢弃（无终端伪造）、TSS03 tool_calls 中截断丢弃（参数不全则丢整把，不伪造 `success`）、TSS04 Responses 截断合成 `failed`（形态与阻断 `completed` 互斥）、真实 reasoning 开环保留分片 + 真实 toolcalls 开环无伪造。Anthropic 截断走 `message_stop` 正常闭合不断言失败合成。

**理由**：当前仅 Chat TSS02 开环，Responses 合成语义与 tool 丢弃语义是 fail-closed 核心，必须 e2e 锁定。

### D2：SDK 级回放逐项移植或豁免

**决策**：以 Python `api_spec_conformance 12` 为清单逐项移植到 `tests/sentinel_sdk_replay.rs`（handler 级还原断言，非纯解析回放）：thinking `signature_delta` 单帧块透传、`tool_use.input` 跨帧累积后 `stop` 提交可 parse、`CR-only` 快慢双路径一致、`error(overloaded)` 插帧中断、`message_delta usage` 累计覆盖、`stop_sequence` 回显、`fallback` 无 delta 块、`display:omitted` 空思考块。逐项 `移植 | 豁免(理由)` 在 tasks 登记。

**理由**：`sentinel 9` 仅解析器回放，无 handler 还原断言，合规性存疑点正在还原层。

### D3：流泵边界八项

**决策**：补：上游断连重试 3 次（仅 connect/timeout，500/1000/2000ms 退避）、`choices_n2` 不广播（index 隔离）、多 `data:` 逐行拼接、`retry:` 非数字忽略、`refusal` 分片重组、fast 链 BOM+comment 透传、三片段单 flush、flush 失败不双还原、hold 溢出 fail-closed、中途 abort fail-closed、超时 vs 断连竞态、早断清理、deny 后 content 转发、`done` 回退审计。每项独立单测或 e2e，失败形态为注入阻断帧或丢弃，不挂起。

### D4：凭据分支与可观测语义

**决策**：凭据补解锁超时 300s、并发单 ask（双请求单 Matrix ask）、审批三文案（已注册/未注册/终端直调）、清理双删幂等、无库/无效 JSON/缺条目分支。可观测补 SSE 事件计数（`sse_event_count` 与 `hop_filtered_total` 可查）、`series` 四窗（`five_min/hourly/daily` + `since+protocol`）、`metrics/events?model=&upstream=` 全局口径 + 弃用标注断言、`events?verdict=` 归一断言、pii 跨日聚合/模型近似、ENOSPC 内存-only 降级。`admin.html` 重申 Non-Goal 不测。

### D5：性能锚与并发隔离

**决策**：补审计链扫描耗时锚、字典 5000 防联合正则爆炸分支耗时锚（124μs→13.8ms 量级回归线）、增量扫描耗时锚；PII `Scope` 请求隔离并发单测（替代 Python `ContextVar` 等价断言）；`BoundaryHold` 组合 fuzz（占位符残片 × 信封分隔 × 多 `data:`），`usage` 递减乱序（与 gateway change 实现对应，此处只验收）。

### D6：BREAKING/收敛验收二选一

**决策**：下表逐项要么迁移测试要么 spec 接受风险标注，不留缺口：6.1 默认开误伤（显式 `0` 关闭透传 + 默认开脱敏断言）、6.2 采样双开关（总开关关则零落盘 + 开启无 HMAC key 告警谓词）、6.3 LRU 热点驻留（淘汰顺序单测，FIFO 兼容明确不测）、6.4 pending 不断链（建单 + 原文按 pending 语义 + 监控查环指引 e2e）、`registrations` 401 迁移（旧直读 401 断言）、HOP 8 项逐头（过滤 × 透传矩阵）、legacy 三变量静默忽略（启动 warn 断言，见 hygiene change D5 实现）、`DEBUG_DIR` 无落盘（显式豁免）、Mock TPM 精确 `1` 放行（非 `1` 值仍门禁断言）。

## Risks / Trade-offs

- [e2e 数量膨胀致 CI 变慢] → 截断/SDK/边界优先单测化，仅跨层语义走 e2e → tasks 标注每项级别。
- [真实数据夹具涉密] → 用合成 reasoning/toolcalls 载荷，不录真实 PII → fixture 脱敏审查。
- [接受风险项被误读为遗漏] → spec 设 `ACCEPTED RISK` 章节逐项签字 → tasks 设比对任务。

## Migration Plan

1. 先 D1+D2（合规核心），再 D3 流边界，再 D4 凭据可观测，再 D5 锚，最后 D6 验收签字。
2. 每批 `cargo test` + conformance 回归。
3. 回滚：纯测试新增，整批 revert 零风险。

## Open Questions

- 无。
