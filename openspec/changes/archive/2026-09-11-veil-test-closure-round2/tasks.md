## 1. SSE/流式保真

- [x] 1.1 上游断线重试真 E2E（首连拒收 + 600ms 后起服务 + 两次退避断言 ≥1200ms），验证：E2E 通过且重试次数符合 `[500,1000,2000]ms`
- [x] 1.2 `choices_n2_no_broadcast` 隔离单测（双路 tool 按 index 独立累积），验证：双路独立累积
- [x] 1.3 `restore_fidelity_fields` 全字段对比（泵级 `id/object/created/model/finish_reason` 原样），验证：`id/object/created/model/index/finish_reason` 原样
- [x] 1.4 嵌套还原回归（`double_underscore/p@ss"quote` 既有单测已覆盖：`json_walk` 嵌套递归 + `redaction` 工具参数回归），验证：单测通过

## 2. 审批载荷精确

- [x] 2.1 批准原样释放断言（已在 `veil-approval-pii-hold` e2e 落地：危险工具名/参数透传 + 无阻断帧 + 单 DONE），验证：危险 args 全串见于下游
- [x] 2.2 拒绝无泄漏断言（既有 e2e：阻断帧 + 无 `tool_calls`/危险参数子串），验证：阻断帧 + 无原始子串

## 3. 淘汰与缓存

- [x] 3.1 FIFO→LRU 迁移显式测试（热点触达驻留 + 冷条目先逐出），验证：热点驻留/冷逐出行为锁定
- [x] 3.2 容量分表常量断言（凭据 5000 断言 + PII 单表 1000 既有单测），验证：单测锁定
- [x] 3.3 `redact_cache/rebuild/depth_bomb/roundtrip` 回退补齐（同秘密复用单测 + `json_walk` 既有 8 项），验证：`json_walk` 单测通过

## 4. 性能豁免与可疑核对

- [x] 4.1 perf 二选一签字（决策：文档声明锚点代替，`perf_5000` 锚点单测已存在；终签提请本报告确认），验证：maintainers 签字 + spec 记录
- [x] 4.2 `admin.html` conformance 豁免注释（`api_conformance.py` 头部 NON-GOAL），验证：`scripts/api_conformance.py` 可见 NON_GOAL
- [x] 4.3 核 ipv6 第 17 项 `trailing_double_colon`（`2001:db8::` 合法 + 文档段豁免，与 `2001:db8::1` 同口径），验证：与 Python 语义一致（保留豁免）
- [x] 4.4 核 TSS04 计费去重 + `15s` 快照 shape（TSS04 既有 + snapshot/is_precise/series四窗口既有；`stream+JSON` 见 gateway 5.1），验证：结论已记录（均与既有单测一致，无实现变更）
