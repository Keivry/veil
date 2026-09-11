## Context

现状：网关主体合规，9 处边缘口径未锁定。约束：只改注入与合成与声明与选路，不碰审计 verdict 与 PII 集合；README §7.7 为归一化契约真源，新 change 名固定 `veil-review-llm-edge`，capability 名固定 `llm-edge-gateway`。

## Goals / Non-Goals

**Goals：**

- 给出每项修复的函数级改动形状与单测锁定方式，使 apply 可逐项落地独立验证。
- 收敛二选一（D1 置位或声明、D5 统一或注释），消除口径疑问。

**Non-Goals：**

- 不设计审计 verdict 与 PII recognizer 变更。
- 不输出逐行代码 diff，只定签名形状、判定口径与声明语义。
- 不引入新依赖。

## Decisions

### D1：占位符注入归一化二选一

**决策**：方案 A：在 `request_rewrite` 占位符注入成功分支置 `normalized_out = true`，作为 README §7.7 置位条件③；方案 B：保持不置位并在 §7.7 明确声明占位符注入不声明。apply 时二选一，单测锁定所选。

**理由**：注入经 `to_string` 紧凑化，字节已非等价；要么声明，要么书面豁免，不留沉默缺口。

**备选**：维持现状不声明不文档，不采用。

### D2：纯脱敏字节替换不置位书面化

**决策**：README §7.7 补一句：纯脱敏子串替换（字节级，未重序列化）与原文透传不置位，即使长度变化；`rewrite.rs` 单元测试锁定长度变化用例仍 `normalized_out == false`。

**理由**：长度变化是替换的自然结果，非归一化；书面化避免后续误报。

### D3：非流回退前残缺重试

**决策**：`serve_nonstream` 还原后校验失败分支改为：先 `strip_partials(&restored)` 再校验一次，成功则用剥离后文本；仍失败则回退上游原文并保留既有 warn，同时记一次还原回退 metrics。

**理由**：引号破裂多由半截 token 形态引起，剥离常可挽回；直接放行原文丢还原价值。

**备选**：维持直接回退，不采用。

### D4：错误 JSON 后处理书面化

**决策**：文档声明非 502/401 错误状态的 JSON 体仍进完整后处理链；`nonstream.rs` 尾部分支加注释说明该意图，单测锁定 400 系 JSON 走后处理。

**理由**：用量与审计在错误体上同样有价值；显式声明避免被误认为遗漏豁免。

### D5：双缓冲统一或分工注释二选一

**决策**：方案 A：移除 `pending_tool_frames`，tool 分片缓冲统一由 `AuditHold` 持有；方案 B：保留双缓冲并在 `pump.rs:289-320` 处加注释说明分工（`AuditHold` 管审计判定持有，`pending_tool_frames` 管 Chat/Anthropic 完成前重放排序）。apply 时二选一，单测锁定所选。

**理由**：双缓冲并存无注释不可维护；统一或书面分工均可接受，关键是可追踪。

### D6：注释帧排除出空流守门

**决策**：`is_comment_only` 分支保持不置位 `any_frame_sent`（现状已然），并加单测锁定纯心跳流 `should_synthesize_empty_stream(false, false, false) == true`；若发现其他路径误置位，一并清理。

**理由**：注释心跳不是内容帧；计入会饿死真空合成，下游悬空。

### D7：转泵透传请求会话

**决策**：`serve_nonstream` 转泵前从请求体提取会话标识并随 `NonstreamOutcome::Stream` 交给泵；泵内 `resolve_conv_id` 首选透传值，缺失才合成。调用方（`gateway_serve`）负责传递请求会话。

**理由**：请求会话是最佳追踪锚；空值合成割裂审计链。

### D8：Host 方括号 IPv6 解析

**决策**：`gateway_serve` 入口端口解析改为：`]` 存在时取 `]:` 后段解析端口；否则沿用现有冒号逻辑；解析失败回退 `None`。

**理由**：`rsplit(':')` 在裸 IPv6 上取尾段误判端口；方括号是 RFC 3986 标准形态。

**备选**：维持 `rsplit`，不采用。

### D9：编码剥离一行声明

**决策**：`filter_hop_headers_counted` 编码剥离分支加一行 `tracing::debug`，README §7.1 补一句对外统一 `identity`；单测锁定 `decode_enabled=true` 时 `content-encoding`/`content-length` 被剥离。

**理由**：行为正确但无声；一行声明即可闭环可观测。

## Risks / Trade-offs

- [D1 选 A 后存量单测断言无头失效] → 同步更新快照 → tasks 设快照更新任务。
- [D3 重试后仍破裂] → 回退原文 → warn 加 metrics 双可观测。
- [D5 选 A 统一缓冲回归面大] → 优先选 B 注释 → 统一留后续 change。
- [D8 方括号解析误伤 `user:pass@host` 形态] → Host 头无 userinfo → 风险可忽略，单测覆盖端口缺失回退。

## Migration Plan

1. 按 tasks 顺序逐项修，每项独立单测验证，任一项失败只回滚该项。
2. D1 与 D5 的二选一在 apply 开工时先定，单测按所选锁定。
3. 文档（README §7.1/§7.7）与实现同批次更新，最后跑 `cargo test` 全绿。

## Open Questions

- 无。二选一已在本 design 收敛；若 apply 实测另有形态要求，以实测为准提后续小 change。
