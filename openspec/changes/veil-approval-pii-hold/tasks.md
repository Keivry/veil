## 1. approve 语义决策与断言

- [x] 1.1 按 design 拍板 A/B 案并更新 spec 语义句（决策：B 案挂起声明；spec 已锁定 + README 6.4 BREAKING），验证： Maintainers 签字 + spec 与实现一致
- [x] 1.2 A 案则泵内挂起 `await_audit_approval` + 超时阻断帧，B 案则 e2e 改断言 pending 建单（B 案：e2e 批准分支断言原文透传 + 无阻断帧 + 单 DONE），验证：批准/拒绝双 e2e 通过
- [x] 1.3 危险 args 释放精确断言（批准原样释放/拒绝注入载荷；实现 owner，用例沉淀复用 `veil-test-closure-round2/tasks.md 2.1-2.2`，文案互引不双改），验证：载荷级断言通过而非仅 `!blocked`

## 2. 跨片 hold

- [x] 2.1 A 案实现尾窗扫描 + safe/pending 分割 + 超时 flush（`BoundaryHold` 整帧延迟 + 解码文本窗口 + 跨缝掩码 + 泵接线 + 单元/泵级回放单测），验证：跨帧切片回放无半截泄漏
- [x] 2.2 B 案则 README 威胁模型声明接受（不适用：A 案已实现并经 conformance 回归，二选一结论见 design D2），验证：文档评审确认二选一有结论
- [x] 2.3 `strip_partials` 与 hold 职责注释分离（`BoundaryHold` 文档 + `strip_partials` 出口卫生注记），验证：代码评审确认无混淆

## 3. 口径与采样锁

- [x] 3.1 usage max 迁移注释进 README + 双段 max 单测（README 7.2 已有 + `流式usage双段单调max` 单测已存在），验证：旧 sum 对比不再误读
- [x] 3.2 审计读原文注释进 `audit.rs` 头（头注释已更新， stale TODO 已删），验证：注释与实现一致
- [x] 3.3 请求隔离 + prompt-cache 影响一句声明（README 7.3 新增），验证：文档评审通过
- [x] 3.4 HMAC 缺失 warn + 旧关闭回归单测 + `REDACTION_ENABLED=0` 回透回归（`needs_hmac_warn` 谓语 + 单测 + main 启动 warn + 改写回透单测），验证：warn 单测 + 无落盘单测 + 无脱敏单测通过
