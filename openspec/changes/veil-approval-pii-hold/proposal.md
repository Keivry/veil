## Why

审查发现两处语义级降级未被任何 change 收敛：其一 `approve` 从 Python 同步阻塞（流中 `_request_audit_approval` 挂起等 `✅/❎`，`keepalive 10s`，超时默认拒绝并注入阻断帧）变为 Rust 挂起声明（泵内 `NeedApproval→PendingRecord insert`，`audit_hold.rs Pending→None` 占位，真人审批由凭据链承载，流不挂起），e2e 仅断言 `!blocked` 会误判漏拦为正常；其二 PII 跨 `data:` 半截持有缺失（Python `_has_partial_pii_candidate/_split_safe_hold` 三层等待，`138`+`12345678` 切两帧时不透出半截，Rust 仅叶级 walk + `strip_partials` 清残缺占位符，半截明文可能提前透出）。另有三处口径需锁定：`usage max`（Rust，不双计）vs `sum`（Python，双计）大盘不可比；审计读原文（Rust，抗混淆）vs 读还原后（Python 非流，会被掩码干扰）；PII 请求隔离（Rust，隐私严但 prompt-cache 命中降）vs 全局复用（Python，可关联）。本 change 对每项做“实现补齐或接受风险文档化”二选一决策，不留静默降级。

## What Changes

- **决策 1，`approve` 同步/挂起二选一**：A 案恢复流中同步等待（泵内挂起 + Matrix `ask` + 超时拒绝注入阻断帧，与 Python 同形）；B 案保留挂起声明但文档升为 BREAKING（流式网关危险调用转 pending 不阻塞，拒绝/过期由凭据审批链承载，e2e 断言改为“pending 建单 + 无泄漏”而非“阻断帧”）。design 定其一，spec 锁定所选语义与 e2e 断言。
- **决策 2，PII 跨片 hold 补齐或接受**：A 案实现跨 `data:` 半截明文 hold（移植 Python D5：尾窗扫描 + `safe/pending` 分割 + 完成/超时 flush）；B 案文档接受风险（威胁模型声明分片切断 PII 不在防护内）。design 定其一，A 案需补实现与单测，B 案需进威胁模型声明。
- **锁定 3，usage/审计源/隔离口径**：`usage max` 为准（旧大盘 `sum` 虚高，迁移声明已在 README 7.2，加 dashboard 对比注释）；审计读上游原文为准（Python 非流读还原后视为实现矛盾，统一为原文）；PII 请求隔离为准（全局 `vault` 还原不断链保持，`Scope::pii` 请求级容器保持，prompt-cache 影响文档化）。
- **加固 4，采样与默认开关测试锁**：`REDACTION_ENABLED` 默认开、`PII_VALUE_SAMPLE_PERSIST` 默认落盘、`HMAC` 未设退化 sha256 三项加“旧关闭语料回归 + 生产 HMAC 缺失告警”单测，防止静默变严与可枚举 hash 落盘。

## Capabilities

### New Capabilities

- `approval-hold-parity`：approve 同步/挂起语义、PII 跨片 hold、usage/审计源/隔离口径、采样默认锁。

### Modified Capabilities

- 无。既有 change 契约不动；本 change 只新增决策与锁定。

## Non-Goals（显式）

- 不改网关 P0 注入/阻断形态（另见 `veil-gateway-p0-fix`）。
- 不改 recognizer 集合与 ReDoS 策略。
- 不改 `openspec/changes/` 既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-approval-pii-hold/` 下 proposal/design/specs/tasks；apply 阶段可能改 `src/service/audit_hold.rs`、`src/handler.rs` 流泵、`src/service/sse.rs`/`redaction.rs`（A 案）或仅改 README 威胁模型（B 案）。
- **影响系统**：流式审批阻塞语义、PII 分片泄漏面、usage 大盘可比性、审计对抗性。
- **依赖**：Matrix `ask` 超时口径（`AUDIT_TIMEOUT` 默认 90s，禁 110-130s）、`AUDIT_HOLD_MAX_BYTES` 1MB 上限。
