## Why

审查确认 Rust 测试骨干完整（4 集成 + 25 内联约 400 用例，conformance 20/20），但相对 Python 42 测试文件的矩阵缺角未立项：截断仅 Chat 开环 2 用例，缺 TSS01 静默丢弃 / TSS03 tool 中截断丢弃 / TSS04 Responses 合成 `failed` + 真实 reasoning/toolcalls 数据；SDK 级三协议全量回放缺（thinking `signature_delta` 单帧、`tool_use.input` 跨 `input_json_delta` 累积提交、`CR-only` 快慢双路径、`error(overloaded)` 插帧、`message_delta usage` 累计覆盖）；`sse_stream_loop` 后 4 项（上游断连重试、`choices_n2` 不广播、多 `data:` 逐行、`retry:` 非数字忽略）未覆盖；`refusal` 行缓冲重组、`fast` 链 BOM+comment、三片段单 flush、flush 失败不双还原缺；`audit_approve_stream` 13 语义中 hold 溢出 fail-closed、中途 abort、超时 vs 断连竞态、早断清理缺（BREAKING pending 本身已声明，此处补边界）；deny 后 content 转发、`done` 回退审计、非流危险全路径缺；凭据解锁超时/并发单 ask/审批三文案/清理双删缺；可观测 8 文件大半缺（SSE 事件计数、upstream/model 过滤、`series` 四窗、pii 跨日/模型近似、ENOSPC 降级）；性能锚（审计链耗时、字典 5000 防爆炸、增量扫描）缺；PII 并发隔离、`BoundaryHold` 组合 fuzz、`usage` 乱序、HOP 逐头、`stream_options` 冲突、`GET /registrations` 401 迁移、`Mock TPM` 生产风险、`PII_VALUE_SAMPLE` 默认双开关、`redaction` 默认开误伤、`FIFO→LRU` 兼容缺。本 change 一次闭环测试矩阵，或对 BREAKING 逐项显式接受风险。

## What Changes

- **截断矩阵补齐**：TSS01/TSS03/TSS04 + 真实 reasoning 开环 + 真实 toolcalls 无伪造 `success`，三协议各一 e2e。
- **SDK 级回放移植**：`api_spec 12` 逐项移植或显式豁免（thinking 签名透传、`tool_use` 还原、`CR-only` 双路径、`error` 终端、`usage` 累计、`stop_sequence` 回显）。
- **流泵边界**：断连重试、`n2` 隔离、多 `data:`、`retry:` 非法、`refusal` 重组、BOM+comment、flush 幂等、hold 溢出/abort/竞态/早断清理、deny 后转发、`done` 回退。
- **凭据与可观测**：解锁超时/并发单 ask/三文案/双删；SSE 事件计数、过滤语义、`series` 四窗、pii 跨日/近似、ENOSPC 降级；审计/PII 性能锚。
- **BREAKING 验收**：6.1–6.4 与收敛项（`registrations` 401、HOP 全集、legacy 忽略、`DEBUG_DIR` 缺落盘）逐项迁移测试或 spec 接受风险标注，无静默缺口。

## Capabilities

### New Capabilities

- `test-parity-close`：截断/SDK/流边界/凭据/可观测/BREAKING 验收测试矩阵闭环。

### Modified Capabilities

- 无既有 spec 需求变更；仅测试资产新增与风险接受标注。

## Non-Goals（显式）

- 不改生产语义（实现修复见 `veil-gateway-protocol-fix` 与 `veil-arch-hygiene-round3`）。
- 不交付 `admin.html`（Non-Goal，重申）。
- 不恢复 `CREDENTIAL_PROXY_DEBUG_DIR` 四件落盘（显式豁免，见 §7.4）。
- 不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-test-parity-close/` 下 proposal/design/specs/tasks；apply 阶段新增 `tests/` e2e 与 `src/` 内联单测。
- **影响系统**：仅测试代码与文档标注；生产行为零变更。
- **依赖**：mock 上游与 sentinel 回放夹具复用既有。
