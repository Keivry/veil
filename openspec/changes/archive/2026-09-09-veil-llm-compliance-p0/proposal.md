## Why

第三方系统性审查（对照原 Python `_llm.py` 8676行 + 官方三API规范）发现非流/流式核心路径存在 P0 级正确性断裂：非流 502/401 早返跳过用量/审计/还原（`nonstream.rs:110-114` 已复核）；流/非流内外层 `index` 优先级双实现打架致分桶分叉（`tool.rs:185-191` vs `pump.rs:832,844`）；截断残缺 tool 分片已透传下游违背 TSS-03 丢弃语义（`pump.rs:419-436`）；泵入口 `hold_max/boundary` 无钳位（`pump.rs:74-98`）；非流无 JSON 破裂回退、无残缺 token 剥离、approve 被过收紧为阻断。若不修复，下游可能执行不完整工具调用、审计漏检、SDK 解析失败。

## What Changes

- 非流 502/401/空体走完整后处理或显式豁免：usage 记录 + 审计判定 + 还原链路二选一，不再静默直返。
- 统一内外层 `index` 优先级（以外层为准或以 Python `_accumulate_tool_calls` 为准），合并流/非流分桶实现，补冲突单测。
- TSS-03：截断残缺 tool 分片 hold-until-complete，残缺即丢弃不转发；`_synthesize_truncation` 覆盖 chat/anthropic。
- 泵入口钳位 `pii_boundary_chars/hold_max`（0→默认值/最小值，超大→上限），非法值 warn。
- 非流还原加双 `_jloads` 校验失败回退原文；加 `strip_partials`（凭据+PII 残缺前缀剥离）。
- 非流 approve 语义与 Python 对齐：仅 `deny` 阻断，`NeedApproval` 走 pending/透传（与流式 B 案一致）。
- NonDialog 非流臂决策：明确透传 vs 补还原/审计/用量二选一并文档化（F1）。

## Capabilities

### New Capabilities

- `nonstream-compliance`: 非流后处理完整性（502/401/JSON 回退/残缺剥离/approve 对齐/NonDialog 决策）。

### Modified Capabilities

- `llm-streaming-parity`：截断残缺丢弃、泵入口钳位、index 优先级统一（不改终止帧形态，形态归 `protocol-termination-fix`）。

## Impact

- 影响 `src/handler/llm/nonstream.rs`、`pump.rs`、`service/llm_gateway/tool.rs`、`service/sse.rs`、`service/block_inject.rs`、`service/audit_hold.rs`。
- **BREAKING**：截断残缺 tool 由“透传”改为“丢弃”（与 Python 一致，下游不再收到不完整调用）；非流 approve 由“阻断”改为“pending/透传”（与流式 B 案一致）。
- 不碰 metrics 采样器（另立 `veil-metrics-sampler-fix`）、Responses 起始事件（另立 `veil-llm-protocol-parity`）。
