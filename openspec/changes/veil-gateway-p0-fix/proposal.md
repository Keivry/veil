## Why

深度审查（Python `credential-proxy` v0.9.46 vs Rust `veil` master）发现 LLM 网关存在 7 处 P0 级合规分叉：`stream_options` 用户自带非空时漏注 `include_usage`（`llm_gateway/protocol.rs:107 is_none` vs Python `setdefault` 合并）（勘误：原文 `llm_gateway.rs:190`，路径已拆分，语义不变）；Anthropic 非流阻断体缺 `id/type/role/usage/model`（严格 SDK 校验失败）；Responses 阻断空 `completed` 无可读文本（可用性低于 Python 明文块）；`count_done` 用 `contains("[DONE]")` 误计 `arguments` 内同串；`stream:true + application/json` 组合双边路由分叉（Rust 转流泵 vs Python 走非流）；`data:` 双空格剥离口径不一；Chat 流阻断 `message` vs `delta`、Anthropic `blocked` 占位名二次调用风险未锁定。三 API（`v1/chat/completions` / `v1/messages` / `v1/responses`）其余结构/语义/工具调用均合规，本 change 只收敛上述分叉，不碰审计 verdict 与脱敏 recognizer 口径。

## What Changes

- **修复 1，`stream_options` 键内合并**：`should_inject_stream_options` 由整键 `is_none` 改为键内 `include_usage` 缺失即合并注入，保留用户自带其他键；仅 Chat/Responses 流式、Anthropic 永不注入保持不变。
- **修复 2，Anthropic 非流阻断体补齐**：`nonstream_block_body(anthropic)` 补 `id/type/role/usage/model` 五字段，与 Python `_build_block_body` 同形，严格 SDK 可解析。
- **修复 3，Responses 阻断补可读文本**：`responses_block_frames` 在 `response.completed` 前补 `output_text.delta` 明文（中文 BLOCK 文案或原因码文本二选一，design 定），空完成不再无内容；截断 `failed` 保持不伪造完成，另补 `TRUNCATED_MESSAGE` 可读提示或明确空语义为有意。
- **修复 4，`count_done` 行级精确**：`count_done` 由 `contains` 改为与 `is_done_frame/is_done_payload` 同口径的行级精确判定，`arguments` 内同串不再误计。
- **收敛 5，`stream:true+JSON` 组合锁定**：明确该组合走流泵还是非流（二选一，design 定），双边对齐并加单测锁定；默认建议以 `Content-Type: event-stream` 为准、否则按 `stream` 标志转泵，行为文档化。
- **收敛 6，`data:` 空格与大小写口径文档化**：`data:` 后多空格/tab（Python `lstrip` vs Rust 单空格剥离）以 `serde_json` 容忍前导空白为依据声明无碍，加回归单测；`tail` 大小写不敏感 + `stream` 严格 JSON 语义以 Rust 为准（Python 正则误命中为已知妥协），文档显式声明。
- **收敛 7，阻断帧形态锁定**：Chat `message` 自闭合 vs `delta` 增量二选一并统一rack文案（中文 `BLOCK_MESSAGE` vs 英文 `[blocked: reason]`）；Anthropic `blocked` 占位名经“不触发下游二次调用”验证（单测断言占位 `input:{}` 合法且无工具名碰撞）。

## Capabilities

### New Capabilities

- `gateway-p0-compliance`：上述 7 项网关 P0 合规修复的输入输出、错误映射与可验证场景。

### Modified Capabilities

- 无。本 change 不修改任何既有 spec 需求；`openspec/specs/` 当前为空，既有 change 行为契约保持不动。

## Non-Goals（显式）

- 不碰审计 verdict 判定口径（`block/approve` 语义、`approve` 同步/挂起决策留待 `veil-approval-pii-hold`）。
- 不碰 PII 跨片 hold（留待 `veil-approval-pii-hold`）。
- 不碰脱敏 recognizer 集合、豁免与 ReDoS 策略。
- 不改 `openspec/changes/` 内任何既有文件；不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-gateway-p0-fix/` 下 proposal/design/specs/tasks；apply 阶段改 `src/service/llm_gateway/mod.rs`、`src/service/block_inject.rs` 及对应单测（勘误：原文 `src/service/llm_gateway.rs`，路径已拆分，语义不变）。
- **影响系统**：三协议流式/非流式阻断与 usage 尾包完整性、严格 SDK 兼容性、下游 Hermes 展示文案。
- **依赖**：`serde_json` 前导空白容忍、`axum` SSE 帧形态；无需新依赖。
