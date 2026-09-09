## Why

深度审查（2026-09-10 六维报告 §1/§6）发现 LLM 网关剩 4 处未收敛缺陷：Responses 用量取数双层嵌套与官方顶层 `usage` 不对齐、多 `choices` tool 桶碰撞、占位符字面 `__PII_*__` 误触发重复注入、流式用量快路径逐事件全量 `to_string()` 浪费。单监听 `127.0.0.1:8877` 下真相源为 `src/service/llm_gateway/usage.rs`、`handler/llm/pump/fragments.rs`、`service/llm_gateway/tool.rs`、`placeholder.rs`。本 change 只收敛这 4 项，不碰审计 verdict、PII recognizer、阻断帧形态。

引用规范：Responses 非流顶层 `usage`（`developers.openai.com/api/reference/resources/responses`）；Chat `tool_calls[].index` 按 choice 隔离拼接（`chat/completions/streaming-events`）；Anthropic 累计用量覆盖语义。

## What Changes

- **修复 F-P1a（Responses 用量双层嵌套）**：`usage.rs:105-142/150-197` 非流与流式要求 `response.usage` 甚至 `response.response.usage`，官方为顶层 `usage` 与 `response.completed.response.usage`。改为顶层优先、嵌套回退，并用真实 `resp_xxx` 体回归锁定。
- **修复 F-P1b（多 choice 桶碰撞）**：`fragments.rs:43-47` 与 `tool.rs:146-150` 的 `idx` 未混入外层 `ci`，`n>1` 时两 choice 同 `index:0` 落同槽串扰。改为桶键 `(ci, index)` 或 `ci * 64 + index`，legacy `function_call` 已用 `ci` 保持一致。
- **修复 F-P2a（占位符字面误触发）**：`placeholder.rs:13-22` 前缀匹配把说明文案自身的 `__PII_*__` 当 token，致重复前插。改为精确形态校验（`__PII_<seq>_<hex8>__` / `__VG_CRED_<digits>__` 全形态，`*` 通配不算），已含说明不再注入。
- **优化 F-P2b（用量快路径性能）**：`usage.rs:153` 每分片 `payload.to_string()` 只为 `contains` 判断。改为借用检查（`get("usage").is_some()` 等），零分配快路径。

## Capabilities

### New Capabilities

- `llm-followup-fix`：上述 4 项的输入输出、错误映射与可验证场景。

### Modified Capabilities

- 无。不修改既有 spec 需求；真相源为 `stream-protocol-parity` 与 `nonstream-compliance`，行为契约保持不动。

## Non-Goals（显式）

- 不碰审计 verdict 口径、不碰 PII recognizer 集合与采样策略。
- 不改阻断帧形态与终止判定、不改 `stream_options` 合并语义。
- 不改 `openspec/changes/` 内任何既有文件；不提交 commit。
- 五处 BREAKING（§6.1-6.5）与 F1/F2 裁剪已在 README §6-8 声明，本 change 不回滚、不重申，只做回归不漂移验证。

## Impact

- **新增文件**：本目录下 proposal/design/specs/tasks；apply 改 `usage.rs`、`fragments.rs`、`tool.rs`、`placeholder.rs` 及对应单测。
- **影响系统**：Responses 用量记录准确性、多 choice 工具审计正确性、占位注入幂等性、流式泵 CPU。
- **依赖**：`serde_json`，无需新依赖。
