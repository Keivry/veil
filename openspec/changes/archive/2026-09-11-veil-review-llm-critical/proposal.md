## Why

全量审查发现 LLM 网关三协议（Chat、Anthropic、Responses）在流式与非流式各剩 6 处关键合规缺口，集中在审计漏审、终止误判、归档不一致、用量语义未声明、注入全有全无、阻断状态码不对称六类。单进程单监听 `127.0.0.1:8877` 下，`src/handler/llm/pump.rs`（1660 行）是流泵唯一真相源，`src/service/llm_gateway/protocol.rs` 管注入语义，`placeholder.rs` 管占位注入，`nonstream.rs` 管非流阻断。本 change 只收敛这 6 项，不碰审计 verdict 口径与 PII recognizer 集合。

引用规范四条：Chat 侧 `delta` 为增量、`message` 为自闭合；Anthropic 侧 `event` 须等于 `data.type`；Responses 侧 `completed/failed` 为终结帧；用量取 `max` 口径不双计。

## What Changes

- **修复 1（E7-P0，thinking 混帧漏提）**：`pump.rs:322-357` 现状是 `is_minor_event` 与 `extract_tool_fragments` 互斥（`minor = !is_tool_event && is_minor_event(...)`），`content_block_delta` 同时含 `thinking_delta` 与 `partial_json` 工具增量时整帧标 minor，工具增量漏审。改为先提工具片段，非空则走 tool 通道进 hold 审计，剩余 thinking 部分才走 minor 透传，并补混帧单测。
- **修复 2（E8-P1，terminal contains 字符串判定）**：`pump.rs:202-234` Responses 终止判定用 `contains("response.completed")` 等字符串匹配，`type:error` 带空格变体（`"type": "error"` 靠双 contains 兜底）仍有误判与漏判风险。改为 `serde_json` 解析后按 `type` 字段精确判定。
- **修复 3（E9-P1，incomplete 合成 conv 不一致）**：`pump.rs:235-275` 对 `incomplete/error` 合成截断帧时用 `resolve_conv_id(None, Null)` 归档值，与流内真实 `id` 不一致，下游难关联。改为优先采用流内首见 `id`，缺失时才回退归档值。
- **收敛 4（E1-P1，stream_options=false 保留）**：`protocol.rs:126-145` 配 `rewrite.rs:172-190` 按 key 合并保留既有 `false`，行为正确（显式 false 即用户放弃流式用量）。本项不改代码，只在 `README §7.2` 追加声明“显式 false 即放弃流式用量”，并加 metrics 空 usage 桶告警说明。
- **修复 5（E2-P1，Responses 双字段部分非法整体回退）**：`placeholder.rs:189-213` 经 `placeholder_schema_ok` 整对象校验，`input` 合法加 `instructions` 非法时整体返回 `None`，丢弃合法字段的改动。改为按 `input` 与 `instructions` 字段独立注入、独立回退。
- **收敛 6（E4-P1，阻断体状态码不对称）**：`nonstream.rs:150-189` 非流阻断保留上游错误码（如 502/401），而流式阻断恒 200 闭合。改为二选一并单测锁定：统一阻断恒 200，或文档声明差异为有意。

## Capabilities

### New Capabilities

- `llm-critical-compliance`：上述 6 项 LLM 关键合规修复的输入输出、错误映射与可验证场景。

### Modified Capabilities

- 无。本 change 不修改任何既有 spec 需求；真相源为 `openspec/specs/stream-protocol-parity` 与 `nonstream-compliance`，既有 change 行为契约保持不动。

## Non-Goals（显式）

- 不碰审计 verdict 判定口径（`block/approve/allow` 语义不变）。
- 不碰 PII recognizer 集合、豁免与采样策略。
- 不改 `openspec/changes/` 内任何既有文件；不提交 commit。
- 不在 artifact 中复制 skill 的 context/rules 块。

## Impact

- **新增文件**：`openspec/changes/veil-review-llm-critical/` 下 proposal/design/specs/tasks；apply 阶段改 `src/handler/llm/pump.rs`、`src/service/llm_gateway/placeholder.rs`、`src/handler/llm/nonstream.rs`（E1 只改 `README §7.2` 与 metrics 文档），及对应单测。
- **影响系统**：Anthropic thinking 混帧审计覆盖率、Responses 终止判定精度与 conv 关联性、显式 false 用量语义文档、Responses 占位注入粒度、非流阻断状态码一致性。
- **依赖**：`serde_json` 解析与前导空白容忍、`axum` SSE 帧形态；无需新依赖。
