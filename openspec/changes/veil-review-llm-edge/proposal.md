## Why

深度审查发现 LLM 边缘与网关层存在 9 处 P2/P1 级边缘问题，集中在归一化声明口径、非流回退链、流泵缓冲分工、空流合成守门、会话标识透传、入口选路与编码声明七类。现状：`request_rewrite` 中占位符说明注入经 `to_string` 紧凑化却未置 `normalized_out`（`src/handler/llm/rewrite.rs:83-93`），与 README §7.7 注入即声明契约存在缺口；纯脱敏字节替换长度变化同样不声明（`rewrite.rs:55-77`），口径未文档化；非流还原后 JSON 破裂直接回退原文，未先做残缺剥离重试（`nonstream.rs:192-207`）；400 系如 `truncation:disabled` 走 JSON 分支仍进后处理改写，非字节等价却无声明（`nonstream.rs:225-231`）；流泵内 `AuditHold` 与 `pending_tool_frames` 双缓冲并存，分工未注释（`pump.rs:289-320`）；纯心跳注释帧若计入 `any_frame_sent` 会导致真空流不再合成终端（`pump.rs:637-680`）；`stream:false` 回 SSE 场景转泵时会话标识用空值合成，未透传请求会话（`nonstream.rs:118-129` 经 `resolve_conv_id(None, Null)`）；`Host` 头用 `rsplit(':')` 取尾段，IPv6 字面量选路误判（`src/handler/llm/mod.rs:127-139`）；下游解码开启时剥离 `content-encoding`/`content-length` 对外统一 `identity`，但无显式 `accept-encoding` 改写与一行声明（`hop.rs:33-73`）。三协议主体合规，本 change 只收敛上述边缘口径，不碰审计 verdict 与 PII 集合。

## What Changes

- **修复 1，Responses 注入归一化声明**：占位符说明注入纳入 `x-veil-normalized` 置位条件作条件③，或明确声明占位符注入不声明，二选一并单测锁定。
- **修复 2，纯脱敏字节替换口径声明**：文档声明字节级子串替换不置位，加单测锁定长度变化仍不置位。
- **修复 3，非流回退前残缺重试**：还原 JSON 校验失败后先 `strip_partials` 重试一次，仍失败再回退原文并记 metrics。
- **修复 4，非 502/401 错误 JSON 后处理声明**：文档声明非 502/401 错误 JSON 仍进后处理链，加单测锁定。
- **修复 5，双缓冲分工统一**：`AuditHold` 与 `pending_tool_frames` 统一为一套或注释说明分工，加单测锁定。
- **修复 6，空流合成排除注释帧**：`any_frame_sent` 排除 `comment_only` 帧，纯心跳仍合成终端，加单测锁定。
- **修复 7，非流转泵透传请求会话**：转泵时透传请求会话标识，不再以空值合成，加单测锁定。
- **修复 8，Host IPv6 方括号解析**：`Host` 解析支持方括号 IPv6 字面量，加单测锁定。
- **修复 9，gzip 长度头剥离声明**：补一行日志或文档声明对外统一 `identity`，加单测锁定。

## Capabilities

### New Capabilities

- `llm-edge-gateway`：上述 9 项 LLM 边缘与网关口径修复的输入输出、声明语义与可验证场景。

### Modified Capabilities

- 无。本 change 不修改任何既有 spec 需求；既有 change 行为契约保持不动，README §7.1/§7.6/§7.7 契约文字按本 change 补齐。

## Non-Goals（显式）

- 不碰审计 verdict 判定口径（`block/approve` 语义不变）。
- 不碰 PII recognizer 集合、豁免与阈值。
- 不改 `openspec/changes/` 内任何既有文件；不提交 commit。
- 不输出逐行代码 diff，只定判定口径、声明语义与单测锁定方式。

## Impact

- **新增文件**：`openspec/changes/veil-review-llm-edge/` 下 proposal/design/specs/tasks；apply 阶段改 `src/handler/llm/rewrite.rs`、`src/handler/llm/nonstream.rs`、`src/handler/llm/pump.rs`、`src/handler/llm/mod.rs`、`src/service/llm_gateway/hop.rs` 及对应单测，README §7.7 与 HOP 声明补一行。
- **影响系统**：`x-veil-normalized` 声明完整性、非流还原可用性、流泵终端合成正确性、IPv6 入口选路、上游编码协商可观测性。
- **依赖**：`serde_json` 紧凑序列化、`axum` 头操作；无需新依赖。
