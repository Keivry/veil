## Why

系统性审查（Python `credential-proxy` → Rust `veil`，对照 OpenAI Chat/Responses 与 Anthropic Messages 官方规范）确认网关主链等价，但阻断/截断合成帧与三处状态机存在合规偏离，未立项：`src/service/block_inject.rs:11 chat_block_frames` 流式阻断误用非流形态 `choices[].message`（规范流式必须 `choices[].delta`，严格 SDK 流解析器可能丢弃）；`block_inject.rs:20` Anthropic 阻断用 `tool_use(name=blocked)` 伪装文本且 `message_stop` 自造 `reason` 字段（规范为空 `{}`，文本期望方误触发 tool 链）；`block_inject.rs:29` Responses 阻断/截断仅 `delta+completed/failed` 两帧，缺 `output_item.added/done、content_part.done` 全序列（按 `output_index` 对齐的严格客户端失败）；非流 Chat 阻断体仅 `choices`，缺 `id/object/created/model/usage` 回显（严格 SDK 缺 `id` 报错）；`ensure_event_lines` 给 Chat 帧补 `event:message`（规范 Chat 帧仅 `data:` + 裸 `[DONE]`）；`usage max` 口径未覆盖递减/乱序；空流合成依赖 `forwarded==0` 计数器（残余已发但计数未增时误触发二次空流帧）；`redaction.rs:445 mask_span_bytes` 含信封字符即拒掩 + `filter_window:328` 全字母组 IPv6 紧邻缝可误删（注释自认残留，跨缝 PII 贴信封漏掩）；Anthropic 非流 `blocked` 与流帧 `blocked-0` 双形态、`NonDialog` 回 SSE 转泵 `init_conv=None` 归档不一致。本 change 一次收敛网关协议语义，不碰测试门限与架构拆分。

## What Changes

- **阻断帧形态修正**：Chat 流阻断改 `delta:{content}` + 终端 `delta:{} finish_reason:stop` + 裸 `[DONE]`；Anthropic 改 `text` 块、`message_stop` 回归空对象；Responses 补全 `output_item.added/done + content_part.done` 全序列（或 spec 显式声明两帧为终态二选一）；非流 Chat 阻断补 `id/object/created/model/usage` 上游回显透传；Anthropic `conv` 空回退与流帧统一 `blocked-0` 口径。
- **SSE 信封合规**：Chat 帧去 `event:` 补全（仅 `data:` + 裸 `[DONE]` 豁免），`is_done_frame/count_done/dedupe` 行级精确保持；`message_delta usage` 累计覆盖语义单测锁定（递减/乱序不虚高）。
- **状态机加固**：空流守门改“是否已发终端”而非 `forwarded` 计数；`BoundaryHold` 信封守卫漏掩收窄（结构字符逐字豁免而非整段拒绝）+ `filter_window` IPv6 全字母组保护；`stream_options` 键冲突覆盖、`truncation disabled+400` 透传、`thinking/signature` 不透明透传三项回归单测。
- **口径统一**：`NonDialog` 转泵 `conv` 归档与对话路径一致；`hop` 8 项逐头断言；`audit_hold` 双实现 `index` 语义对齐注释。

## Capabilities

### New Capabilities

- `gateway-protocol-fix`：三协议阻断/截断/终端帧合规修正与状态机加固。

### Modified Capabilities

- 无既有 spec 需求变更；`llm-gateway` 能力行为向规范收敛（属 bugfix，非 BREAKING，正常阻断文案 `[blocked: reason]` 不变）。

## Non-Goals（显式）

- 不改测试门限与新增 e2e 矩阵（见 `veil-test-parity-close`）。
- 不做 `handler/llm/mod.rs` 二次拆分与锁选型变更（见 `veil-arch-hygiene-round3`）（勘误：原文 `handler/llm.rs`，路径已拆分，语义不变）。
- 不改 `approve` pending 不断链 BREAKING（README §6.4 已声明，维持）。
- 不提交 commit。

## Impact

- **新增文件**：`openspec/changes/veil-gateway-protocol-fix/` 下 proposal/design/specs/tasks。
- **影响系统**：`src/service/block_inject.rs`、`src/service/sse.rs`、`src/service/redaction.rs`、`src/service/llm_gateway/mod.rs`、`src/handler/llm/pump.rs` 泵尾；严格 SDK 兼容性提升，宽松客户端无感知（勘误：原文 `llm_gateway.rs`/`handler/llm.rs`，路径已拆分，语义不变）。
- **依赖**：无新依赖；conformance 20/20 回归 + 新增合规单测。
