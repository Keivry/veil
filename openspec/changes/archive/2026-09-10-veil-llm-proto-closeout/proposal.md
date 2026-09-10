## Why

六维深度审查（2026-09-10）维度 6（三协议合规）确认 4 项偏差/风险与 4 项待锁定项，均集中在 LLM 网关协议面：

- **P1-1（用户决策 b）**：`should_inject_stream_options`（`protocol.rs:111-128`）对 `Chat | Responses` 同等注入 `stream_options.include_usage`；官方 Responses 规范中 `stream_options` 仅接受 `include_obfuscation`，无 `include_usage`。Python 原仓同样注入（`_llm.py:8539-8541`），属忠实奇偶但规范外。**用户决策：收窄为仅 `Protocol::Chat`**；Responses 用量经 `response.completed.response.usage` 携带，`extract_usage_stream` 三级回退（`usage.rs:177-191`）已闭环，不依赖注入。
- **P1-2**：Chat/Anthropic 真空流 open-ended（`empty_stream_frames` 仅 responses 合成 failed，`frames.rs:290`；`spawn.rs:623-632` 仅记 `OpenEnded`），与原仓 `_ensure_nonempty_stream`（`_llm.py:2633`，三协议均注入最小可解析事件，目的「避免 Hermes JSONDecodeError 空体」）不一致；Rust 为 spec 有意（`stream-protocol-parity`），但缺 Anthropic 对应用例、缺风险书面声明、缺三协议 e2e 对照。
- **P2-2**：Chat 终端仅认 `data: [DONE]`（`event.rs:154-166`）；上游以 `finish_reason` 结束却不发 `[DONE]` 时 `terminal_sent` 永假，已有帧时跳过空流守门，流以 open-ended 结束且**无任何截断标记**。
- **P3（声明核对）**：`error` 事件统一合成 `response.failed`（`spawn.rs:215-238`）已声明为有意（README §7.2）——补测试与字面复核，不改行为。
- **待锁定**：Anthropic `message_delta` 双角色（粘滞终止 `event.rs:66` + 按槽清理）一致性；Responses `sequence_number` 仅保序不校验连续性（`event.rs:182-187`）；凭据占位符门控 `\d{6,}`（`placeholder.rs:25-34`）窄于 vault `\d{4,}` 的有意保守。

本 change 只收敛协议面这些点，不动审计判定、PII recognizer、阻断帧形态与截断四态（TSS）。

## What Changes

- **B1 收窄 Responses 注入（决策 b）**：`should_inject_stream_options` 仅 `Protocol::Chat`；`inject_stream_options` 不变；更新 `protocol.rs:213` 与 `rewrite.rs:490` 测试；新增「Responses stream:true 不注入且字节保留」「用户自带 `stream_options` 原样保留」用例；README §7.2/§7.7 表述限定 Chat；design 登记 R1 回退条款。
- **B2 空流对齐**：补 Anthropic 真空流 open-ended 单测（对齐 chat 用例）；补三协议空流 e2e 对照（chat/anthropic 零合成帧；responses failed）；README §8 新增 8.6 决策声明（与原仓差异、风险、依赖下游 stub）；Hermes stub 证据复核并登记结论。
- **B3 Chat finish_reason 观测**：流泵记录 `finish_reason` 非 null；流末缺 `[DONE]` 时置 `set_truncated(OpenEnded)` + warn + 指标（不改字节、不合成帧）；补单测；README §7.2 增口径句。
- **B4 error 统一锁定**：补「`error` 事件 → 恰一 `response.failed`、无 completed」单测；README 字面复核保持。
- **B5 message_delta 一致性**：核验双路径；补「tool_use 槽完成 + message_delta 同帧 → 审计恰一次、无重复清理」单测；若不一致则最小修复。
- **B6 sequence_number 容忍锁定**：补断序帧透传不 panic、恰一终端单测；README §7.2 增容忍口径句。
- **B7 占位符门控口径**：核验既有单测锁定 `\d{6,}` 保守门控；README 增口径句。
- **B8 全文措辞 sweep**：§7.4/§7.7/§8 凡涉 `include_usage`/`stream_options` 表述与 B1 收窄对齐。

## Capabilities

### New Capabilities

- `llm-proto-closeout`：协议面收窄、容忍锁定与声明的可验证场景。

### Modified Capabilities

- 无。既有 `stream-protocol-parity` 的 SHALL 文本不变（空流行为保持 open-ended）；新增测试与 README §8.6 声明由本 change 的 `llm-proto-closeout` capability 锁定。

## 附录：已评估无需动作（本轮审查结论）

- **Content-Type 不参与协议分发**（`protocol.rs:93-97` 仅日志）：对齐原仓 tail-only 语义，非缺陷。
- **Chat 流式 usage 仅顶层**（`usage.rs:176`）：符合官方 `include_usage` 末帧语义。
- **`req_conv` 提取口径**（`nonstream.rs:81-83` 改写后 body vs `rewrite.rs:98` 原始 body）：非 JSON 双 None；注入不改 `id`，语义等价。
- **Responses `error` → `response.failed` 统一**：已声明行为，B4 仅锁定测试。

## Non-Goals（显式）

- 不改截断四态（TSS-01~04）、不改阻断帧形态、不改审计 verdict 与白名单口径（归 `veil-nonstream-audit-align`）。
- 不按选项 (a) 处理——用户已选 (b)；真上游回归时的回退路径见 design R1。
- 不改 `hygiene-round4` 或既有已归档 change 文件；不提交 commit。

## Impact

- **新增文件**：本目录文档；新增/修改测试（`protocol.rs`、`rewrite.rs`、`stream_tests.rs`、空流 e2e）。
- **影响系统**：Responses 请求体不再被注入 `include_usage`（行为变更；潜在影响上游对用量帧的返回意愿——见 design Risks 与 R1）；Chat 不变；空流语义不变（仅补测与声明）；Chat 无 `[DONE]` 场景新增可观测标记。
- **依赖**：`cargo test` + `scripts/api_conformance.py` + sentinel 回放。
