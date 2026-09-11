## Context

现状（见 proposal.md Why）：网关三协议分发、透传、WHATWG 解析、工具分桶均合规，7 处 P0 分叉集中在注入合并语义、阻断体形态、终止计数精度三类。约束：只改网关注入/合成/计数，不碰审计 verdict 与 PII hold；与既有 6 个 change 零重叠；新 change 名固定 `veil-gateway-p0-fix`。

## Goals / Non-Goals

**Goals：**

- 给出每项修复的函数级改动形状与单测锁定方式，使 apply 可逐项落地独立验证。
- 收敛形态二选一（message/delta、文案中英文、stream+JSON 路由），消除“以谁为准”疑问。

**Non-Goals：**

- 不设计 `approve` 同步/挂起（另见 `veil-approval-pii-hold`）。
- 不输出逐行代码 diff，只定签名形状、判定口径与帧形态。
- 不引入新依赖。

## Decisions

### D1：`stream_options` 键内合并，Anthropic 永不注入

**决策**：`should_inject_stream_options` 改为“协议为 Chat/Responses 且 `is_stream` 且 `stream_options.include_usage` 缺失”即真；`inject_stream_options` 改为反序列化既有 `stream_options` 对象后 `insert(include_usage,true)` 写回，非对象形态则整体替换为 `{"include_usage":true}` 并 warn。Anthropic 分支恒假。

**理由**：Python `setdefault` 即键内合并，用户自带 `stream_options:{other:1}` 时 usage 不可缺，否则尾包 usage 丢失。整键跳过是保守过度。

**备选**：保持 `is_none` 整键跳过——尾包缺 usage，不采用。

### D2：Anthropic 非流阻断体向 Python 对齐补全

**决策**：`nonstream_block_body(Anthropic)` 返回 `{"id":"blocked","type":"message","role":"assistant","model":<透传或缺省>,"content":[{"type":"text","text":<BLOCK>}],"stop_reason":"end_turn","usage":{"input_tokens":0,"output_tokens":1}}`；`id` 固定 `blocked` 或沿用 `conv_id`（apply 时定其一），`model` 有则透传。

**理由**：Messages 非流 schema 要求 `id/type/role/content/stop/usage/model`，极简体在严格 SDK 必败。Python 形态已验证可解析。

**备选**：维持极简体——严格客户端失败，不采用。

### D3：Responses 阻断/截断补可读 delta，状态语义不变

**决策**：阻断仍为 `response.completed`（不伪造 `failed`），但其前追加一帧 `response.output_text.delta` 明文（BLOCK 文案）；截断仍为 `response.failed`，但其前追加一帧 `output_text.delta(TRUNCATED_MESSAGE)` 或文档声明空语义为有意（apply 时二选一，单测锁定所选）。

**理由**：空 `completed` 下游见空完成不可用；Python 明文块可用性更高。状态语义（阻断 completed/截断 failed）维持 Rust 正确方向不变。

**备选**：维持空 `completed`/纯 `failed`——可用性降，不采用。

### D4：终止计数与 `data:` 空格口径收紧并单测锁定

**决策**：`count_done` 复用 `is_done_frame` 行级判定（`trim` 后 `== "data: [DONE]"` 或等价），不再 `contains`；`data:` 解析保持单空格剥离 + `serde_json` 前导空白容忍，加双空格回归单测（`data:  {json}` 可解析）。

**理由**：`arguments` 内 `"data: [DONE]"` 字符串是合法工具参数，宽松计数会误判终止。空格侧 Python `lstrip` 与 Rust 单空格剥离经 `serde_json` 容忍后等价，无需改解析器，只需单测锁定。

### D5：`stream:true+application/json` 以流泵为准并文档化

**决策**：当请求 `stream==true` 但上游回 `application/json`（非 `event-stream`）时，以 Rust 现行“转流泵”为准（泵内 `looks_sse=ct event-stream || stream_flag`），Python 非流分支视为历史形态；加组合单测锁定。若 apply 实测上游恒按 `Content-Type` 分流，则以实测为准翻转决策并同步文档。

**理由**：`stream` 是客户端意图，`Content-Type` 是上游实际；意图优先可避免客户端等不到 `[DONE]`。关键是双边一致而非谁对谁错。

### D6：大小写/严格探测/占位名以 Rust 为准并验证

**决策**：`tail` 大小写不敏感 + `query strip` + `lenient` 计数保留；`is_stream_body` 严格 JSON 语义保留（Python 字节正则误命中为已知妥协）；Chat 阻断以 `message` 自闭合保留（`delta` vs `message` 皆可解析，自闭合更稳），文案统一为中文 `BLOCK_MESSAGE` 或英文原因码其一（apply 定）；Anthropic `blocked` 占位须过“二次调用”验证：占位 `name=blocked` 不在任何策略 `allow` 名单，`input={}` 经 schema 校验合法。

**理由**：Rust 侧在每项上都更严或更稳，Python 侧为轻量妥协。统一为准可减少双边维护成本。

## Risks / Trade-offs

- [`stream_options` 非对象形态] → 合并失败 → 整体替换 + warn，回退可解析。
- [Anthropic 阻断补字段后快照断言失效] → 既有单测更新 → tasks 设快照更新独立任务。
- [Responses 补 delta 后 `dedupe_terminal` 误判] → 终止恰一被破坏 → delta 帧不计入终止计数，仅 `completed/failed` 计数。
- [`stream+JSON` 选泵后旧客户端等非流] → 超时 → 文档声明 + 组合单测 + 回滚开关（配置项显式切回非流）。

## Migration Plan

1. 按 tasks G1→G7 顺序逐项修，每项独立单测验证，任一项失败只回滚该项。
2. 阻断体形态变更先更新单测快照，再改实现，最后跑三协议 conformance（`scripts/api_conformance.py` 14/14）。
3. 回滚策略：每项修复保持旧函数可 feature-gate 切回，直至 conformance 全绿再删旧路径。

## Open Questions

- 无。形态二选一已在本 design 收敛；若 apply 实测严格 SDK 对补全字段另有要求，以实测为准提后续小 change。
