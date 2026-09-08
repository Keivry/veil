## Context

现状：`block_inject.rs` 三协议阻断帧可被宽松客户端接受，但与官方规范逐项比对有 5 处偏离 + 3 处状态机残留风险。约束：阻断文案 `[blocked: reason]` 不变；终端恰一约束不变；`approve` pending 语义不动；conformance 20/20 保持。

## Goals / Non-Goals

**Goals：**

- 给出每处偏离的修正后帧形态（可直接照写）。
- 给出状态机加固的最小改法与回归锚点。
- 给出 `BoundaryHold` 漏掩收窄方案。

**Non-Goals：**

- 不重定义审计 verdict 语义（`eveluate` 四阶不动）。
- 不引入新帧类型。

## Decisions

### D1：Chat 流阻断改 `delta` 形态，去 `event:` 补全

**决策**：`chat_block_frames` 改为两帧：`data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"[blocked: reason]"}}]}` + 终端 `data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + 裸 `data: [DONE]`（三帧，`count_done==1`）。`ensure_event_lines` 对 Chat 协议不再补 `event:`（Anthropic/Responses 保持补全）。

**理由**：规范流式增量载体为 `delta`，`message` 为非流形态；规范 Chat 帧无 `event` 行。严格 SDK 按 `delta` 拼接，`message` 形态会被忽略致空输出。

**备选**：维持 `message` 自闭合——宽松客户端可过但严格 SDK 失败，不采用。

### D2：Anthropic 阻断改 `text` 块，`message_stop` 回归空对象

**决策**：`anthropic_block_frames` 四帧顺序锁定（`content_block_start/content_block_stop/message_delta/message_stop`），首块改 `{"type":"text","text":"[blocked: reason]"}`；`message_stop` 数据回归 `{"type":"message_stop"}` 空对象，去自造 `reason` 字段；`content_block_start` 块类型同步改 `text`。

**理由**：文本阻断用 `tool_use` 会使下游 tool 调度器误触发空调用；`message_stop` 额外字段违反规范空对象约定。

### D3：Responses 补全输出项序列，非流 Chat 阻断补回显字段

**决策**：`responses_block_frames` 扩展为 `output_item.added → content_part.added → output_text.delta → output_text.done → content_part.done → output_item.done → response.completed` 全序列（`output_index:0` 对齐，`item_id` 统一用 `response_id`）；截断 `responses_truncated_frames` 同序列尾帧改 `response.failed`。非流 `nonstream_block_body(Chat)` 补 `id/object:chat.completion/created/model/usage` 四字段，值回显上游响应（无上游值时 `id:"blocked-<conv>"`、`model:"blocked"`、`usage:{0,1,1}`）。

**理由**：按 `output_index` 对齐的客户端缺中间帧即乱序；严格 Chat SDK 要求 `id` 非空。

**备选**：spec 声明两帧为终态——若全序列改动风险高可退守，但默认按全序列执行。

### D4：空流守门改终端状态，`usage` 累计覆盖锁定

**决策**：泵尾空流合成条件由 `forwarded==0` 改为 `!terminal_sent && !any_frame_sent`（以是否已发终端/任意帧为准，残余 `send` 即记位）；`merge_usage` 保持三列 `max`，追加递减/乱序单测（递减输入仍取历史 max，不回退）。

**理由**：计数器与实际发送位可分叉，状态位是唯一真源；`max` 口径在乱序下行为须锁定防未来改 `sum` 回退。

### D5：`BoundaryHold` 漏掩收窄 + IPv6 保护

**决策**：`mask_span_bytes` 结构字符守卫由“整段含即拒”改为“逐字符豁免”（信封字符位跳过，仅掩码其余位，坐标长度不变仍用 `*` 等字符替换非信封位）；`filter_window` 的 `"key":` 误删加护：冒号后首段全字母且长度≤4 且紧邻缝合缝时不删（覆盖 IPv6 组 `abcd` 误伤，JSON 键多为更长词或已在他处处理）。

**理由**：当前整段拒绝使贴信封 PII 零掩码；IPv6 全字母组是唯一已知误删形态，定向护栏最小。

### D6：口径统一与注释对齐

**决策**：Anthropic `conv` 空回退统一 `blocked-0`（非流与流一致）；`NonDialog` 转泵 `init_conv` 归档走同一 `resolve_conv_id` 路径；`extract_tool_calls` 与 `extract_tool_fragments` 外层 `index` 语义在 `llm_gateway.rs:831` 头注释一句对齐声明；`is_done_payload/is_done_frame/count_done/terminal_count` 四函数头注释标定载荷级/帧级/行级分工。

## Risks / Trade-offs

- [全序列 Responses 阻断帧被旧客户端不识别] → 中间帧忽略 → 保留首尾 `delta+completed` 兼容，旧客户端按首尾仍闭合。
- [`mask` 逐字豁免破坏 JSON] → 信封位原样保留 → 掩码前后 `serde_json`  roundtrip 单测。
- [Chat 去 `event:` 后旧断言失败] → 同步改 `block_inject` 内 18 个单测期望 → tasks 设单测同步任务。

## Migration Plan

1. 先 D1+D2+D3 帧形态（单测同步），再 D4 泵尾守门，再 D5 hold 收窄（fuzz 在 test change 验收）。
2. 每步 conformance 回归；全量 `cargo test` 通过。
3. 回滚：按帧类型独立 revert（chat/anthropic/responses 各自单提交）。

## Open Questions

- 无（D3 全序列 vs 两帧声明二选一，默认全序列，apply 遇阻可降级）。
