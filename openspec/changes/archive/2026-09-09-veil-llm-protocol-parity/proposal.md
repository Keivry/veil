## Why

系统性审查发现流式协议边缘语义与可观测性列存在 11 项中/低风险偏离：chat 真空流伪造成功终止违背原 open-ended 语义（`pump.rs:536-565`）；Responses 起始事件丢名致截断漏审（`pump.rs:1011-1013`）；流/非流 `file_search/web_search` tool 判定相反；超长行整块静默丢（`sse.rs:203-211`）；行内 BOM 帧丢弃；`model` 维度与缓存列丢失致可观测性回归；另有 4 项低风险声明缺口（重序列化、空 tool 条目、空心跳帧、usage max 迁移）。单列 P0 change 已收核心，本 change 收敛剩余协议奇偶。

## What Changes

- chat/anthropic 截断回归 open-ended：真空流不再合成成功终止（按尾缀区分：有残余才合成，无残余保持开放）。
- Responses `output_item.added` 建槽保留 name/id；流式补 `custom_tool_call` 覆盖；流/非流 tool 判定统一（含 `file_search/web_search` 口径二选一并文档化）。
- 超长行（>16KB）由丢弃改为截断标记+metrics 计数+审计可见；行内 BOM 先剥离再解析（与 Python `_strip_bom` 一致）。
- 恢复 `model` 分桶（`record_chat` 加 model 维，阻断体 model 回退上游值而非字面 `blocked`）；恢复 `cached_read/cached_write` 列。
- 低风险声明：`x-veil-normalized` 注入即声明；空 tool 增量不建条目；空心跳帧丢弃；usage max 迁移须知文档化。

## Capabilities

### New Capabilities

- `stream-protocol-parity`: 流式终止/起始事件/超长行/BOM/判定一致性 + 可观测性列恢复 + 低风险声明。

### Modified Capabilities

- `llm-streaming-parity`：空流合成规则修正（open-ended 回归）。
- `observability-compat`：model 分桶与缓存列恢复（只加列不改旧列）。

## Impact

- 影响 `pump.rs`、`tool.rs`、`sse.rs`、`block_inject.rs`、`metrics.rs`、`usage.rs`、`rewrite.rs`、`README.md`。
- **BREAKING**：真空流不再伪造成功终止（Hermes 靠 `finish_reason is None` 走 stub 的路径恢复原语义）；`file_search/web_search` 审计口径统一（流/非流一致后一方行为变化，需 release note）。
- 与 `veil-llm-compliance-p0` 联动验证截断矩阵 E2E。
