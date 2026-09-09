## Context

See proposal.md Why. Current code: `pump.rs:536-565 + block_inject.rs:16-25` 真空流恒合成 `delta+stop+[DONE]`；`pump.rs:1011-1013/tool.rs:357-359` 起始事件直接 return；非流 `tool.rs:367-373 contains("tool")` vs 流式 `pump.rs:683-695` 判 minor；`sse.rs:203-211` 超 16KB clear；`sse.rs:690-694` `\uFEFFdata:` 不产出事件；`metrics.rs:191 record_chat` 无 model；`block_inject.rs:217-223` model 回退 `blocked`；`usage.rs:17-51` 忽略缓存键；`rewrite.rs:58-67` 注入即重序列化但 `normalized_out` 取配置值；`tool.rs:106-115` 空增量建空条目；`pump.rs:463-470` 空 `data:` 透传。

## Goals / Non-Goals

**Goals:**

- 终止/起始/判定语义与 Python 及官方规范一致，截断永不漏审。
- 超长/BOM 行可观测不丢失；model/缓存列恢复。
- 低风险项全部有声明或行为对齐，无悬空。

**Non-Goals:**

- 非流 502/401/index/TSS-03/钳位（`veil-llm-compliance-p0`）。
- 采样器修正（`veil-metrics-sampler-fix`）。

## Decisions

- 空流合成：按 `bytes_written==0 && 200` 且有残余才合成；真空流（零残余）chat/anthropic 保持 open-ended（Python `_synthesize_truncation` 语义），Responses 仍合成 failed 终端（TSS04）。
- 起始事件：`output_item.added` 建槽（name/id 入槽），后续 delta 累积；流式加 `custom_tool_call` 分支（复用非流 `tool.rs:377-392` 逻辑）。
- tool 判定：统一为“`function_call` + `custom_tool_call` 计 tool，`file_search/web_search` 计 tool（与非流一致）”，流式 `pump.rs:683-695` 改为计 tool；备选“全不计”会漏审检索调用，不采用。
- 超长行：截断至 16KB + 置 `truncated_line_dropped_bytes` 计数 + 记截断标记参与审计（不静默丢）。
- BOM：先 `strip_sse_bom` 再判 DONE/JSON（Python 语义），统一复用 `json_walk::strip_bom`（与 `veil-arch-hygiene-round4` R1 联动）。
- model：`record_chat` 加 `model` 参数（调用方透传上游值，截断 128+去控制字符沿用 Python 口径）；阻断体 model 回退上游值。
- 缓存：`usage.rs` 加 `cached_read/cached_write` 透出（`normalize_usage` 对齐 `_metrics.py:155`）。
- 低风险：`rewrite.rs` 注入即置 `x-veil-normalized`（行为不变，声明补齐）；空增量（无 function）不建条目只 warn；空 `data:` 帧丢弃不透传。

## Risks / Trade-offs

- [Risk] open-ended 回归让等成功终止的客户端 hung → Mitigation：与 Python 一致，属合规回归；E2E 断言 Hermes stub 路径。
- [Risk] file_search 计 tool 增加审计量 → Mitigation：与非流一致，误报优于漏审；release note 声明。

## Migration Plan

- 按 tasks 落地，与 P0 change 联合跑截断矩阵 + sentinel 回放；model/缓存列只加不改，旧大盘按 sum 会虚高需迁移须知；回滚 revert 本 change。
