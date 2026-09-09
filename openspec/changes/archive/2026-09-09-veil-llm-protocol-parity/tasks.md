## 1. 终止与起始事件（C8/C9）

- [x] 1.1 空流合成改 open-ended（C8）：`pump.rs:536-565` 真空流（零残余）chat/anthropic 不合成成功终止；Responses 仍合成 failed；补真空流 E2E
- [x] 1.2 起始事件建槽（C9）：`pump.rs:1011-1013`/`tool.rs:357-359` `output_item.added` 保留 name/id 建槽，截断可审计；补起始截断漏审回归
- [x] 1.3 流式补 `custom_tool_call` 分支（C9）：复用非流逻辑，补覆盖单测

## 2. 判定一致与行处理（C10/C11/C12）

- [x] 2.1 tool 判定统一（C10）：`pump.rs:683-695` 改为与非流一致（`file_search/web_search` 计 tool），补流/非流同调用同结论单测
- [x] 2.2 超长行截断标记化（C11）：`sse.rs:203-211` 改丢弃为截断+`truncated_line_dropped_bytes` 计数+审计可见，补超长 tool 分片单测
- [x] 2.3 行内 BOM 先剥离再解析（C12）：复用 `json_walk::strip_bom`（与 hygiene R1 联动），补 BOM 帧单测

## 3. 可观测性列恢复（C13/C14）

- [x] 3.1 `record_chat` 恢复 model 分桶（C13）：截断128+去控制字符；阻断体 model 回退上游值（`block_inject.rs:217-223` 去字面 `blocked`）
- [x] 3.2 `usage.rs:17-51` 恢复 `cached_read/cached_write` 列（C14，对齐 `_metrics.py:155`），补缓存列单测

## 4. 低风险声明与对齐（L15/L16/L17/L18）

- [x] 4.1 `rewrite.rs:58-67` 注入即置 `x-veil-normalized` 头（L15，声明补齐，行为不变）
- [x] 4.2 空 tool 增量不建条目（L16）：`tool.rs:106-115` 改 warn 跳过，补空心跳单测
- [x] 4.3 空 `data:` 帧丢弃（L17）：`pump.rs:463-470` 改透传为丢弃
- [x] 4.4 README 补 usage max 迁移须知 + `file_search` 口径声明（L18）；全量门禁 `fmt/clippy/test` 全绿
