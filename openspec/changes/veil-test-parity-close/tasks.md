## 1. 截断矩阵（D1，e2e）

- [x] 1.1 TSS01 完整残余静默丢弃 + TSS02 文本中截断开环（Chat）
  - Verify: `tests/http_e2e_truncation_matrix.rs` 存在且 TSS01 不合成任何成功终端帧
  - Verify: TSS02 保留已收分片且以开环语义闭合（无伪造 `DONE` 载荷）
  - Verify: conformance 20/20 保持
- [x] 1.2 TSS03 tool_calls 中截断丢弃 + 真实 toolcalls 无伪造
  - Verify: 参数不全的 tool 整把丢弃，不含 `"status":"completed"` 伪造
  - Verify: 真实 toolcalls 载荷 fixture 已脱敏（含多 index 聚合形态）
- [x] 1.3 TSS04 Responses 合成 `failed` + 真实 reasoning 开环
  - Verify: 截断合成帧含 `response.failed` 且不含 `response.completed`
  - Verify: Anthropic 截断走 `message_stop` 正常闭合（不断言 failed 合成）

## 2. SDK 回放（D2，单测为主）

- [x] 2.1 thinking 签名单帧 + `display:omitted` 空块 + `redacted_thinking` 透传
  - Verify: `tests/sentinel_sdk_replay.rs` 存在，`signature_delta` 单帧块字节一致
  - Verify: `redacted_thinking.data` 未被 PII/审计改写
- [x] 2.2 `tool_use.input` 跨帧累积提交 + `fallback` 无 delta + `stop_sequence` 回显
  - Verify: 中途分片不可 parse，仅 `content_block_stop` 后提交可 parse
  - Verify: `fallback` 块 start+stop 无 delta 不误判未完成
- [x] 2.3 `CR-only` 快慢双路径 + `error(overloaded)` 插帧 + 未知 event 跳过 + `ping` 忽略
  - Verify: CR 切分与 LF 切分还原字节一致
  - Verify: `error` 插帧后流中断且审计记账（非挂起）
- [x] 2.4 `usage` 累计覆盖 + 清单登记（12 项逐项 移植|豁免）
  - Verify: `message_delta usage` 为覆盖而非累加（递减用例见 gateway change 实现，此处验收）
  - Verify: 清单 12 项每项标注移植位置或豁免理由，无第三状态

## 3. 流泵边界（D3）

- [x] 3.1 重试 + `n2` 隔离 + 多 `data:` + `retry:` 非法
  - Verify: 仅 connect/timeout 重试 3 次（500/1000/2000ms 退避），业务 4xx/5xx 体不重试
  - Verify: `choices index:1` 帧不广播污染 index:0 累积
  - Verify: 多 `data:` 行按 `\n` 拼接，非数字 `retry:` 被忽略
- [x] 3.2 `refusal` 重组 + BOM+comment + 三片段单 flush + flush 失败不双还原
  - Verify: `refusal` 分片重组后单次还原，幂等哨兵有效
  - Verify: BOM 单次剥离，comment 帧透传不计事件
- [x] 3.3 hold 溢出/abort/竞态/早断清理 + deny 转发 + `done` 回退
  - Verify: hold 超 `AUDIT_HOLD_MAX_BYTES` 注入阻断且不泄漏原文
  - Verify: 中途 abort 与超时 vs 断连竞态均为 fail-closed 且无挂起
  - Verify: deny 后已收 content 按策略转发或丢弃有断言，`done` 回退审计有单测

## 4. 凭据与可观测（D4）

- [x] 4.1 解锁超时/并发单 ask/三文案/双删/分支
  - Verify: 解锁 300s 超时后 pending 置 rejected 且无死锁
  - Verify: 并发双解锁仅一次 Matrix ask（计数器断言）
  - Verify: 已注册/未注册/终端直调三文案各有断言，清理双删幂等
- [x] 4.2 SSE 计数 + 过滤 + `series` 四窗 + 归一 + 跨日/近似 + ENOSPC
  - Verify: `sse_event_count` 与 `hop_filtered_total{dir}` 可查且剥离即计数
  - Verify: `series?granularity=daily|hourly|five_min` 四窗映射与 `since+protocol` 过滤有断言
  - Verify: 旧 `model/upstream` 过滤返回全局 + 弃用标注，`verdict` 归一全别名通过
  - Verify: ENOSPC 降级内存-only 后 `sqlite_ok=false` 且计数不丢（单测 mock）
- [x] 4.3 `admin.html` Non-Goal 重申（文档标注，无测试）
  - Verify: README 与 spec `NON_GOAL` 三处同字
  - Verify: `GET /_admin/` 返回 JSON 索引占位不断言 HTML

## 5. 性能锚与并发（D5）

- [x] 5.1 审计链 + 字典 5000 + 增量扫描耗时锚
  - Verify: 三锚各有耗时上界断言（字典防 13.8ms 爆炸回归线）
  - Verify: CI 慢机波动下锚为宽松上界（不 flakes）
- [x] 5.2 PII `Scope` 并发隔离 + `BoundaryHold` 组合 fuzz
  - Verify: 并发注册互不可见（请求隔离断言，替代 ContextVar 等价）
  - Verify: fuzz 覆盖占位符残片 × 信封分隔 × 多 `data:` 组合，JSON roundtrip 不破坏

## 6. BREAKING 验收（D6，二选一签字）

- [x] 6.1 六组验收：默认开 / 采样双开关 / LRU / pending / 401 迁移 / HOP 逐头 / legacy warn / MockTPM
  - Verify: 每组有迁移测试或 spec `ACCEPTED RISK` 签字，无遗漏项
  - Verify: `DEBUG_DIR` 无落盘为显式豁免（与 README §7.4 同字）
  - Verify: 全量 `cargo test` + conformance 20/20 通过
