## Context

See proposal.md Why. Current code: `nonstream.rs:110-114` 502/401 直接返回原始字节；`nonstream.rs:183-188` 还原后直接返回无校验回退、无 `strip_partials`；`block_inject.rs:269-290 NeedApproval` 同 Block 返回阻断体；`tool.rs:185-191` 内层优先 vs `pump.rs:832,844` 外层优先；`pump.rs:419-436` 逐帧即转发；`pump.rs:74-98` 信任配置值；`nonstream.rs:82-108` NonDialog 直接字节透传。

## Goals / Non-Goals

**Goals:**

- 非流任何状态码路径都有明确的用量/审计/还原语义（走全链或显式豁免+注释）。
- 流/非流 tool 分桶单实现、单优先级，冲突行为有单测锁定。
- 残缺 tool 永不透传下游；泵入口非法配置永不导致未定义行为。

**Non-Goals:**

- metrics 采样器修正（`veil-metrics-sampler-fix`）。
- Responses 起始事件/超长行/BOM/model 列（`veil-llm-protocol-parity`）。
- 胖文件拆分与循环依赖（`veil-arch-hygiene-round4`）。

## Decisions

- 502/401：走正常后处理链（usage+审计+还原），还原失败回退原文；若上游体非 JSON 则按 `classify_empty`  istniejący 规则转 502。备选“显式豁免+注释”仅当体为非对话/非 JSON 时采用。
- index 优先级：统一为**外层优先**（与 `pump.rs` 现状一致），`tool.rs` 改为外层优先；`clear_index` 按统一槽位清理。备选“内层优先”需同步改 pump，diff 更大不采用。
- TSS-03：`extract_tool_fragments` 累积至 `done` 才转发审计；截断时丢弃未 `done` 分片（chat/anthropic 不合成成功终止，见 `veil-llm-protocol-parity` C8 联动）。
- 钳位：`pii_boundary_chars < 1 → 64 默认并 warn`；`hold_max < 1 → 1MB 默认并 warn`；超 `8MB AUDIT_SUBLIMIT_CEILING` → 截断至上限并 warn。
- JSON 回退：还原后 `jloads` 双校验（原 Python `_nonstream_build` 语义），失败回退上游原文并 warn（预览 4000 字符）。
- approve：非流 `NeedApproval` 不再返回阻断体，改为记录 pending + 透传上游响应（与流式 B 案 `README 6.4` 一致）。
- NonDialog：默认保持透传（与 Python 同直通语义），但补 `GatewayMetrics.nondialog_passthrough` 计数 + README 声明；若 Python 实为还原则跟进补还原（先以计数验证流量）。

## Risks / Trade-offs

- [Risk] 502/401 走还原可能改写错误体 → Mitigation：错误体还原仅做凭据/PII 剥离（只删不增），JSON 校验失败回退原文。
- [Risk] 残缺丢弃让依赖残缺参数的调试客户端行为变化 → Mitigation：与 Python 一致，属合规回归；日志记 `truncated_tool_dropped` 计数。
- [Risk] 外层优先改变现有单测预期 → Mitigation：逐个更新冲突单测并新增交错 index 回归。

## Migration Plan

- 按 tasks 顺序落地，每组 `cargo test`；联动 `veil-llm-protocol-parity` 的 C8（空流合成）一起验证截断矩阵 E2E；回滚：revert 本 change 文件，无存储迁移。
