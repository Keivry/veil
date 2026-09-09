## Why

系统性审查抽查 `service/metrics.rs:991-1119`（已复核源码实锤）发现 PII 值采样器 5 项逻辑偏离原仓 `_pii.py mask_pii_value` / `_pii_value_hash` 规范：`sample_mask` 丢 `kind` 致全部分类同掩码；`hash_value` 返回 64hex 未截断 `[:16]` 致去重/落盘/展示键错位；缺 64 截断致长 email 溢出；空值直接 `None` 不计数致空 PII 统计消失；去重与 SQL `ON CONFLICT(hash)` 均不含 `kind` 致跨 kind 互相覆盖。同时原 `observability_pii_value` 18 + `pii_value_samples` 14 项几乎全缺。若不修复，前端 hover 下钻、TopN、7天落盘全错。

## What Changes

- `sample_mask` 加 `kind` 参数，按 kind 分掩码（phone/email/bank/ipv4/api_key/other，原仓形态）。
- `hash_value` 截断 `[:16]`（HMAC-SHA256 hex 前 16 字符；无 key 退化 SHA256 同样截断）。
- 掩码 64 截断（`len(mask) <= 64`）。
- 空值语义对齐原仓：`mask('other','') == '***'`，空 PII 计入采样。
- 去重键与落盘主键改为复合键 `(day,upstream,kind,hash)`（内存 `find` + SQL `ON CONFLICT` 同改），迁移存量表（重建或 backfill）。
- 回补 `observability_pii_value` + `pii_value_samples` 32 项对应单测（掩码分kind/Top5/HMAC/非对话不采样/64上限/开关/hash16hex/并发隔离）。

## Capabilities

### New Capabilities

- `sampler-correctness`: 值采样掩码/hash/截断/空值/复合键正确性 + 32 项回补测试。

### Modified Capabilities

- `observability-compat`：落盘键由 `hash` 改为复合键（需迁移说明）。

## Impact

- 影响 `src/service/metrics.rs`（采样器 + SQL schema + 聚合）、前端 hover/TopN 展示。
- **BREAKING**：落盘主键变更（旧表按单 `hash` 去重，升级需重建 `pii_value_samples` 表或按新键 backfill）；hash 由 64 改 16，旧键失效需重算。
- 不碰网关泵/审计判定（P0/P1 changes）。
