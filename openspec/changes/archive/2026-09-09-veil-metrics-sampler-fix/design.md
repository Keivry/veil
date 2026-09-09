## Context

See proposal.md Why. Current code (`metrics.rs:991-1119` 已复核): `pub fn sample_mask(value: &str)` 通用首***尾；`hash_value` 返回 `hex::encode` 完整 32 字节=64hex；无 64 截断；`sample()` 对 `value.is_empty()` 直接 `return None`；内存 `find(|v| v.hash == hash)` 与 SQL `ON CONFLICT(hash)` 均不含 kind。

## Goals / Non-Goals

**Goals:**

- 采样器与原仓 `mask_pii_value/hash` 逐项对齐，键变更可迁移。
- 32 项原测试语义全部有对应单测锁定。

**Non-Goals:**

- model/缓存列（`veil-llm-protocol-parity` C13/C14）。
- series 桶口径（`veil-test-parity-fill`）。

## Decisions

- kind 掩码表（原仓形态）：phone `138****8000`（前3后4）、email `***@***.com`、bank `**** **** **** 6789`（后4）、ipv4 `192.168.**.**`、api_key `abcd****1234`（前后各4）、other 通用首***尾。备选“保持通用”与规范不一致不采用。
- hash：`HMAC-SHA256(SALT)[:16]`，未设 key 退化 `SHA256[:16]` + warn（README 6.2 已有无盐警告，保持）。
- 64 截断：掩码生成后统一截断 64（UTF-8 边界保护，复用 `truncate_utf8`）。
- 空值：`sample(kind, "", _)` 返回 `('***', hash(""))` 并计数（原仓语义）。
- 复合键：内存 `find(|v| v.hash == hash && v.kind == kind)`；SQL 主键/ON CONFLICT 改 `(day, upstream, kind, hash)`；升级迁移：删除旧表重建（采样表可重建，7天滚动无须 backfill），启动日志声明。
- 签名变更：`sample_mask(value)` → `sample_mask(kind, value)`，调用方全量更新。

## Risks / Trade-offs

- [Risk] 签名变更波及调用方 → Mitigation：grep 全量更新 + 编译门禁。
- [Risk] 表重建丢失 7 天采样 → Mitigation：采样为趋势参考可重建；release note 声明。

## Migration Plan

- 按 tasks 落地，`cargo test` 锁定 32 项；升级：重建 `pii_value_samples` 表；回滚 revert 本 change（旧表需重建回单键，仅回滚时执行）。
