## 1. 采样器 5 项修正（M1/M2/M3/M4/M5）

- [x] 1.1 `sample_mask` 加 `kind` 参数并按 kind 分掩码（M1：phone/email/bank/ipv4/api_key/other），更新全部调用方
- [x] 1.2 `hash_value` 截断 `[:16]`（M2：HMAC/退化 SHA256 同），补 16hex 单测
- [x] 1.3 掩码 64 截断（M3：UTF-8 边界保护），补长 email 单测（`len(mask) <= 64`）
- [x] 1.4 空值语义对齐（M4）：空串返回 `***` 并计数（非 `None`），补空值单测
- [x] 1.5 复合键（M5）：内存去重 + SQL `ON CONFLICT(day,upstream,kind,hash)` + 表重建迁移，补跨 kind 同明文不覆盖单测

## 2. 32 项回补（T10）

- [x] 2.1 掩码分 kind / Top5 / HMAC 有 key/无 key 退化 warn / 非对话不采样 / 开关 / 并发隔离单测（对齐原 `observability_pii_value` 18 + `pii_value_samples` 14）
- [x] 2.2 全量门禁：`cargo fmt --check` + `clippy --tests -- -D warnings` + `cargo test` 全绿
