## Why

六维深度审查（2026-09-10）维度 3 发现：`openspec/specs/hygiene-round4/spec.md:19` 真源「No business file SHALL exceed 800 lines」被 8 个业务文件违反，且 `veil-review-followup-arch-hygiene`（A-D2）只覆盖 `sse.rs`/`block_inject.rs` 与 `env_parse`/`registry`/`custom_file` 三看护文件，**遗漏全部 8 个超线文件**；长度守卫 `file_len_under_800_or_split` 全仓仅 3 处（`env_parse.rs:506`/`registry.rs:485`/`custom_file.rs:368`），与「全仓红线」不匹配。

实测（总行 / 生产段 / 测试段）：

| 文件 | 总行 | 生产段 | 测试段 |
|---|---|---|---|
| `src/service/llm_gateway/placeholder.rs` | 1011 | 603 | 408 |
| `src/service/metrics/store.rs` | 929 | 521 | 408 |
| `src/service/llm_gateway/tool.rs` | 879 | 599 | 280 |
| `src/service/pii/detector.rs` | 849 | 565 | 284 |
| `src/service/metrics/aggregate.rs` | 833 | 451 | 382 |
| `src/service/pii/chunk.rs` | 806 | 705 | 101 |
| `src/service/metrics/sample.rs` | 806 | 361 | 445 |
| `src/handler/llm/nonstream.rs` | 804 | 255 | 549 |

（`nonstream.rs` 804 曾在 arch-docs 2.2 备案，但同样无守卫。）超线全部由测试段贡献，生产段最高 705（chunk）。

本 change 只做文件体量收口与守卫网补全：不搬生产符号、不改行为、不修改历史 change 文件。

## What Changes

- **S1 测试外迁 8 文件**：将各文件内联 `#[cfg(test)] mod tests` 迁出为同目录兄弟文件（如 `src/service/pii/chunk.rs` → 同目录 `chunk/tests.rs`，父文件保留 `#[cfg(test)] mod tests;`），主文件与测试文件双 ≤800；测试语义不变（`use super::*` 解析路径一致）。
- **S2 守卫补全**：新增 `scripts/check_file_sizes.py`（扫描 `src/**/*.rs`，任一 >800 非零退出，无白名单）；为 8 个曾超线文件补 `file_len_under_800_or_split` 守守卫单测（口径=文件总行含测试与注释，与 `env_parse.rs` 模板一致）；复核 3 个存量守卫保持。
- **S3 登记与验证**：`scripts/README.md` 增 `check_file_sizes.py` 条目；design 附录记录拆前/拆后实测表；四门禁全绿收口。

## Capabilities

### New Capabilities

- `arch-file-size-closeout`：8 文件收口与全仓守卫的可验证场景（全仓 0 超线、双文件 ≤800、测试全绿）。

### Modified Capabilities

- 无。行为零变更；`hygiene-round4` 真源不修改，只履行。

## Non-Goals（显式）

- 不搬生产符号、不改任何协议/PII/审计/指标语义。
- 不修改历史 change 文件（`veil-review-arch-docs`、`veil-review-followup-arch-hygiene` 的备案文本保持原样）。
- 不引入新依赖；不提交 commit。

## Impact

- **新增文件**：本目录文档；`scripts/check_file_sizes.py`；8 个 `*/tests.rs` 兄弟测试文件。
- **影响系统**：可维护性；测试组织变化，行为零变更。
- **顺序**：纯结构变更，建议先于 `veil-nonstream-audit-align`（同触 `nonstream.rs`）应用；同窗口时先 S1 后其逻辑改动。
- **依赖**：`cargo test` + `python3 scripts/check_file_sizes.py`。
