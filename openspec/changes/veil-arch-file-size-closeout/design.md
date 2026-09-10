## Context

真源：`openspec/specs/hygiene-round4/spec.md:19`「No business file SHALL exceed 800 lines; splits SHALL re-export legacy paths」。口径先例：`env_parse.rs:505-515` 守卫注释「口径=文件总行，含测试与注释」，且 `veil-review-followup-arch-hygiene` 以含测试总行（`sse.rs` 884）判定超线——本 change 沿用同口径。8 文件超线中仅 `nonstream.rs` 804 在 arch-docs 2.2 有备案文本，其余 7 文件从未被登记；全仓守卫仅 3 处。

## Goals / Non-Goals

**Goals：** `src/**/*.rs` 单文件（含测试文件）≤800；全仓守卫可执行（脚本 + 单测双锁）；主文件与测试文件双 ≤800；测试语义与数量不减少。

**Non-Goals：** 不重排生产符号、不改 `hygiene-round4` 真源、不动历史备案文件、不加新依赖。

## Decisions

### D1：测试外迁优先于生产拆分

决策：内联 `#[cfg(test)] mod tests` 迁出至兄弟文件（`<file>/tests.rs`），不按 `sse.rs` 模板抽生产子模块。

理由：8 文件生产段均 ≤705（`chunk.rs` 最高），超线全部由测试段贡献；外迁风险最低、语义零变（Rust 2018 file-module + 同名目录映射，`use super::*` 解析到父模块不变）、双文件可同时达标。

备选：生产子模块拆分（`chunk.rs` 705 逼近线、需动调用方与重导出）风险高，不采用。

### D2：守卫三件套（脚本 + 就地单测 + 文档条）

决策：
1. `scripts/check_file_sizes.py`：扫描 `src/**/*.rs`，>800 非零退出并列出文件与行数；**无白名单**（全仓强制）。
2. 8 文件各补 `file_len_under_800_or_split` 单测（主文件与 tests.rs 双断言）。
3. `scripts/README.md` 增脚本文档条目。

理由：单测只覆盖被登记文件，脚本防新增文件漏网；两者互补，且与既有 `check_doc_paths.py` 门禁形态一致。

备选：仅单测（新增文件漏网）或仅脚本（就近定位弱），均不采用。

### D3：守卫文件归位与外迁后 `include_str!` 相对路径

决策：守卫单测统一放外迁后的 `tests.rs`，双断言：

- 主文件：`include_str!("../<name>.rs")`（相对 `tests.rs` 所在目录）；
- 测试文件：`include_str!("<name>_tests.rs")` 或 `include_str!("tests.rs")`（按实际文件名）。

目录层级按实际路径书写（如 `detector/tests.rs` 以 `include_str!("../detector.rs")` 计主文件）。失败消息须含文件名、实测行数、指向拆分任务。

理由：避免自计循环与相对路径陷阱；就近失败，触发条件明确。

### D4：与既有守卫和备案的衔接

决策：存量 3 守卫（`env_parse`/`registry`/`custom_file`）保持原样不动；历史备案文本（arch-docs 2.2、followup H1/H2.1）不改写，本 change 的 S3.2 附录记录收口结果，形成「历史备案 → 本 change 闭环」链条。

## Risks / Trade-offs

- 外迁后模块路径错误会造成编译失败（`#[cfg(test)] mod tests;` 未找到文件）。缓解：逐文件 `cargo test <module>` 验证。
- 行数硬断言在后续功能增行时失败属预期（触发拆分），失败消息须指向本 change 与 `hygiene-round4` 真源。
- 8 文件同窗口大改测试组织，diff 较大但纯移动；建议独立 commit，先于 `veil-nonstream-audit-align`。

## 附录 A：拆前/拆后实测行数（S3.2）

口径：`wc -l`（与 `scripts/check_file_sizes.py` 的 `splitlines()` 及就地守卫 `lines().count()` 一致）。
「拆后主文件」= 生产段 + `#[cfg(test)] mod tests;`；「拆后测试文件」= 外迁 `<stem>/tests.rs`（含就地守卫，已过 `cargo fmt`）。

| 文件（拆前） | 拆前总行 | 拆后主文件 | 拆后测试文件 |
|---|---:|---:|---:|
| `src/service/llm_gateway/placeholder.rs` | 1011 | 744 | 284 |
| `src/service/metrics/store.rs` | 929 | 523 | 423 |
| `src/service/llm_gateway/tool.rs` | 879 | 601 | 295 |
| `src/service/pii/detector.rs` | 849 | 567 | 296 |
| `src/service/metrics/aggregate.rs` | 833 | 453 | 389 |
| `src/service/pii/chunk.rs` | 806 | 451 | 368 |
| `src/service/metrics/sample.rs` | 806 | 363 | 458 |
| `src/handler/llm/nonstream.rs` | 804 | 257 | 563 |

拆后 16 文件全部 ≤800；`python3 scripts/check_file_sizes.py` 全仓 88 个 `src/**/*.rs` 退出码 0；
`cargo test file_len_under_800` 11 处（3 存量 + 8 新增）全过。存量三守卫
（`src/config/env_parse.rs` / `src/registry.rs` / `src/config/custom_file.rs`）diff 为空、未改写。
