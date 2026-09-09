## Why

文档审查发现 P0 级路径过期：`README.md:295` 写 `src/service/llm_gateway.rs::HOP_HEADERS` 而文件已拆为 `llm_gateway/hop.rs:7`（已复核旧文件不存在）；5 个 proposal + `rust-rewrite-veil/tasks` 同类过期引用；`src/handler.rs`/`src/handler/llm.rs`（实际为 `handler/llm/mod+pump+nonstream+rewrite`）。另 2 个隐藏配置（`CREDENTIAL_BLOCK_WAIT`/`PII_GLOBAL_PERSIST`）代码存在但 env 全表无行；`x-veil-normalized` 注入即声明缺失；usage max 迁移须知分散；NonDialog/调试落盘/Go 未闭环/入口语义无决策记录。<!-- doc-paths-ignore -->

## What Changes

- 批量替换过期路径：README + 5 proposal + `rust-rewrite-veil/tasks` 的 `llm_gateway.rs`→`llm_gateway/`、`handler.rs`→`handler/llm/mod.rs` 等，附路径校验脚本（CI 断言引用路径存在）。<!-- doc-paths-ignore -->
- env 全表补行或删代码二选一：`CREDENTIAL_BLOCK_WAIT`/`PII_GLOBAL_PERSIST`（与 hygiene D1/D2 联动：留则补行，删则本 change 只补校验）。
- 补声明：`x-veil-normalized` 语义、usage max 迁移、`file_search` 口径（与 protocol-parity 联动）、NonDialog 透传语义（与 P0 F1 联动）。
- 补决策记录：调试落盘缺失（日志代替的排障指引）、Go 未闭环清单（`veil-hardening 5.x` 承接）、入口三态语义（`approve→block` 降级、`_ask` 自动批准）。
- 阈值表零漂移校验：README 第 4 节与 `admin-ratelimit-contract` spec 同字断言。

## Capabilities

### New Capabilities

- `contract-docs`: 路径校验脚本 + env 全表完整性 + 遗留决策记录（NonDialog/落盘/Go/入口）。

### Modified Capabilities

- `docs-contract-alignment`：README 路径/声明增补（只加不改行为）。

## Impact

- 只改 `README.md`、5 个历史 proposal（注明勘误不改语义）、`rust-rewrite-veil/tasks.md` 路径注释 + 新增 `scripts/check_doc_paths.py`。
- 历史 proposal 修路径属于勘误，不改变已 archive change 的语义结论。
- 与 hygiene/protocol-parity/P0 联动：隐藏配置去留、model/缓存列、空流规则的文档侧落点在本 change。
