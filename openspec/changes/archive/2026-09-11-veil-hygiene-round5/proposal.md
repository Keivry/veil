## Why

`veil-code-hygiene-closeout` 收口后，新一轮结构卫生复核（2026-09-11，死码/重复/尺寸/扩展性四面）确认 6 项发现（`D1`-`D6`）与 2 条非缺陷澄清（`C1`/`C2`）。`src/lib.rs:1-11` 以 `pub mod` 暴露全部模块，rustc `dead_code` lint 对 pub 可达项按公开 API 处理、不产生告警，故「`cargo clippy` 全绿」与「存在生产零引用 pub 项」并存（`D1`/`D2` 即此类）；因此死码收编 MUST NOT 依赖 lint，必须以降可见性/`#[cfg(test)]` gating + 单独编译验证，并同步测试 import。

- **`D1`（LOW，死码）`PiiScope::contains_request_token`**：`src/service/pii/scope.rs:269` 为 `pub fn`，生产零调用（全仓 grep 仅同文件），仅测试引用（`:391/395/403/424/454/650`）。要求降为 `#[cfg(test)] fn`（对齐 `PiiScope::next_available_index` 的既有处置，`scope.rs:121-129`）或 `pub(crate)`。
- **`D2`（LOW，死码）`CallerRegistry::migrate_python_registry`**：`src/registry/migrate.rs:41` 为 `pub fn`，生产零调用（`load_from` 为生产唯一加载入口），仅测试 `:644` 引用（含 `.bak` 备份断言）。要求移入 `#[cfg(test)]` 或 `examples/`。
- **`D3`（LOW，死码）`load_admin_token_file`**：`src/service/admin/events.rs:41` 生产零调用，仅测试 `:123-148`；经复核 HEAD 已含 `#[cfg(test)]` gating（`:37-45`），与 README §3「B1.2 token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变）」已同字。本项改为**验证锁定**（防回退），无代码改动；如 apply 时发现 gating 漂移则按 spec 恢复。
- **`D4`（Medium，重复分叉）掩码双引擎静默分叉**：`src/service/pii/detector.rs:189 mask_pii_value`（LLM 可见掩码）vs `src/service/metrics/sample.rs:142 sample_mask`（指标采样掩码）为两套六分支实现；经逐分支核对已分叉：bank 别名集（`bank_card|bankcard|id_card` vs `bank|bank_card`）、`apikey` 别名（detector 有 vs sample 无）、ipv4 非四段且 len≥8 回退（detector `short` vs sample 前4后4）、email 无点域名回退（detector `short` vs sample `***@***`）；phone 各长度边界（<2/2-5/6/≥7）经核对当前等价。消费方不同（给 LLM 的掩码 vs 指标采样）**不宜强合并**，要求差分测试锁定预期差异，并在 design.md 明确取舍。
- **`D5`（LOW，结构观察）700+ 行踩线文件**：`placeholder.rs(737)` / `env_parse.rs(720)` / `custom_file.rs(718)` / `spawn.rs(717)` / `audit/hold.rs(710)` / `pii/scope.rs(708)` 职责混合，但均低于 800 行红线。要求 design.md 记录「观察不强制拆」，仅在超过 800 行门禁时按既有模板（`file_len_under_800_or_split`）拆；不立强制拆分 task。
- **`D6`（LOW，扩展性）协议扩展非数据驱动**：`src/service/llm_gateway/protocol.rs:24 STRICT_TAILS` 是数据表，但新增第 4 协议仍需同步 8-12 处 `match`/判定（`usage.rs`/`tool.rs`/`sse/meta.rs`/`block_inject/frames.rs`/`placeholder.rs`/`handler/llm/mod.rs:48` 等）。要求 design.md 记录「暂不重构，补新增协议检查清单注释」，或作为可选项。
- **`D7`（LOW，可维护性）facade 全量 glob 重导出**：`src/config.rs`、`src/service/{pii,metrics,redaction,audit,matrix}.rs` 以 `pub use {a::*, b::*}` 全量重导出，子模块出现同名符号时易产生歧义导入。要求 design.md 记录为 LOW 观察项，可选改显式重导出或加 owner 注释（无强制实现）。
- **记录非缺陷（`C1`–`C4`，design.md 澄清）**：`env_parse.rs:189 credential_approval_timeout_secs` 生产有效（`src/service/credential/approval.rs:77` 读取用于阻塞审批超时），非死代码（`C1`）；`credential_vault.rs:63-64 snapshot_calls` 已 `#[cfg(test)]` gating，非问题（`C2`）；`src/service/audit/log.rs::sanitize_for_log` 与 `src/service/metrics/summarize.rs::redact_summary` 为文档化契约分治双引擎（不合并，`C3`）；`src/service/metrics/store.rs::wal_checkpoint_truncate` 为生产错误路径容错调用（非死码，`C4`）。四条登记以避免后续 change 误删/误合并。

真相源：`src/service/pii/scope.rs`、`src/registry.rs`、`src/service/admin/events.rs`、`src/service/pii/detector.rs`、`src/service/metrics/sample.rs`、`src/service/llm_gateway/protocol.rs`、`src/lib.rs:1-11`、README §3。本 change 只规划修复（proposal/design/spec/tasks），不改 `src/`。

## What Changes

- **`D1` 测试专用化**：`PiiScope::contains_request_token` 由 `pub fn` 降为 `#[cfg(test)] fn`（对齐 `next_available_index`；不选 `pub(crate)`，因测试全部在同文件 `mod tests`，且目标是「生产构建零引用」）；六处测试调用保持可编译、跨请求隔离与 LRU 淘汰断言不删。
- **`D2` 测试专用化**：`CallerRegistry::migrate_python_registry` 移入 `#[cfg(test)]`（不选 `examples/`，无独立运行需求且会新增构建目标）；`load_from` 新格式加载路径不动，Python 旧格式解析与 `.bak` 备份语义逐项保持，测试 `:644` 全绿。
- **`D3` 验证锁定（无代码改动）**：复核 `events.rs:37-45` 的 `#[cfg(test)]` gating 与 README §3 声明同字；补 grep + `cargo build --release` + `cargo test` 三重验证；如发现漂移按 spec Requirement 恢复 gating。
- **`D4` 差分测试锁定**：新增跨引擎差分测试（kind×value 矩阵），一致项断言相等、差异项断言具体允许输出并注释理由；差异清单至少覆盖 bank 别名集、`apikey` 别名、ipv4 非四段长值回退、email 无点域名回退，phone 边界等价由测试锁定；不抽 `mask_core`、不合并两实现、消费方既有输出零变更。
- **`D5` 记录 + 可选拆分**：design.md 记录六文件行数与「观察不强制拆」决策（标注 `placeholder`/`env_parse`/`custom_file` 已有红线看护，`spawn`/`hold`/`scope` 尚无）；可选 task 为后三者补 `file_len_under_800_or_split` 守护，不立强制拆分。
- **`D6` 记录 + 可选注释**：design.md 记录「暂不数据驱动重构」与需同步的 match 点清单；可选 task 在 `protocol.rs:24` 附近补「新增协议检查清单」注释，零行为影响。
- **`D7` 记录观察**：design.md 记录 facade 全量 glob 重导出的同名义歧义观察（`config.rs`/`pii.rs`/`metrics.rs`/`redaction.rs`/`audit.rs`/`matrix.rs`），可选显式化，无强制实现。
- **记录项落 design.md**：`C1`–`C4` 非缺陷澄清与证据行号；`D3` 已满足状态说明。

## Capabilities

### New Capabilities

- `hygiene-round5`：代码卫生第五轮契约——生产零引用的测试专用符号（`contains_request_token`/`migrate_python_registry`/`load_admin_token_file`）SHALL 以 `#[cfg(test)]` 或 `pub(crate)` 收编且测试保持可用；掩码双引擎（`mask_pii_value` vs `sample_mask`）差异 SHALL 由差分测试显式锁定、SHALL NOT 强合并；700+ 行文件为观察项、800 行红线门禁为拆分扳机；协议扩展暂不数据驱动重构并保留检查清单。

### Modified Capabilities

- 无。`openspec/specs/` 既有契约（`hygiene-round4`、`code-quality-cleanup` 等）的行为不动；本 change 新增 capability，README 与脱敏/指标口径均不改。

## 发现覆盖表（ID → 严重度 → 修复要点 → task）

| ID | 严重度 | 修复要点 | task |
|:---|:-------|:---------|:-----|
| `D1` | LOW（死码） | `scope.rs:269` `pub fn contains_request_token` 降为 `#[cfg(test)] fn`（对齐 `next_available_index`，`scope.rs:121-129`）；生产构建零引用、六处测试调用不受影响 | 1.1、1.2 |
| `D2` | LOW（死码） | `registry.rs:372` `pub fn migrate_python_registry` 移入 `#[cfg(test)]`（不选 `examples/`）；`load_from` 唯一入口与 `.bak` 语义不变，测试 `:644` 全绿 | 2.1、2.2 |
| `D3` | LOW（死码，已满足） | 复核 `events.rs:37-45` 已 `#[cfg(test)]` gating、README §3 同字；仅验证锁定 + 防回退，无代码改动（漂移时按 spec 恢复） | 3.1、3.2 |
| `D4` | MED（重复分叉） | 双引擎不合并；差分测试锁定差异清单（bank 别名/`apikey`/ipv4 非四段/email 无点域名 + phone 等价），消费方输出零变更 | 4.1、4.2、4.3 |
| `D5` | LOW（结构观察） | design 记录六文件行数（737/720/718/717/710/708）与「观察不强制拆」；仅越 800 行门禁时按模板拆（可选为三文件补守护） | 5.1、5.2 |
| `D6` | LOW（扩展性） | design 记录「暂不数据驱动重构」+ 需同步 match 点清单；可选补 `protocol.rs` 新增协议检查清单注释 | 6.1、6.2 |
| `C1` | 记录（非缺陷） | `credential_approval_timeout_secs` 生产有效（`env_parse.rs:189/362` 定义装配、`approval.rs:77` 读取），禁止当死码删除 | 7.1 |
| `C2` | 记录（非缺陷） | `credential_vault.rs:63-64 snapshot_calls` 已 `#[cfg(test)]` gating，非问题 | 7.2 |
| `D7` | LOW（可维护性） | facade 全量 glob `pub use {a::*, b::*}` 潜在同名歧义；记录观察、可选显式化（无强制实现） | 8.1 |
| `C3` | 记录（非缺陷） | 审计/指标脱敏双引擎为文档化契约分治（`sanitize_for_log` vs `redact_summary`），禁止合并 | 8.2 |
| `C4` | 记录（非缺陷） | `metrics/store.rs::wal_checkpoint_truncate` 非死码（错误路径容错调用），禁止当死码删除 | 8.3 |

## Non-Goals（显式）

- **不改 `src/` 与 README**：本 change 只交付规划 artifacts（proposal/design/spec/tasks），实现与测试改动留待 apply 阶段；不改 `openspec/changes/` 内任何既有文件、不改 `openspec/specs/` 既有 canonical spec；不提交 commit。
- **不合并掩码双引擎**：不抽公共 `mask_core`、不让 `mask_pii_value` 与 `sample_mask` 语义完全对齐——差异即设计（消费方不同），合并属行为变更，须另立 change 逐差异裁定。
- **不强制拆分 700+ 行文件**：仅记录观察；800 行红线为唯一拆分扳机，且拆分须按既有模板并保持 re-export 兼容。
- **不做协议数据驱动重构**：不新增第 4 协议、不改 `STRICT_TAILS` 形态；仅在 design 记录清单（可选补注释）。
- **不删除 `C1`/`C2` 两处**：`credential_approval_timeout_secs` 与 `snapshot_calls` 均为有效代码，仅登记澄清。
- **不放宽 fail-closed 语义**：脱敏/审计/审批/限流口径与阈值均不变。
- **与 `veil-runtime-robustness` 的叠加顺序**：`D2` 的 `migrate_python_registry` 与 runtime `B6`（registry 拆分）可能同区——无论先后，落点随拆分后形态（`src/registry/migrate.rs`），行号以 apply 时为准；`D1` 的 `pii/scope.rs` 可见性与 runtime `B3` 的锁中毒修复互不改语义（可见性归本 change、锁语义归 runtime），串行合入避免同函数双改。

## Impact

- **新增文件**：`openspec/changes/veil-hygiene-round5/` 下 `.openspec.yaml`、`proposal.md`、`design.md`、`specs/hygiene-round5/spec.md`、`tasks.md`。
- **apply 阶段改动面**：`src/service/pii/scope.rs`（D1 gating）、`src/registry.rs`（D2 gating）、跨引擎差分测试新文件（D4，建议落 `src/service/metrics/sample/tests.rs` 或新 `tests/` 文件）、可选 `src/service/llm_gateway/protocol.rs`（D6 注释）与三个红线守护测试（D5 可选）；`D3` 预期零代码改动。
- **影响系统**：pub 面死码可见性（生产构建零引用）、掩码双引擎可维护性（分叉显式化）、文件尺寸门禁覆盖、协议扩展 checklist。
- **依赖**：无新依赖；仅既有 `cargo fmt`/`clippy`/`test`/`cargo build --release` 与 OpenSpec CLI。
