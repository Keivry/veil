## Context

`veil-code-hygiene-closeout`（已完成）与 `hygiene-round4` 收口后，新一轮结构卫生复核（2026-09-11）确认 6 项发现（`D1`-`D6`）与 2 条非缺陷澄清（`C1`/`C2`）。现状证据（只读复核，行号为当前 HEAD）：

- **lint 盲区**：`src/lib.rs:1-11` 将全部顶层模块以 `pub mod` 暴露，rustc `dead_code` lint 对 pub 可达项不告警；`D1`/`D2` 的生产零引用 pub 项与该盲区长期并存，故收编 MUST 依赖可见性变更 + 单独编译验证，而非 lint。
- **`D1`**：`src/service/pii/scope.rs:269-274` `pub fn contains_request_token`，全仓 grep 仅同文件命中：定义 `:269`，测试调用 `:391/395/403/424/454/650`，生产零调用。既有对齐样本：`PiiScope::next_available_index`（`scope.rs:119-129`）已以 `#[cfg(test)] fn` 收编。
- **`D2`**：`src/registry.rs:372` `pub fn migrate_python_registry`，生产零调用；`CallerRegistry::load_from`（`registry.rs:208-240`）为生产唯一加载入口（含新格式与 `integrity_of` 校验），测试仅 `:644`（断言 Python 旧格式解析与 `.bak` 备份）。
- **`D3`**：`src/service/admin/events.rs:37-45` `load_admin_token_file` **已含 `#[cfg(test)]` gating**（HEAD 已满足）；README §3「诚实声明：B1.2 token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变）」与代码同字。本项为审计快照过时项，处理方式为验证锁定。
- **`D4`**：`src/service/pii/detector.rs:189-269 mask_pii_value`（LLM 可见掩码，六分支）vs `src/service/metrics/sample.rs:142-228 sample_mask`（指标采样掩码，六分支）。逐分支核对后的**实际分叉清单**：
  1. bank 别名集：detector `bank_card | bankcard | id_card`（`:231`）vs sample `bank | bank_card`（`:188`）——sample 不识别 `bankcard`/`id_card`，detector 不识别 `bank`；
  2. `apikey` 别名：detector `ipv6 | api_key | apikey`（`:250`）vs sample `ipv6 | api_key`（`:206`）；
  3. ipv4 非四段且 len≥8：detector 走 `short`（前3后3，`:247`）vs sample 前4后4（`:200-202`）；apply 实测补充同族子例 6≤len<8：detector `short` 前3后3 vs sample 短值首末（已由 `tests/mask_engine_diff.rs` 锁定并入清单）；
  4. email 无点域名：detector 走 `short(value)`（`:229`）vs sample `***@***`（`:180`）；
  5. phone 各长度边界（<2 / 2-5 / 6 / ≥7）逐分支核对为**等价**（detector 的 `short` 闭合与 sample 的 `short()`/n==6 分支输出一致），以差分测试锁定该等价。
- **`D5`**：六文件行数由 `wc -l` 实测：`src/service/llm_gateway/placeholder.rs` 737、`src/config/env_parse.rs` 720、`src/config/custom_file.rs` 718、`src/handler/llm/pump/spawn.rs` 717、`src/service/audit/hold.rs` 710、`src/service/pii/scope.rs` 708；均 <800 红线。其中 `placeholder.rs`（守护在 `placeholder/tests.rs:2`）、`env_parse.rs`（`env_parse.rs:710`）、`custom_file.rs`（`custom_file.rs:370`）已有 `file_len_under_800_or_split` 看护；`spawn.rs`/`audit/hold.rs`/`pii/scope.rs` 尚无。
- **`D6`**：`src/service/llm_gateway/protocol.rs:24 STRICT_TAILS` 为识别数据表（3 项）；解除数据表之外，协议语义分支分散于多处 `match`/判定：`usage.rs`（11 处 `Protocol::Chat` 引用）、`tool.rs`、`sse/meta.rs:38`（`protocol != Protocol::Responses`）、`block_inject/frames.rs`、`placeholder.rs`（24 处）、`handler/llm/mod.rs::protocol_header_value`（`:48` 附近，4 臂）、`rewrite.rs`、`block_inject.rs` 等；新增第 4 协议预估需同步 8-12 处。
- **`C1`/`C2`（非缺陷）**：`credential_approval_timeout_secs` 定义/装配于 `config/env_parse.rs:189/362`、生产读取于 `service/credential/approval.rs:77`（`CREDENTIAL_BLOCK_WAIT` 阻塞审批超时）——有效配置；`credential_vault.rs:63-64 snapshot_calls` 已 `#[cfg(test)]`（X3/D4 复杂度回归观测）——非问题。

约束：本 change 只写规划 artifacts，不改 `src/`、README、既有 change 与既有 `openspec/specs/`；不放宽任何 fail-closed 语义；不合并掩码双引擎；不强制拆分文件；不提交 commit。

## Goals / Non-Goals

**Goals：**

- 使 `D1`/`D2` 的生产零引用符号退出 release 面（`#[cfg(test)]` gating），测试断言与消费方输出零变更，可用 `grep` + `cargo build --release` 证伪/证实。
- 使 `D3` 的「代码 gating ↔ README §3 声明」一致性被验证锁定，防止后续回退。
- 使 `D4` 双引擎的既有分叉从「静默」转为「显式」：差分测试锁定允许差异与等价项，任何新增未登记分叉导致测试失败。
- 记录 `D5`/`D6` 的观察与决策及 `C1`/`C2` 澄清，避免后续 change 误拆/误删/误重构。

**Non-Goals：**

- 不改两掩码引擎的语义（不抽 `mask_core`、不对齐别名与回退差异）。
- 不拆分 700+ 行文件；不数据驱动重构协议分支；不新增第 4 协议。
- 不改脱敏/审计/指标/审批口径；不改 README；不碰其他 change 文件。

## Decisions

### D1：`contains_request_token` 选 `#[cfg(test)]`，不选 `pub(crate)`

**决策**：把 `src/service/pii/scope.rs:269` 的 `pub fn contains_request_token` 降为 `#[cfg(test)] fn`（函数体不变），六处测试调用（`:391/395/403/424/454/650`）留在同文件 `mod tests` 内继续可用；函数 doc 注释补「仅测试口径」。

**理由**：生产零调用已被全仓 grep 证实；测试全部位于同文件 `mod tests`，`#[cfg(test)]` 即可满足可见性且使 release 构建完全不含该符号，对齐 `next_available_index`（`scope.rs:121-129`）的既有处置先例。`pub(crate)` 虽可消除 pub 面盲区，但符号仍进入 release 构建，不满足「生产构建零引用」的收编目标。

**备选**：
- `pub(crate)`：仍进 release 构建，仅缩小可见性，不采用（若未来出现同 crate 生产调用方，再评估）。
- 删除函数、测试改用公开接口：跨请求隔离与 LRU 淘汰断言依赖「token 是否在请求表」的直接查询，公开接口无等价能力，删除会降低断言强度，不采用。
- `#[allow(dead_code)]`：掩盖而非收编，违背 hygiene 零容忍口径，不采用。

### D2：`migrate_python_registry` 选 `#[cfg(test)]`，不选 `examples/`

**决策**：把 `src/registry.rs:372` 的 `migrate_python_registry` 整函数移入 `#[cfg(test)]`（或等价测试专用模块），测试 `:644` 保持；`load_from` 新格式加载路径（`registry.rs:208-240`）不动，Python 旧格式解析、`tracing::warn!` 迁移告警与 `.bak` 备份语义逐项保持。

**理由**：该函数无生产调用点，是「一次性迁移工具 + 回归测试载体」；`load_from` 已是生产唯一入口。`#[cfg(test)]` 与 `D1` 同口径、零新增构建目标，且 gating 后 `RegistryFile`/`integrity_of` 仍被 `load_from` 使用，不会产生 release unused import。

**备选**：
- 移入 `examples/`：examples 会新增构建目标与发布面维护成本，且无独立 CLI 使用需求（真实迁移应由运维一次性执行并以测试锁定），不采用。
- 保留 pub 并文档标注「兼容 API」：生产零调用仍占 pub 面，违背收编目标，不采用。
- 删除函数并删测试：丢失 Python `caller_registry.json` 旧格式回归保障，不采用。

### D3：`load_admin_token_file` 现状已满足——验证锁定，无代码改动

**决策**：复核确认 `events.rs:37-45` 已含 `#[cfg(test)]`，README §3 已声明「仅 `cfg(test)` 生效」，两者同字；本项不产生代码改动，仅以 grep + `cargo build --release` + `cargo test` 验证并登记防回退。若 apply 时发现 gating 缺失或 README 漂移，按 spec「admin token 文件加载测试专用化」恢复 gating/声明。

**理由**：审计快照将该项列为「要求加 gating」，但 HEAD 已由既有工作收编（`git show HEAD:src/service/admin/events.rs` 可见 `#[cfg(test)]` 紧邻定义）。如实记录「已满足」，避免为已达标项制造无意义 diff；同时保留 Requirement 作为防回退契约。

### D4：双引擎保留 + 差分测试锁定；拒绝强合并与 `mask_core`

**决策**：
- 保留 `mask_pii_value`（LLM 侧）与 `sample_mask`（指标侧）两实现，SHALL NOT 合并；
- 新增跨引擎差分测试：同一 `(kind, value)` 矩阵下，一致项断言相等、差异项断言各自的**具体允许输出**并以注释注明理由；
- 差异清单固化：bank 别名集、`apikey` 别名、ipv4 非四段 len≥8 回退、email 无点域名回退为**预期差异**；phone 各长度边界为**等价项**（差分测试锁定，若实测暴露差异则并入差异清单并注明，不改变消费方）；
- 两引擎既有单测保持全绿，消费方输出零变更。

**理由**：两实现的消费方语义不同——`mask_pii_value` 产出面向 LLM/上游可见的脱敏展示与 hold 文本，`sample_mask` 产出仅用于指标采样与落盘聚合；历史别名集与回退行为各自承载既有契约（如 sample 侧 `bank` 别名、detector 侧 `apikey`/`id_card`）。强合并必然改变至少一个消费方的输出，属行为变更，超出卫生轮范围。差分测试把「静默分叉」转为「显式允许清单」：新增未登记分叉会立即失败，且测试本身即差异文档。

**备选**：
- 抽公共 `mask_core` 由两处调用：需先裁定所有差异去留（bank/`apikey`/ipv4/email），任一裁定都会改变某个消费方输出；且两函数契约含 64 字符截断与空值语义的细微差别，合并重构面大于收益，不采用（如后续业务要求完全一致，另立 change 逐差异裁定）。
- 删除一方改为调用另一方：同强合并，不采用。
- 仅补注释不测试：注释无法防漂移，不采用。

### D5：700+ 行文件「观察不强制拆」，800 行为唯一扳机

**决策**：在 design 记录六文件实测行数与职责混合观察（`placeholder.rs` 737、`env_parse.rs` 720、`custom_file.rs` 718、`spawn.rs` 717、`audit/hold.rs` 710、`pii/scope.rs` 708），均为 <800；不立强制拆分 task。仅当任一文件超过 800 行红线时，按既有 `file_len_under_800_or_split` 模板拆分并保持 re-export 兼容。可选：为尚无看护的 `spawn.rs`/`audit/hold.rs`/`pii/scope.rs` 补守护测试（若 apply 阶段任务预算允许）。

**apply 复核（2026-09-11）**：`veil-runtime-robustness` B1/B3 增测试行后，apply 实测 `spawn.rs` 772、`pii/scope.rs` 760（含本 change D1 gating +3 行）；其余四项维持 `placeholder.rs` 737、`env_parse.rs` 720、`custom_file.rs` 718、`audit/hold.rs` 710；六文件仍全部 <800。`spawn`/`hold`/`scope` 的 `file_len_under_800_or_split` 守护由 task 5.2 补足（N/A 三项自此有看护）。

**理由**：行数是职责混合的弱信号；六文件均在红线内且承担高耦合业务（掩码扫描/泵/审计 hold/scope 容器），为行数而拆会扩大 diff 与回归面。既有红线看护（3/6 文件）已提供扳机，本 change 以记录 + 可选守护补足覆盖，符合「观察不强制拆」的卫生口径。

**备选**：
- 强制拆到 500 行/单一职责：无既有契约要求，且拆分动机不足，不采用。
- 完全不记录：后续审查会重复发现，不采用。

### D6：协议扩展暂不数据驱动重构，保留检查清单

**决策**：不重构 `STRICT_TAILS` 之外的协议分支；在 design 记录需同步的 match 点清单（`usage.rs`/`tool.rs`/`sse/meta.rs`/`block_inject/frames.rs`/`placeholder.rs`/`handler/llm/mod.rs::protocol_header_value`/`rewrite.rs`/`block_inject.rs` 等，新增协议预估 8-12 处）；可选在 `protocol.rs:24` `STRICT_TAILS` 附近补「新增协议检查清单」注释（列出这些同步点），零行为影响。

**理由**：四态（含 `NonDialog`）protocol 枚举稳定，数据驱动重构需引入 trait/表驱动分发，触达流/非流/终止帧/注入/header 全部热路径，风险大于「改 8-12 处 match」的现状成本；而清单注释能把隐性知识显式化，供未来第 4 协议 change 使用。

**备选**：
- 立即数据驱动重构：跨多模块行为保持重构，收益未验证，不采用（另立 change）。
- 仅口头记录：清单易失，不采用（至少落 design，注释可选）。

### D7：非缺陷澄清（`C1`/`C2`）登记

- **`C1` `credential_approval_timeout_secs` 生产有效，非死码**：定义/装配于 `src/config/env_parse.rs:189` 与 `:362`，生产读取于 `src/service/credential/approval.rs:77`（`CREDENTIAL_BLOCK_WAIT` 阻塞审批的 `Duration` 超时）。grep 同时命中定义与使用点，禁止当死码删除（任何死码清理 SHALL NOT 删除该字段）。
- **`C2` `snapshot_calls` 已 `#[cfg(test)]` gating，非问题**：`src/service/credential_vault.rs:63-64` 的 `snapshot_calls: AtomicUsize` 已由 `#[cfg(test)]` 收编，仅服务于 `X3/D4` 复杂度回归观测；生产构建不含该字段，无需处理。

- **`C3` 脱敏双引擎契约分治（非缺陷）**：`src/service/audit/log.rs::sanitize_for_log`（审计 JSONL 单行、全剥控制字符）与 `src/service/metrics/summarize.rs::redact_summary`（指标摘要、保留 `\t\n`、`[REDACTED:*]` 词表）输出契约不同，双方注释已互引声明「契约分治、不合并」；强合并会改变可观测面，SHALL NOT 合并（后续如要求统一，另立 change 裁定）。
- **`C4` `wal_checkpoint_truncate` 非死码（非缺陷）**：`src/service/metrics/store.rs::wal_checkpoint_truncate` 在 SQLite 错误路径（`:425` 附近）容错调用，并有单测覆盖，属有效维护代码，禁止当死码删除。

四条登记入 proposal 覆盖表（`C1`–`C4`）并在 tasks 第 7/8 节以 grep 证据验证，防止后续 change 误删/误合并。

### D8：facade 全量 glob 重导出为观察项（`D7`）

**决策**：登记 facade 层 `pub use {a::*, b::*}` 全量 glob（`src/config.rs`、`src/service/{pii,metrics,redaction,audit,matrix}.rs`）在同名符号出现时可能产生歧义导入的风险，作为 LOW 可维护性观察项；不强制实现，可选改为显式重导出或在注释中锚定 owner。

**理由**：当前各子模块无同名公共符号，实际无编译冲突；glob 实现路径稳定性收益（保持旧 Python 镜像路径可解析），风险为将来新增同名项时的隐式歧义。属「记录 + 可选」级别，与 `runtime-robustness` B6 的「re-export 保持公开路径兼容」互补而非重复（B6 管 registry 门面拆分，本项管既有 facade glob 形态）。

**备选**：立即全量改显式重导出——触达多个 facade 文件、收益未验证，且会改变 `pub use` 形态，不采用（如需另立 change）；仅口头记录不落 design——易失，不采用。

## Risks / Trade-offs

- [`D1`/`D2` gating 误伤测试可见性] → 测试均在同文件/同 crate 的 `mod tests` 内，`#[cfg(test)]` 可见；以 `cargo test -p veil` 全绿验证。
- [`D2` gating 触发 release unused import 告警] → `RegistryFile`/`integrity_of` 仍被 `load_from` 使用；以 `cargo build --release` 零告警验证。
- [`D4` 差分测试把有意差异误判为失败] → 差异项用显式允许输出断言 + 理由注释；等价项才断言相等；禁止「宽泛不等断言」。
- [`D4` phone 等价结论被测试推翻] → 以差分测试实测为准：若暴露差异，并入差异清单并锁死，仍不改变消费方（本 change 不改语义）。
- [`D5` 记录后长期不拆，最终越线] → 800 行既有看护为扳机；可选 task 为三无看护文件补守护，越线即失败并指向拆分。
- [`D6` 清单注释与代码漂移] → 注释指向清单为「最低覆盖」；新增协议 change 仍须全量 grep 复查，注释不替代审查。
- [`D3` 视为已满足漏掉真实漂移] → Requirement 保留「生产构建零引用/README 同字」契约；apply 验证如发现漂移立即恢复 gating 并按失败处理。

## Migration Plan

1. `D1`/`D2` 逐项 gating，每项单独 `cargo build --release` + `cargo test`（禁止两项一起改后一次性编译，lint 盲区下逐项验证是唯一可靠捕获手段）。
2. `D4` 新增差分测试并跑通（新增测试文件，不动两引擎实现）。
3. `D3` 验证锁定（grep/README 对照/release 构建）。
4. `D5`/`D6` 记录（可选：三文件红线守护、`protocol.rs` 清单注释），每步 `cargo test` 全绿。
5. 全量门禁：`cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、`cargo build --release`（零 dead_code/unused 告警）、`openspec validate veil-hygiene-round5 --strict`。
6. 回滚策略：按节 revert 对应 diff；无 schema/数据迁移、无新依赖、无部署形态变化。

## Open Questions

- 无阻塞项。`D4` 的 phone 等价结论以差分测试实测为准（若推翻则并入差异清单）；`D5`/`D6` 的可选 task（红线守护/清单注释）由 apply 阶段按预算决定，若不做须在归档说明中记录「未做理由」，不改变 spec 契约。
