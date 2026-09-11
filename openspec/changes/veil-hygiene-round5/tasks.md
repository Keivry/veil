## 1. `D1` `PiiScope::contains_request_token` 测试专用化

- [x] 1.1 `src/service/pii/scope.rs:269`：将 `pub fn contains_request_token` 降为 `#[cfg(test)] fn`（函数体不变；doc 注释补「仅测试口径」），对齐 `PiiScope::next_available_index`（`scope.rs:121-129`）的既有处置；不选 `pub(crate)`（仍进 release 构建，不满足生产零引用）
    - Verify: `grep -rn "pub fn contains_request_token" src/` 零命中；`grep -n -B1 "fn contains_request_token" src/service/pii/scope.rs` 命中 `#[cfg(test)]` 前置行
    - Verify: `cargo build --release` 退出码 0 且无 `dead_code`/unused 告警
- [x] 1.2 保持六处测试调用（`scope.rs:391/395/403/424/454/650`）在 `#[cfg(test)]` 下编译运行；跨请求还原隔离与 LRU 淘汰断言不得删除或弱化
    - Verify: `cargo test -p veil pii` 全绿（含跨请求隔离与淘汰用例）
    - Verify: `grep -c "contains_request_token" src/service/pii/scope.rs` 为 7（1 定义 + 6 测试调用），且调用全部位于 `mod tests` 内

## 2. `D2` `CallerRegistry::migrate_python_registry` 测试专用化

- [x] 2.1 `src/registry.rs:372`：将 `migrate_python_registry` 移入 `#[cfg(test)]`（或等价测试专用模块），不选 `examples/`（无独立运行需求且新增构建目标）；确认 `load_from`（`registry.rs:208-240`）仍为生产唯一加载入口；若 change `veil-runtime-robustness` 的 B6 已先落地模块拆分，则以 `src/registry/migrate.rs` 为落点、行号以拆分后为准（避免引用失效）
    - Verify: `grep -rn "pub fn migrate_python_registry" src/` 零命中；`grep -n "fn migrate_python_registry" src/registry.rs` 仅测试可见定义
    - Verify: `cargo build --release` 零告警（`RegistryFile`/`integrity_of` 仍被 `load_from` 使用，无 unused import）
- [x] 2.2 保持迁移语义测试（`registry.rs:644`）：Python 旧格式（`version/callers/allowed_entries`）解析、字段映射、`.bak` 备份断言全绿
    - Verify: `cargo test -p veil registry` 全绿；Python 旧格式用例与 `.bak` 断言未被删改
    - Verify: `grep -c "migrate_python_registry" src/registry.rs` 为 2（gated 定义 + 测试调用），无生产调用点

## 3. `D3` `load_admin_token_file` gating 验证锁定（预期零代码改动）

- [x] 3.1 复核 `src/service/admin/events.rs:37-45`：确认 `#[cfg(test)]` gating 已在位（HEAD 已满足）；如 apply 时发现 gating 缺失/漂移，按 spec「admin token 文件加载测试专用化」恢复
    - Verify: `grep -n -B1 "pub fn load_admin_token_file" src/service/admin/events.rs` 上一行为 `#[cfg(test)]`
    - Verify: `cargo build --release` 无 `load_admin_token_file` 符号与告警；`cargo test -p veil admin_token_file` 全绿
- [x] 3.2 对照 README §3「B1.2 token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变）」与代码 gating，登记防回退证据（无新增运行时测试）
    - Verify: `grep -n "B1.2 token 文件加载仅" README.md` 命中且表述含 `cfg(test)`，与 `events.rs` gating 同字
    - Verify: 漂移分支演练：临时移除 `#[cfg(test)]` 后 `cargo build --release` 出现该符号（验证后还原，确认守护有效）

## 4. `D4` 掩码双引擎差异锁定（差分测试）

- [x] 4.1 新增跨引擎差分测试（建议落 `src/service/metrics/sample/tests.rs` 或新 `tests/` 文件）：对 `pii::detector::mask_pii_value` 与 `metrics::sample::sample_mask` 建 kind×value 矩阵，一致项断言相等、差异项断言各自具体允许输出并注释理由
    - Verify: `cargo test -p veil mask_engine` 全绿；矩阵覆盖 phone/email/bank/bankcard/id_card/ipv4/ipv6/api_key/apikey/other × 空值/短值(2-5)/边界(6/7/8)/非四段/无点域名/超长(>64)
    - Verify: 变异演练——临时改任一引擎一个分支（如 sample bank 别名）后差分测试失败（验证后还原），确认新增分叉必被捕获
- [x] 4.2 差异清单固化并保持消费方输出零变更：bank 别名集、`apikey` 别名、ipv4 非四段 len≥8 回退、email 无点域名回退为预期差异；phone 各长度边界（<2/2-5/6/≥7）等价由测试锁定（如实测有差异以测试为准并入清单）
    - Verify: `grep -n "bankcard\|apikey\|非四段\|无点域名" openspec/changes/veil-hygiene-round5/design.md` 命中四类差异记录
    - Verify: `cargo test -p veil detector` 与 `cargo test -p veil sample` 全绿（两引擎实现未改，既有输出逐项不变）
- [x] 4.3 不合并决策可追溯：design D4 记录拒绝抽公共 `mask_core` 的取舍与理由；本项为记录型，无实现改动
    - Verify: `grep -n "mask_core" openspec/changes/veil-hygiene-round5/design.md` 命中「不采用」理由
    - Verify: apply 阶段 `git diff --stat` 不含 `src/service/pii/detector.rs`、`src/service/metrics/sample.rs` 的语义改动（仅新增测试文件）

## 5. `D5` 700+ 行文件观察记录（不强制拆）

- [x] 5.1 design.md 记录六文件实测行数与「观察不强制拆」决策：`placeholder.rs(737)`/`env_parse.rs(720)`/`custom_file.rs(718)`/`spawn.rs(717)`/`audit/hold.rs(710)`/`pii/scope.rs(708)`，并标注 `placeholder`/`env_parse`/`custom_file` 已有红线看护、`spawn`/`hold`/`scope` 尚无
    - Verify: `grep -n "737\|720\|718\|717\|710\|708" openspec/changes/veil-hygiene-round5/design.md` 命中六个行数与文件对应
    - Verify: `wc -l src/service/llm_gateway/placeholder.rs src/config/env_parse.rs src/config/custom_file.rs src/handler/llm/pump/spawn.rs src/service/audit/hold.rs src/service/pii/scope.rs` 全部 ≤800（apply 阶段复核）
- [x] 5.2（可选）为 `spawn.rs`/`audit/hold.rs`/`pii/scope.rs` 按既有模板补 `file_len_under_800_or_split` 红线守护；不立强制拆分
    - Verify: 若执行：`cargo test file_len_under_800_or_split` 全绿，新守护在对应测试模块内且旧路径 re-export 编译通过
    - Verify: 若不执行：在 change 归档说明记录未做理由；`openspec validate veil-hygiene-round5 --strict` valid 且无强制拆分任务残留

## 6. `D6` 协议扩展检查清单（暂不数据驱动重构）

- [x] 6.1 design.md 记录「暂不重构」决策与需同步的 match 点清单：`usage.rs`/`tool.rs`/`sse/meta.rs`/`block_inject/frames.rs`/`placeholder.rs`/`handler/llm/mod.rs::protocol_header_value`/`rewrite.rs`/`block_inject.rs` 等（新增第 4 协议预估 8-12 处）
    - Verify: `grep -n "STRICT_TAILS\|暂不" openspec/changes/veil-hygiene-round5/design.md` 命中决策与清单
    - Verify: `grep -rn "Protocol::" src/service/llm_gateway/usage.rs src/service/llm_gateway/placeholder.rs src/service/sse/meta.rs src/handler/llm/mod.rs` 命中点与 design 清单一致（复核记录）
- [x] 6.2（可选）在 `src/service/llm_gateway/protocol.rs:24` `STRICT_TAILS` 附近补「新增协议检查清单」注释（列出同步点），零行为影响
    - Verify: `grep -n "新增协议" src/service/llm_gateway/protocol.rs` 命中注释且 `cargo build` 通过
    - Verify: `cargo test -p veil llm_gateway` 全绿（注释零行为影响，`STRICT_TAILS` 数据不变）

## 7. 非缺陷澄清记录（`C1`/`C2`，无代码改动）

- [x] 7.1 design D7 记录 `C1`：`credential_approval_timeout_secs` 定义/装配于 `env_parse.rs:189/362`、生产读取于 `credential/approval.rs:77`（阻塞审批超时）——有效配置，禁止当死码删除
    - Verify: `grep -rn "credential_approval_timeout_secs" src/` 同时命中定义/装配与 `approval.rs:77` 使用点
    - Verify: `grep -n "credential_approval_timeout_secs" openspec/changes/veil-hygiene-round5/design.md` 命中澄清且含「禁止当死码删除」
- [x] 7.2 design D7 记录 `C2`：`credential_vault.rs:63-64 snapshot_calls` 已 `#[cfg(test)]` gating，非问题（X3/D4 复杂度回归观测）
    - Verify: `grep -n -B2 "snapshot_calls" src/service/credential_vault.rs` 命中 `#[cfg(test)]` 邻近行
    - Verify: `grep -n "snapshot_calls" openspec/changes/veil-hygiene-round5/design.md` 命中澄清记录

## 8. `D7` 观察记录 + `C3`/`C4` 非缺陷登记（无强制实现）

- [x] 8.1 design D8 记录 `D7`：facade 层 `pub use {a::*, b::*}` 全量 glob（`src/config.rs`、`src/service/{pii,metrics,redaction,audit,matrix}.rs`）同名歧义观察；可选显式重导出或加 owner 注释，无强制实现
    - Verify: `grep -n "全量 glob\|glob 重导出\|同名" openspec/changes/veil-hygiene-round5/design.md` 命中 D8 记录
    - Verify: `grep -rn "pub use" src/config.rs src/service/pii.rs src/service/metrics.rs src/service/redaction.rs src/service/audit.rs src/service/matrix.rs` 命中 glob 形态（观察证据，apply 阶段复核）
- [x] 8.2 design D7 记录 `C3`：审计/指标脱敏双引擎为文档化契约分治，SHALL NOT 合并
    - Verify: `grep -rn "契约分治\|不合并" src/service/audit/log.rs src/service/metrics/summarize.rs` 命中两处声明
    - Verify: `grep -n "C3" openspec/changes/veil-hygiene-round5/design.md` 命中澄清
- [x] 8.3 design D7 记录 `C4`：`wal_checkpoint_truncate` 非死码（错误路径容错调用），禁止当死码删除
    - Verify: `grep -rn "wal_checkpoint_truncate" src/service/metrics/store.rs` 命中定义与错误路径调用
    - Verify: `grep -n "C4" openspec/changes/veil-hygiene-round5/design.md` 命中澄清

## 9. 门禁与回归

- [x] 9.1 `cargo fmt --check`、`cargo clippy --tests --all-targets -- -D warnings`、`cargo test`、`cargo build --release` 全绿；`D1`/`D2`/`D3` 符号在 release 构建零引用
    - Verify: 四条命令退出码 0，`cargo build --release` 无 `dead_code`/unused 告警
    - Verify: `grep -rn "pub fn contains_request_token\|pub fn migrate_python_registry" src/` 零命中（两者生产零引用）；`load_admin_token_file` 保留 `#[cfg(test)] pub fn` 形态（release 构建零符号，故不纳入该 grep）
- [x] 9.2 `openspec validate veil-hygiene-round5 --strict` 0 failures；未修改既有 change/spec
    - Verify: 命令输出 `is valid`
    - Verify: `git status --porcelain openspec/changes/ openspec/specs/` 仅新增 `veil-hygiene-round5/`，无其他 change/spec 修改

> 说明：`D3` 经复核 HEAD 已满足（`events.rs:37-45` 已 `#[cfg(test)]`，README §3 同字），第 3 节为验证锁定，预期零代码改动；`D1`/`D2` 每项 MUST 单独编译验证（pub 面 lint 盲区下逐项验证是唯一可靠捕获手段，禁止两项合并后一次性编译）。
