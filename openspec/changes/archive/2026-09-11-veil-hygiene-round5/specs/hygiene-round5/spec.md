## Purpose

锁定代码卫生第五轮（`hygiene-round5`）的四项可验证契约：生产零引用的测试专用符号收编（`D1` `PiiScope::contains_request_token`、`D2` `CallerRegistry::migrate_python_registry`、`D3` `load_admin_token_file`）与掩码双引擎差异显式锁定（`D4` `mask_pii_value` vs `sample_mask`）。全部为行为保持型清理/测试加固，不放宽任何 fail-closed 与脱敏语义。

## ADDED Requirements

### Requirement: PII 请求 token 查询测试专用化

`PiiScope::contains_request_token`（`src/service/pii/scope.rs:269`）SHALL NOT 以生产可见的 `pub fn` 形态存在；SHALL 降为 `#[cfg(test)]` 测试专用（对齐 `PiiScope::next_available_index` 的既有处置，`scope.rs:121-129`）。生产构建 SHALL 不含该符号且无 `dead_code`/unused 告警；`#[cfg(test)]` 编译下测试 SHALL 保持可用，跨请求还原隔离与 LRU 淘汰断言 SHALL NOT 被删除或弱化。

#### Scenario: 生产构建零引用

- **WHEN** 执行 `cargo build --release` 并 grep `pub fn contains_request_token` in `src/`
- **THEN** grep 零命中，release 构建无 dead_code/unused 告警

#### Scenario: 测试仍可用

- **WHEN** 执行 `cargo test -p veil pii`，覆盖 `scope.rs:391/395/403/424/454/650` 六处测试调用
- **THEN** 全部通过；跨请求隔离（响应期 token 不入请求表）与 LRU 淘汰断言保持原样

### Requirement: Python 注册表迁移测试专用化

`CallerRegistry::migrate_python_registry`（`src/registry/migrate.rs:41`）SHALL NOT 以生产可见的 `pub fn` 形态存在；SHALL 移入 `#[cfg(test)]`（若改走 `examples/` 须在 design 记录理由）。生产加载入口 SHALL 保持唯一：`CallerRegistry::load_from` 的新格式解析与完整性校验路径不变；Python 旧格式（`version/callers/allowed_entries`）解析、迁移告警与 `.bak` 备份语义 SHALL 保持不变，测试（`registry.rs:644`）SHALL 保持通过。

#### Scenario: 生产构建零引用

- **WHEN** 执行 `cargo build --release` 并 grep `pub fn migrate_python_registry` in `src/`
- **THEN** grep 零命中，生产二进制不含迁移函数

#### Scenario: 迁移语义不变

- **WHEN** 执行 `cargo test -p veil registry`（含 Python 旧格式迁移用例）
- **THEN** 迁移条目字段（`script_path`/`script_hash`/`name`/`enabled`/`allowed_entries`）与 `.bak` 备份断言全绿，`load_from` 新格式路径不受影响

### Requirement: admin token 文件加载测试专用化

`load_admin_token_file`（`src/service/admin/events.rs:41`）SHALL 仅以 `#[cfg(test)]` gating 存在，生产构建 SHALL 零引用；README §3「B1.2 token 文件加载仅 `cfg(test)` 生效（生产 fail-closed 口径不变）」SHALL 与代码同字。测试 SHALL 保持缺文件/空文件/纯空白/首尾空白 trim 生效四类边界断言。

#### Scenario: 生产构建零引用

- **WHEN** 执行 `cargo build --release` 并检查 release 产物符号（`nm`/`strings`）中的 `load_admin_token_file`
- **THEN** release 产物零命中；源码中 `#[cfg(test)]` 前置的 gating 定义仍在（`events.rs:40-41`，保留 `pub fn` 形态），生产构建不编译该符号

#### Scenario: README 声明与代码同字

- **WHEN** 对照 README §3 的「仅 `cfg(test)` 生效」声明与 `events.rs` gating 状态
- **THEN** 两处零矛盾；若 gating 缺失或声明漂移，按本 Requirement 恢复 gating 并保持 fail-closed 口径

#### Scenario: 测试边界保持

- **WHEN** 执行 `cargo test -p veil admin_token_file`
- **THEN** `admin_token_file_isolation` 与 `admin_token_file_empty_vs_missing_edges` 全绿，边界断言不被删除

### Requirement: 掩码双引擎差异锁定

`pii::detector::mask_pii_value`（LLM 侧）与 `metrics::sample::sample_mask`（指标侧）SHALL NOT 被强合并（SHALL NOT 以公共 `mask_core` 统一或互相委托）。两引擎 SHALL 由新增差分测试以同一 `(kind, value)` 矩阵显式锁定输出关系：一致项 SHALL 断言相等，预期差异项 SHALL 断言各自的具体允许输出并注明理由。差异清单 SHALL 至少覆盖：bank 别名集（detector `bank_card|bankcard|id_card` vs sample `bank|bank_card`）、`apikey` 别名（detector 有 vs sample 无）、ipv4 非四段且 len≥8 回退（detector 前3后3 vs sample 前4后4）、email 无点域名回退（detector 短值 vs sample `***@***`）；phone 各长度边界（<2/2-5/6/≥7）经逐分支核对为等价，SHALL 由差分测试锁定该等价（如实测有差异，以测试实测为准并入差异清单）。两消费方既有输出 SHALL 保持不变，两引擎各自既有单测 SHALL 全绿。

#### Scenario: 差异被锁定

- **WHEN** 以 kind×value 矩阵执行跨引擎差分测试
- **THEN** 上述四类差异按允许输出断言通过；任何新增未登记分叉使测试失败

#### Scenario: 一致项不被误改

- **WHEN** 两引擎接收 phone 各边界长度（<2/2-5/6/≥7）及其余非差异 `(kind, value)` 输入
- **THEN** 输出相等；`mask_pii_value`/`sample_mask` 各自既有单测（`detector/tests.rs`、`sample/tests.rs`）全绿

#### Scenario: 不合并决策可追溯

- **WHEN** 查阅 `design.md` D4 与差分测试注释
- **THEN** 记录「不抽 `mask_core`、不合并两实现」的取舍与理由；如后续要求完全一致，须另立 change 逐差异裁定
