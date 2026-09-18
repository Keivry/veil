# deadcode-positional-cleanup Specification

## Purpose

清除生产零引用符号与残留空码，移除不可达分支，确定化缺省上游选择，闭合 ENV 回环免 token 的未声明项。

## Requirements

### Requirement: 零生产引用符号清零

系统 SHALL NOT 保留以下生产零引用符号：`CredentialVault::contains_token`、`CredentialVault::global`、`CredentialVault::snapshot`/`VaultSnapshot`（除非 `#[cfg(test)]` 收编并注释）、`CredentialVault::redact`、`has_chat_terminal`、`should_discard_after_terminal`、`reject_new_dangerous_during_hold`、`AUDIT_TIMEOUT_SECS`、leaf 三测试辅助（`#[cfg(test)]` 收编即可）。该清单 SHALL 扩展覆盖死亡抽象 `ApprovalGateway` trait、`NoopApproval`、`ApprovalOutcome`（SHALL 删除或接线到生产路径），以及全部仅测试引用的 `pub` API（现 20 个，含 6 个 metrics getter）。仅测试引用的 `pub` API SHALL 收敛可见性（降为 `pub(crate)`/`#[cfg(test)]`）或接线到生产；其中 metrics getter（6 个）SHALL 随运行时可靠性指标在 `/_admin/metrics` 暴露（见 `runtime-reliability`），SHALL NOT 停留于仅测试引用。测试引用 SHALL 同步清理；保留者均为 `#[cfg(test)]` 收编且有注释。

`src/service/block_inject/terminal.rs` 的 `dedupe_terminal_frames` 与 `count_done` 为仅测试引用符号，SHALL 以 `#[cfg(test)]` 收编（与已收编的 `terminal_count` 同口径，`R7-07`）；门面重导出（`src/service/block_inject.rs`）SHALL 使非 test 构建不暴露被收编符号且编译通过——glob 重导出（`pub use {frames::*, terminal::*}`）随 `cfg` 自动收窄，若存在显式重导出则 SHALL 同加 `#[cfg(test)]`。收编 SHALL NOT 改变测试语义（含二者在测试内的字符串分派行为）。

r3 收敛集 SHALL 至少覆盖以下 5 个仅测试引用项：`GatewayMetrics::truncated_count`、`GatewayMetrics::hop_filtered_count`、`GatewayMetrics::nondialog_passthrough_count`、`MatrixApproval::pending_event_ids`、`chunk::scan_builtin`。该 5 项 SHALL NOT 存在生产路径引用。收敛方式 SHALL 按引用面判定：**仅被 lib 内单测引用且无级联依赖者**降为 `#[cfg(test)] pub(crate)`（与既有 `conv_missing_count`/`terminal_fallback_count` 模式一致）；**被 `tests/**` 集成测试引用者**（集成测试以非 `cfg(test)` 构建链接本库，`pub(crate)` 与 `#[cfg(test)]` 均不可见）或因级联依赖（如 `cached_*` 助手、`use` 面、`ValidationCache` 保留项）不可降者 SHALL 保留 `pub`，并以注释登记该构建约束与后续收敛条件，SHALL NOT 以误降破坏编译。

#### Scenario: 符号面收敛

- **WHEN** grep 上述符号的定义与引用
- **THEN** 无生产引用残留；保留者均为 `#[cfg(test)]` 收编且有注释

#### Scenario: 死抽象清零或接线

- **WHEN** grep `ApprovalGateway` / `NoopApproval` / `ApprovalOutcome`
- **THEN** 无生产零引用残留（删除）或已在生产路径接线，测试引用同步清理

#### Scenario: 仅测试 pub API 收敛或接线

- **WHEN** grep 仅测试引用的 `pub` API（含 6 个 metrics getter 与 r3 收敛集的 5 项）
- **THEN** 无仅测试引用残留：可见性已收敛或已接入生产；6 个 metrics getter 经 `/_admin/metrics` 暴露；r3 收敛集中仅被 lib 内单测引用者已降为 `#[cfg(test)] pub(crate)`，被集成测试引用或级联不可降者以注释登记保留 `pub`

#### Scenario: 终端去重与计数 helper 收编

- **WHEN** grep `dedupe_terminal_frames` 与 `count_done` 的定义、重导出与调用点
- **THEN** 二者均带 `#[cfg(test)]`、零生产调用点；非 test 构建（`cargo build`）通过且不暴露该符号；`cargo test` 全绿、测试语义不变

### Requirement: 残留空码清除

`credential/auth.rs` 的丢弃赋值（`let _ = effective;`）与 `credential/approval.rs` 的丢弃调用（`let _ = gateway.request_approval(...)`）SHALL 被移除，行为不变。

#### Scenario: 空码零命中

- **WHEN** grep `let _ = effective` / `let _ = gateway.request_approval`
- **THEN** 零命中，相关单测全绿

### Requirement: classify_empty 无死分支

`classify_empty` SHALL NOT 含生产不可达的 `StreamInjectThen502` 变体与 `is_stream` 参数；流式空流策略 SHALL 唯一归 `should_synthesize_empty_stream`。

#### Scenario: 三分支收敛

- **WHEN** 查阅并测试 `classify_empty`
- **THEN** 仅存生产可达分支；注释指向 `should_synthesize_empty_stream`

### Requirement: 缺省上游确定性

`resolve_upstream` 无默认上游时 SHALL 按端口升序取首个并记录 warn，SHALL NOT 依赖 HashMap 迭代序。

#### Scenario: 多端口缺省确定

- **WHEN** 配置两个 `LLM_<port>` 且无默认上游
- **THEN** 选择最小端口，warn 一次；重复运行结果一致

### Requirement: ENV 回环免 token 声明闭合

`ENV=dev` / `ALLOW_LOOPBACK_NO_TOKEN` 回环免 token 未迁移 SHALL 以 README §6.6 BREAKING 与 §7.4 表行声明；§6 首句计数 SHALL 与 README 当前口径一致（现为「十处」，`veil-docs-test-parity` 同步）。

#### Scenario: 声明可查

- **WHEN** 查阅 README §6.6 与 §7.4
- **THEN** 均含「回环免 token 未迁移」条目；§6 首句为「十处」

### Requirement: 矩阵授权死代码与注释清理

`authorize_entry` 与 `TurnToApproval` 的生产零引用死代码 SHALL 被清理或接线到生产路径；其相关注释 SHALL 与实现一致，SHALL NOT 保留误导性描述。

#### Scenario: 死代码清零或接线

- **WHEN** grep `authorize_entry` / `TurnToApproval`
- **THEN** 无生产零引用残留（删除）或已在生产路径接线

#### Scenario: 注释与实现一致

- **WHEN** 查阅上述符号相关注释
- **THEN** 注释描述与实现一致，无误导性描述

### Requirement: MXID 校验单一实现

`is_valid_mxid` SHALL 由单一实现承载，各调用点 SHALL 复用同一实现（经重导出）；SHALL NOT 保留逐字复制的多份实现。行为 SHALL 不变。

#### Scenario: 单一实现无副本

- **WHEN** grep `is_valid_mxid` 的定义
- **THEN** 仅一处定义，调用点复用，无逐字复制副本

#### Scenario: 校验行为等价

- **WHEN** 运行等价测试
- **THEN** 校验结果与合并前逐例一致

### Requirement: YAML 去引号单一实现

`strip_yaml_quotes` 与 `unquote` SHALL 合并为单一实现，SHALL NOT 保留两份重复逻辑；行为 SHALL 不变。

#### Scenario: 合并为单一实现

- **WHEN** grep `strip_yaml_quotes` / `unquote`
- **THEN** 仅存在单一实现（另一名称为重导出或已移除），无重复逻辑

#### Scenario: 去引号行为不变

- **WHEN** 运行去引号相关测试
- **THEN** 行为与合并前逐例一致

### Requirement: 锁中毒 helper 单一实现

重复的 poison helper（现三份）SHALL 合并为单一 helper，SHALL NOT 保留多份逐字复制实现；行为 SHALL 不变。

#### Scenario: 合并为单一 helper

- **WHEN** grep poison helper
- **THEN** 仅一处实现，各调用点复用

#### Scenario: 锁中毒行为不变

- **WHEN** 运行锁中毒相关测试
- **THEN** 行为与合并前逐例一致

### Requirement: 测试支撑 helper 提取共享模块

`file_len_under_800_or_split`（现复制 18 份）SHALL 提取至共享测试支撑模块并由各测试复用，SHALL NOT 保留逐字复制副本。

#### Scenario: helper 单一来源

- **WHEN** grep `file_len_under_800_or_split`
- **THEN** 仅一处定义（共享模块），各测试引用同一实现

#### Scenario: 测试行为不变

- **WHEN** 运行文件大小/拆分相关测试
- **THEN** 全部通过，行为不变

### Requirement: 生产重复逻辑有界抽取

系统 SHALL 将以下生产重复且语义关键的处理收敛为单一实现并复用：① 还原守卫纯逻辑（`inner_json_intact` 与 `restore_guard_ok`）收敛至零 axum 依赖的 `service::redaction::restore_guard`，供流式 `frame_feed` 与非流路径共用；② `x-veil-*` 内部头剥离收敛为 `llm_gateway::strip_veil_internal_headers`；③ `NORMALIZED_HEADER_NAME`/`NORMALIZED_HEADER_VALUE` 提升为生产 `pub(crate) const` 并替换字面量；④ Chat `[DONE]` 帧统一走 `chat_done_frame()`；⑤ SSE `data:` 帧构造统一走 `sse::data_frame`。

系统 SHALL 追加收敛：⑥ 还原帧发送收敛为单一 `emit_restored_json_frame`（handler 层，恒守卫 + 失败回退占位符帧），残余帧与正常帧共用；⑦ 下游 `x-veil-protocol` 头名提升为生产 `pub(crate) const PROTOCOL_HEADER_NAME`（与 `NORMALIZED_HEADER_NAME` 同址常量区）并替换 `src/handler/llm/dispatch.rs:366`、`src/handler/llm/nonstream.rs:239,509,554`、`src/handler/llm/mod.rs:61` 的字面量；⑧ `src/service/redaction/leaf.rs` 的近同形 helper 对（`prescan_custom`/`prescan_custom_response`、`redact_leaf_inner`/`redact_leaf_response`）以 `bool` 参（或共享私有实现）合并为单一实现；⑨ **文件体量驱动的有界抽取**（`B-2`，`veil-audit-r4-remediation`）：把 Responses 工具类型派生面（`responses_item_tool_name`、`responses_derived_tool_kind` 与 Responses `output[]`/delta 工具收集 helper）迁至 sibling 模块（如 `src/service/llm_gateway/tool_responses.rs`<!-- doc-paths-ignore -->），使其在 A/B 增补后 `src/service/llm_gateway/tool.rs`（当前 788 行）与各触及文件均 ≤800 行。

**文件体量约束（`B-2`）**：本 change 所有源码任务的落点文件 SHALL 在改动后满足 `scripts/check_file_sizes.py` 的 800 行硬上限（计全文件总行）。新增的 `emit_restored_json_frame` SHALL NOT 落在 `src/handler/llm/pump/spawn/event_loop.rs`（当前 753 行，已近上限）——SHALL 置于 sibling/新模块或 `src/handler/llm/pump/spawn/terminal.rs`（当前 343 行，余量充足）。

抽取 SHALL 为行为保持，字节与判定结果 SHALL 不变（请求表 vs 响应表注册语义、`minted` 追踪、仲裁与 `apply_spans` 逐项不变）。**测试内断言文本**（含 `#[cfg(test)] mod tests` 内的 `"data: [DONE]\n\n"` 字面量）与 `hop.rs` 动态项处理 SHALL NOT 纳入本次抽取。canonical `r2 归档勾选更正与保留范围声明` 中「`x-veil-protocol` 内联保留 SHALL NOT 属收敛范围」的旧声明 SHALL 被本要求取代（见相邻 requirement）。

#### Scenario: 还原守卫单一实现

- **WHEN** 检查流式帧路径与非流路径的还原守卫
- **THEN** 两处均调用 `service::redaction::restore_guard` 的共享谓词，无逐字重复实现，判定等价

#### Scenario: 内部头剥离与 DONE 帧单点

- **WHEN** grep `strip_veil_internal_headers` 与 `chat_done_frame`
- **THEN** 各自仅一处定义，全部调用点复用，剥离/信封字节与既有口径等价

#### Scenario: 还原帧发送单一 helper

- **WHEN** 检查残余帧路径与正常帧路径的还原发送点
- **THEN** 均调用 `emit_restored_json_frame`，守卫与失败回退口径一致，无内联直通

#### Scenario: 协议头名常量化

- **WHEN** grep `"x-veil-protocol"` 的生产代码
- **THEN** 仅命中 `PROTOCOL_HEADER_NAME` 常量定义，字面量全部被替换，响应头值不变

#### Scenario: leaf helper 合并行为保持

- **WHEN** 调用合并后的 `prescan_custom`/`redact_leaf_inner` 等价入口
- **THEN** 请求表与响应表注册、凭据还原授权与 PII 双向语义逐项不变，既有 `scope_tests`/`custom/tests` 全绿

#### Scenario: Responses 工具派生面抽取后行数合规

- **WHEN** A/B 增补落地并执行 `python3 scripts/check_file_sizes.py`（或逐文件 `wc -l`）
- **THEN** `src/service/llm_gateway/tool.rs` 抽出的 Responses 派生面已迁至 sibling 模块，`tool.rs` 与新增 sibling 文件均 ≤800 行，门禁 exit 0

#### Scenario: 还原帧 helper 落点不越线

- **WHEN** 检查 `emit_restored_json_frame` 的定义落点
- **THEN** 其不在 `src/handler/llm/pump/spawn/event_loop.rs`（避免 753 行文件越 800 上限），而在 sibling/新模块或 `src/handler/llm/pump/spawn/terminal.rs`（343 行）

### Requirement: r2 归档勾选更正与保留范围声明

本 change SHALL 显式注记：r2 归档变更 `veil-audit-r2-remediation` 的 `tasks.md` §8.4 勾选存在虚高，已在 `veil-audit-r3-remediation` 的 design 覆盖表中更正；归档目录 SHALL NOT 被修改（仅注记，apply 期历史快照非现行契约）。

r2/r3 声明的 `ValidationCache` 内联保留 SHALL NOT 属本 change 范围。`x-veil-protocol` 内联保留的旧声明 SHALL 被**取代**：其头名 SHALL 收敛为 `PROTOCOL_HEADER_NAME` 生产常量并替换全部字面量（与 `x-veil-normalized` 已常量化口径一致），SHALL NOT 继续以「内联保留」为由阻止收敛。该取代仅改声明与常量收敛，**SHALL NOT** 改变线协议头名与头值（改名即 BREAKING，本次不改名）。

#### Scenario: 更正注记存在

- **WHEN** 查阅 r3 design 覆盖表与 canonical `deadcode-positional-cleanup` spec
- **THEN** 含 r2 归档 §8.4 勾选更正的注记，归档目录未被修改

#### Scenario: x-veil-protocol 内联保留被取代

- **WHEN** 核查 `x-veil-protocol` 头名的收敛口径
- **THEN** spec 声明其由 `PROTOCOL_HEADER_NAME` 常量承载、字面量已替换；旧「内联保留」声明不再生效，线协议头名/头值不变

#### Scenario: 保留范围不重开

- **WHEN** 核查本 change 范围
- **THEN** `ValidationCache` 内联保留不在范围内，未被重开
