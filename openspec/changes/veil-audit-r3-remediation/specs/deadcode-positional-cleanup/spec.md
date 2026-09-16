## MODIFIED Requirements

### Requirement: 零生产引用符号清零

系统 SHALL NOT 保留以下生产零引用符号：`CredentialVault::contains_token`、`CredentialVault::global`、`CredentialVault::snapshot`/`VaultSnapshot`（除非 `#[cfg(test)]` 收编并注释）、`CredentialVault::redact`、`has_chat_terminal`、`should_discard_after_terminal`、`reject_new_dangerous_during_hold`、`AUDIT_TIMEOUT_SECS`、leaf 三测试辅助（`#[cfg(test)]` 收编即可）。该清单 SHALL 扩展覆盖死亡抽象 `ApprovalGateway` trait、`NoopApproval`、`ApprovalOutcome`（SHALL 删除或接线到生产路径），以及全部仅测试引用的 `pub` API（现 20 个，含 6 个 metrics getter）。仅测试引用的 `pub` API SHALL 收敛可见性（降为 `pub(crate)`/`#[cfg(test)]`）或接线到生产；其中 metrics getter（6 个）SHALL 随运行时可靠性指标在 `/_admin/metrics` 暴露（见 `runtime-reliability`），SHALL NOT 停留于仅测试引用。测试引用 SHALL 同步清理；保留者均为 `#[cfg(test)]` 收编且有注释。

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

## ADDED Requirements

### Requirement: 生产重复逻辑有界抽取

系统 SHALL 将以下生产重复且语义关键的处理收敛为单一实现并复用：① 还原守卫纯逻辑（`inner_json_intact` 与 `restore_guard_ok`）收敛至零 axum 依赖的 `service::redaction::restore_guard`，供流式 `frame_feed` 与非流路径共用；② `x-veil-*` 内部头剥离收敛为 `llm_gateway::strip_veil_internal_headers`；③ `NORMALIZED_HEADER_NAME`/`NORMALIZED_HEADER_VALUE` 提升为生产 `pub(crate) const` 并替换字面量；④ Chat `[DONE]` 帧统一走 `chat_done_frame()`；⑤ SSE `data:` 帧构造统一走 `sse::data_frame`。抽取 SHALL 为行为保持，字节与判定结果 SHALL 不变。测试内断言文本与 `hop.rs` 动态项处理 SHALL NOT 纳入本次抽取。

#### Scenario: 还原守卫单一实现

- **WHEN** 检查流式帧路径与非流路径的还原守卫
- **THEN** 两处均调用 `service::redaction::restore_guard` 的共享谓词，无逐字重复实现，判定等价

#### Scenario: 内部头剥离与 DONE 帧单点

- **WHEN** grep `strip_veil_internal_headers` 与 `chat_done_frame`
- **THEN** 各自仅一处定义，全部调用点复用，剥离/信封字节与既有口径等价

### Requirement: r2 归档勾选更正与保留范围声明

本 change SHALL 显式注记：r2 归档变更 `veil-audit-r2-remediation` 的 `tasks.md` §8.4 勾选存在虚高，已在本 change 的 design 覆盖表中更正；归档目录 SHALL NOT 被修改（仅注记，apply 期历史快照非现行契约）。r2 已声明的 `ValidationCache` 与 `x-veil-protocol` 内联保留 SHALL NOT 属本 change 范围。

#### Scenario: 更正注记存在

- **WHEN** 查阅本 change 的 design 覆盖表与 canonical `deadcode-positional-cleanup` spec
- **THEN** 含 r2 归档 §8.4 勾选更正的注记，归档目录未被修改

#### Scenario: 保留范围不重开

- **WHEN** 核查本 change 范围
- **THEN** `ValidationCache` 与 `x-veil-protocol` 内联保留不在范围内，未被重开
