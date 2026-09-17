# Spec Delta

## MODIFIED Requirements

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
