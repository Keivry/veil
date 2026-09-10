# arch-file-size-closeout Specification

## Purpose

使全仓 `src/**/*.rs` 单文件不超过 800 行可维护红线（含测试与注释口径），以脚本 + 单测双锁防漂移，并收口 8 个历史超线文件。

## Requirements

### Requirement: 全仓单文件 800 行上限

系统 SHALL 使 `src/**/*.rs` 任一文件行数 ≤800；`scripts/check_file_sizes.py` SHALL 扫描全仓并在超线时非零退出（无白名单）。

#### Scenario: 全仓扫描零超线

- **WHEN** 运行 `python3 scripts/check_file_sizes.py`
- **THEN** 退出码 0 且输出无超线文件

#### Scenario: 新增超线文件即失败

- **WHEN** 任一 `src/**/*.rs`（含新增文件）超过 800 行
- **THEN** 脚本非零退出并列出文件路径与行数

### Requirement: 曾超线八文件双 ≤800 与就地守卫

`service/llm_gateway/placeholder.rs`、`service/metrics/store.rs`、`service/llm_gateway/tool.rs`、`service/pii/detector.rs`、`service/metrics/aggregate.rs`、`service/pii/chunk.rs`、`service/metrics/sample.rs`、`handler/llm/nonstream.rs` 及其外迁测试文件 SHALL 各自 ≤800 行，且各含 `file_len_under_800_or_split` 守卫单测（口径 = 文件总行含测试与注释）。

#### Scenario: 守卫就近失败

- **WHEN** 上述任一主文件或测试文件超过 800 行
- **THEN** 对应 `file_len_under_800_or_split` 单测失败，消息含文件名、实测行数与拆分指引

#### Scenario: 外迁后测试语义与数量不变

- **WHEN** 运行 `cargo test`
- **THEN** 全绿，且 8 文件外迁测试的函数数量与断言不减少

### Requirement: 既有三守卫保持有效

`src/config/env_parse.rs`、`src/registry.rs`、`src/config/custom_file.rs` 的现有 `file_len_under_800_or_split` 守卫 SHALL 保持有效且不被改写。

#### Scenario: 存量守卫不回归

- **WHEN** 运行 `cargo test file_len_under_800`
- **THEN** 3 处存量守卫与 8 处新增守卫全部通过（共 11 处）
