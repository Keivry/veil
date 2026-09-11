## Purpose

锁定拆分收敛与文档修正的可验证行为：超限拆分、红线看护、垫片收敛、引用全绿。

## ADDED Requirements

### Requirement: A-D2 超限拆分或改线二选一

系统 SHALL 使 `sse.rs` 与 `block_inject.rs` 单文件均 ≤800 且对外路径不变，或 SHALL 书面修正验收线并同步文档，二选一 SHALL 由全绿锁定。

#### Scenario: 拆后全绿

- **WHEN** 拆分完成
- **THEN** `cargo test` + conformance + `check_doc_paths` 全绿（H4.1 实测 183 处）

### Requirement: A-NEAR 红线看护

系统 SHALL 对 `src/config/env_parse.rs`/`src/registry.rs`/`src/config/custom_file.rs` 加长度断言或拆分预案，超 800 SHALL 触发拆分任务。

#### Scenario: 超限触发

- **WHEN** 任一文件超 800 行
- **THEN** 看护单测失败并指向拆分任务

### Requirement: A-SHIM 垫片收敛

系统 SHALL 明确四组垫片 owner 为 `service/*` 实体，根垫片 SHALL 仅重导出加废弃指引。

#### Scenario: 新代码走实体

- **WHEN** grep 四组符号引用
- **THEN** 生产引用指向实体路径，根仅重导出与测试

### Requirement: D-800 文档实测一致与 Z 常驻验证

系统 SHALL 使文档 800 断言与实测同字；每任务 SHALL 以零死代码/重复与 `check_doc_paths` 全绿（H4.1 实测 183 处）为常驻 Verify。

#### Scenario: 文档可信

- **WHEN** 查阅 800 断言
- **THEN** 与实测行数一致
