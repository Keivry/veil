# Spec Delta

## MODIFIED Requirements

### Requirement: 文档行号引用可校验

`scripts/check_doc_paths.py` SHALL 在路径存在性校验之外，解析 `path:line`（含 `path:start-end`）形式的行号引用并校验其落在目标文件实际行数范围内；行号越界 SHALL 非零退出并打印悬空引用所在文件与行。该校验 SHALL 纳入 `scripts/gate.sh` 的文档路径步骤，作为文档行号漂移的根因治理。

对符号引用（`文件::符号`，含多段 `文件::A::B`）SHALL 增加**存在性校验**：取符号链末段标识符，SHALL 在目标 `.rs` 文件内以标识符形态出现；目标为门面模块（同名目录存在，如 `src/service/block_inject.rs` 与 `src/service/block_inject/` 并存）时 SHALL 允许在该模块子树（同名目录下 `**/*.rs`）内解析，以覆盖 `pub use <子模块>::*` 重导出形态。解析失败 SHALL 非零退出并打印引用所在文件、行与符号（`R6-07`）。

在界校验 SHALL NOT 被当作内容一致性的充分条件：内容可能漂移的行号锚点 SHALL 改用符号锚点（`文件::符号`），使指针随实现演进保持可解析。符号存在性校验 SHALL 仅为**结构校验**（末段标识符存在性），SHALL NOT 被当作符号可见性、签名或「被引行/符号语义与文档叙述一致」的充分条件——后者的内容一致性 SHALL 仍由 code review 保证；`scripts/check_doc_paths.py` 的职责边界为「路径存在性 + 行号在界 + 符号末段标识符存在性」。归档 change 目录（`openspec/changes/archive/**`）的 `::Symbol` 引用为归档时刻冻结快照，SHALL 整体豁免存在性断言并按处数打印（与行号引用同口径）。README 的 `src/` 指针 SHALL 以此口径改写（含 §7.2 终端合成、§8.6 空流守门与漂移的 `dispatch.rs` 行号锚点）。本条为 `R5-22`（源码注释/文档指针校正）与 design D14（「符号锚点优先」）的规范落点；`R5-22` 的源码注释侧指针校正（见 `docs-test-parity` capability）SHALL 与本条同口径，两者 SHALL NOT 对同一指针给出不同要求。

#### Scenario: 越界行号致门禁失败

- **WHEN** 文档某 `path:line` 引用的行号超出目标文件实际行数（以临时构造的越界用例验证）
- **THEN** `scripts/check_doc_paths.py` 非零退出并列出该悬空引用，gate 文档路径步骤失败

#### Scenario: 合法行号引用通过

- **WHEN** 文档引用 `src/handler/llm/pump/spawn/event_loop.rs:414`（在文件行数范围内）
- **THEN** 校验通过、退出码 0，并报告行号引用校验计数

#### Scenario: 不稳定行号改符号锚点

- **WHEN** 核查 README 中实现位置易漂移的 `src/` 指针
- **THEN** 其采用符号锚点（如 `src/handler/llm/pump/spawn/terminator.rs::StreamTerminator::plan_midstream`），经 `scripts/check_doc_paths.py` 的路径存在性校验通过，不依赖易漂移的行号

#### Scenario: 缺失符号致门禁失败

- **WHEN** 文档引用 `src/error.rs::NoSuchSymbolForTest`（目标文件内不存在的末段标识符，临时构造用例）<!-- doc-paths-ignore -->
- **THEN** `scripts/check_doc_paths.py` 非零退出并打印该引用所在文件、行与符号，gate 文档路径步骤失败

#### Scenario: 门面重导出符号可解析

- **WHEN** 文档引用 `src/service/block_inject.rs::protocol_block_frames_modeled`（实现位于 `src/service/block_inject/frames.rs`，经门面 `pub use` 重导出）
- **THEN** 校验通过（模块子树解析），符号引用计数包含该处

#### Scenario: 归档符号引用豁免

- **WHEN** 归档 change 文档（`openspec/changes/archive/**`）含现行源码已不存在的符号引用
- **THEN** 该引用不被判失败，脚本按处数打印「归档文档符号引用 N 处未校验」（与行号引用同口径）
