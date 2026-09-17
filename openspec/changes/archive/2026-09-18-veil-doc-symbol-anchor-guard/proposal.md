# Proposal

## Why

R6 Oracle 复审登记项：README 与 canonical spec 现有 130 处唯一 `::symbol` 符号锚点引用，但 `scripts/check_doc_paths.py` 的职责边界仅为「路径存在性 + 行号在界」（该边界由 canonical `docs-contract-sync`「文档行号引用可校验」明文界定，R6 design D1 亦因此拒绝扩展语义校验）。后果：**符号锚点末段标识符被写错或改名后，门禁完全不拦截**——把 `VeilError::code` 的末段拼错、或把已重命名的符号留在文档里，都能与路径存在性校验一并通过并静默漂移。

Oracle 复审明确区分两件事：「行内容/符号语义与文档叙述一致」（需改写 canonical 边界、交由 code review）与本项「标识符存在性结构校验」（廉价、独立）。本 change 只做后者。

## What Changes

- `scripts/check_doc_paths.py`：
  - 新增 `::symbol` 引用通道：解析 `src/...rs::Sym[::Sym2]`，取末段标识符，在目标 `.rs` 内做标识符存在性断言；目标为门面模块（`X.rs` 与 `X/` 目录并存，如 `src/service/block_inject.rs`）时允许在模块子树 `X/**/*.rs` 内解析，以覆盖 `pub use <子模块>::*` 重导出。
  - 归档 change 目录（`openspec/changes/archive/**`）的符号引用为归档时刻冻结快照，整体豁免并按处数打印（与行号引用同口径）。
  - `--self-test` 扩展为确定性覆盖：缺失符号检出、门面子树放行、归档豁免判定。
  - 新增符号引用计数与 FAIL 明细输出。
- 文档口径：`scripts/README.md` 的 `check_doc_paths.py` 段、`scripts/gate.sh` 第 4 步头注、脚本模块 docstring 同步新边界。
- Canonical 边界更新：`docs-contract-sync`「文档行号引用可校验」MODIFIED（经本 change delta，归档时合并）。

### Non-goals

- 不做符号可见性/签名/语义校验，也不做「被引行内容与文档叙述一致性」校验（仍由 code review 保证）。
- 不新增 `PENDING_SYMBOL_REFS` 登记表：例外出口沿用既有行级 `<!-- doc-paths-ignore -->`、`（勘误：…）` 剥离与归档豁免。
- 不为宏生成符号做完备解析（启发式边界已在 design 声明）。

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `docs-contract-sync`: 「文档行号引用可校验」扩展为「路径存在性 + 行号在界 + 符号存在性」；新增门面子树解析、归档符号豁免与 3 条 scenario。

## Impact

- **脚本**：`scripts/check_doc_paths.py`（扫描、计数、失败输出、`--self-test`、docstring）。
- **文档**：`scripts/README.md`、`scripts/gate.sh`（第 4 步头注）。
- **规范**：1 个 canonical capability delta（`docs-contract-sync`）。
- **存量影响（预扫实测）**：非归档符号引用 200 处（106 唯一），其中仅 1 处（`src/service/block_inject.rs::protocol_block_frames_modeled`）依赖门面子树回退（经核实门面 `pub use {frames::*, terminal::*}` 真实重导出），其余直接命中 —— 新增 0 失败；归档 change 目录的 199 处符号引用按冻结快照整体豁免。
- 无 API/配置/依赖变更；无 BREAKING（对存量引用零新增失败）。
