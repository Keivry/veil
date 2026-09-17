# Design

## Context

见 `proposal.md` → Why。影响本设计的既有约束：

- canonical `docs-contract-sync`「文档行号引用可校验」当前明文：「对非 `path:line` 形态的引用（如纯符号引用）SHALL 保持路径存在性校验不变」——本 change 正是改写该句，故必须走 delta。
- `scripts/check_doc_paths.py` 既有机制：行级 `<!-- doc-paths-ignore -->`、`（勘误：…）` 片段剥离、归档 change 行号豁免 + 计数打印、`PENDING_REFS`/`PENDING_LINE_REFS` 登记表、`--self-test`（行号越界检出）。
- R6 实测数据：全仓 130 处唯一 `::symbol` 引用中，1 处落在门面重导出（`src/service/block_inject.rs::protocol_block_frames_modeled`，实现在 `src/service/block_inject/frames.rs`，经门面 `pub use {frames::*, terminal::*}` 导出）、2 处在归档快照，其余直接命中。

## Goals / Non-Goals

**Goals:**

- 让 `::symbol` 末段标识符的笔误/改名在门禁失败（根因治理）。
- 对存量引用零误报（含门面重导出与归档快照两类）。
- 实现、例外机制与报告口径与既有行号通道对称。

**Non-Goals:**

- 符号可见性（`pub`）、签名、语义或文档叙述一致性校验。
- 宏生成符号的完备解析。
- 为其他 change 目录引入新登记表。

## Decisions

### D1 解析规则：末段标识符 + 门面子树回退（采纳）

- 取 `::` 链末段标识符，在目标文件内以 `\b<ident>\b` 匹配即通过（`fn`/`struct`/`enum`/`const`/`static`/`mod`/`trait`/`type`/`macro_rules!`/变体/方法均以标识符形态出现）。
- 未命中且存在同名目录（`X.rs` 与 `X/` 目录并存）时，在该子树 `**/*.rs` 内匹配即通过——覆盖门面 `pub use <子模块>::*`（R6 实测唯一误报源）。
- **备选（拒绝）**：仅校验目标文件（产生 1 处既有文档假阳性）；解析 `pub use` 链做可达性（复杂、宏重导出不可判定）；调用 `rustc`/`cargo doc`（重、慢、需构建）。

### D2 归档豁免（采纳）

- `openspec/changes/archive/**` 的符号引用与行号引用同口径整体豁免，打印「归档文档符号引用 N 处未校验」。
- 理由：冻结快照不得回改（canonical `docs-test-parity` 同口径）；归档中的 `recover_mutex` 等已消失符号属历史记录。
- **备选（拒绝）**：按 `PENDING_REFS` 逐项登记归档符号 —— 登记表膨胀且语义重复。

### D3 不新增 `PENDING_SYMBOL_REFS`（采纳）

- 例外出口：行级 ignore marker、勘误剥离、归档豁免。当前无任何存量违规需要登记，不预置空表（避免死代码）。
- **备选（拒绝）**：对称引入登记表 —— YAGNI；未来若出现「其他 change 规划期引用未落地符号」，再按 `PENDING_REFS` 模式补建。

### D4 报告与失败语义（采纳）

- 新增计数 `symbol_checked`、`archived_symbol_refs`；失败走既有 `FAIL:` 列表 + 非零退出，与路径/行号失败并列展示。
- `--self-test` 扩展为确定性覆盖：缺失符号检出、门面子树放行、归档豁免判定。

## Risks / Trade-offs

- [仅出现在注释/字符串的同名标识符会被判定为存在（假阴性）] → 已实测确认该局限；对本仓现存语料零影响（逐项扫描无任何引用仅靠注释命中），且与「结构校验、非语义校验」边界一致；若未来出现，以行级 ignore marker 或勘误标注处置。
- [宏生成符号无法匹配] → 生成名通常也以宏调用/定义标识符出现；若仍假阳性，用行级 ignore marker 或勘误标注（启发式边界已声明）。
- [极短标识符（如 `new`）可能同名误判] → 本校验只防「名字写错」，不防「同名不同物」——与「结构校验、非语义校验」的边界声明一致。
- [门面子树匹配会放过未重导出的私有符号] → 接受：目标是可解析性下限；可达性校验列为非目标。
- [门禁对存量引用产生新增失败] → 已全量预扫（130 处唯一引用，预期 0 失败），apply 期实测验证。

## Migration Plan

- 无数据/配置迁移；推送后无需运维动作。
- 回滚：`git revert` 单提交即可（脚本 + 文档 + 规范同步，无运行时影响）。

## Open Questions

无。若未来出现需登记的符号例外，按 D3 补 `PENDING_SYMBOL_REFS`。
