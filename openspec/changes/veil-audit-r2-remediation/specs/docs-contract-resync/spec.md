## ADDED Requirements

### Requirement: 归档 change spec 历史行号指针修正

对归档 change 的 spec 中失效的历史 `path:line` 指针，系统 SHALL 以「仅修正指针、不改决策文本」为原则批量对齐到实际内容（覆盖 `docs-contract-resync`、`code-quality-cleanup` 等归档 spec），SHALL 保留归档语义与历史判定；修正后 SHALL NOT 引入与归档结论冲突的新陈述，SHALL NOT 改写需求正文或结论。指针修正的根因治理由 `docs-contract-sync`「文档行号引用可校验」承接。

#### Scenario: 归档 spec 指针对齐

- **WHEN** 扫描归档 change spec 中的 `path:line` 引用并与目标文件内容比对
- **THEN** 失效指针被修正到实际内容对应行，决策文本与归档结论逐字保留

#### Scenario: 归档语义不被改写

- **WHEN** 检查任一被修正的归档 spec 的变更集
- **THEN** 变更仅涉及指针（路径/行号），无需求正文或结论语义改动

## MODIFIED Requirements

### Requirement: spec 引用路径可校验

README 与 OpenSpec 制品中的 spec 路径引用 SHALL 由 `scripts/check_doc_paths.py` 校验存在性，覆盖 canonical（`openspec/specs/<capability>/spec.md`）与 change-local（`openspec/changes/<change>/specs/<capability>/spec.md`）两种完整路径形态；指向未归档 change 的 README 引用 SHALL 保留完整路径并标注「未归档」；`veil-hardening` 归档后 SHALL 更新为 canonical 且门禁保持通过。`scripts/README.md` SHALL 文档化 `check_doc_paths.py` 的 `PENDING_REFS` 例外语义：仅历史/情景性悬空引用以精确「源文件 + 引用」组合登记并打印 `PENDING`（不算失败），其余悬空引用（含 README.md 全部引用）一律 FAIL，使例外可被复核。

#### Scenario: 门禁通过并计数

- **WHEN** 运行 `python3 scripts/check_doc_paths.py`
- **THEN** 退出码 0，输出同时报告 `src/*.rs` 与 spec 引用校验计数；README:5/203 的 `admin-ratelimit-contract` change-local 路径判定存在

#### Scenario: 归档迁移触发更新

- **WHEN** `veil-hardening` 归档（或路径被移动）导致 `openspec/changes/veil-hardening/specs/admin-ratelimit-contract/spec.md` 不再存在<!-- doc-paths-ignore -->
- **THEN** 门禁非零退出并列出悬空引用的 `README.md` 行号，迫使同批更新为 canonical 路径；不得静默通过

#### Scenario: 未归档引用完整标注

- **WHEN** 检索 README 的 `admin-ratelimit-contract` 引用
- **THEN** 均为完整 change-local 路径 + 「未归档」标注，零裸名引用

#### Scenario: PENDING_REFS 例外已文档化

- **WHEN** 查阅 `scripts/README.md` 对 `check_doc_paths.py` 的说明
- **THEN** 命中 `PENDING_REFS` 例外语义（仅精确「源文件 + 引用」组合登记并打印 PENDING，README 引用永不登记），与脚本内注释同源
